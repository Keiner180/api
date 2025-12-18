// server.js
const jsonServer = require("json-server");
const auth = require("json-server-auth");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const cloudinary = require("./cloudinary");
const multer = require("multer");
const upload = multer();
const db = require("./db.json");
const stream = require("stream");
const { log } = require("console");


const server = jsonServer.create();
const router = jsonServer.router("db.json");
const middlewares = jsonServer.defaults();

// --- Configuración CORS ---
server.use(cors({
    origin: [
        "http://localhost:5173",
        "http://localhost:5174",
        "https://emma-25413.web.app"
    ],
    methods: ["GET", "POST", "PUT", "PATCH", "DELETE"],
    allowedHeaders: ["Content-Type", "Authorization"],
}));

server.use(jsonServer.bodyParser);
server.db = router.db;
server.use(middlewares);

server.use((req, res, next) => {
    res.setHeader("Cache-Control", "no-store, no-cache, must-revalidate, proxy-revalidate");
    res.setHeader("Pragma", "no-cache");
    res.setHeader("Expires", "0");
    next();
});


const SECRET_KEY = "mi_secreto_super_seguro"; // tu clave secreta JWT

server.post("/login", async (req, res) => {
    const { email, password } = req.body;

    const user = server.db.get("users").find({ email }).value();

    if (!user) return res.status(401).json({ error: "Usuario no encontrado " });

    const valid = await bcrypt.compare(password, user.password);

    if (!valid) return res.status(401).json({ error: "Contraseña incorrect" });

    const token = jwt.sign({ ...user }, SECRET_KEY, { expiresIn: "3h" });
    res.json({ token, user });
});



// --- Subir imagen a Cloudinary ---
server.post("/upload", upload.single("file"), async (req, res) => {
    const file = req.file;
    if (!file) return res.status(400).json({ error: "Archivo requerido" });

    try {
        const result = await cloudinary.uploader.upload_stream(
            { folder: "emma-img" },
            (error, result) => {
                if (error) return res.status(500).json({ error: "Error subiendo imagen" });
                res.json({ url: result.secure_url, public_id: result.public_id });
            }
        );
        // Convertir buffer en stream
        const stream = require("stream");
        const bufferStream = new stream.PassThrough();
        bufferStream.end(file.buffer);
        bufferStream.pipe(result);
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Error subiendo imagen" });
    }
});

server.post("/upload-document", upload.single("file"), (req, res) => {
    const file = req.file;
    if (!file) return res.status(400).json({ error: "Archivo requerido" });

    const bufferStream = new stream.PassThrough();
    bufferStream.end(file.buffer);

    cloudinary.uploader.upload_stream(
        {
            resource_type: "raw",
            folder: "documentos",
            use_filename: true,
            unique_filename: false,
            filename_override: file.originalname,
            type: "authenticated",
        },
        (error, result) => {
            if (error) {
                console.error(error);
                return res.status(500).json({ error: "Error subiendo documento" });
            }

            // URL temporal válida 5 min
            const tempUrl = cloudinary.utils.private_download_url(
                result.public_id,
                null,
                {
                    resource_type: "raw",
                    expires_at: Math.floor(Date.now() / 1000) + 300,
                }
            );

            res.json({
                public_id: result.public_id,  // Ej: "documentos/foto_1.docx"
                original_name: file.originalname,
                size: result.bytes,
                format: result.format,
                url: tempUrl,
            });
        }
    ).end(file.buffer);
});

// =====================
// 2️⃣ Endpoint: Obtener URL temporal de un documento existente
// =====================
server.get("/document/:publicId/download", (req, res) => {
  const publicId = decodeURIComponent(req.params.publicId);

  try {
    const url = cloudinary.utils.private_download_url(
      publicId,
      null,
      { resource_type: "raw", expires_at: Math.floor(Date.now()/1000)+300 }
    );

    // Redirigir al navegador a la URL temporal
    res.redirect(url);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "No se pudo generar la URL" });
  }
});










// --- Eliminar imagen de Cloudinary ---
server.delete("/delete-image/:folder/:id", async (req, res) => {
    const { folder, id } = req.params;
    const public_id = `${folder}/${id}`;

    try {
        const result = await cloudinary.uploader.destroy(public_id);
        res.json({ ok: true, result });
    } catch (err) {
        console.error(err);
        res.status(500).json({ error: "Error eliminando imagen" });
    }
});

server.get("/verify-token", (req, res) => {
    const auth = req.headers.authorization;

    if (!auth) {
        return res.status(401).json({ valid: false, message: "Token no enviado" });
    }

    const token = auth.split(" ")[1];

    try {
        const decoded = jwt.verify(token, SECRET_KEY);
        return res.json({ valid: true, user: decoded });
    } catch (error) {
        return res.status(401).json({ valid: false, message: "Token inválido o expirado" });
    }
});

// --- Endpoint de verificación de token ---
server.get("/verify-token", (req, res) => {
    const auth = req.headers.authorization;

    if (!auth) {
        return res.status(401).json({ valid: false, message: "No token provided" });
    }

    const token = auth.split(" ")[1];

    try {
        const decoded = jwt.verify(token, server.get("key")); // tu clave del token
        return res.json({ valid: true });
    } catch (error) {
        return res.status(401).json({ valid: false, message: "Invalid token" });
    }
});

// --- Autenticación JSON Server Auth ---
server.use(auth);

server.use(auth);        // json-server-auth

server.use(async (req, res, next) => {
    if ((req.method === "PUT" || req.method === "PATCH") && req.path.startsWith("/users/")) {

        // Extraer ID y convertir a número
        const userId = Number(req.path.replace("/users/", ""));

        const users = server.db.get("users");
        const currentUser = users.find({ id: userId }).value();

        if (!currentUser) {
            return res.status(404).json({ error: "Usuario no encontrado" });
        }

        // Si password viene vacío → conservar el actual
        if (!req.body.password || req.body.password.trim() === "") {
            req.body.password = currentUser.password;
        } else {
            // Si viene uno nuevo → hashear
            const salt = await bcrypt.genSalt(10);
            req.body.password = await bcrypt.hash(req.body.password, salt);
        }
    }

    next();
});


// ——— FIN DEL FIX ———

server.use(router);

// --- Rutas normales de json-server ---
server.use(router);

// --- Iniciar servidor ---
const PORT = 3000;
server.listen(PORT, () => {
    console.log(`Servidor corriendo en http://localhost:${PORT}`);
});