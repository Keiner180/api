// server.js
const jsonServer = require("json-server");
const auth = require("json-server-auth");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const cloudinary = require("./cloudinary");
const multer = require("multer");
const stream = require("stream");

const server = jsonServer.create();
const router = jsonServer.router("db.json");
const middlewares = jsonServer.defaults();

server.use(cors());
server.use(jsonServer.bodyParser);
server.use(middlewares);

server.db = router.db;

// 🔐 CLAVE JWT
const SECRET_KEY = "mi_secreto_super_seguro";


// =====================
// LOGIN
// =====================
server.post("/auth/login", async (req, res) => {
    const { email, password } = req.body;

    const user = server.db.get("users").find({ email }).value();

    if (!user) {
        return res.status(401).json({ error: "Usuario no encontrado" });
    }

    const valid = await bcrypt.compare(password, user.password);

    if (!valid) {
        return res.status(401).json({ error: "Contraseña incorrecta" });
    }

    // 🚨 Validar si está activo
    if (user.active === false) {
        return res.status(403).json({ error: "Usuario inactivo" });
    }

    const token = jwt.sign({ id: user.id, email: user.email }, SECRET_KEY, {
        expiresIn: "3h",
    });

    res.json({ token, user });
});

// =====================
// VALIDAR SI BENEFICIARIO EXISTE (Por Documento)
// =====================
server.get("/beneficiaries/exists", (req, res) => {
    const { documentNumber, excludeId } = req.query;

    if (!documentNumber) {
        return res.status(400).json({ exists: false });
    }

    const beneficiaries = server.db.get("beneficiaries").value() || [];

    const exists = beneficiaries.some((b) => {
        if (excludeId && String(b.id) === String(excludeId)) return false;
        return String(b.documentNumber) === String(documentNumber);
    });

    res.json({ exists });
});


// =====================
// VERIFICAR TOKEN
// =====================
server.get("/verify-token", (req, res) => {
    const authHeader = req.headers.authorization;

    if (!authHeader) {
        return res.status(401).json({ valid: false, message: "Token no enviado" });
    }

    const token = authHeader.split(" ")[1];

    try {
        const decoded = jwt.verify(token, SECRET_KEY);
        return res.json({ valid: true, user: decoded });
    } catch (error) {
        return res.status(401).json({ valid: false, message: "Token inválido" });
    }
});


// =====================
// VALIDAR SI USUARIO EXISTE
// =====================
server.get("/users/exists", (req, res) => {
    const { field, value, excludeId } = req.query;

    if (!field || !value) {
        return res.status(400).json({ exists: false });
    }

    const users = server.db.get("users").value();

    const exists = users.some((user) => {
        if (excludeId && String(user.id) === String(excludeId)) return false;
        return String(user[field]).toLowerCase() === String(value).toLowerCase();
    });

    res.json({ exists });
});


// =====================
// HASH PASSWORD AL CREAR USUARIO
// =====================
server.use(async (req, res, next) => {
    if (req.method === "POST" && req.path === "/users") {
        if (req.body.password) {
            const salt = await bcrypt.genSalt(10);
            req.body.password = await bcrypt.hash(req.body.password, salt);
        }
    }
    next();
});


// =====================
// HASH PASSWORD AL ACTUALIZAR
// =====================
server.use(async (req, res, next) => {
    if ((req.method === "PUT" || req.method === "PATCH") && req.path.startsWith("/users/")) {

        const userId = Number(req.path.replace("/users/", ""));
        const users = server.db.get("users");
        const currentUser = users.find({ id: userId }).value();

        if (!currentUser) {
            return res.status(404).json({ error: "Usuario no encontrado" });
        }

        if (!req.body.password || req.body.password.trim() === "") {
            req.body.password = currentUser.password;
        } else {
            const salt = await bcrypt.genSalt(10);
            req.body.password = await bcrypt.hash(req.body.password, salt);
        }
    }

    next();
});


// =====================
// SUBIR IMAGEN
// =====================
const upload = multer();

server.post("/upload", upload.single("file"), async (req, res) => {
    if (!req.file) return res.status(400).json({ error: "Archivo requerido" });

    const bufferStream = new stream.PassThrough();
    bufferStream.end(req.file.buffer);

    cloudinary.uploader.upload_stream(
        { folder: "emma-img" },
        (error, result) => {
            if (error) return res.status(500).json({ error: "Error subiendo imagen" });

            res.json({
                url: result.secure_url,
                public_id: result.public_id,
            });
        }
    ).end(req.file.buffer);
});


// =====================
// ELIMINAR ARCHIVO
// =====================
server.delete("/delete-file", async (req, res) => {
    const { public_id, type } = req.query;

    if (!public_id) {
        return res.status(400).json({ message: "public_id requerido" });
    }

    const resourceType = type === "raw" ? "raw" : "image";

    const result = await cloudinary.uploader.destroy(public_id, {
        resource_type: resourceType,
    });

    res.json({ ok: true, result });
});


// =====================
// JSON SERVER AUTH + ROUTES
// =====================
server.use(auth);
server.use(router);


// =====================
// START SERVER
// =====================
const PORT = process.env.PORT || 3000;

server.listen(PORT, () => {
    console.log(`Servidor corriendo en puerto ${PORT}`);
});