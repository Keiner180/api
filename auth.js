const jwt = require("jsonwebtoken");
const db = require("./db.json"); // tu base de datos de json-server
const bcrypt = require("bcrypt");

const SECRET_KEY = "mi_secreto_super_seguro"; // tu clave secreta

async function login(req, res) {
    const { email, password } = req.body;

    // Buscar usuario
    const user = db.users.find(u => u.email.toLowerCase() === email.toLowerCase());
    if (!user) return res.status(401).json({ error: "Usuario o contraseña incorrecta" });

    // Verificar contraseña
    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ error: "Usuario o contraseña incorrecta" });

    // Crear token con toda la info del usuario
    const token = jwt.sign(
        { ...user }, // payload: toda la info del usuario
        SECRET_KEY,
        { expiresIn: "1h" } // duración del token
    );

    res.json({ token });
}

module.exports = { login };
