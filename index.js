require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");

const app = express();
app.use(cors());
app.use(express.json());

const db = new Pool({ connectionString: process.env.DATABASE_URL });

async function iniciarDB() {
  await db.query(`
    CREATE TABLE IF NOT EXISTS usuarios (
      id SERIAL PRIMARY KEY,
      nombre TEXT NOT NULL,
      dni TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      rol TEXT DEFAULT 'actuario',
      debe_cambiar_password INTEGER DEFAULT 1
    )
  `);

  await db.query(`
    CREATE TABLE IF NOT EXISTS actuaciones (
      id SERIAL PRIMARY KEY,
      usuario_id INTEGER REFERENCES usuarios(id),
      numero TEXT NOT NULL,
      damnificado TEXT NOT NULL,
      lugar TEXT NOT NULL,
      caratula TEXT NOT NULL,
      fecha_recepcion TEXT NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);

  await db.query(`
    CREATE TABLE IF NOT EXISTS tareas (
      id SERIAL PRIMARY KEY,
      actuacion_id INTEGER REFERENCES actuaciones(id) ON DELETE CASCADE,
      nombre TEXT NOT NULL,
      completada INTEGER DEFAULT 0
    )
  `);

  // Crear admin por defecto si no existe
  const admin = await db.query("SELECT * FROM usuarios WHERE rol = 'admin'");
  if (admin.rows.length === 0) {
    const hash = await bcrypt.hash("admin1234", 10);
    await db.query(
      "INSERT INTO usuarios (nombre, dni, password, rol, debe_cambiar_password) VALUES ($1, $2, $3, $4, $5)",
      ["Administrador", "00000000", hash, "admin", 0]
    );
    console.log("Admin creado — DNI: 00000000 / Password: admin1234");
  }

  console.log("Base de datos lista");
}

iniciarDB();

// ---- MIDDLEWARE ----
function autenticar(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) return res.status(401).json({ error: "No autorizado" });
  try {
    const datos = jwt.verify(token, process.env.JWT_SECRET);
    req.usuario = datos;
    next();
  } catch {
    res.status(401).json({ error: "Token inválido" });
  }
}

function soloAdmin(req, res, next) {
  if (req.usuario.rol !== "admin") return res.status(403).json({ error: "Solo admins" });
  next();
}

// ---- AUTH ----
app.post("/auth/login", async (req, res) => {
  const { dni, password } = req.body;
  const resultado = await db.query("SELECT * FROM usuarios WHERE dni = $1", [dni]);
  const usuario = resultado.rows[0];
  if (!usuario) return res.status(400).json({ error: "DNI o contraseña incorrectos" });
  const valido = await bcrypt.compare(password, usuario.password);
  if (!valido) return res.status(400).json({ error: "DNI o contraseña incorrectos" });
  const token = jwt.sign(
    { id: usuario.id, nombre: usuario.nombre, rol: usuario.rol, debe_cambiar_password: usuario.debe_cambiar_password },
    process.env.JWT_SECRET,
    { expiresIn: "7d" }
  );
  res.json({ token, usuario: { id: usuario.id, nombre: usuario.nombre, dni: usuario.dni, rol: usuario.rol, debe_cambiar_password: usuario.debe_cambiar_password } });
});

app.post("/auth/cambiar-password", autenticar, async (req, res) => {
  const { password_nueva } = req.body;
  const hash = await bcrypt.hash(password_nueva, 10);
  await db.query(
    "UPDATE usuarios SET password = $1, debe_cambiar_password = 0 WHERE id = $2",
    [hash, req.usuario.id]
  );
  res.json({ mensaje: "Contraseña actualizada" });
});

// ---- ADMIN — GESTIÓN DE USUARIOS ----
app.get("/admin/usuarios", autenticar, soloAdmin, async (req, res) => {
  const resultado = await db.query("SELECT id, nombre, dni, rol, debe_cambiar_password FROM usuarios ORDER BY nombre");
  res.json(resultado.rows);
});

app.post("/admin/usuarios", autenticar, soloAdmin, async (req, res) => {
  const { nombre, dni } = req.body;
  const passwordTemporal = dni; // la contraseña temporal es el mismo DNI
  const hash = await bcrypt.hash(passwordTemporal, 10);
  try {
    const resultado = await db.query(
      "INSERT INTO usuarios (nombre, dni, password, rol, debe_cambiar_password) VALUES ($1, $2, $3, 'actuario', 1) RETURNING id, nombre, dni",
      [nombre, dni, hash]
    );
    res.status(201).json({ ...resultado.rows[0], password_temporal: passwordTemporal });
  } catch {
    res.status(400).json({ error: "El DNI ya está registrado" });
  }
});

app.delete("/admin/usuarios/:id", autenticar, soloAdmin, async (req, res) => {
  await db.query("DELETE FROM usuarios WHERE id = $1 AND rol != 'admin'", [req.params.id]);
  res.json({ mensaje: "Usuario eliminado" });
});

// ---- ACTUACIONES ----
app.get("/actuaciones", autenticar, async (req, res) => {
  const resultado = await db.query(
    "SELECT * FROM actuaciones WHERE usuario_id = $1 ORDER BY created_at DESC",
    [req.usuario.id]
  );
  res.json(resultado.rows);
});

app.post("/actuaciones", autenticar, async (req, res) => {
  const { numero, damnificado, lugar, caratula, fecha_recepcion } = req.body;
  const resultado = await db.query(
    "INSERT INTO actuaciones (usuario_id, numero, damnificado, lugar, caratula, fecha_recepcion) VALUES ($1, $2, $3, $4, $5, $6) RETURNING *",
    [req.usuario.id, numero, damnificado, lugar, caratula, fecha_recepcion]
  );
  const actuacion = resultado.rows[0];
  const tareasDefault = ["Leer", "Oficiar", "Analizar", "Elevar"];
  for (const nombre of tareasDefault) {
    await db.query("INSERT INTO tareas (actuacion_id, nombre) VALUES ($1, $2)", [actuacion.id, nombre]);
  }
  res.status(201).json(actuacion);
});

app.delete("/actuaciones/:id", autenticar, async (req, res) => {
  await db.query("DELETE FROM actuaciones WHERE id = $1 AND usuario_id = $2", [req.params.id, req.usuario.id]);
  res.json({ mensaje: "Eliminada" });
});

// ---- TAREAS ----
app.get("/actuaciones/:id/tareas", autenticar, async (req, res) => {
  const resultado = await db.query("SELECT * FROM tareas WHERE actuacion_id = $1", [req.params.id]);
  res.json(resultado.rows);
});

app.post("/actuaciones/:id/tareas", autenticar, async (req, res) => {
  const resultado = await db.query(
    "INSERT INTO tareas (actuacion_id, nombre) VALUES ($1, $2) RETURNING *",
    [req.params.id, req.body.nombre]
  );
  res.status(201).json(resultado.rows[0]);
});

app.put("/tareas/:id", autenticar, async (req, res) => {
  const resultado = await db.query(
    "UPDATE tareas SET completada = $1 WHERE id = $2 RETURNING *",
    [req.body.completada, req.params.id]
  );
  res.json(resultado.rows[0]);
});

app.delete("/tareas/:id", autenticar, async (req, res) => {
  await db.query("DELETE FROM tareas WHERE id = $1", [req.params.id]);
  res.json({ mensaje: "Tarea eliminada" });
});

const PORT = process.env.PORT || 3000;

app.put("/admin/usuarios/:id/reset-password", autenticar, soloAdmin, async (req, res) => {
  const resultado = await db.query("SELECT dni FROM usuarios WHERE id = $1", [req.params.id])
  const usuario = resultado.rows[0]
  if (!usuario) return res.status(404).json({ error: "Usuario no encontrado" })
  
  const hash = await bcrypt.hash(usuario.dni, 10)
  await db.query(
    "UPDATE usuarios SET password = $1, debe_cambiar_password = 1 WHERE id = $2",
    [hash, req.params.id]
  )
  res.json({ mensaje: "Contraseña reseteada al DNI" })
})

app.listen(PORT, () => console.log("Servidor corriendo en puerto " + PORT));