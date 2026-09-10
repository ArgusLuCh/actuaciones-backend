require("dotenv").config();
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const { Pool } = require("pg");

const app = express();
app.use(cors());
app.use(express.json());

// Punto público y liviano para comprobar disponibilidad o despertar el servicio.
app.get("/health", function(req, res) {
  res.json({ ok: true })
})

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
      actuario_responsable TEXT,
      elevada INTEGER NOT NULL DEFAULT 0,
      elevada_en TIMESTAMP,
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);

  // Mantener compatibilidad con bases de datos creadas antes del historial.
  await db.query("ALTER TABLE actuaciones ADD COLUMN IF NOT EXISTS elevada INTEGER NOT NULL DEFAULT 0");
  await db.query("ALTER TABLE actuaciones ADD COLUMN IF NOT EXISTS elevada_en TIMESTAMP");
  await db.query("ALTER TABLE actuaciones ADD COLUMN IF NOT EXISTS actuario_responsable TEXT");

  await db.query(`
    CREATE TABLE IF NOT EXISTS tareas (
      id SERIAL PRIMARY KEY,
      actuacion_id INTEGER REFERENCES actuaciones(id) ON DELETE CASCADE,
      nombre TEXT NOT NULL,
      completada INTEGER DEFAULT 0
    )
  `);

  // Base extensible para el registro general de actividad. Las actuaciones
  // existentes se conservan mientras se realiza una migración posterior.
  await db.query(`
    CREATE TABLE IF NOT EXISTS registros_actividad (
      id SERIAL PRIMARY KEY,
      tipo TEXT NOT NULL,
      numero_interno TEXT,
      referencia TEXT,
      fecha_ingreso DATE,
      caratula TEXT,
      fiscalia TEXT,
      actuario TEXT,
      causa TEXT,
      acusados TEXT,
      damnificado TEXT,
      diligencia TEXT,
      resultado TEXT,
      elevacion TEXT,
      destino_elevacion TEXT,
      capital_interior TEXT,
      cantidad INTEGER,
      observaciones TEXT,
      usuario_id INTEGER REFERENCES usuarios(id),
      created_at TIMESTAMP DEFAULT NOW()
    )
  `);
  await db.query(`
    CREATE UNIQUE INDEX IF NOT EXISTS registros_tipo_numero_interno_unico
    ON registros_actividad (tipo, numero_interno)
    WHERE numero_interno IS NOT NULL
  `);
  await db.query(`
    CREATE TABLE IF NOT EXISTS allanamiento_domicilios (
      id SERIAL PRIMARY KEY,
      registro_id INTEGER REFERENCES registros_actividad(id) ON DELETE CASCADE,
      domicilio TEXT NOT NULL,
      localidad TEXT,
      resultado TEXT,
      detenidos INTEGER NOT NULL DEFAULT 0,
      secuestros JSONB NOT NULL DEFAULT '[]'::jsonb,
      observaciones TEXT,
      UNIQUE (registro_id, domicilio)
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

app.get("/admin/actuaciones", autenticar, soloAdmin, async (req, res) => {
  const resultado = await db.query(`
    SELECT
      actuaciones.*,
      COALESCE(actuaciones.actuario_responsable, usuarios.nombre) AS responsable_nombre,
      usuarios.dni AS responsable_dni
    FROM actuaciones
    INNER JOIN usuarios ON usuarios.id = actuaciones.usuario_id
    ORDER BY actuaciones.created_at DESC
  `);
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
  // Primero eliminar las actuaciones del usuario (las tareas se borran en cascada)
  await db.query("DELETE FROM actuaciones WHERE usuario_id = $1", [req.params.id])
  // Después eliminar el usuario
  await db.query("DELETE FROM usuarios WHERE id = $1 AND rol != 'admin'", [req.params.id])
  res.json({ mensaje: "Usuario eliminado" })
});

// ---- ACTUACIONES ----
app.get("/actuaciones", autenticar, async (req, res) => {
  const resultado = await db.query(
    "SELECT * FROM actuaciones WHERE usuario_id = $1 AND elevada = 0 ORDER BY created_at DESC",
    [req.usuario.id]
  );
  res.json(resultado.rows);
});

app.get("/actuaciones/historial", autenticar, async (req, res) => {
  const resultado = await db.query(
    "SELECT * FROM actuaciones WHERE usuario_id = $1 AND elevada = 1 ORDER BY elevada_en DESC",
    [req.usuario.id]
  );
  res.json(resultado.rows);
});

app.post("/actuaciones", autenticar, async (req, res) => {
  const { numero, damnificado, lugar, caratula, fecha_recepcion, actuario_responsable } = req.body;
  const numeroNormalizado = String(numero || "").replace(/\s+/g, "").toUpperCase();
  const existente = await db.query(
    "SELECT id FROM actuaciones WHERE UPPER(REGEXP_REPLACE(numero, '\\s+', '', 'g')) = $1 LIMIT 1",
    [numeroNormalizado]
  );
  if (existente.rows.length > 0) {
    return res.status(409).json({ error: "Ya existe una actuación con ese número" });
  }
  const responsableTexto = String(actuario_responsable || "").trim().toUpperCase() || null;
  if (req.usuario.rol === "admin" && !responsableTexto) {
    return res.status(400).json({ error: "Seleccioná el actuario responsable" });
  }
  const resultado = await db.query(
    "INSERT INTO actuaciones (usuario_id, numero, damnificado, lugar, caratula, fecha_recepcion, actuario_responsable) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING *",
    [req.usuario.id, numero, damnificado, lugar, caratula, fecha_recepcion, responsableTexto]
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

app.put("/actuaciones/:id/elevar", autenticar, async (req, res) => {
  const actuacion = await db.query(
    "SELECT id FROM actuaciones WHERE id = $1 AND usuario_id = $2 AND elevada = 0",
    [req.params.id, req.usuario.id]
  );

  if (actuacion.rows.length === 0) {
    return res.status(404).json({ error: "Actuación no encontrada" });
  }

  const pendientes = await db.query(
    "SELECT COUNT(*) AS cantidad FROM tareas WHERE actuacion_id = $1 AND completada = 0",
    [req.params.id]
  );

  if (Number(pendientes.rows[0].cantidad) > 0) {
    return res.status(400).json({ error: "Completá todas las tareas antes de elevar la actuación" });
  }

  const resultado = await db.query(
    "UPDATE actuaciones SET elevada = 1, elevada_en = NOW() WHERE id = $1 AND usuario_id = $2 RETURNING *",
    [req.params.id, req.usuario.id]
  );
  res.json(resultado.rows[0]);
});

// ---- TAREAS ----
app.get("/actuaciones/:id/tareas", autenticar, async (req, res) => {
  const resultado = await db.query(
    "SELECT * FROM tareas WHERE actuacion_id = $1 ORDER BY id ASC",
    [req.params.id]
  )
  res.json(resultado.rows)
})

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

// ESTADÍSTICAS — solo admin
app.get("/estadisticas", autenticar, soloAdmin, async (req, res) => {
  const resultado = await db.query(`
    SELECT 
      a.id,
      a.numero,
      a.damnificado,
      a.lugar,
      a.caratula,
      a.fecha_recepcion,
      a.created_at,
      a.elevada,
      a.elevada_en,
      COALESCE(a.actuario_responsable, u.nombre) AS actuario_nombre,
      u.dni AS actuario_dni
    FROM actuaciones a
    JOIN usuarios u ON a.usuario_id = u.id
    ORDER BY a.created_at DESC
  `)
  res.json(resultado.rows)
})

app.get("/estadisticas/resumen", autenticar, soloAdmin, async (req, res) => {
  const anio = Number(req.query.anio) || null;
  const actuaciones = await db.query(`
    SELECT COUNT(*)::int AS total, COUNT(*) FILTER (WHERE elevada = 1)::int AS elevadas
    FROM actuaciones
    WHERE ($1::int IS NULL OR EXTRACT(YEAR FROM created_at) = $1)
  `, [anio]);
  const actividades = await db.query(`
    SELECT tipo, COUNT(*)::int AS cantidad_registros, COALESCE(SUM(cantidad), 0)::int AS cantidad_total
    FROM registros_actividad
    WHERE ($1::int IS NULL OR EXTRACT(YEAR FROM created_at) = $1)
    GROUP BY tipo
  `, [anio]);
  const allanamientos = await db.query(`
    SELECT COUNT(DISTINCT r.id)::int AS ordenes,
           COUNT(d.id)::int AS domicilios,
           COALESCE(SUM(d.detenidos), 0)::int AS detenidos
    FROM registros_actividad r
    LEFT JOIN allanamiento_domicilios d ON d.registro_id = r.id
    WHERE r.tipo = 'allanamiento'
      AND ($1::int IS NULL OR EXTRACT(YEAR FROM r.created_at) = $1)
  `, [anio]);
  res.json({
    actuaciones: actuaciones.rows[0],
    actividades: actividades.rows,
    allanamientos: allanamientos.rows[0]
  });
});

// ---- REGISTRO GENERAL DE ACTIVIDAD ----
const tiposActividad = ["allanamiento", "oficio_judicial", "inspeccion_ocular", "colaboracion", "dcco"];

function textoNormalizado(valor) {
  return String(valor || "").trim().replace(/\s+/g, " ").toUpperCase();
}

app.get("/registros-actividad", autenticar, async (req, res) => {
  const resultado = await db.query(`
    SELECT r.*, COALESCE(
      json_agg(json_build_object(
        'id', d.id, 'domicilio', d.domicilio, 'localidad', d.localidad,
        'resultado', d.resultado, 'detenidos', d.detenidos,
        'secuestros', d.secuestros, 'observaciones', d.observaciones
      ) ORDER BY d.id) FILTER (WHERE d.id IS NOT NULL), '[]'
    ) AS domicilios
    FROM registros_actividad r
    LEFT JOIN allanamiento_domicilios d ON d.registro_id = r.id
    GROUP BY r.id
    ORDER BY r.created_at DESC
  `);
  res.json(resultado.rows);
});

app.get("/registros-actividad/posibles-duplicados", autenticar, async (req, res) => {
  const tipo = textoNormalizado(req.query.tipo).toLowerCase();
  const numeroInterno = textoNormalizado(req.query.numero_interno);
  const referencia = textoNormalizado(req.query.referencia);
  const causa = textoNormalizado(req.query.causa);

  if (!tiposActividad.includes(tipo)) return res.status(400).json({ error: "Tipo de actividad inválido" });
  const resultado = await db.query(`
    SELECT id, tipo, numero_interno, referencia, causa, fecha_ingreso, created_at
    FROM registros_actividad
    WHERE tipo = $1 AND (
      ($2 <> '' AND numero_interno = $2)
      OR ($3 <> '' AND referencia = $3 AND COALESCE(causa, '') = $4)
    )
    ORDER BY created_at DESC
    LIMIT 5
  `, [tipo, numeroInterno, referencia, causa]);
  res.json(resultado.rows);
});

app.post("/registros-actividad", autenticar, async (req, res) => {
  const datos = req.body || {};
  const tipo = textoNormalizado(datos.tipo).toLowerCase();
  const numeroInterno = textoNormalizado(datos.numero_interno) || null;
  const referencia = textoNormalizado(datos.referencia) || null;
  const causa = textoNormalizado(datos.causa) || null;
  const domicilios = Array.isArray(datos.domicilios) ? datos.domicilios : [];

  if (!tiposActividad.includes(tipo)) return res.status(400).json({ error: "Tipo de actividad inválido" });
  if (["oficio_judicial", "inspeccion_ocular", "colaboracion"].includes(tipo) && !numeroInterno) {
    return res.status(400).json({ error: "El número interno es obligatorio" });
  }
  if (tipo === "allanamiento" && (!referencia || !causa || domicilios.length === 0)) {
    return res.status(400).json({ error: "Completá actuación o reporte NMCEC, causa y al menos un domicilio" });
  }
  if (tipo === "dcco" && (!Number.isInteger(Number(datos.cantidad)) || Number(datos.cantidad) < 0)) {
    return res.status(400).json({ error: "Ingresá una cantidad válida para DCCO" });
  }

  try {
    const registro = await db.query(`
      INSERT INTO registros_actividad (
        tipo, numero_interno, referencia, fecha_ingreso, caratula, fiscalia,
        actuario, causa, acusados, damnificado, diligencia, resultado,
        elevacion, destino_elevacion, capital_interior, cantidad, observaciones, usuario_id
      ) VALUES (
        $1, $2, $3, COALESCE($4::date, CURRENT_DATE), $5, $6,
        $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18
      ) RETURNING *
    `, [
      tipo, numeroInterno, referencia, datos.fecha_ingreso || null,
      textoNormalizado(datos.caratula) || null, textoNormalizado(datos.fiscalia) || null,
      textoNormalizado(datos.actuario) || null, causa, textoNormalizado(datos.acusados) || null,
      textoNormalizado(datos.damnificado) || null, String(datos.diligencia || "").trim() || null,
      textoNormalizado(datos.resultado) || null, textoNormalizado(datos.elevacion) || null,
      textoNormalizado(datos.destino_elevacion) || null, textoNormalizado(datos.capital_interior) || null,
      tipo === "dcco" ? Number(datos.cantidad) : null, String(datos.observaciones || "").trim() || null,
      req.usuario.id
    ]);

    for (const domicilio of domicilios) {
      const direccion = textoNormalizado(domicilio.domicilio);
      if (!direccion) throw new Error("Cada domicilio debe tener dirección");
      await db.query(`
        INSERT INTO allanamiento_domicilios
        (registro_id, domicilio, localidad, resultado, detenidos, secuestros, observaciones)
        VALUES ($1, $2, $3, $4, $5, $6::jsonb, $7)
      `, [
        registro.rows[0].id, direccion, textoNormalizado(domicilio.localidad) || null,
        textoNormalizado(domicilio.resultado) || null, Number(domicilio.detenidos) || 0,
        JSON.stringify(Array.isArray(domicilio.secuestros) ? domicilio.secuestros : []),
        String(domicilio.observaciones || "").trim() || null
      ]);
    }
    res.status(201).json(registro.rows[0]);
  } catch (error) {
    if (error.code === "23505") return res.status(409).json({ error: "Ya existe un registro con ese número interno" });
    res.status(400).json({ error: error.message || "No se pudo registrar la actividad" });
  }
});

app.listen(PORT, () => console.log("Servidor corriendo en puerto " + PORT));
