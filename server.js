const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');
const path = require('path');
const os = require('os');

const app = express();
const PORT = process.env.PORT || 3002;
const JWT_SECRET = process.env.JWT_SECRET || 'bela-transporte-secret-2026';

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL ? { rejectUnauthorized: false } : false
});

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.static(__dirname));

// ── INIT DB ──────────────────────────────────────────────────
async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS usuarios (
      id SERIAL PRIMARY KEY,
      nombre TEXT NOT NULL,
      usuario TEXT UNIQUE NOT NULL,
      password TEXT NOT NULL,
      rol TEXT DEFAULT 'chofer',
      activo BOOLEAN DEFAULT true,
      creado TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS vehiculos (
      id SERIAL PRIMARY KEY,
      placa TEXT UNIQUE NOT NULL,
      marca TEXT, modelo TEXT, anio TEXT, tipo TEXT,
      km_actuales NUMERIC DEFAULT 0,
      vence_soat DATE, vence_matricula DATE,
      chofer_asignado TEXT,
      estado TEXT DEFAULT 'activo',
      ultimo_mantenimiento DATE, proximo_mantenimiento DATE,
      creado TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS viajes (
      id SERIAL PRIMARY KEY,
      origen TEXT, destino TEXT, tipo_carga TEXT,
      vehiculo_id INT, vehiculo_placa TEXT,
      flete NUMERIC DEFAULT 0,
      horas_extra NUMERIC DEFAULT 0,
      km_recorridos NUMERIC DEFAULT 0,
      observacion TEXT, foto TEXT,
      fecha DATE, mes TEXT,
      chofer_id INT, chofer_nombre TEXT,
      estado TEXT DEFAULT 'completado',
      creado TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS gastos (
      id SERIAL PRIMARY KEY,
      tipo TEXT, monto NUMERIC DEFAULT 0,
      descripcion TEXT, foto TEXT,
      vehiculo_id INT, vehiculo_placa TEXT,
      viaje_id INT,
      fecha DATE, mes TEXT,
      chofer_id INT, chofer_nombre TEXT,
      aprobado BOOLEAN DEFAULT false,
      creado TIMESTAMP DEFAULT NOW()
    );
    CREATE TABLE IF NOT EXISTS meta_compra (
      id SERIAL PRIMARY KEY,
      mes TEXT UNIQUE NOT NULL,
      qq_meta NUMERIC DEFAULT 0
    );
  `);

  // Usuario admin inicial
  const { rows } = await pool.query('SELECT id FROM usuarios WHERE usuario = $1', ['admin']);
  if (rows.length === 0) {
    const hash = await bcrypt.hash('admin123', 10);
    await pool.query(
      'INSERT INTO usuarios (nombre, usuario, password, rol) VALUES ($1,$2,$3,$4)',
      ['Victor (Admin)', 'admin', hash, 'admin']
    );
    console.log('  Usuario admin creado: admin / admin123');
  }
}

// ── AUTH MIDDLEWARE ──────────────────────────────────────────
function auth(req, res, next) {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  if (!token) return res.status(401).json({ error: 'No autorizado' });
  try { req.user = jwt.verify(token, JWT_SECRET); next(); }
  catch(e) { res.status(401).json({ error: 'Token inválido' }); }
}
function soloAdmin(req, res, next) {
  if (req.user.rol !== 'admin') return res.status(403).json({ error: 'Solo admin' });
  next();
}

// ── LOGIN ────────────────────────────────────────────────────
app.post('/api/login', async (req, res) => {
  try {
    const { usuario, password } = req.body;
    const { rows } = await pool.query('SELECT * FROM usuarios WHERE usuario=$1 AND activo=true', [usuario]);
    if (!rows[0]) return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
    const ok = await bcrypt.compare(password, rows[0].password);
    if (!ok) return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
    const token = jwt.sign({ id: rows[0].id, nombre: rows[0].nombre, usuario: rows[0].usuario, rol: rows[0].rol }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, nombre: rows[0].nombre, rol: rows[0].rol, usuario: rows[0].usuario });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── USUARIOS ─────────────────────────────────────────────────
app.get('/api/usuarios', auth, soloAdmin, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT id,nombre,usuario,rol,activo,creado FROM usuarios ORDER BY nombre');
    res.json(rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/usuarios', auth, soloAdmin, async (req, res) => {
  try {
    const { nombre, usuario, password, rol } = req.body;
    const hash = await bcrypt.hash(password, 10);
    await pool.query('INSERT INTO usuarios (nombre,usuario,password,rol) VALUES ($1,$2,$3,$4)', [nombre, usuario, hash, rol||'chofer']);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/usuarios/:id', auth, soloAdmin, async (req, res) => {
  try {
    const { nombre, activo, rol } = req.body;
    await pool.query('UPDATE usuarios SET nombre=$1,activo=$2,rol=$3 WHERE id=$4', [nombre, activo, rol, req.params.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── VEHÍCULOS ────────────────────────────────────────────────
app.get('/api/vehiculos', auth, async (req, res) => {
  try {
    const { rows } = await pool.query('SELECT * FROM vehiculos ORDER BY placa');
    res.json(rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/vehiculos', auth, soloAdmin, async (req, res) => {
  try {
    const { placa, marca, modelo, anio, tipo, km_actuales, vence_soat, vence_matricula } = req.body;
    await pool.query(
      'INSERT INTO vehiculos (placa,marca,modelo,anio,tipo,km_actuales,vence_soat,vence_matricula) VALUES ($1,$2,$3,$4,$5,$6,$7,$8)',
      [placa, marca, modelo, anio, tipo, km_actuales||0, vence_soat||null, vence_matricula||null]
    );
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/vehiculos/:id', auth, soloAdmin, async (req, res) => {
  try {
    const campos = req.body;
    const sets = Object.keys(campos).map((k,i) => `${k}=$${i+1}`).join(',');
    const vals = [...Object.values(campos), req.params.id];
    await pool.query(`UPDATE vehiculos SET ${sets} WHERE id=$${vals.length}`, vals);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── VIAJES ───────────────────────────────────────────────────
app.get('/api/viajes', auth, async (req, res) => {
  try {
    const { mes } = req.query;
    let q = 'SELECT * FROM viajes WHERE 1=1';
    const params = [];
    if (req.user.rol !== 'admin') { params.push(req.user.id); q += ` AND chofer_id=$${params.length}`; }
    if (mes) { params.push(mes); q += ` AND mes=$${params.length}`; }
    q += ' ORDER BY fecha DESC, id DESC';
    const { rows } = await pool.query(q, params);
    res.json(rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/viajes', auth, async (req, res) => {
  try {
    const { origen, destino, tipo_carga, vehiculo_id, vehiculo_placa, flete, horas_extra, km_recorridos, observacion, fecha, foto } = req.body;
    const hoy = fecha || new Date().toISOString().split('T')[0];
    const mes = hoy.slice(0,7);
    const vid = vehiculo_id && vehiculo_id !== '' && vehiculo_id !== 'undefined' ? parseInt(vehiculo_id) : null;
    await pool.query(
      'INSERT INTO viajes (origen,destino,tipo_carga,vehiculo_id,vehiculo_placa,flete,horas_extra,km_recorridos,observacion,fecha,mes,chofer_id,chofer_nombre,foto) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)',
      [origen, destino, tipo_carga, vid, vehiculo_placa||'', parseFloat(flete)||0, parseFloat(horas_extra)||0, parseFloat(km_recorridos)||0, observacion, hoy, mes, req.user.id, req.user.nombre, foto||null]
    );
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/viajes/:id', auth, soloAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM viajes WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── GASTOS ───────────────────────────────────────────────────
app.get('/api/gastos', auth, async (req, res) => {
  try {
    const { mes } = req.query;
    let q = 'SELECT * FROM gastos WHERE 1=1';
    const params = [];
    if (req.user.rol !== 'admin') { params.push(req.user.id); q += ` AND chofer_id=$${params.length}`; }
    if (mes) { params.push(mes); q += ` AND mes=$${params.length}`; }
    q += ' ORDER BY fecha DESC, id DESC';
    const { rows } = await pool.query(q, params);
    res.json(rows);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/gastos', auth, async (req, res) => {
  try {
    const { tipo, monto, descripcion, vehiculo_id, vehiculo_placa, fecha, foto } = req.body;
    const hoy = fecha || new Date().toISOString().split('T')[0];
    const mes = hoy.slice(0,7);
    const aprobado = req.user.rol === 'admin';
    const vid = vehiculo_id && vehiculo_id !== '' && vehiculo_id !== 'undefined' ? parseInt(vehiculo_id) : null;
    await pool.query(
      'INSERT INTO gastos (tipo,monto,descripcion,vehiculo_id,vehiculo_placa,fecha,mes,chofer_id,chofer_nombre,aprobado,foto) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)',
      [tipo, parseFloat(monto)||0, descripcion, vid, vehiculo_placa||'', hoy, mes, req.user.id, req.user.nombre, aprobado, foto||null]
    );
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/gastos/:id/aprobar', auth, soloAdmin, async (req, res) => {
  try {
    await pool.query('UPDATE gastos SET aprobado=true WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/gastos/:id', auth, soloAdmin, async (req, res) => {
  try {
    await pool.query('DELETE FROM gastos WHERE id=$1', [req.params.id]);
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── DASHBOARD ────────────────────────────────────────────────
app.get('/api/dashboard', auth, async (req, res) => {
  try {
    const mes = new Date().toISOString().slice(0,7);
    const esAdmin = req.user.rol === 'admin';
    const filtro = esAdmin ? '' : `AND chofer_id=${req.user.id}`;

    const viajesR = await pool.query(`SELECT * FROM viajes WHERE mes=$1 ${filtro} ORDER BY fecha DESC`, [mes]);
    const gastosR = await pool.query(`SELECT * FROM gastos WHERE mes=$1 ${filtro} ORDER BY fecha DESC`, [mes]);
    const vehiculosR = await pool.query('SELECT * FROM vehiculos ORDER BY placa');

    const total_fletes = viajesR.rows.reduce((s,v) => s + parseFloat(v.flete||0), 0);
    const total_gastos = gastosR.rows.reduce((s,g) => s + parseFloat(g.monto||0), 0);

    const hoy = new Date();
    const alertas_vehiculos = vehiculosR.rows.filter(v => {
      if (!v.vence_soat) return false;
      const dias = Math.floor((new Date(v.vence_soat) - hoy) / 86400000);
      return dias < 30;
    });

    const data = {
      num_viajes: viajesR.rows.length,
      total_fletes, total_gastos,
      viajes_recientes: viajesR.rows.slice(0,5),
      gastos_recientes: gastosR.rows.slice(0,5),
      alertas_vehiculos,
      vehiculos: vehiculosR.rows
    };
    if (esAdmin) data.utilidad = total_fletes - total_gastos;
    res.json(data);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── REPORTES ─────────────────────────────────────────────────
app.get('/api/reportes/mes', auth, soloAdmin, async (req, res) => {
  try {
    const mes = req.query.mes || new Date().toISOString().slice(0,7);
    const viajesR = await pool.query('SELECT * FROM viajes WHERE mes=$1', [mes]);
    const gastosR = await pool.query('SELECT * FROM gastos WHERE mes=$1', [mes]);

    const viajes = viajesR.rows;
    const gastos = gastosR.rows;
    const total_fletes = viajes.reduce((s,v) => s + parseFloat(v.flete||0), 0);
    const total_combustible = gastos.filter(g=>g.tipo==='combustible').reduce((s,g) => s+parseFloat(g.monto||0), 0);
    const total_viaticos = gastos.filter(g=>g.tipo==='viatico').reduce((s,g) => s+parseFloat(g.monto||0), 0);
    const total_mantenimiento = gastos.filter(g=>g.tipo==='mantenimiento').reduce((s,g) => s+parseFloat(g.monto||0), 0);
    const total_otros = gastos.filter(g=>!['combustible','viatico','mantenimiento'].includes(g.tipo)).reduce((s,g) => s+parseFloat(g.monto||0), 0);
    const total_gastos = gastos.reduce((s,g) => s+parseFloat(g.monto||0), 0);

    const choferes = {};
    viajes.forEach(v => {
      if (!choferes[v.chofer_nombre]) choferes[v.chofer_nombre] = { nombre: v.chofer_nombre, viajes: 0, fletes: 0, horas_extra: 0 };
      choferes[v.chofer_nombre].viajes++;
      choferes[v.chofer_nombre].fletes += parseFloat(v.flete||0);
      choferes[v.chofer_nombre].horas_extra += parseFloat(v.horas_extra||0);
    });

    res.json({ mes, num_viajes: viajes.length, total_fletes, total_combustible, total_viaticos, total_mantenimiento, total_otros, total_gastos, utilidad: total_fletes - total_gastos, por_chofer: Object.values(choferes) });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── INICIO ───────────────────────────────────────────────────
app.listen(PORT, '0.0.0.0', async () => {
  console.log('\n╔════════════════════════════════════════╗');
  console.log('║        BELA Transporte — v2.0          ║');
  console.log('║   Con PostgreSQL permanente            ║');
  console.log('╚════════════════════════════════════════╝');
  console.log(`\n  Puerto: ${PORT}\n`);
  await initDB();
  console.log('  Base de datos lista ✅\n');
});
