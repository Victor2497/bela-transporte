const express = require('express');
const Datastore = require('@seald-io/nedb');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path');
const os = require('os');

const app = express();
const PORT = process.env.PORT || 3002;
const JWT_SECRET = process.env.JWT_SECRET || 'bela-transporte-secret-2026';
const DATA = path.join(__dirname, 'data');

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));
app.use(express.static(__dirname)); // también busca en raíz

// ── BASE DE DATOS ────────────────────────────────────────────
const db = {
  usuarios:     new Datastore({ filename: path.join(DATA, 'usuarios.db'),     autoload: true }),
  vehiculos:    new Datastore({ filename: path.join(DATA, 'vehiculos.db'),    autoload: true }),
  viajes:       new Datastore({ filename: path.join(DATA, 'viajes.db'),       autoload: true }),
  gastos:       new Datastore({ filename: path.join(DATA, 'gastos.db'),       autoload: true }),
  horas_extra:  new Datastore({ filename: path.join(DATA, 'horas_extra.db'),  autoload: true }),
};

const find    = (col, q={}, sort={}) => new Promise((res,rej) => col.find(q).sort(sort).exec((e,d) => e?rej(e):res(d)));
const findOne = (col, q={})          => new Promise((res,rej) => col.findOne(q,(e,d) => e?rej(e):res(d)));
const insert  = (col, doc)           => new Promise((res,rej) => col.insert(doc,(e,d) => e?rej(e):res(d)));
const update  = (col, q, u, opts={}) => new Promise((res,rej) => col.update(q,u,opts,(e,n) => e?rej(e):res(n)));
const remove  = (col, q, opts={})    => new Promise((res,rej) => col.remove(q,opts,(e,n) => e?rej(e):res(n)));
const count   = (col, q={})          => new Promise((res,rej) => col.count(q,(e,n) => e?rej(e):res(n)));

// ── MIDDLEWARE AUTH ──────────────────────────────────────────
function authMiddleware(req, res, next) {
  const token = req.headers['authorization']?.replace('Bearer ', '');
  if(!token) return res.status(401).json({ error: 'No autorizado' });
  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch(e) { res.status(401).json({ error: 'Token inválido' }); }
}

function soloAdmin(req, res, next) {
  if(req.user.rol !== 'admin') return res.status(403).json({ error: 'Solo el administrador puede ver esto' });
  next();
}

// ── DATOS INICIALES ──────────────────────────────────────────
async function inicializar() {
  const n = await count(db.usuarios);
  if(n === 0) {
    const hash = await bcrypt.hash('admin123', 10);
    await insert(db.usuarios, { nombre: 'Victor (Admin)', usuario: 'admin', password: hash, rol: 'admin', activo: true, creado: new Date() });
    console.log('  Usuario admin creado: admin / admin123');
    console.log('  Cambia la contraseña después de entrar!');
  }
}

// ── AUTH ─────────────────────────────────────────────────────
app.post('/api/login', async (req, res) => {
  try {
    const { usuario, password } = req.body;
    const user = await findOne(db.usuarios, { usuario, activo: true });
    if(!user) return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
    const ok = await bcrypt.compare(password, user.password);
    if(!ok) return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
    const token = jwt.sign({ id: user._id, nombre: user.nombre, usuario: user.usuario, rol: user.rol }, JWT_SECRET, { expiresIn: '30d' });
    res.json({ token, nombre: user.nombre, rol: user.rol, usuario: user.usuario });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/cambiar-password', authMiddleware, async (req, res) => {
  try {
    const { password_actual, password_nuevo } = req.body;
    const user = await findOne(db.usuarios, { _id: req.user.id });
    const ok = await bcrypt.compare(password_actual, user.password);
    if(!ok) return res.status(400).json({ error: 'Contraseña actual incorrecta' });
    const hash = await bcrypt.hash(password_nuevo, 10);
    await update(db.usuarios, { _id: req.user.id }, { $set: { password: hash } });
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── USUARIOS (solo admin) ────────────────────────────────────
app.get('/api/usuarios', authMiddleware, soloAdmin, async (req, res) => {
  try {
    const users = await find(db.usuarios, {}, { nombre: 1 });
    res.json(users.map(u => ({ ...u, password: undefined })));
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/usuarios', authMiddleware, soloAdmin, async (req, res) => {
  try {
    const { nombre, usuario, password, rol } = req.body;
    const existe = await findOne(db.usuarios, { usuario });
    if(existe) return res.status(400).json({ error: 'Ese usuario ya existe' });
    const hash = await bcrypt.hash(password, 10);
    const doc = await insert(db.usuarios, { nombre, usuario, password: hash, rol: rol||'chofer', activo: true, creado: new Date() });
    res.json({ ok: true, id: doc._id });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/usuarios/:id', authMiddleware, soloAdmin, async (req, res) => {
  try {
    const { nombre, activo, rol } = req.body;
    await update(db.usuarios, { _id: req.params.id }, { $set: { nombre, activo, rol } });
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── VEHÍCULOS ────────────────────────────────────────────────
app.get('/api/vehiculos', authMiddleware, async (req, res) => {
  try {
    const vehiculos = await find(db.vehiculos, {}, { placa: 1 });
    res.json(vehiculos);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/vehiculos', authMiddleware, soloAdmin, async (req, res) => {
  try {
    const { placa, marca, modelo, anio, tipo, km_actuales, vence_soat, vence_matricula, chofer_asignado } = req.body;
    const doc = await insert(db.vehiculos, { placa, marca, modelo, anio, tipo, km_actuales: km_actuales||0, vence_soat, vence_matricula, chofer_asignado, estado: 'activo', ultimo_mantenimiento: null, proximo_mantenimiento: null, creado: new Date() });
    res.json({ ok: true, id: doc._id });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/vehiculos/:id', authMiddleware, soloAdmin, async (req, res) => {
  try {
    const campos = req.body;
    await update(db.vehiculos, { _id: req.params.id }, { $set: campos });
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── VIAJES ───────────────────────────────────────────────────
app.get('/api/viajes', authMiddleware, async (req, res) => {
  try {
    let query = {};
    // Chofer solo ve sus viajes
    if(req.user.rol !== 'admin') query.chofer_id = req.user.id;
    const { mes } = req.query;
    if(mes) query.mes = mes;
    const viajes = await find(db.viajes, query, { fecha: -1 });
    res.json(viajes);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/viajes', authMiddleware, async (req, res) => {
  try {
    const { origen, destino, tipo_carga, vehiculo_id, vehiculo_placa, flete, horas_extra, km_recorridos, observacion, fecha } = req.body;
    const hoy = fecha || new Date().toISOString().split('T')[0];
    const mes = hoy.slice(0,7);
    const doc = await insert(db.viajes, {
      origen, destino, tipo_carga, vehiculo_id, vehiculo_placa,
      flete: parseFloat(flete)||0,
      horas_extra: parseFloat(horas_extra)||0,
      km_recorridos: parseFloat(km_recorridos)||0,
      observacion, fecha: hoy, mes,
      chofer_id: req.user.id,
      chofer_nombre: req.user.nombre,
      estado: 'completado',
      creado: new Date()
    });
    res.json({ ok: true, id: doc._id });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/viajes/:id', authMiddleware, async (req, res) => {
  try {
    const viaje = await findOne(db.viajes, { _id: req.params.id });
    if(!viaje) return res.status(404).json({ error: 'No encontrado' });
    if(req.user.rol !== 'admin' && viaje.chofer_id !== req.user.id) return res.status(403).json({ error: 'Sin permiso' });
    await update(db.viajes, { _id: req.params.id }, { $set: req.body });
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/viajes/:id', authMiddleware, soloAdmin, async (req, res) => {
  try {
    await remove(db.viajes, { _id: req.params.id });
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── GASTOS ───────────────────────────────────────────────────
app.get('/api/gastos', authMiddleware, async (req, res) => {
  try {
    let query = {};
    if(req.user.rol !== 'admin') query.chofer_id = req.user.id;
    const { mes } = req.query;
    if(mes) query.mes = mes;
    const gastos = await find(db.gastos, query, { fecha: -1 });
    res.json(gastos);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/gastos', authMiddleware, async (req, res) => {
  try {
    const { tipo, monto, descripcion, vehiculo_id, vehiculo_placa, viaje_id, fecha } = req.body;
    const hoy = fecha || new Date().toISOString().split('T')[0];
    const mes = hoy.slice(0,7);
    const doc = await insert(db.gastos, {
      tipo, monto: parseFloat(monto)||0, descripcion,
      vehiculo_id, vehiculo_placa, viaje_id,
      fecha: hoy, mes,
      chofer_id: req.user.id,
      chofer_nombre: req.user.nombre,
      aprobado: req.user.rol === 'admin',
      creado: new Date()
    });
    res.json({ ok: true, id: doc._id });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.put('/api/gastos/:id/aprobar', authMiddleware, soloAdmin, async (req, res) => {
  try {
    await update(db.gastos, { _id: req.params.id }, { $set: { aprobado: true } });
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/gastos/:id', authMiddleware, soloAdmin, async (req, res) => {
  try {
    await remove(db.gastos, { _id: req.params.id });
    res.json({ ok: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── REPORTES (solo admin) ────────────────────────────────────
app.get('/api/reportes/mes', authMiddleware, soloAdmin, async (req, res) => {
  try {
    const mes = req.query.mes || new Date().toISOString().slice(0,7);
    const viajes = await find(db.viajes, { mes });
    const gastos = await find(db.gastos, { mes });

    const total_fletes = viajes.reduce((s,v) => s + (v.flete||0), 0);
    const total_horas_extra = viajes.reduce((s,v) => s + (v.horas_extra||0), 0);
    const total_combustible = gastos.filter(g => g.tipo==='combustible').reduce((s,g) => s + (g.monto||0), 0);
    const total_viaticos = gastos.filter(g => g.tipo==='viatico').reduce((s,g) => s + (g.monto||0), 0);
    const total_mantenimiento = gastos.filter(g => g.tipo==='mantenimiento').reduce((s,g) => s + (g.monto||0), 0);
    const total_otros = gastos.filter(g => !['combustible','viatico','mantenimiento'].includes(g.tipo)).reduce((s,g) => s + (g.monto||0), 0);
    const total_gastos = gastos.reduce((s,g) => s + (g.monto||0), 0);
    const utilidad = total_fletes - total_gastos;

    // Por chofer
    const choferes = {};
    viajes.forEach(v => {
      if(!choferes[v.chofer_nombre]) choferes[v.chofer_nombre] = { nombre: v.chofer_nombre, viajes: 0, fletes: 0, horas_extra: 0 };
      choferes[v.chofer_nombre].viajes++;
      choferes[v.chofer_nombre].fletes += v.flete||0;
      choferes[v.chofer_nombre].horas_extra += v.horas_extra||0;
    });

    res.json({
      mes, num_viajes: viajes.length,
      total_fletes, total_horas_extra,
      total_combustible, total_viaticos, total_mantenimiento, total_otros,
      total_gastos, utilidad,
      por_chofer: Object.values(choferes),
      viajes, gastos
    });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── DASHBOARD ────────────────────────────────────────────────
app.get('/api/dashboard', authMiddleware, async (req, res) => {
  try {
    const mes = new Date().toISOString().slice(0,7);
    let query_viajes = { mes };
    let query_gastos = { mes };
    if(req.user.rol !== 'admin') {
      query_viajes.chofer_id = req.user.id;
      query_gastos.chofer_id = req.user.id;
    }
    const viajes = await find(db.viajes, query_viajes, { fecha: -1 });
    const gastos = await find(db.gastos, query_gastos, { fecha: -1 });
    const vehiculos = await find(db.vehiculos, {});

    const total_fletes = viajes.reduce((s,v) => s + (v.flete||0), 0);
    const total_gastos = gastos.reduce((s,g) => s + (g.monto||0), 0);

    // Alertas de vehículos (documentos próximos a vencer)
    const hoy = new Date();
    const alertas_vehiculos = vehiculos.filter(v => {
      if(!v.vence_soat) return false;
      const dias = Math.floor((new Date(v.vence_soat) - hoy) / 86400000);
      return dias < 30;
    });

    const data = {
      num_viajes: viajes.length,
      total_fletes,
      total_gastos,
      viajes_recientes: viajes.slice(0,5),
      gastos_recientes: gastos.slice(0,5),
      alertas_vehiculos,
      vehiculos
    };

    if(req.user.rol === 'admin') {
      data.utilidad = total_fletes - total_gastos;
    }

    res.json(data);
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── INICIO ───────────────────────────────────────────────────
app.listen(PORT, '0.0.0.0', async () => {
  const ifaces = os.networkInterfaces();
  let ip = 'localhost';
  for(const iface of Object.values(ifaces)) {
    for(const addr of iface) {
      if(addr.family==='IPv4' && !addr.internal){ ip=addr.address; break; }
    }
  }
  console.log('');
  console.log('╔════════════════════════════════════════╗');
  console.log('║        BELA Transporte — v1.0          ║');
  console.log('║   Control de fletes y gastos           ║');
  console.log('╚════════════════════════════════════════╝');
  console.log(`\n  Local:   http://localhost:${PORT}`);
  console.log(`  Red:     http://${ip}:${PORT}\n`);
  await inicializar();
});
