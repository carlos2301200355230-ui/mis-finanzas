// API de Mis Finanzas: usuarios y nube (Vercel + Upstash Redis).
// La contraseña NUNCA llega aquí: el celular manda una "prueba" (token) derivada de ella,
// y aquí solo se guarda el hash de esa prueba. Los datos llegan ya CIFRADOS: este servidor no puede leerlos.
const crypto = require('crypto');
const URL_DB = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
const TOKEN = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;
const MAX_DATOS = 3_500_000, MAX_FOTO = 2_000_000, MAX_FALLOS = 10, BLOQUEO_SEG = 900;

async function redis(cmd) {
  const r = await fetch(URL_DB, {
    method: 'POST',
    headers: { Authorization: 'Bearer ' + TOKEN, 'Content-Type': 'application/json' },
    body: JSON.stringify(cmd),
  });
  const j = await r.json();
  if (j.error) throw new Error(j.error);
  return j.result;
}

// Guarda solo si nadie más guardó en el medio (evita que un equipo pise al otro).
const GUARDAR_SI_VERSION = `
local v = redis.call('GET', KEYS[2]) or '0'
if v ~= ARGV[1] then return -1 end
redis.call('SET', KEYS[1], ARGV[2])
return redis.call('INCR', KEYS[2])`;

const sha = s => crypto.createHash('sha256').update(String(s)).digest('hex');
const igual = (a, b) => a.length === b.length && crypto.timingSafeEqual(Buffer.from(a), Buffer.from(b));
const normU = u => String(u || '').trim().toLowerCase();
const okU = u => /^[a-z0-9._-]{3,30}$/.test(u);
const okHex = s => typeof s === 'string' && /^[0-9a-f]{64}$/.test(s);
const okSal = s => typeof s === 'string' && s.length >= 16 && s.length <= 64;
const okIter = n => Number.isInteger(n) && n >= 100000 && n <= 5000000;
const okCif = (d, max) => d && typeof d.iv === 'string' && typeof d.data === 'string' && d.iv.length < 64 && d.data.length < max;
const okClave = n => n && okSal(n.salt) && okIter(n.iter) && okHex(n.token) && okCif(n.wrapPw, 4096);

class Err extends Error { constructor(code, msg) { super(msg); this.code = code; } }
const kU = u => 'mfu:' + u, kD = u => 'mfd:' + u, kF = u => 'mfl:' + u;
async function leerUsuario(u) { const c = await redis(['GET', kU(u)]); return c ? JSON.parse(c) : null; }

// Revisa usuario + prueba de contraseña (o de clave de recuperación), con límite de intentos.
async function verificar(u, token, campo) {
  if (!okU(u) || !okHex(token)) throw new Err(401, 'Usuario o contraseña incorrectos');
  const [c, fallos] = await Promise.all([leerUsuario(u), redis(['GET', kF(u)])]);
  if (Number(fallos || 0) >= MAX_FALLOS) throw new Err(429, 'Demasiados intentos. Espera 15 minutos.');
  if (!c || !igual(sha(token), c[campo])) {
    await redis(['INCR', kF(u)]);
    await redis(['EXPIRE', kF(u), BLOQUEO_SEG]);
    throw new Err(401, campo === 'recAuth' ? 'Usuario o clave de recuperación incorrectos' : 'Usuario o contraseña incorrectos');
  }
  if (fallos) await redis(['DEL', kF(u)]);
  return c;
}

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type,X-Usuario,X-Token');
  res.setHeader('Cache-Control', 'no-store');
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (!URL_DB || !TOKEN) return res.status(503).json({ error: 'Falta conectar la base de datos en Vercel' });

  const a = String(req.query.a || '');
  let b = {};
  try { b = typeof req.body === 'string' ? JSON.parse(req.body || '{}') : (req.body || {}); } catch (e) { b = {}; }

  try {
    // ---------- sin sesión ----------
    if (a === 'sal' || a === 'salrec') {
      const u = normU(req.query.u);
      const c = okU(u) && await leerUsuario(u);
      if (!c) throw new Err(404, 'Ese usuario no existe');
      return res.json(a === 'sal' ? { salt: c.salt, iter: c.iter } : { salt: c.recSalt, iter: c.recIter });
    }

    if (a === 'registro' && req.method === 'POST') {
      const u = normU(b.u);
      if (!okU(u)) throw new Err(400, 'Usuario inválido');
      if (!okClave(b) || !okSal(b.recSalt) || !okIter(b.recIter) || !okHex(b.recToken) || !okCif(b.wrapRec, 4096))
        throw new Err(400, 'Datos inválidos');
      const c = {
        salt: b.salt, iter: b.iter, auth: sha(b.token), wrapPw: b.wrapPw,
        recSalt: b.recSalt, recIter: b.recIter, recAuth: sha(b.recToken), wrapRec: b.wrapRec, creado: Date.now(),
      };
      const ok = await redis(['SET', kU(u), JSON.stringify(c), 'NX']);
      if (ok !== 'OK') throw new Err(409, 'Ese usuario ya existe, elige otro');
      return res.json({ ok: true });
    }

    if (a === 'rec' && req.method === 'POST') { // olvidé mi contraseña
      const u = normU(b.u);
      const c = await verificar(u, b.recToken, 'recAuth');
      if (!b.nuevo) return res.json({ wrapRec: c.wrapRec });
      if (!okClave(b.nuevo)) throw new Err(400, 'Datos inválidos');
      Object.assign(c, { salt: b.nuevo.salt, iter: b.nuevo.iter, auth: sha(b.nuevo.token), wrapPw: b.nuevo.wrapPw });
      await redis(['SET', kU(u), JSON.stringify(c)]);
      return res.json({ ok: true });
    }

    // ---------- con sesión ----------
    const u = normU(req.headers['x-usuario']);
    const c = await verificar(u, String(req.headers['x-token'] || ''), 'auth');
    const base = kD(u);

    if (a === 'cuenta') return res.json({ wrapPw: c.wrapPw });

    if (a === 'clave' && req.method === 'POST') {
      if (!okClave(b)) throw new Err(400, 'Datos inválidos');
      Object.assign(c, { salt: b.salt, iter: b.iter, auth: sha(b.token), wrapPw: b.wrapPw });
      await redis(['SET', kU(u), JSON.stringify(c)]);
      return res.json({ ok: true });
    }

    if (a === 'nuevarec' && req.method === 'POST') {
      if (!okSal(b.recSalt) || !okIter(b.recIter) || !okHex(b.recToken) || !okCif(b.wrapRec, 4096)) throw new Err(400, 'Datos inválidos');
      Object.assign(c, { recSalt: b.recSalt, recIter: b.recIter, recAuth: sha(b.recToken), wrapRec: b.wrapRec });
      await redis(['SET', kU(u), JSON.stringify(c)]);
      return res.json({ ok: true });
    }

    if (a === 'datos') {
      if (req.method === 'GET') {
        const [d, v, fotos] = await Promise.all([redis(['GET', base]), redis(['GET', base + ':v']), redis(['SMEMBERS', base + ':fs'])]);
        return res.json({ ver: Number(v || 0), data: d ? JSON.parse(d) : null, fotos: fotos || [] });
      }
      if (req.method === 'PUT') {
        if (!okCif(b.data, MAX_DATOS)) throw new Err(400, 'Datos inválidos');
        const s = JSON.stringify({ iv: b.data.iv, data: b.data.data });
        const r = await redis(['EVAL', GUARDAR_SI_VERSION, '2', base, base + ':v', String(Number(b.ver) || 0), s]);
        if (r === -1) throw new Err(409, 'Otro equipo guardó primero');
        return res.json({ ver: r });
      }
    }

    if (a === 'foto') {
      const f = String(req.query.f || '');
      if (!/^[A-Za-z0-9_-]{1,40}$/.test(f)) throw new Err(400, 'Foto inválida');
      if (req.method === 'GET') {
        const d = await redis(['GET', base + ':f:' + f]);
        return res.json({ data: d ? JSON.parse(d) : null });
      }
      if (req.method === 'PUT') {
        if (!okCif(b.data, MAX_FOTO)) throw new Err(400, 'Foto inválida o muy grande');
        await redis(['SET', base + ':f:' + f, JSON.stringify({ iv: b.data.iv, data: b.data.data })]);
        await redis(['SADD', base + ':fs', f]);
        return res.json({ ok: true });
      }
    }

    if (a === 'borrar' && req.method === 'POST') { // borrar usuario y todos sus datos
      const fotos = (await redis(['SMEMBERS', base + ':fs'])) || [];
      await redis(['DEL', kU(u), base, base + ':v', base + ':fs', ...fotos.map(f => base + ':f:' + f)]);
      return res.json({ ok: true });
    }

    throw new Err(404, 'Acción no encontrada');
  } catch (e) {
    if (e instanceof Err) return res.status(e.code).json({ error: e.message });
    console.error(e);
    res.status(500).json({ error: 'Error en la nube, intenta más tarde' });
  }
};
