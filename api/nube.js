// API de Mis Finanzas en la nube (Vercel + Upstash Redis).
// Solo guarda texto CIFRADO en el celular: este servidor no puede leer los datos.
// k = identificador de 64 caracteres sacado del código de enlace (el código nunca llega aquí).
const URL_DB = process.env.KV_REST_API_URL || process.env.UPSTASH_REDIS_REST_URL;
const TOKEN = process.env.KV_REST_API_TOKEN || process.env.UPSTASH_REDIS_REST_TOKEN;
const MAX_DATOS = 3_500_000, MAX_FOTO = 2_000_000;

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

const cifrado = d => d && typeof d.iv === 'string' && typeof d.data === 'string' && d.iv.length < 64;

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET,PUT,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Cache-Control', 'no-store');
  if (req.method === 'OPTIONS') return res.status(204).end();
  if (!URL_DB || !TOKEN) return res.status(503).json({ error: 'Falta conectar la base de datos en Vercel' });

  const k = String(req.query.k || '');
  const f = req.query.f ? String(req.query.f) : '';
  if (!/^[0-9a-f]{64}$/.test(k)) return res.status(400).json({ error: 'Código inválido' });
  if (f && !/^[A-Za-z0-9_-]{1,40}$/.test(f)) return res.status(400).json({ error: 'Foto inválida' });
  const base = 'mf:' + k;

  try {
    if (req.method === 'GET') {
      if (f) {
        const d = await redis(['GET', base + ':f:' + f]);
        return res.json({ data: d ? JSON.parse(d) : null });
      }
      const [d, v, fotos] = await Promise.all([
        redis(['GET', base]), redis(['GET', base + ':v']), redis(['SMEMBERS', base + ':fs']),
      ]);
      return res.json({ ver: Number(v || 0), data: d ? JSON.parse(d) : null, fotos: fotos || [] });
    }

    if (req.method === 'PUT') {
      const b = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
      if (!b || !cifrado(b.data)) return res.status(400).json({ error: 'Datos inválidos' });
      const s = JSON.stringify({ iv: b.data.iv, data: b.data.data });
      if (f) {
        if (s.length > MAX_FOTO) return res.status(413).json({ error: 'Foto muy grande' });
        await redis(['SET', base + ':f:' + f, s]);
        await redis(['SADD', base + ':fs', f]);
        return res.json({ ok: true });
      }
      if (s.length > MAX_DATOS) return res.status(413).json({ error: 'Datos muy grandes' });
      const r = await redis(['EVAL', GUARDAR_SI_VERSION, '2', base, base + ':v', String(Number(b.ver) || 0), s]);
      if (r === -1) return res.status(409).json({ error: 'Otro equipo guardó primero' });
      return res.json({ ver: r });
    }

    res.status(405).json({ error: 'Método no permitido' });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: 'Error en la nube, intenta más tarde' });
  }
};
