// api/data.js — Vercel Serverless Function (Node runtime)
import { neon } from '@neondatabase/serverless';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';

const sql = neon(process.env.DATABASE_URL);
const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_USER = process.env.ADMIN_USER;
const ADMIN_PASS_HASH = process.env.ADMIN_PASS_HASH; // bcrypt hash, NOT plaintext
const COOKIE = 'vv_session';

/* ---------- helpers ---------- */
function parseCookies(req) {
  const raw = req.headers.cookie || '';
  return Object.fromEntries(
    raw.split(';').map(c => {
      const [k, ...v] = c.trim().split('=');
      return [k, decodeURIComponent(v.join('='))];
    }).filter(([k]) => k)
  );
}

function setCookie(res, name, value, maxAge) {
  const parts = [
    `${name}=${encodeURIComponent(value)}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
    'Secure',
    `Max-Age=${maxAge}`
  ];
  res.setHeader('Set-Cookie', parts.join('; '));
}

function auth(req) {
  const token = parseCookies(req)[COOKIE];
  if (!token) return null;
  try { return jwt.verify(token, JWT_SECRET); }
  catch { return null; }
}

async function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    req.on('data', c => (data += c));
    req.on('end', () => {
      try { resolve(data ? JSON.parse(data) : {}); }
      catch (e) { reject(e); }
    });
    req.on('error', reject);
  });
}

/* ---------- main handler ---------- */
export default async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');

  const action = (req.query.action || '').toString();

  // ---- GET /api/data  → public content (key/value map) ----
  if (req.method === 'GET' && !action) {
    try {
      const rows = await sql`SELECT key, value FROM content`;
      const out = {};
      for (const r of rows) out[r.key] = r.value;
      return res.status(200).json(out);
    } catch (e) {
      return res.status(500).json({ error: 'db_error', detail: String(e.message) });
    }
  }

  // ---- POST /api/data?action=login ----
  if (req.method === 'POST' && action === 'login') {
    try {
      const { username, password } = await readBody(req);
      if (!username || !password)
        return res.status(400).json({ error: 'missing_credentials' });

      const userOk = username === ADMIN_USER;
      const passOk = userOk && await bcrypt.compare(password, ADMIN_PASS_HASH);

      if (!userOk || !passOk) {
        await new Promise(r => setTimeout(r, 400)); // small delay on failure
        return res.status(401).json({ error: 'invalid_credentials' });
      }

      const token = jwt.sign({ u: username }, JWT_SECRET, { expiresIn: '12h' });
      setCookie(res, COOKIE, token, 60 * 60 * 12);
      return res.status(200).json({ ok: true });
    } catch (e) {
      return res.status(500).json({ error: 'server_error' });
    }
  }

  // ---- POST /api/data?action=logout ----
  if (req.method === 'POST' && action === 'logout') {
    setCookie(res, COOKIE, '', 0);
    return res.status(200).json({ ok: true });
  }

  // ---- GET /api/data?action=me  → is the session valid? ----
  if (req.method === 'GET' && action === 'me') {
    const user = auth(req);
    return res.status(200).json({ authed: !!user, user: user?.u || null });
  }

  // ---- POST /api/data?action=save  → protected bulk upsert ----
  if (req.method === 'POST' && action === 'save') {
    if (!auth(req)) return res.status(401).json({ error: 'unauthorized' });
    try {
      const body = await readBody(req); // { key: value, ... }
      const entries = Object.entries(body).filter(
        ([k, v]) => typeof k === 'string' && typeof v === 'string'
      );
      if (!entries.length) return res.status(400).json({ error: 'no_fields' });

      for (const [key, value] of entries) {
        await sql`
          INSERT INTO content (key, value, updated_at)
          VALUES (${key}, ${value}, now())
          ON CONFLICT (key) DO UPDATE
            SET value = EXCLUDED.value,
                updated_at = now()
        `;
      }
      return res.status(200).json({ ok: true, saved: entries.length });
    } catch (e) {
      return res.status(500).json({ error: 'db_error', detail: String(e.message) });
    }
  }

  return res.status(405).json({ error: 'method_not_allowed' });
}
