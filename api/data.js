import { neon } from '@neondatabase/serverless';
import jwt from 'jsonwebtoken';

const sql = neon(process.env.DATABASE_URL);
const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_USER = process.env.ADMIN_USER;
const ADMIN_PASS = process.env.ADMIN_PASS;
const COOKIE = 'vv_session';

// Cookie kept for ~10 years — effectively "forever".
// The JWT itself has NO exp claim, so it never expires until JWT_SECRET rotates.
const COOKIE_MAX_AGE = 60 * 60 * 24 * 365 * 10;

function parseCookies(req){
  const raw = req.headers.cookie || '';
  return Object.fromEntries(
    raw.split(';').map(c=>{
      const [k,...v] = c.trim().split('=');
      return [k, decodeURIComponent(v.join('='))];
    }).filter(([k])=>k)
  );
}

function setCookie(res, name, value, maxAge = COOKIE_MAX_AGE){
  res.setHeader('Set-Cookie', [
    `${name}=${encodeURIComponent(value)}`,
    'Path=/', 'HttpOnly', 'SameSite=Lax', 'Secure',
    `Max-Age=${maxAge}`
  ].join('; '));
}

function auth(req){
  const token = parseCookies(req)[COOKIE];
  if(!token) return null;
  try { return jwt.verify(token, JWT_SECRET); } catch { return null; }
}

function readBody(req){
  return new Promise((resolve,reject)=>{
    let d='';
    req.on('data',c=>d+=c);
    req.on('end',()=>{ try{ resolve(d?JSON.parse(d):{}); }catch(e){ reject(e); } });
    req.on('error',reject);
  });
}

export default async function handler(req, res){
  // ---------- CORS ----------
  const origin = req.headers.origin || '';
  const allowed = [
    'https://www.vinayvelpula.in',
    'https://vinayvelpula.in',
    'http://localhost:3000',
    'http://localhost:5173',
  ];
  if(allowed.includes(origin)){
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if(req.method === 'OPTIONS') return res.status(204).end();

  res.setHeader('Cache-Control','no-store');
  const action = (req.query.action||'').toString();

  // ---------- public read ----------
  if(req.method==='GET' && !action){
    try{
      const rows = await sql`select doc from pages where id='home'`;
      const doc = rows[0]?.doc;
      if(!doc){
        return res.status(200).json({});
      }
      return res.status(200).json(doc);
    }catch(e){
      return res.status(500).json({error:'db_error',detail:String(e.message)});
    }
  }

  // ---------- who am I ----------
  if(req.method==='GET' && action==='me'){
    const u = auth(req);
    return res.status(200).json({authed: !!u, user: u?.u || null});
  }

  // ---------- login ----------
  if(req.method==='POST' && action==='login'){
    try{
      const { username, password } = await readBody(req);
      if(username!==ADMIN_USER || password!==ADMIN_PASS){
        await new Promise(r=>setTimeout(r,400));
        return res.status(401).json({error:'invalid_credentials'});
      }
      // NO expiresIn — the token never expires.
      const token = jwt.sign({u: username}, JWT_SECRET);
      setCookie(res, COOKIE, token);
      return res.status(200).json({ok:true});
    }catch(e){ return res.status(500).json({error:'server_error'}); }
  }

  // ---------- logout ----------
  if(req.method==='POST' && action==='logout'){
    setCookie(res, COOKIE, '', 0);
    return res.status(200).json({ok:true});
  }

  // ---------- save ----------
  if(req.method==='POST' && action==='save'){
    if(!auth(req)) return res.status(401).json({error:'unauthorized'});
    try{
      const body = await readBody(req);
      if(!body || typeof body!=='object' || Array.isArray(body)){
        return res.status(400).json({error:'expected_object'});
      }
      const json = JSON.stringify(body);
      await sql`
        insert into pages (id, doc, updated_at) values ('home', ${json}::jsonb, now())
        on conflict (id) do update set doc = ${json}::jsonb, updated_at = now()
      `;
      return res.status(200).json({ok:true});
    }catch(e){ return res.status(500).json({error:'db_error',detail:String(e.message)}); }
  }

  return res.status(405).json({error:'method_not_allowed'});
}

// Allow large payloads (for base64 images)
export const config = { api: { bodyParser: { sizeLimit: '15mb' } } };
