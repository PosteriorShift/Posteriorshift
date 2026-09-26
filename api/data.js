import { neon } from '@neondatabase/serverless';
import jwt from 'jsonwebtoken';

const sql = neon(process.env.DATABASE_URL);
const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_USER = process.env.ADMIN_USER;
const ADMIN_PASS = process.env.ADMIN_PASS;
const COOKIE = 'vv_session';
const SESSION_SECONDS = 15 * 60;

function parseCookies(req){
  const raw = req.headers.cookie || '';
  return Object.fromEntries(
    raw.split(';').map(c=>{
      const [k,...v] = c.trim().split('=');
      return [k, decodeURIComponent(v.join('='))];
    }).filter(([k])=>k)
  );
}
function setCookie(res, name, value, maxAge){
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
  res.setHeader('Cache-Control','no-store');
  const action = (req.query.action||'').toString();

  // public read of the whole document
  if(req.method==='GET' && !action){
    try{
      const rows = await sql`select doc from pages where id='home'`;
      return res.status(200).json(rows[0]?.doc || {});
    }catch(e){ return res.status(500).json({error:'db_error',detail:String(e.message)}); }
  }

  // who am I?
  if(req.method==='GET' && action==='me'){
    const u = auth(req);
    return res.status(200).json({authed: !!u, user: u?.u || null});
  }

  // login
  if(req.method==='POST' && action==='login'){
    try{
      const { username, password } = await readBody(req);
      if(username!==ADMIN_USER || password!==ADMIN_PASS){
        await new Promise(r=>setTimeout(r,400));
        return res.status(401).json({error:'invalid_credentials'});
      }
      const token = jwt.sign({u:username}, JWT_SECRET, {expiresIn: SESSION_SECONDS});
      setCookie(res, COOKIE, token, SESSION_SECONDS);
      return res.status(200).json({ok:true, expiresIn:SESSION_SECONDS});
    }catch(e){ return res.status(500).json({error:'server_error'}); }
  }

  // logout
  if(req.method==='POST' && action==='logout'){
    setCookie(res, COOKIE, '', 0);
    return res.status(200).json({ok:true});
  }

  // save — replace entire document
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
