import fs from 'node:fs/promises';
import path from 'node:path';
import crypto from 'node:crypto';

const COOKIE = 'kfch_library_auth';
const ROOT = process.cwd();

function token(password) {
  return crypto.createHash('sha256').update(password + ':KFCH-Stroke-Library').digest('hex');
}
function login(message='') {
  return new Response(`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>KFCH Library Access</title><style>*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;background:#f4f7f9;font-family:Arial,sans-serif;color:#17384b}.card{width:min(92vw,430px);background:#fff;padding:36px;border-radius:18px;box-shadow:0 12px 42px #1233;text-align:center}h1{font-size:23px;margin:0 0 9px}p{font-size:14px;color:#607785;margin:0 0 24px}input{width:100%;padding:14px;border:1px solid #cbd7de;border-radius:9px;font-size:16px;margin-bottom:12px}button{width:100%;padding:14px;border:0;border-radius:9px;background:#155b75;color:#fff;font-size:15px;font-weight:700}.err{color:#b42318;margin-top:12px;font-size:13px}</style></head><body><main class="card"><h1>KFCH Medical Electronic Library</h1><p>Authorized access only. Enter the site password to continue.</p><form method="POST"><input name="password" type="password" required autofocus placeholder="Password"><button>Access Library</button></form>${message?`<div class="err">${message}</div>`:''}</main></body></html>`,{status:401,headers:{'content-type':'text/html; charset=utf-8','cache-control':'private, no-store'}});
}
function authorized(req,password){const c=req.headers.get('cookie')||'';return c.split(';').some(v=>v.trim()===`${COOKIE}=${token(password)}`);}
function mime(file){const e=path.extname(file).toLowerCase();return ({'.html':'text/html; charset=utf-8','.css':'text/css; charset=utf-8','.js':'text/javascript; charset=utf-8','.json':'application/json','.pdf':'application/pdf','.png':'image/png','.jpg':'image/jpeg','.jpeg':'image/jpeg','.svg':'image/svg+xml','.ico':'image/x-icon','.webp':'image/webp'}[e]||'application/octet-stream');}
async function resolveFile(parts){let rel=(parts||[]).map(decodeURIComponent).join('/');if(!rel) rel='index.html';let file=path.resolve(ROOT,rel);if(!file.startsWith(ROOT+path.sep)) return null;try{const s=await fs.stat(file);if(s.isDirectory()) file=path.join(file,'index.html');await fs.access(file);return file;}catch{return null;}}
export async function GET(req,{params}){const password=process.env.SITE_PASSWORD;if(!password)return new Response('SITE_PASSWORD is not configured.',{status:503});if(!authorized(req,password))return login();const p=await params;const file=await resolveFile(p.path);if(!file)return new Response('Document unavailable.',{status:404});const data=await fs.readFile(file);const headers={'content-type':mime(file),'cache-control':'private, no-store'};if(path.extname(file).toLowerCase()==='.pdf')headers['content-disposition']=`inline; filename*=UTF-8''${encodeURIComponent(path.basename(file))}`;return new Response(data,{headers});}
export async function POST(req){const password=process.env.SITE_PASSWORD;if(!password)return new Response('SITE_PASSWORD is not configured.',{status:503});const form=await req.formData();if(String(form.get('password')||'')!==password)return login('Incorrect password.');return new Response(null,{status:303,headers:{location:new URL(req.url).pathname,'set-cookie':`${COOKIE}=${token(password)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=28800`,'cache-control':'private, no-store'}});}
