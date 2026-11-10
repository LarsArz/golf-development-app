// The Swing Lab API: authenticated parent and paired golfer sessions.
// D1 binding: DB. Secret: PARENT_PIN. Run auth-migration.sql before using auth.
const ORIGIN='https://larsarz.github.io';
const headers={'content-type':'application/json; charset=utf-8','cache-control':'no-store','access-control-allow-origin':ORIGIN,'vary':'Origin'};
const reply=(data,status=200)=>new Response(JSON.stringify(data),{status,headers});
const now=()=>Math.floor(Date.now()/1000);
const hex=bytes=>Array.from(bytes,b=>b.toString(16).padStart(2,'0')).join('');
const randomToken=()=>hex(crypto.getRandomValues(new Uint8Array(32)));
async function hash(value){return hex(new Uint8Array(await crypto.subtle.digest('SHA-256',new TextEncoder().encode(value))))}
async function bodyJSON(request){try{return await request.json()}catch{return null}}
async function session(request,env){
  const bearer=request.headers.get('authorization')||'';
  if(!bearer.startsWith('Bearer '))return null;
  const token=bearer.slice(7);if(!/^[a-f0-9]{64}$/.test(token))return null;
  return await env.DB.prepare('SELECT s.id,s.user_id,u.role,u.display_name FROM device_sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.revoked_at IS NULL AND s.expires_at>?').bind(await hash(token),new Date().toISOString()).first();
}
async function issueSession(env,userId,days){
  const token=randomToken(),id=crypto.randomUUID();
  const expires=new Date(Date.now()+days*86400000).toISOString();
  await env.DB.prepare('INSERT INTO device_sessions(id,user_id,token_hash,expires_at) VALUES(?,?,?,?)').bind(id,userId,await hash(token),expires).run();
  return {token,expiresAt:expires};
}
async function countAttempt(env,bucket,limit){
  const t=now(),reset=t+3600;
  await env.DB.prepare('INSERT INTO auth_attempts(bucket,failures,reset_at) VALUES(?,1,?) ON CONFLICT(bucket) DO UPDATE SET failures=CASE WHEN reset_at<=? THEN 1 ELSE failures+1 END,reset_at=CASE WHEN reset_at<=? THEN ? ELSE reset_at END').bind(bucket,reset,t,t,reset).run();
  const row=await env.DB.prepare('SELECT failures FROM auth_attempts WHERE bucket=?').bind(bucket).first();
  return row.failures<=limit;
}
async function route(request,env,url){
  const path=url.pathname,method=request.method;
  if(path==='/health'&&method==='GET'){
    try{const row=await env.DB.prepare('SELECT 1 AS ok').first();return reply({ok:row?.ok===1,service:'swing-lab-api',database:'connected'})}
    catch{return reply({ok:false,service:'swing-lab-api',database:'unavailable'},503)}
  }
  if(path==='/auth/parent'&&method==='POST'){
    if(!env.PARENT_PIN||!/^[0-9]{4}$/.test(env.PARENT_PIN))return reply({error:'Parent PIN not configured'},503);
    const ip=request.headers.get('cf-connecting-ip')||'unknown';
    // Count every attempt, successful or not, to bound online PIN guessing.
    if(!(await countAttempt(env,'parent:global',10)))return reply({error:'Too many attempts. Try again in an hour.'},429);
    if(!(await countAttempt(env,'parent:ip:'+await hash(ip),5)))return reply({error:'Too many attempts. Try again in an hour.'},429);
    const data=await bodyJSON(request),pin=data?.pin;
    if(typeof pin!=='string'||!/^[0-9]{4}$/.test(pin)||pin!==env.PARENT_PIN)return reply({error:'Invalid PIN'},401);
    await env.DB.prepare("INSERT INTO users(id,display_name,role) VALUES('parent','Parent','parent') ON CONFLICT(id) DO NOTHING").run();
    return reply({role:'parent',...(await issueSession(env,'parent',30))});
  }
  const user=await session(request,env);
  if(path==='/auth/me'&&method==='GET')return user?reply({role:user.role,name:user.display_name}):reply({error:'Unauthorized'},401);
  if(path==='/auth/logout'&&method==='POST'){
    if(!user)return reply({error:'Unauthorized'},401);
    await env.DB.prepare('UPDATE device_sessions SET revoked_at=? WHERE id=?').bind(new Date().toISOString(),user.id).run();
    return reply({ok:true});
  }
  if(path==='/auth/pairing'&&method==='POST'){
    if(user?.role!=='parent')return reply({error:'Parent access required'},403);
    const code=String(crypto.getRandomValues(new Uint32Array(1))[0]%90000000+10000000);
    const codeHash=await hash(code),expires=new Date(Date.now()+10*60000).toISOString();
    await env.DB.prepare("INSERT INTO users(id,display_name,role) VALUES('mackenzie','Mackenzie','golfer') ON CONFLICT(id) DO NOTHING").run();
    await env.DB.prepare('INSERT INTO pairing_codes(code_hash,user_id,expires_at) VALUES(?,?,?)').bind(codeHash,'mackenzie',expires).run();
    return reply({code,expiresAt:expires});
  }
  if(path==='/auth/claim'&&method==='POST'){
    const ip=request.headers.get('cf-connecting-ip')||'unknown';
    if(!(await countAttempt(env,'pair:ip:'+await hash(ip),10)))return reply({error:'Too many attempts. Try again in an hour.'},429);
    const data=await bodyJSON(request),code=data?.code;
    if(typeof code!=='string'||!/^[0-9]{8}$/.test(code))return reply({error:'Invalid or expired pairing code'},401);
    const codeHash=await hash(code),stamp=new Date().toISOString();
    const result=await env.DB.prepare('UPDATE pairing_codes SET used_at=? WHERE code_hash=? AND used_at IS NULL AND expires_at>?').bind(stamp,codeHash,stamp).run();
    if(result.meta.changes!==1)return reply({error:'Invalid or expired pairing code'},401);
    return reply({role:'golfer',name:'Mackenzie',...(await issueSession(env,'mackenzie',180))});
  }
  if(path==='/inspiration'&&method==='GET'){
    if(!user)return reply({error:'Unauthorized'},401);
    const date=url.searchParams.get('date');
    if(!/^\d{4}-\d{2}-\d{2}$/.test(date||''))return reply({error:'Date required (YYYY-MM-DD)'},400);
    const row=await env.DB.prepare('SELECT date,quote,attribution FROM daily_inspiration WHERE date=?').bind(date).first();
    return reply({inspiration:row||null});
  }
  if(path==='/inspiration'&&method==='PUT'){
    if(user?.role!=='parent')return reply({error:'Parent access required'},403);
    const data=await bodyJSON(request);
    if(!/^\d{4}-\d{2}-\d{2}$/.test(data?.date||'')||typeof data?.quote!=='string'||!data.quote.trim()||data.quote.length>2000||typeof(data.attribution??'')!=='string'||(data.attribution??'').length>150)return reply({error:'Invalid inspiration entry'},400);
    await env.DB.prepare("INSERT INTO daily_inspiration(date,quote,attribution,updated_at) VALUES(?,?,?,CURRENT_TIMESTAMP) ON CONFLICT(date) DO UPDATE SET quote=excluded.quote,attribution=excluded.attribution,updated_at=CURRENT_TIMESTAMP").bind(data.date,data.quote.trim(),data.attribution||'').run();
    return reply({ok:true});
  }
  if(path==='/inspiration'&&method==='DELETE'){
    if(user?.role!=='parent')return reply({error:'Parent access required'},403);
    const date=url.searchParams.get('date');
    if(!/^\d{4}-\d{2}-\d{2}$/.test(date||''))return reply({error:'Invalid date'},400);
    await env.DB.prepare('DELETE FROM daily_inspiration WHERE date=?').bind(date).run();return reply({ok:true});
  }
  return reply({error:'Not found'},404);
}
export default {
 async fetch(request,env){
   const origin=request.headers.get('origin');
   if(origin&&origin!==ORIGIN)return reply({error:'Origin not allowed'},403);
   if(request.method==='OPTIONS')return new Response(null,{status:204,headers:{'access-control-allow-origin':ORIGIN,'access-control-allow-methods':'GET,POST,PUT,DELETE,OPTIONS','access-control-allow-headers':'authorization,content-type','access-control-max-age':'600','vary':'Origin'}});
   try{return await route(request,env,new URL(request.url))}
   catch(e){console.error('API error',e);return reply({error:'Service unavailable'},503)}
 }
};
