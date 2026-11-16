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

const mysteryPrizes=[
  {id:'spinach',name:'Skip Dinner Spinach',icon:'🥬'},
  {id:'froyo',name:'$5 Froyo',icon:'🍦'},
  {id:'goodgood',name:'$5 Good Good Credit',icon:'⛳'},
  {id:'takeout',name:'Pick Takeout Any Night (Chick-fil-A, Santo Matador, Shake Shack)',icon:'🍔'},
  {id:'gaming',name:'$10 Roblox/Fortnite Credit',icon:'🎮'},
  {id:'cash20',name:'$20 Cash',icon:'💵'},
  {id:'breakfast',name:'Breakfast at Another Broken Egg',icon:'🥞'},
  {id:'steak',name:'Steak Dinner',icon:'🥩'},
  {id:'hat',name:'Golf Hat',icon:'🧢'}
];
async function ensureMysteries(env){
  await env.DB.prepare("CREATE TABLE IF NOT EXISTS practice_mysteries (date TEXT PRIMARY KEY, kind TEXT NOT NULL, prize_id TEXT, bonus_xp INTEGER NOT NULL DEFAULT 0, fulfilled INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)").run();
}
async function drawMystery(env,date){
  await ensureMysteries(env);
  const existing=await env.DB.prepare('SELECT date,kind,prize_id,bonus_xp,fulfilled FROM practice_mysteries WHERE date=?').bind(date).first();
  if(existing)return {mystery:existing,newDraw:false};
  const roll=crypto.getRandomValues(new Uint32Array(1))[0]/4294967296;
  let kind='none',prize=null,bonus=0;
  if(roll<.055){kind='bonus';bonus=100}
  else if(roll<.10){
    kind='prize';
    const prior=await env.DB.prepare("SELECT prize_id FROM practice_mysteries WHERE kind='prize' AND prize_id IS NOT NULL").all();
    const used=new Set((prior.results||[]).map(r=>r.prize_id));
    const choices=mysteryPrizes.filter(p=>!used.has(p.id));
    const pool=choices.length?choices:mysteryPrizes;
    prize=pool[crypto.getRandomValues(new Uint32Array(1))[0]%pool.length].id;
  }
  const result=await env.DB.prepare('INSERT INTO practice_mysteries(date,kind,prize_id,bonus_xp) VALUES(?,?,?,?) ON CONFLICT(date) DO NOTHING').bind(date,kind,prize,bonus).run();
  const mystery=await env.DB.prepare('SELECT date,kind,prize_id,bonus_xp,fulfilled FROM practice_mysteries WHERE date=?').bind(date).first();
  return {mystery,newDraw:result.meta.changes===1};
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

  // Shared practice plan. Existing local device data is never overwritten by this API.
  if(path==='/schedule'&&method==='GET'){
    if(!user)return reply({error:'Unauthorized'},401);
    const start=url.searchParams.get('start'),end=url.searchParams.get('end');
    if(!/^\d{4}-\d{2}-\d{2}$/.test(start||'')||!/^\d{4}-\d{2}-\d{2}$/.test(end||'')||end<start)return reply({error:'Valid start and end dates required'},400);
    const rows=await env.DB.prepare('SELECT date,assignments_json FROM practice_days WHERE date BETWEEN ? AND ? ORDER BY date').bind(start,end).all();
    await env.DB.prepare('CREATE TABLE IF NOT EXISTS practice_rest_days (date TEXT PRIMARY KEY)').run();
    const rests=await env.DB.prepare('SELECT date FROM practice_rest_days WHERE date BETWEEN ? AND ?').bind(start,end).all();
    const done=await env.DB.prepare('SELECT date,task_index FROM practice_completion WHERE date BETWEEN ? AND ? ORDER BY date,task_index').bind(start,end).all();
    return reply({days:(rows.results||[]).map(r=>({date:r.date,tasks:JSON.parse(r.assignments_json)})),completed:done.results||[],restDays:(rests.results||[]).map(r=>r.date)});
  }
  if(path==='/schedule/day'&&method==='PUT'){
    if(user?.role!=='parent')return reply({error:'Parent access required'},403);
    const data=await bodyJSON(request);
    if(!/^\d{4}-\d{2}-\d{2}$/.test(data?.date||'')||!Array.isArray(data?.tasks)||data.tasks.length>30||data.tasks.some(t=>typeof t!=='string'||!t.trim()||t.length>500))return reply({error:'Invalid practice day'},400);
    const tasks=data.tasks.map(t=>t.trim());
    await env.DB.prepare('INSERT INTO practice_days(date,assignments_json,updated_at) VALUES(?,?,CURRENT_TIMESTAMP) ON CONFLICT(date) DO UPDATE SET assignments_json=excluded.assignments_json,updated_at=CURRENT_TIMESTAMP').bind(data.date,JSON.stringify(tasks)).run();
    // Discard stale completion indices if the parent edits assignments.
    await env.DB.prepare('DELETE FROM practice_completion WHERE date=?').bind(data.date).run();
    return reply({ok:true});
  }
  if(path==='/schedule/rest'&&method==='PUT'){
    if(user?.role!=='parent')return reply({error:'Parent access required'},403);
    const data=await bodyJSON(request);
    if(!/^\d{4}-\d{2}-\d{2}$/.test(data?.date||'')||typeof data?.rest!=='boolean')return reply({error:'Invalid rest day'},400);
    await env.DB.prepare('CREATE TABLE IF NOT EXISTS practice_rest_days (date TEXT PRIMARY KEY)').run();
    if(data.rest){
      const row=await env.DB.prepare('SELECT assignments_json FROM practice_days WHERE date=?').bind(data.date).first();
      if(row&&JSON.parse(row.assignments_json).length)return reply({error:'Remove assigned tasks before marking rest'},409);
      await env.DB.prepare('INSERT INTO practice_rest_days(date) VALUES(?) ON CONFLICT(date) DO NOTHING').bind(data.date).run();
    }else await env.DB.prepare('DELETE FROM practice_rest_days WHERE date=?').bind(data.date).run();
    return reply({ok:true});
  }
  if(path==='/store'&&method==='GET'){
    if(!user)return reply({error:'Unauthorized'},401);
    await env.DB.prepare("CREATE TABLE IF NOT EXISTS shared_store (id INTEGER PRIMARY KEY CHECK(id=1), data TEXT NOT NULL, version INTEGER NOT NULL DEFAULT 0)").run();
    const row=await env.DB.prepare('SELECT data,version FROM shared_store WHERE id=1').first();
    return reply({store:row?JSON.parse(row.data):null,version:row?.version??0});
  }
  if(path==='/store'&&method==='PUT'){
    if(!user)return reply({error:'Unauthorized'},401);
    const data=await bodyJSON(request),store=data?.store;
    if(!Number.isInteger(data?.version)||data.version<0||!store||typeof store!=='object'||!Number.isFinite(store.spent)||store.spent<0||!Array.isArray(store.claims)||!Array.isArray(store.draws)||!Array.isArray(store.remaining)||JSON.stringify(store).length>40000)return reply({error:'Invalid store data'},400);
    await env.DB.prepare("CREATE TABLE IF NOT EXISTS shared_store (id INTEGER PRIMARY KEY CHECK(id=1), data TEXT NOT NULL, version INTEGER NOT NULL DEFAULT 0)").run();
    if(data.version===0)await env.DB.prepare('INSERT INTO shared_store(id,data,version) VALUES(1,?,1) ON CONFLICT(id) DO NOTHING').bind(JSON.stringify(store)).run();
    else await env.DB.prepare('UPDATE shared_store SET data=?,version=version+1 WHERE id=1 AND version=?').bind(JSON.stringify(store),data.version).run();
    const row=await env.DB.prepare('SELECT data,version FROM shared_store WHERE id=1').first();
    if(row.version!==data.version+1)return reply({error:'Store changed on another device; refresh before trying again',store:JSON.parse(row.data),version:row.version},409);
    return reply({ok:true,version:row.version});
  }
  if(path==='/rewards/test-audit'&&method==='GET'){
    if(user?.role!=='parent')return reply({error:'Parent access required'},403);
    await env.DB.prepare('CREATE TABLE IF NOT EXISTS practice_rewards (date TEXT PRIMARY KEY, xp INTEGER NOT NULL DEFAULT 100, awarded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)').run();
    const date='2026-11-17';
    const award=await env.DB.prepare('SELECT date,xp,awarded_at FROM practice_rewards WHERE date=?').bind(date).first();
    const completion=await env.DB.prepare('SELECT task_index FROM practice_completion WHERE date=?').bind(date).all();
    return reply({date,award:award||null,checkedTasks:(completion.results||[]).map(x=>x.task_index)});
  }
  if(path==='/rewards/test-clear'&&method==='POST'){
    if(user?.role!=='parent')return reply({error:'Parent access required'},403);
    const data=await bodyJSON(request);
    if(data?.date!=='2026-11-17'||data?.confirm!=='CLEAR_TEST_AWARD')return reply({error:'Explicit test award confirmation required'},400);
    const completion=await env.DB.prepare('SELECT COUNT(*) AS n FROM practice_completion WHERE date=?').bind(data.date).first();
    if(completion.n!==0)return reply({error:'Cannot clear award while lesson is checked'},409);
    await env.DB.prepare('CREATE TABLE IF NOT EXISTS practice_rewards (date TEXT PRIMARY KEY, xp INTEGER NOT NULL DEFAULT 100, awarded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)').run();
    const result=await env.DB.prepare('DELETE FROM practice_rewards WHERE date=?').bind(data.date).run();
    await ensureMysteries(env);
    await env.DB.prepare('DELETE FROM practice_mysteries WHERE date=?').bind(data.date).run();
    return reply({ok:true,deleted:result.meta.changes});
  }
  // Parent-only integration test: isolated D1 table; never touches real XP, prizes or practice.
  if(path==='/rewards/mysteries/test'&&method==='POST'){
    if(user?.role!=='parent')return reply({error:'Parent access required'},403);
    await env.DB.prepare("CREATE TABLE IF NOT EXISTS mystery_test_runs (id TEXT PRIMARY KEY, kind TEXT NOT NULL, prize_id TEXT, bonus_xp INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)").run();
    const data=await bodyJSON(request);
    if(!/^[a-zA-Z0-9_-]{8,80}$/.test(data?.id||''))return reply({error:'Invalid test identifier'},400);
    const existing=await env.DB.prepare('SELECT id,kind,prize_id,bonus_xp FROM mystery_test_runs WHERE id=?').bind(data.id).first();
    if(existing)return reply({result:{...existing,prize:mysteryPrizes.find(p=>p.id===existing.prize_id)||null},created:false,isolated:true});
    const roll=crypto.getRandomValues(new Uint32Array(1))[0]/4294967296;
    let kind='none',prize=null,bonus=0;
    if(roll<.055){kind='bonus';bonus=100}
    else if(roll<.10){kind='prize';prize=mysteryPrizes[crypto.getRandomValues(new Uint32Array(1))[0]%mysteryPrizes.length].id}
    const saved=await env.DB.prepare('INSERT INTO mystery_test_runs(id,kind,prize_id,bonus_xp) VALUES(?,?,?,?) ON CONFLICT(id) DO NOTHING').bind(data.id,kind,prize,bonus).run();
    const row=await env.DB.prepare('SELECT id,kind,prize_id,bonus_xp FROM mystery_test_runs WHERE id=?').bind(data.id).first();
    return reply({result:{...row,prize:mysteryPrizes.find(p=>p.id===row.prize_id)||null},created:saved.meta.changes===1,isolated:true});
  }
  if(path==='/rewards/mysteries/test'&&method==='DELETE'){
    if(user?.role!=='parent')return reply({error:'Parent access required'},403);
    await env.DB.prepare("CREATE TABLE IF NOT EXISTS mystery_test_runs (id TEXT PRIMARY KEY, kind TEXT NOT NULL, prize_id TEXT, bonus_xp INTEGER NOT NULL DEFAULT 0, created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)").run();
    const data=await bodyJSON(request);
    if(!/^[a-zA-Z0-9_-]{8,80}$/.test(data?.id||''))return reply({error:'Invalid test identifier'},400);
    const deleted=await env.DB.prepare('DELETE FROM mystery_test_runs WHERE id=?').bind(data.id).run();
    return reply({ok:true,deleted:deleted.meta.changes,isolated:true});
  }
  if(path==='/rewards/mysteries'&&method==='GET'){
    if(!user)return reply({error:'Unauthorized'},401);
    await ensureMysteries(env);
    const rows=await env.DB.prepare('SELECT date,kind,prize_id,bonus_xp,fulfilled FROM practice_mysteries ORDER BY date').all();
    return reply({mysteries:(rows.results||[]).map(r=>({...r,prize:mysteryPrizes.find(p=>p.id===r.prize_id)||null}))});
  }
  if(path==='/rewards/mysteries/fulfill'&&method==='POST'){
    if(user?.role!=='parent')return reply({error:'Parent access required'},403);
    const data=await bodyJSON(request);
    if(!/^\d{4}-\d{2}-\d{2}$/.test(data?.date||''))return reply({error:'Invalid date'},400);
    await ensureMysteries(env);
    await env.DB.prepare("UPDATE practice_mysteries SET fulfilled=1 WHERE date=? AND kind='prize'").bind(data.date).run();
    return reply({ok:true});
  }
  if(path==='/rewards/progress'&&method==='GET'){
    if(!user)return reply({error:'Unauthorized'},401);
    await env.DB.prepare('CREATE TABLE IF NOT EXISTS practice_rewards (date TEXT PRIMARY KEY, xp INTEGER NOT NULL DEFAULT 100, awarded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)').run();
    const rows=await env.DB.prepare('SELECT date,xp FROM practice_rewards ORDER BY date').all();
    await ensureMysteries(env);
    const bonuses=await env.DB.prepare("SELECT COALESCE(SUM(bonus_xp),0) AS total FROM practice_mysteries WHERE date IN (SELECT date FROM practice_rewards)").first();
    await env.DB.prepare('CREATE TABLE IF NOT EXISTS practice_rest_days (date TEXT PRIMARY KEY)').run();
    const rests=await env.DB.prepare('SELECT date FROM practice_rest_days ORDER BY date').all();
    return reply({awards:rows.results||[],restDays:(rests.results||[]).map(r=>r.date),totalXP:(rows.results||[]).reduce((n,r)=>n+r.xp,0)+(bonuses?.total||0),bonusXP:bonuses?.total||0});
  }
  if(path==='/schedule/completion'&&method==='PUT'){
    if(!user)return reply({error:'Unauthorized'},401);
    const data=await bodyJSON(request);
    if(!/^\d{4}-\d{2}-\d{2}$/.test(data?.date||'')||!Number.isInteger(data?.index)||data.index<0||typeof data?.completed!=='boolean')return reply({error:'Invalid completion'},400);
    const row=await env.DB.prepare('SELECT assignments_json FROM practice_days WHERE date=?').bind(data.date).first();
    if(!row)return reply({error:'No scheduled practice for date'},404);
    const tasks=JSON.parse(row.assignments_json);if(data.index>=tasks.length)return reply({error:'Assignment not found'},404);
    if(data.completed)await env.DB.prepare('INSERT INTO practice_completion(date,task_index) VALUES(?,?) ON CONFLICT(date,task_index) DO NOTHING').bind(data.date,data.index).run();
    else await env.DB.prepare('DELETE FROM practice_completion WHERE date=? AND task_index=?').bind(data.date,data.index).run();
    await env.DB.prepare('CREATE TABLE IF NOT EXISTS practice_rewards (date TEXT PRIMARY KEY, xp INTEGER NOT NULL DEFAULT 100, awarded_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP)').run();
    const completed=await env.DB.prepare('SELECT COUNT(*) AS count FROM practice_completion WHERE date=?').bind(data.date).first();
    let awarded=false,mystery=null,newDraw=false;
    if(tasks.length>0&&completed.count===tasks.length){
      const reward=await env.DB.prepare('INSERT INTO practice_rewards(date,xp) VALUES(?,100) ON CONFLICT(date) DO NOTHING').bind(data.date).run();
      awarded=reward.meta.changes===1;
      const draw=await drawMystery(env,data.date);mystery=draw.mystery;newDraw=draw.newDraw;
    }
    const awards=await env.DB.prepare('SELECT date,xp FROM practice_rewards ORDER BY date').all();
    return reply({ok:true,awarded,awards:awards.results||[],mystery:newDraw?{...mystery,prize:mysteryPrizes.find(p=>p.id===mystery.prize_id)||null}:null});
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
