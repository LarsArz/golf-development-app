// The Swing Lab API — shared schedule and daily inspiration.
// D1 binding DB is configured in Cloudflare. This Worker intentionally does not
// enable public writes: parent authentication must be configured first.
const allowedOrigin = 'https://larsarz.github.io';
const json=(data,status=200)=>new Response(JSON.stringify(data),{status,headers:{'content-type':'application/json; charset=utf-8','cache-control':'no-store','access-control-allow-origin':allowedOrigin,'vary':'Origin'}});
export default {
  async fetch(request,env){
    const url=new URL(request.url);
    if(request.method==='OPTIONS')return new Response(null,{status:204,headers:{'access-control-allow-origin':allowedOrigin,'access-control-allow-methods':'GET, OPTIONS','access-control-allow-headers':'content-type','access-control-max-age':'600'}});
    if(url.pathname==='/health'&&request.method==='GET'){
      try{const row=await env.DB.prepare('SELECT 1 AS ok').first();return json({ok:row?.ok===1,service:'swing-lab-api',database:'connected'});}
      catch(e){return json({ok:false,service:'swing-lab-api',database:'unavailable'},503)}
    }
    return json({error:'Not found'},404);
  }
};
