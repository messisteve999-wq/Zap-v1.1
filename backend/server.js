const express=require('express');
const cors=require('cors');
const crypto=require('crypto');
const {DatabaseSync}=require('node:sqlite');
const path=require('path');
const app=express();
app.use(cors()); app.use(express.json({limit:'32kb'}));
const PORT=process.env.PORT||3000;
const db=new DatabaseSync(process.env.DB_PATH||path.join(__dirname,'zap.db'));
db.exec(`PRAGMA journal_mode=WAL;
CREATE TABLE IF NOT EXISTS users(id TEXT PRIMARY KEY,phone TEXT UNIQUE NOT NULL,name TEXT NOT NULL,pin_hash TEXT NOT NULL,created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(token_hash TEXT PRIMARY KEY,user_id TEXT NOT NULL,created_at TEXT NOT NULL,expires_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS requests(id TEXT PRIMARY KEY,requester_id TEXT NOT NULL,target_id TEXT NOT NULL,status TEXT NOT NULL,created_at TEXT NOT NULL,responded_at TEXT);
CREATE TABLE IF NOT EXISTS connections(id TEXT PRIMARY KEY,user_a TEXT NOT NULL,user_b TEXT NOT NULL,status TEXT NOT NULL,created_at TEXT NOT NULL,revoked_at TEXT);`);
const q=(sql,params=[])=>db.prepare(sql).all(...params);
const one=(sql,params=[])=>db.prepare(sql).get(...params);
const run=(sql,params=[])=>db.prepare(sql).run(...params);
const id=p=>p+'_'+crypto.randomBytes(12).toString('hex');
const now=()=>new Date(); const iso=()=>now().toISOString();
function phone(v){return String(v||'').replace(/[^0-9+]/g,'');}
function hashPin(pin,salt=crypto.randomBytes(16).toString('hex')){return salt+':'+crypto.scryptSync(String(pin),salt,32).toString('hex');}
function verifyPin(pin,stored){const [salt,digest]=String(stored).split(':'); if(!salt||!digest)return false; const got=crypto.scryptSync(String(pin),salt,32).toString('hex'); return crypto.timingSafeEqual(Buffer.from(got),Buffer.from(digest));}
function token(){return crypto.randomBytes(32).toString('base64url');}
function tokenHash(t){return crypto.createHash('sha256').update(t).digest('hex');}
function user(id){return one('SELECT id,phone,name,created_at createdAt FROM users WHERE id=?',[id]);}
function auth(req,res,next){const h=req.get('authorization')||''; const raw=h.startsWith('Bearer ')?h.slice(7):''; if(!raw)return res.status(401).json({error:'auth_required'}); const s=one('SELECT * FROM sessions WHERE token_hash=? AND expires_at>?',[tokenHash(raw),iso()]); if(!s)return res.status(401).json({error:'session_expired'}); req.user=user(s.user_id); next();}
app.get('/api/health',(req,res)=>res.json({ok:true,app:'Zap',version:'1.1.0',consentOnly:true,database:'sqlite'}));
app.post('/api/register',(req,res)=>{const p=phone(req.body.phone),name=String(req.body.name||'').trim()||'Zap user',pin=String(req.body.pin||''); if(!p||pin.length<4)return res.status(400).json({error:'phone_and_pin_required'}); if(one('SELECT id FROM users WHERE phone=?',[p]))return res.status(409).json({error:'phone_already_registered'}); const uid=id('usr'); run('INSERT INTO users VALUES(?,?,?,?,?)',[uid,p,name,hashPin(pin),iso()]); res.status(201).json({user:user(uid)});});
app.post('/api/login',(req,res)=>{const p=phone(req.body.phone),pin=String(req.body.pin||'');const u=one('SELECT * FROM users WHERE phone=?',[p]);if(!u||!verifyPin(pin,u.pin_hash))return res.status(401).json({error:'invalid_credentials'});const t=token(),expires=new Date(Date.now()+30*24*3600e3).toISOString();run('INSERT INTO sessions VALUES(?,?,?,?)',[tokenHash(t),u.id,iso(),expires]);res.json({token:t,expiresAt:expires,user:user(u.id)});});
app.post('/api/logout',auth,(req,res)=>{const raw=(req.get('authorization')||'').slice(7);run('DELETE FROM sessions WHERE token_hash=?',[tokenHash(raw)]);res.json({ok:true});});
app.get('/api/me',auth,(req,res)=>res.json({user:req.user}));
app.post('/api/requests',auth,(req,res)=>{const target=one('SELECT id,phone,name FROM users WHERE phone=?',[phone(req.body.targetPhone)]);if(!target)return res.status(404).json({error:'target_not_registered'});if(target.id===req.user.id)return res.status(400).json({error:'cannot_request_self'});const active=one(`SELECT id FROM connections WHERE status='active' AND ((user_a=? AND user_b=?) OR (user_a=? AND user_b=?))`,[req.user.id,target.id,target.id,req.user.id]);if(active)return res.status(409).json({error:'already_connected'});const pending=one(`SELECT id FROM requests WHERE requester_id=? AND target_id=? AND status='pending'`,[req.user.id,target.id]);if(pending)return res.json({request:{id:pending.id,status:'pending'}});const rid=id('req');run('INSERT INTO requests VALUES(?,?,?,?,?,?)',[rid,req.user.id,target.id,'pending',iso(),null]);res.status(201).json({request:{id:rid,status:'pending'},target});});
app.get('/api/requests/incoming',auth,(req,res)=>{const rows=q(`SELECT r.id,r.status,r.created_at createdAt,u.id requesterId,u.name requesterName,u.phone requesterPhone FROM requests r JOIN users u ON u.id=r.requester_id WHERE r.target_id=? AND r.status='pending' ORDER BY r.created_at DESC`,[req.user.id]);res.json({requests:rows});});
app.get('/api/requests/outgoing',auth,(req,res)=>{const rows=q(`SELECT r.id,r.status,r.created_at createdAt,u.id targetId,u.name targetName,u.phone targetPhone FROM requests r JOIN users u ON u.id=r.target_id WHERE r.requester_id=? ORDER BY r.created_at DESC`,[req.user.id]);res.json({requests:rows});});
app.post('/api/requests/:id/respond',auth,(req,res)=>{const r=one('SELECT * FROM requests WHERE id=?',[req.params.id]);if(!r)return res.status(404).json({error:'request_not_found'});if(r.target_id!==req.user.id)return res.status(403).json({error:'not_target'});if(r.status!=='pending')return res.status(409).json({error:'already_processed'});const action=req.body.action;if(!['accept','reject'].includes(action))return res.status(400).json({error:'invalid_action'});run('UPDATE requests SET status=?,responded_at=? WHERE id=?',[action==='accept'?'accepted':'rejected',iso(),r.id]);if(action==='accept'){const c=id('con');run('INSERT INTO connections VALUES(?,?,?,?,?,?)',[c,r.requester_id,r.target_id,'active',iso(),null]);return res.json({ok:true,status:'accepted',connectionId:c});}res.json({ok:true,status:'rejected'});});
app.get('/api/connections',auth,(req,res)=>{const rows=q(`SELECT c.id,c.created_at createdAt,u.id otherId,u.name otherName,u.phone otherPhone FROM connections c JOIN users u ON u.id=CASE WHEN c.user_a=? THEN c.user_b ELSE c.user_a END WHERE (c.user_a=? OR c.user_b=?) AND c.status='active' ORDER BY c.created_at DESC`,[req.user.id,req.user.id,req.user.id]);res.json({connections:rows});});
app.post('/api/connections/:id/revoke',auth,(req,res)=>{const c=one('SELECT * FROM connections WHERE id=? AND status=\'active\'',[req.params.id]);if(!c)return res.status(404).json({error:'connection_not_found'});if(c.user_a!==req.user.id&&c.user_b!==req.user.id)return res.status(403).json({error:'not_member'});run('UPDATE connections SET status=\'revoked\',revoked_at=? WHERE id=?',[iso(),c.id]);res.json({ok:true});});
app.get('/api/notifications',auth,(req,res)=>{const incoming=one(`SELECT COUNT(*) count FROM requests WHERE target_id=? AND status='pending'`,[req.user.id]).count;res.json({pendingRequests:Number(incoming)});});
app.use((err,req,res,next)=>{console.error(err);res.status(500).json({error:'server_error'});});
app.listen(PORT,()=>console.log(`Zap V1.1 listening on ${PORT}`));
