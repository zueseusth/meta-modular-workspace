'use strict';
const express = require('express');
const { Pool } = require('pg');
const crypto = require('crypto');
const app=express();
const origin='https://meta-modular-workspace.onrender.com';
app.disable('x-powered-by');
app.use(express.json({limit:'12mb'}));
app.use((req,res,next)=>{
 res.set('Access-Control-Allow-Origin',origin);
 res.set('Vary','Origin');
 res.set('Access-Control-Allow-Headers','Authorization,Content-Type');
 res.set('Access-Control-Allow-Methods','GET,PUT,POST,DELETE,OPTIONS');
 res.set('Cache-Control','no-store');
 if(req.method==='OPTIONS') return res.sendStatus(204);
 next();
});
const pool=process.env.DATABASE_URL?new Pool({connectionString:process.env.DATABASE_URL,ssl:process.env.DB_SSL==='true'?{rejectUnauthorized:false}:undefined}):null;
let initPromise;
async function init(){
 if(!pool)throw Error('DATABASE_URL not configured');
 await pool.query('CREATE TABLE IF NOT EXISTS meta_workspace (id text primary key, state jsonb not null, revision bigint not null default 0, updated_at timestamptz not null default now())');
 await pool.query('CREATE TABLE IF NOT EXISTS meta_files (id text primary key, payload jsonb not null, updated_at timestamptz not null default now())');
}
function ready(){if(!initPromise)initPromise=init().catch(err=>{initPromise=null;throw err});return initPromise}
function auth(req,res,next){
 const secret=process.env.META_ACCESS_TOKEN;
 const token=(req.get('authorization')||'').replace(/^Bearer\s+/i,'');
 if(!secret||!token||Buffer.byteLength(token)!==Buffer.byteLength(secret)||!crypto.timingSafeEqual(Buffer.from(token),Buffer.from(secret)))return res.status(401).json({error:'Unauthorized'});
 next();
}
app.get('/health',async(req,res)=>{try{await ready();await pool.query('SELECT 1');res.json({status:'ok',database:'connected'})}catch(e){res.status(503).json({status:'unavailable',database:'not_connected'})}});
app.use('/api',auth);
app.get('/api/workspace',async(req,res)=>{try{await ready();const q=await pool.query("SELECT state,revision,updated_at FROM meta_workspace WHERE id='default'");if(!q.rows.length)return res.json({state:null,revision:0});res.json(q.rows[0])}catch(e){res.status(503).json({error:'Database unavailable'})}});
app.put('/api/workspace',async(req,res)=>{
 try{
  await ready();
  const state=req.body.state, revision=req.body.revision;
  if(!state||!Array.isArray(state.nodes)||!Array.isArray(state.edges)||!Array.isArray(state.events)||!Number.isSafeInteger(revision)||revision<0)return res.status(400).json({error:'Invalid workspace or revision'});
  const payload=JSON.stringify(state);
  if(Buffer.byteLength(payload)>8*1024*1024)return res.status(413).json({error:'Workspace too large'});
  const q=await pool.query("INSERT INTO meta_workspace (id,state,revision) VALUES ('default',$1::jsonb,1) ON CONFLICT (id) DO UPDATE SET state=EXCLUDED.state,revision=meta_workspace.revision+1,updated_at=now() WHERE meta_workspace.revision=$2 RETURNING revision,updated_at",[payload,revision]);
  if(!q.rows.length)return res.status(409).json({error:'A newer cloud revision exists. Load cloud before saving.'});
  res.json(q.rows[0]);
 }catch(e){res.status(503).json({error:'Database unavailable'})}
});
app.get('/api/files/:id',async(req,res)=>{try{await ready();const q=await pool.query('SELECT payload FROM meta_files WHERE id=$1',[req.params.id]);if(!q.rows.length)return res.status(404).json({error:'File not found'});res.json(q.rows[0].payload)}catch(e){res.status(503).json({error:'Database unavailable'})}});
app.put('/api/files/:id',async(req,res)=>{try{await ready();const v=req.body;if(!v||v.id!==req.params.id||typeof v.data!=='string'||v.data.length>10*1024*1024||typeof v.name!=='string')return res.status(400).json({error:'Invalid file or size > 7.5MB'});await pool.query('INSERT INTO meta_files(id,payload) VALUES ($1,$2::jsonb) ON CONFLICT(id) DO UPDATE SET payload=EXCLUDED.payload,updated_at=now()',[req.params.id,JSON.stringify(v)]);res.json({ok:true})}catch(e){res.status(503).json({error:'Database unavailable'})}});
app.delete('/api/files/:id',async(req,res)=>{try{await ready();await pool.query('DELETE FROM meta_files WHERE id=$1',[req.params.id]);res.json({ok:true})}catch(e){res.status(503).json({error:'Database unavailable'})}});
app.listen(process.env.PORT||10000,'0.0.0.0',()=>console.log('META cloud API listening'));
