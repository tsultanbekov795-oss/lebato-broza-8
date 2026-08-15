const express = require('express');
const http = require('http');
const path = require('path');
const fs = require('fs');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Server } = require('socket.io');
const dgram = require('dgram');
const os = require('os');

const PORT = Number(process.env.PORT || 3000);
const HOST = String(process.env.HOST || '0.0.0.0');
const JWT_SECRET = process.env.JWT_SECRET || 'CHANGE_ME_BEFORE_PRODUCTION';
const ADMIN_NAME = String(process.env.ADMIN_NAME || '').trim().toLowerCase();
const DB_FILE = path.join(__dirname, 'data.json');

function emptyDB(){ return {users:[],posts:[],comments:[],likes:[],follows:[],reports:[],dictionary:[],notifications:[],messages:[],communities:[],communityMembers:[],verificationRequests:[]}; }
function loadDB(){
  try {
    const d=JSON.parse(fs.readFileSync(DB_FILE,'utf8'));
    const base=emptyDB();
    for(const k of Object.keys(base)) if(!Array.isArray(d[k])) d[k]=base[k];
    // Migrate the previous post shape without losing old content.
    for(const p of d.posts){
      if(!Array.isArray(p.images)) p.images=[];
      if(!Array.isArray(p.videos)) p.videos=[];
      if(!Array.isArray(p.hashtags)) p.hashtags=hashtags(p.text||'');
      if(p.authorId==null){ const u=d.users.find(x=>x.name===p.author); if(u) p.authorId=u.id; }
    }
    if(!Array.isArray(d.communities)) d.communities=[]; if(!Array.isArray(d.communityMembers)) d.communityMembers=[]; if(!Array.isArray(d.verificationRequests)) d.verificationRequests=[];
    for(const u of d.users){
      if(!u.role) u.role=(ADMIN_NAME && String(u.name).toLowerCase()===ADMIN_NAME)?'admin':'user';
      if(typeof u.banned!=='boolean') u.banned=false;
      if(!Array.isArray(u.blocks)) u.blocks=[]; if(!u.username) u.username=(u.name||'user').toLowerCase().replace(/[^\p{L}\p{N}_]+/gu,'_').replace(/^_+|_+$/g,'').slice(0,24)||('user_'+u.id.slice(-6)); if(!Array.isArray(u.stickers)) u.stickers=[]; if(!u.verification) u.verification=null;
    }
    return d;
  } catch { const d=emptyDB(); fs.writeFileSync(DB_FILE,JSON.stringify(d,null,2)); return d; }
}
let db=loadDB();
function saveDB(){ fs.writeFileSync(DB_FILE,JSON.stringify(db,null,2)); }
function id(){ return Math.random().toString(36).slice(2)+Date.now().toString(36); }
function defaultAvatar(name){ return `https://api.dicebear.com/7.x/avataaars/svg?seed=${encodeURIComponent(name)}`; }
function hashtags(text){ return [...new Set((String(text).match(/#[\p{L}\p{N}_]+/gu)||[]).map(x=>x.slice(1).toLowerCase()))].slice(0,10); }
function publicUser(u,viewerId){
  const followers=db.follows.filter(x=>x.followingId===u.id).length;
  const following=db.follows.filter(x=>x.followerId===u.id).length;
  const myPosts=db.posts.filter(p=>p.authorId===u.id).map(p=>p.id);
  const likes=db.likes.filter(l=>myPosts.includes(l.postId)).length;
  return {
    id:u.id,
    name:u.name,
    username:u.username,
    bio:u.bio||'',
    avatar:u.avatar||defaultAvatar(u.name),
    cover:u.cover||'',
    createdAt:u.createdAt,
    role:u.role||'user',
    verification:u.verification||null,
    stickers:u.stickers||[],
    banned:!!u.banned,
    followers,
    following,
    likes,
    isFollowing:!!(viewerId&&db.follows.some(x=>x.followerId===viewerId&&x.followingId===u.id)),
    isBlocked:!!(viewerId&&u.blocks?.includes(viewerId))
  };
}
function tokenFor(u){ return jwt.sign({id:u.id},JWT_SECRET,{expiresIn:'30d'}); }
function auth(req,res,next){
  const h=req.headers.authorization||''; const token=h.startsWith('Bearer ')?h.slice(7):null;
  if(!token) return res.status(401).json({error:'Требуется вход'});
  try{ const p=jwt.verify(token,JWT_SECRET); req.user=db.users.find(u=>u.id===p.id); if(!req.user) throw 0; if(req.user.banned) return res.status(403).json({error:'Аккаунт заблокирован'}); next(); }
  catch(e){ if(e?.status) return; return res.status(401).json({error:'Сессия недействительна'}); }
}
function admin(req,res,next){ if(req.user.role!=='admin') return res.status(403).json({error:'Нужны права администратора'}); next(); }
function findPost(pid){ return db.posts.find(p=>p.id===pid); }
function postView(p,viewerId){
  const u=db.users.find(x=>x.id===p.authorId);
  const blocked=u?.blocks?.includes(viewerId) || db.users.some(x=>x.id===viewerId&&x.blocks?.includes(p.authorId));
  const likes=db.likes.filter(x=>x.postId===p.id).length;
  return {...p,author:u?.name||p.author||'Пользователь',username:u?.username||'',verification:u?.verification||null,avatar:u?.avatar||p.avatar||defaultAvatar(u?.name||'user'),likes,liked:db.likes.some(x=>x.postId===p.id&&x.userId===viewerId),reposts:p.reposts||0,blocked};
}
function notify(userId,type,data){ db.notifications.push({id:id(),userId,type,data,read:false,createdAt:Date.now()}); }

const app=express();
app.use((req,res,next)=>{const origin=req.headers.origin;if(origin){res.setHeader('Access-Control-Allow-Origin',origin);res.setHeader('Vary','Origin');res.setHeader('Access-Control-Allow-Headers','Content-Type, Authorization');res.setHeader('Access-Control-Allow-Methods','GET,POST,PATCH,DELETE,OPTIONS')}if(req.method==='OPTIONS')return res.sendStatus(204);next()});
app.use(express.json({limit:'12mb'}));
app.use(express.static(__dirname));
app.get('/api/health',(req,res)=>res.json({ok:true,service:'Lebato Broza Social',version:'8'}));

app.post('/api/auth/register',async(req,res)=>{
  const name=String(req.body.name||'').trim(), password=String(req.body.password||'');
  if(name.length<2||name.length>30) return res.status(400).json({error:'Имя: от 2 до 30 символов'});
  if(!/^[\p{L}\p{N}_ .-]+$/u.test(name)) return res.status(400).json({error:'Имя содержит недопустимые символы'});
  if(password.length<6) return res.status(400).json({error:'Пароль должен быть не короче 6 символов'});
  if(db.users.some(u=>u.name.toLowerCase()===name.toLowerCase())) return res.status(409).json({error:'Такое имя уже занято'});
  const baseUsername=name.toLowerCase().replace(/[^\p{L}\p{N}_]+/gu,'_').replace(/^_+|_+$/g,'').slice(0,24)||'user'; let username=baseUsername; let n=2; while(db.users.some(u=>u.username===username)) username=(baseUsername.slice(0,20)+'_'+n++).slice(0,24); const user={id:id(),name,username,bio:'',avatar:defaultAvatar(name),passwordHash:await bcrypt.hash(password,10),createdAt:Date.now(),role:(ADMIN_NAME===name.toLowerCase()?'admin':'user'),banned:false,blocks:[]};
  db.users.push(user); saveDB(); res.json({token:tokenFor(user),user:publicUser(user,user.id)});
});
app.post('/api/auth/login',async(req,res)=>{
  const name=String(req.body.name||'').trim(), password=String(req.body.password||'');
  const user=db.users.find(u=>u.name.toLowerCase()===name.toLowerCase());
  if(!user||!(await bcrypt.compare(password,user.passwordHash))) return res.status(401).json({error:'Неверное имя или пароль'});
  if(user.banned) return res.status(403).json({error:'Аккаунт заблокирован'});
  res.json({token:tokenFor(user),user:publicUser(user,user.id)});
});
app.get('/api/me',auth,(req,res)=>res.json(publicUser(req.user,req.user.id)));
app.patch('/api/me',auth,(req,res)=>{
  if(req.body.username!==undefined){const username=String(req.body.username).trim().replace(/^@/,'').toLowerCase();if(!/^[a-zA-Z0-9_]{3,24}$/.test(username))return res.status(400).json({error:'Username: 3-24 символа, только латиница, цифры и _'});if(db.users.some(u=>u.id!==req.user.id&&u.username===username))return res.status(409).json({error:'Этот username уже занят'});req.user.username=username;}
  if(req.body.name!==undefined){const name=String(req.body.name).trim();if(name.length<2||name.length>30)return res.status(400).json({error:'Некорректное имя'});if(db.users.some(u=>u.id!==req.user.id&&u.name.toLowerCase()===name.toLowerCase()))return res.status(409).json({error:'Имя занято'});req.user.name=name;}
  if(req.body.bio!==undefined) req.user.bio=String(req.body.bio).slice(0,160);
  if(req.body.avatar!==undefined){const a=String(req.body.avatar);if(a.length>7000000)return res.status(413).json({error:'Аватар слишком большой'});if(a && !/^data:image\/(png|jpeg|jpg|webp|gif);base64,/i.test(a) && !/^https:\/\//i.test(a)) return res.status(400).json({error:'Неподдерживаемый аватар'});req.user.avatar=a;}
  if(req.body.cover!==undefined){const c=String(req.body.cover);if(c.length>7000000)return res.status(413).json({error:'Обложка слишком большая'});if(c && !/^data:image\/(png|jpeg|jpg|webp|gif);base64,/i.test(c) && !/^https:\/\//i.test(c)) return res.status(400).json({error:'Неподдерживаемая обложка'});req.user.cover=c;}
  saveDB();res.json(publicUser(req.user,req.user.id));
});

// Users, profiles, follows and blocks.
app.get('/api/users',auth,(req,res)=>{const q=String(req.query.q||'').trim().toLowerCase();res.json(db.users.filter(u=>u.id!==req.user.id&&!u.banned&&(!q||(u.name.toLowerCase().includes(q)||u.username?.toLowerCase().includes(q.replace(/^@/,''))))).slice(0,50).map(u=>publicUser(u,req.user.id)));});
app.get('/api/users/:id',auth,(req,res)=>{const u=db.users.find(x=>x.id===req.params.id);if(!u)return res.status(404).json({error:'Пользователь не найден'});res.json(publicUser(u,req.user.id));});
app.get('/api/users/:id/posts',auth,(req,res)=>{const u=db.users.find(x=>x.id===req.params.id);if(!u)return res.status(404).json({error:'Пользователь не найден'});res.json(db.posts.filter(p=>p.authorId===u.id).sort((a,b)=>b.createdAt-a.createdAt).map(p=>postView(p,req.user.id)));});
app.post('/api/users/:id/follow',auth,(req,res)=>{const target=db.users.find(x=>x.id===req.params.id);if(!target||target.id===req.user.id)return res.status(400).json({error:'Нельзя подписаться на этого пользователя'});if(req.user.blocks?.includes(target.id)||target.blocks?.includes(req.user.id))return res.status(403).json({error:'Подписка недоступна'});if(!db.follows.some(x=>x.followerId===req.user.id&&x.followingId===target.id)){db.follows.push({followerId:req.user.id,followingId:target.id,createdAt:Date.now()});notify(target.id,'follow',{userId:req.user.id,userName:req.user.name});saveDB();}res.json(publicUser(target,req.user.id));});
app.delete('/api/users/:id/follow',auth,(req,res)=>{db.follows=db.follows.filter(x=>!(x.followerId===req.user.id&&x.followingId===req.params.id));saveDB();const u=db.users.find(x=>x.id===req.params.id);res.json(u?publicUser(u,req.user.id):{});});
app.get('/api/users/:id/followers',auth,(req,res)=>res.json(db.follows.filter(x=>x.followingId===req.params.id).map(x=>db.users.find(u=>u.id===x.followerId)).filter(Boolean).map(u=>publicUser(u,req.user.id))));
app.get('/api/users/:id/following',auth,(req,res)=>res.json(db.follows.filter(x=>x.followerId===req.params.id).map(x=>db.users.find(u=>u.id===x.followingId)).filter(Boolean).map(u=>publicUser(u,req.user.id))));
app.post('/api/users/:id/block',auth,(req,res)=>{const u=db.users.find(x=>x.id===req.params.id);if(!u||u.id===req.user.id)return res.status(400).json({error:'Нельзя заблокировать этого пользователя'});req.user.blocks=req.user.blocks||[];if(!req.user.blocks.includes(u.id))req.user.blocks.push(u.id);db.follows=db.follows.filter(x=>x.followerId!==req.user.id||x.followingId!==u.id);db.follows=db.follows.filter(x=>x.followerId!==u.id||x.followingId!==req.user.id);saveDB();res.json({ok:true});});
app.delete('/api/users/:id/block',auth,(req,res)=>{req.user.blocks=(req.user.blocks||[]).filter(x=>x!==req.params.id);saveDB();res.json({ok:true});});

// Feed and posts.
app.get('/api/feed',auth,(req,res)=>{
  const type=['all','following','popular'].includes(req.query.type)?req.query.type:'all'; const q=String(req.query.q||'').trim().toLowerCase();
  const blocked=new Set(req.user.blocks||[]); db.users.filter(u=>u.blocks?.includes(req.user.id)).forEach(u=>blocked.add(u.id));
  let posts=db.posts.filter(p=>!blocked.has(p.authorId));
  if(type==='following'){const ids=new Set(db.follows.filter(x=>x.followerId===req.user.id).map(x=>x.followingId));posts=posts.filter(p=>ids.has(p.authorId));}
  if(q) posts=posts.filter(p=>(p.text||'').toLowerCase().includes(q)||p.hashtags?.some(h=>h.includes(q.replace(/^#/,'') )));
  if(type==='popular') posts.sort((a,b)=>(db.likes.filter(x=>x.postId===b.id).length*3+(b.reposts||0)*2+(b.comments?.length||0))-(db.likes.filter(x=>x.postId===a.id).length*3+(a.reposts||0)*2+(a.comments?.length||0)));
  else posts.sort((a,b)=>b.createdAt-a.createdAt);
  res.json(posts.slice(0,100).map(p=>postView(p,req.user.id)));
});
app.post('/api/posts',auth,(req,res)=>{
  const text=String(req.body.text||'').trim().slice(0,5000);
  const sticker=req.body.sticker?String(req.body.sticker).slice(0,30):null;
  const images=Array.isArray(req.body.images)?req.body.images.slice(0,6).map(x=>String(x).slice(0,2500000)):[];
  const videos=Array.isArray(req.body.videos)?req.body.videos.slice(0,2).map(x=>String(x).slice(0,8000000)):[];
  if(!text&&!sticker&&!images.length&&!videos.length)return res.status(400).json({error:'Пустой пост'});
  if(images.some(x=>x.length>2500000||(!x.startsWith('data:image/')&&!x.startsWith('https://'))))return res.status(400).json({error:'Некорректная картинка'});
  if(videos.some(x=>x.length>8000000||(!x.startsWith('data:video/')&&!x.startsWith('https://'))))return res.status(400).json({error:'Некорректное видео (макс. ~6 МБ)'});
  const p={id:id(),authorId:req.user.id,author:req.user.name,avatar:req.user.avatar,text,sticker,images,videos,hashtags:hashtags(text),reposts:0,comments:[],createdAt:Date.now(),editedAt:null};
  db.posts.push(p);saveDB();res.json(postView(p,req.user.id));
});
app.patch('/api/posts/:id',auth,(req,res)=>{const p=findPost(req.params.id);if(!p)return res.status(404).json({error:'Пост не найден'});if(p.authorId!==req.user.id)return res.status(403).json({error:'Это не ваш пост'});if(req.body.text!==undefined){p.text=String(req.body.text).trim().slice(0,5000);p.hashtags=hashtags(p.text);}p.editedAt=Date.now();saveDB();res.json(postView(p,req.user.id));});
app.delete('/api/posts/:id',auth,(req,res)=>{const p=findPost(req.params.id);if(!p)return res.status(404).json({error:'Пост не найден'});if(p.authorId!==req.user.id&&req.user.role!=='admin')return res.status(403).json({error:'Нет прав'});db.posts=db.posts.filter(x=>x.id!==p.id);db.likes=db.likes.filter(x=>x.postId!==p.id);db.comments=db.comments.filter(x=>x.postId!==p.id);saveDB();res.json({ok:true});});
app.post('/api/posts/:id/like',auth,(req,res)=>{const p=findPost(req.params.id);if(!p)return res.status(404).json({error:'Пост не найден'});if(db.likes.some(x=>x.postId===p.id&&x.userId===req.user.id))db.likes=db.likes.filter(x=>!(x.postId===p.id&&x.userId===req.user.id));else{db.likes.push({postId:p.id,userId:req.user.id,createdAt:Date.now()});if(p.authorId!==req.user.id)notify(p.authorId,'like',{postId:p.id,userId:req.user.id,userName:req.user.name});}saveDB();res.json(postView(p,req.user.id));});
app.post('/api/posts/:id/repost',auth,(req,res)=>{const p=findPost(req.params.id);if(!p)return res.status(404).json({error:'Пост не найден'});p.reposts=(p.reposts||0)+1;notify(p.authorId,'repost',{postId:p.id,userId:req.user.id,userName:req.user.name});saveDB();res.json(postView(p,req.user.id));});
app.get('/api/posts/:id/comments',auth,(req,res)=>res.json(db.comments.filter(c=>c.postId===req.params.id).sort((a,b)=>a.createdAt-b.createdAt).map(c=>({...c,user:publicUser(db.users.find(u=>u.id===c.userId)||{id:c.userId,name:'Удалён',createdAt:0},req.user.id)}))));
app.post('/api/posts/:id/comments',auth,(req,res)=>{const p=findPost(req.params.id),text=String(req.body.text||'').trim().slice(0,1000);if(!p)return res.status(404).json({error:'Пост не найден'});if(!text)return res.status(400).json({error:'Пустой комментарий'});const c={id:id(),postId:p.id,userId:req.user.id,text,createdAt:Date.now()};db.comments.push(c);p.comments=p.comments||[];p.comments.push({id:c.id,userId:c.userId,text:c.text,createdAt:c.createdAt});notify(p.authorId,'comment',{postId:p.id,userId:req.user.id,userName:req.user.name});saveDB();res.json(c);});

// Stickers.
app.post('/api/me/stickers',auth,(req,res)=>{const sticker=String(req.body.sticker||'').trim().slice(0,12);if(!sticker)return res.status(400).json({error:'Пустой стикер'});req.user.stickers=req.user.stickers||[];if(!req.user.stickers.includes(sticker))req.user.stickers.unshift(sticker);req.user.stickers=req.user.stickers.slice(0,50);saveDB();res.json(publicUser(req.user,req.user.id));});

// Communities.
app.get('/api/communities',auth,(req,res)=>res.json(db.communities.map(c=>({...c,members:db.communityMembers.filter(x=>x.communityId===c.id).length,joined:db.communityMembers.some(x=>x.communityId===c.id&&x.userId===req.user.id)}))));
app.post('/api/communities',auth,(req,res)=>{const name=String(req.body.name||'').trim().slice(0,50),description=String(req.body.description||'').trim().slice(0,200);if(name.length<2)return res.status(400).json({error:'Название слишком короткое'});if(db.communities.some(c=>c.name.toLowerCase()===name.toLowerCase()))return res.status(409).json({error:'Такое сообщество уже есть'});const c={id:id(),name,description,ownerId:req.user.id,createdAt:Date.now()};db.communities.push(c);db.communityMembers.push({communityId:c.id,userId:req.user.id,createdAt:Date.now()});saveDB();res.json(c);});
app.post('/api/communities/:id/join',auth,(req,res)=>{if(!db.communities.some(c=>c.id===req.params.id))return res.status(404).json({error:'Сообщество не найдено'});if(!db.communityMembers.some(x=>x.communityId===req.params.id&&x.userId===req.user.id))db.communityMembers.push({communityId:req.params.id,userId:req.user.id,createdAt:Date.now()});saveDB();res.json({ok:true});});
app.delete('/api/communities/:id/join',auth,(req,res)=>{db.communityMembers=db.communityMembers.filter(x=>!(x.communityId===req.params.id&&x.userId===req.user.id));saveDB();res.json({ok:true});});

// Verification support.
app.post('/api/verification-requests',auth,(req,res)=>{const type=['red','blue'].includes(req.body.type)?req.body.type:null,reason=String(req.body.reason||'').trim().slice(0,1000);if(!type)return res.status(400).json({error:'Выбери тип галочки'});if(db.verificationRequests.some(x=>x.userId===req.user.id&&x.status==='pending'))return res.status(409).json({error:'Заявка уже рассматривается'});const r={id:id(),userId:req.user.id,type,reason,status:'pending',createdAt:Date.now()};db.verificationRequests.push(r);saveDB();res.json(r);});
app.get('/api/admin/verification-requests',auth,admin,(req,res)=>res.json(db.verificationRequests.slice().sort((a,b)=>b.createdAt-a.createdAt).map(r=>({...r,user:publicUser(db.users.find(u=>u.id===r.userId)||{id:r.userId,name:'Удалён'},req.user.id)}))));
app.patch('/api/admin/verification-requests/:id',auth,admin,(req,res)=>{const r=db.verificationRequests.find(x=>x.id===req.params.id);if(!r)return res.status(404).json({error:'Заявка не найдена'});r.status=['approved','rejected'].includes(req.body.status)?req.body.status:'rejected';if(r.status==='approved'){const u=db.users.find(x=>x.id===r.userId);if(u)u.verification=r.type;}saveDB();res.json(r);});

// Search.
app.get('/api/search',auth,(req,res)=>{const q=String(req.query.q||'').trim().toLowerCase().replace(/^#/,'');if(!q)return res.json({users:[],posts:[],hashtags:[]});const users=db.users.filter(u=>!u.banned&&(u.name.toLowerCase().includes(q)||u.username?.toLowerCase().includes(q.replace(/^@/,'')))).slice(0,20).map(u=>publicUser(u,req.user.id));const posts=db.posts.filter(p=>(p.text||'').toLowerCase().includes(q)||p.hashtags?.includes(q)).sort((a,b)=>b.createdAt-a.createdAt).slice(0,30).map(p=>postView(p,req.user.id));const hs=[...new Set(db.posts.flatMap(p=>p.hashtags||[]).filter(h=>h.includes(q)))].slice(0,20);res.json({users,posts,hashtags:hs});});

// Dictionary.
const DEFAULT_DICTIONARY=[
  {word:'Тапули',note:'приветствие / обращение'},
  {word:'Тифтарик',note:'слово из лексики Лебато Броза'},
  {word:'Пинатута пиката',note:'устойчивое выражение Лебато Броза'},
  {word:'Биздак',note:'слово / прощание из лексики Лебато Броза'},
  {word:'Лебато ван лав',note:'выражение из лексики Лебато Броза'}
];
if(!db.dictionary.length) db.dictionary=DEFAULT_DICTIONARY.map(x=>({...x,id:id(),status:'confirmed',createdAt:Date.now()}));
app.get('/api/dictionary',auth,(req,res)=>res.json(db.dictionary.filter(x=>x.status==='confirmed')));
app.post('/api/dictionary/suggest',auth,(req,res)=>{const word=String(req.body.word||'').trim().slice(0,60),note=String(req.body.note||'').trim().slice(0,200);if(word.length<2)return res.status(400).json({error:'Слово слишком короткое'});if(db.dictionary.some(x=>x.word.toLowerCase()===word.toLowerCase()))return res.status(409).json({error:'Такое слово уже есть или уже предложено'});const d={id:id(),word,note,authorId:req.user.id,status:'pending',createdAt:Date.now()};db.dictionary.push(d);saveDB();res.json(d);});

// Reports + notifications.
app.post('/api/reports',auth,(req,res)=>{const targetType=String(req.body.targetType||''),targetId=String(req.body.targetId||''),reason=String(req.body.reason||'').slice(0,200);if(!['user','post','avatar'].includes(targetType)||!targetId||!reason)return res.status(400).json({error:'Некорректная жалоба'});if(db.reports.some(r=>r.reporterId===req.user.id&&r.targetType===targetType&&r.targetId===targetId&&r.status==='open'))return res.status(409).json({error:'Вы уже пожаловались'});const r={id:id(),reporterId:req.user.id,targetType,targetId,reason,status:'open',createdAt:Date.now()};db.reports.push(r);saveDB();res.json(r);});
app.get('/api/notifications',auth,(req,res)=>res.json(db.notifications.filter(n=>n.userId===req.user.id).sort((a,b)=>b.createdAt-a.createdAt).slice(0,50)));
app.post('/api/notifications/read',auth,(req,res)=>{db.notifications.filter(n=>n.userId===req.user.id).forEach(n=>n.read=true);saveDB();res.json({ok:true});});

// Admin.
app.get('/api/admin/reports',auth,admin,(req,res)=>res.json(db.reports.slice().sort((a,b)=>b.createdAt-a.createdAt).map(r=>({...r,reporter:db.users.find(u=>u.id===r.reporterId)?.name||'Удалён'}))));
app.patch('/api/admin/reports/:id',auth,admin,(req,res)=>{const r=db.reports.find(x=>x.id===req.params.id);if(!r)return res.status(404).json({error:'Жалоба не найдена'});r.status=['open','resolved','rejected'].includes(req.body.status)?req.body.status:'resolved';saveDB();res.json(r);});
app.patch('/api/admin/users/:id/ban',auth,admin,(req,res)=>{const u=db.users.find(x=>x.id===req.params.id);if(!u)return res.status(404).json({error:'Пользователь не найден'});if(u.id===req.user.id)return res.status(400).json({error:'Нельзя заблокировать себя'});u.banned=true;u.banReason=String(req.body.reason||'Нарушение правил').slice(0,300);saveDB();res.json(publicUser(u));});
app.patch('/api/admin/users/:id/unban',auth,admin,(req,res)=>{const u=db.users.find(x=>x.id===req.params.id);if(!u)return res.status(404).json({error:'Пользователь не найден'});u.banned=false;u.banReason='';saveDB();res.json(publicUser(u));});
app.delete('/api/admin/posts/:id',auth,admin,(req,res)=>{const p=findPost(req.params.id);if(!p)return res.status(404).json({error:'Пост не найден'});db.posts=db.posts.filter(x=>x.id!==p.id);db.likes=db.likes.filter(x=>x.postId!==p.id);db.comments=db.comments.filter(x=>x.postId!==p.id);saveDB();res.json({ok:true});});
app.delete('/api/admin/users/:id/avatar',auth,admin,(req,res)=>{const u=db.users.find(x=>x.id===req.params.id);if(!u)return res.status(404).json({error:'Пользователь не найден'});u.avatar=defaultAvatar(u.name);saveDB();res.json(publicUser(u));});
app.get('/api/admin/dictionary',auth,admin,(req,res)=>res.json(db.dictionary.slice().sort((a,b)=>b.createdAt-a.createdAt)));
app.patch('/api/admin/dictionary/:id',auth,admin,(req,res)=>{const d=db.dictionary.find(x=>x.id===req.params.id);if(!d)return res.status(404).json({error:'Слово не найдено'});d.status=['pending','confirmed','rejected'].includes(req.body.status)?req.body.status:'confirmed';saveDB();res.json(d);});

// Simple chats remain available as a secondary feature.
function pair(a,b){return [a,b].sort().join(':');}
app.get('/api/chats',auth,(req,res)=>{const ids=new Set();db.messages.forEach(m=>{if(m.from===req.user.id)ids.add(m.to);if(m.to===req.user.id)ids.add(m.from);});res.json([...ids].map(uid=>db.users.find(u=>u.id===uid)).filter(Boolean).map(u=>publicUser(u,req.user.id)));});
app.get('/api/chats/:uid/messages',auth,(req,res)=>res.json(db.messages.filter(m=>pair(m.from,m.to)===pair(req.user.id,req.params.uid)).sort((a,b)=>a.createdAt-b.createdAt)));
app.post('/api/chats/:uid/messages',auth,(req,res)=>{const to=db.users.find(u=>u.id===req.params.uid),text=String(req.body.text||'').trim().slice(0,4000);if(!to)return res.status(404).json({error:'Пользователь не найден'});if(!text)return res.status(400).json({error:'Пустое сообщение'});const m={id:id(),from:req.user.id,to:to.id,text,createdAt:Date.now()};db.messages.push(m);saveDB();io.to(`user:${to.id}`).emit('message',m);res.json(m);});

app.use((req,res,next)=>{if(req.path.startsWith('/api/'))return res.status(404).json({error:'API endpoint not found'});res.sendFile(path.join(__dirname,'index.html'));});
const server=http.createServer(app);const io=new Server(server,{cors:{origin:true,credentials:true}});
io.on('connection',socket=>socket.on('auth',token=>{try{socket.join('user:'+jwt.verify(token,JWT_SECRET).id)}catch{}}));
server.listen(PORT,HOST,()=>{
  console.log(`Lebato Broza Social v7 running on http://localhost:${PORT}`);
  const nets=os.networkInterfaces(), ips=[];
  for(const list of Object.values(nets)) for(const n of (list||[])){
    if(n.family==='IPv4' && !n.internal) ips.push(n.address);
  }
  console.log('Откройте на телефоне один из адресов:');
  console.log(`  http://lebatobroza.local:${PORT}`);
  for(const ip of ips) console.log(`  http://${ip}:${PORT}`);
  // Tiny dependency-free mDNS responder: http://lebatobroza.local:3000
  // This lets a phone find the computer without manually entering its IP.
  try{
    const mdns=dgram.createSocket('udp4');
    const name=Buffer.from('lebatobroza.local');
    const localIP=ips[0]||'127.0.0.1';
    function readName(buf,offset){
      let labels=[], jumped=false, next=offset;
      while(offset<buf.length){
        const len=buf[offset];
        if(len===0){ if(!jumped) next=offset+1; break; }
        if((len&0xc0)===0xc0){
          const ptr=((len&0x3f)<<8)|buf[offset+1];
          if(!jumped) next=offset+2;
          offset=ptr; jumped=true; continue;
        }
        offset++; labels.push(buf.subarray(offset,offset+len).toString()); offset+=len;
      }
      return {name:labels.join('.').toLowerCase(), next};
    }
    mdns.on('message',(msg,rinfo)=>{
      try{
        if(msg.length<12) return;
        const qd=msg.readUInt16BE(4); if(!qd) return;
        let off=12;
        for(let i=0;i<qd;i++){
          const q=readName(msg,off); off=q.next;
          if(off+4>msg.length) return;
          const type=msg.readUInt16BE(off), cls=msg.readUInt16BE(off+2); off+=4;
          if(q.name==='lebatobroza.local' && (type===1||type===255) && (cls===1||cls===255)){
            const ip=Buffer.from(localIP.split('.').map(Number));
            const ans=Buffer.alloc(16);
            msg.copy(ans,0,0,2); // transaction id (normally 0 for mDNS)
            ans.writeUInt16BE(0x8400,2); // response + authoritative
            ans.writeUInt16BE(1,4); ans.writeUInt16BE(1,6); ans.writeUInt16BE(0,8); ans.writeUInt16BE(0,10);
            const question=msg.subarray(12,off);
            const rr=Buffer.alloc(2+2+2+4+2+4);
            rr.writeUInt16BE(0xc00c,0); rr.writeUInt16BE(1,2); rr.writeUInt16BE(1,4); rr.writeUInt32BE(120,6); rr.writeUInt16BE(4,10); ip.copy(rr,12);
            const out=Buffer.concat([ans,question,rr]);
            mdns.send(out,0,out.length,5353,'224.0.0.251');
          }
        }
      }catch{}
    });
    mdns.bind(5353,()=>{try{mdns.addMembership('224.0.0.251');}catch{}});
  }catch(e){ console.log('mDNS автообнаружение недоступно:',e.message); }
});
