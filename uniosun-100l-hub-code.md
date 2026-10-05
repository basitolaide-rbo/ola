# UNIOSUN 100L Hub: all project files

Create each file below at the exact path shown (GitHub: Add file > Create new file, type the path including the folder, paste the code, commit). Also add the UNIOSUN logo as `public/logo.png` (Add file > Upload files).

```
uniosun-100l-hub/
├── .env.example
├── .gitignore
├── package.json
├── README.md
├── server.js
└── public/
    ├── index.html
    ├── style.css
    ├── app.js
    └── logo.png   (you add this)
```


---

## 1. `package.json`

````json
{
  "name": "uniosun-100l-hub",
  "version": "1.0.0",
  "description": "Study hub for UNIOSUN 100 Level students: course PDFs plus an AI tutor",
  "main": "server.js",
  "scripts": { "start": "node server.js", "dev": "node --watch server.js" },
  "engines": { "node": ">=18" },
  "dependencies": {
    "@anthropic-ai/sdk": "^0.60.0",
    "bcryptjs": "^2.4.3",
    "better-sqlite3": "^11.3.0",
    "cookie-parser": "^1.4.6",
    "dotenv": "^16.4.5",
    "express": "^4.19.2",
    "express-rate-limit": "^7.4.0",
    "jsonwebtoken": "^9.0.2",
    "multer": "^1.4.5-lts.1",
    "pdf-parse": "1.1.1"
  }
}
````


---

## 2. `.gitignore`

````text
node_modules/
.env
uploads/
data.db*
````


---

## 3. `.env.example`

````bash
# Copy to .env and fill in. Never commit .env.
JWT_SECRET=change-me-to-a-long-random-string
ADMIN_EMAIL=admin
ADMIN_PASSWORD=change-me-now
ANTHROPIC_API_KEY=sk-ant-...
MODEL=claude-sonnet-5-5
PORT=3000
````


---

## 4. `server.js`

````js
require('dotenv').config();
const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const pdfParse = require('pdf-parse');
const Anthropic = require('@anthropic-ai/sdk');
const crypto = require('crypto');
const path = require('path');
const fs = require('fs');

const { JWT_SECRET, ADMIN_EMAIL, ADMIN_PASSWORD, ANTHROPIC_API_KEY, PORT = 3000, MODEL = 'claude-sonnet-5-5' } = process.env;
if (!JWT_SECRET || !ADMIN_PASSWORD) throw new Error('Set JWT_SECRET and ADMIN_PASSWORD in .env');

fs.mkdirSync('uploads', { recursive: true });
const db = new Database('data.db');
db.exec(`
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, login TEXT UNIQUE, name TEXT, hash TEXT, role TEXT);
CREATE TABLE IF NOT EXISTS materials(id INTEGER PRIMARY KEY, title TEXT, course TEXT, file TEXT, text TEXT, created TEXT DEFAULT CURRENT_TIMESTAMP);`);
if (!db.prepare('SELECT 1 FROM users WHERE role=?').get('admin')) {
  db.prepare('INSERT INTO users(login,name,hash,role) VALUES(?,?,?,?)')
    .run((ADMIN_EMAIL || 'admin').toLowerCase(), 'Admin', bcrypt.hashSync(ADMIN_PASSWORD, 12), 'admin');
}

const claude = new Anthropic({ apiKey: ANTHROPIC_API_KEY });
const app = express();
app.use(express.json({ limit: '100kb' }), cookieParser(), express.static('public'));

const auth = role => (req, res, next) => {
  try {
    const u = jwt.verify(req.cookies.token, JWT_SECRET);
    if (role && u.role !== role) return res.status(403).json({ error: 'Not allowed' });
    req.user = u; next();
  } catch { res.status(401).json({ error: 'Please sign in' }); }
};

// ---- auth
const loginLimit = rateLimit({ windowMs: 15 * 60 * 1000, max: 20, message: { error: 'Too many attempts. Try again in 15 minutes.' } });
app.post('/api/login', loginLimit, (req, res) => {
  const { login = '', password = '' } = req.body;
  const u = db.prepare('SELECT * FROM users WHERE login=?').get(String(login).trim().toLowerCase());
  if (!u || !bcrypt.compareSync(String(password), u.hash)) return res.status(401).json({ error: 'Wrong ID or password' });
  const token = jwt.sign({ id: u.id, role: u.role, name: u.name }, JWT_SECRET, { expiresIn: '7d' });
  res.cookie('token', token, { httpOnly: true, sameSite: 'strict', secure: process.env.NODE_ENV === 'production', maxAge: 7 * 864e5 });
  res.json({ role: u.role, name: u.name });
});
app.post('/api/logout', (req, res) => res.clearCookie('token').json({ ok: true }));
app.get('/api/me', auth(), (req, res) => res.json({ role: req.user.role, name: req.user.name }));

// ---- students (admin only)
app.get('/api/students', auth('admin'), (req, res) =>
  res.json(db.prepare("SELECT id,login,name FROM users WHERE role='student' ORDER BY id DESC").all()));
app.post('/api/students', auth('admin'), (req, res) => {
  const { login = '', name = '', password = '' } = req.body;
  if (!login.trim() || !name.trim() || password.length < 6) return res.status(400).json({ error: 'Enter matric number, name and a password of 6+ characters' });
  try {
    db.prepare('INSERT INTO users(login,name,hash,role) VALUES(?,?,?,?)')
      .run(login.trim().toLowerCase(), name.trim(), bcrypt.hashSync(password, 12), 'student');
    res.json({ ok: true });
  } catch { res.status(409).json({ error: 'That matric number already has an account' }); }
});
app.delete('/api/students/:id', auth('admin'), (req, res) => {
  db.prepare("DELETE FROM users WHERE id=? AND role='student'").run(req.params.id); res.json({ ok: true });
});

// ---- materials
const upload = multer({
  storage: multer.diskStorage({ destination: 'uploads', filename: (r, f, cb) => cb(null, crypto.randomBytes(12).toString('hex') + '.pdf') }),
  limits: { fileSize: 20 * 1024 * 1024 },
  fileFilter: (r, f, cb) => cb(null, f.mimetype === 'application/pdf'),
});
app.get('/api/materials', auth(), (req, res) =>
  res.json(db.prepare('SELECT id,title,course,created,length(text)>0 AS readable FROM materials ORDER BY id DESC').all()));
app.get('/api/materials/:id/file', auth(), (req, res) => {
  const m = db.prepare('SELECT file,title FROM materials WHERE id=?').get(req.params.id);
  if (!m) return res.status(404).json({ error: 'Not found' });
  res.sendFile(path.resolve('uploads', m.file));
});
app.post('/api/materials', auth('admin'), upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'Choose a PDF file (max 20 MB)' });
  let text = '';
  try { text = (await pdfParse(fs.readFileSync(req.file.path))).text.replace(/\s+/g, ' ').trim(); } catch {}
  db.prepare('INSERT INTO materials(title,course,file,text) VALUES(?,?,?,?)')
    .run((req.body.title || req.file.originalname).trim(), (req.body.course || '').trim(), req.file.filename, text);
  res.json({ ok: true, readable: text.length > 0 });
});
app.delete('/api/materials/:id', auth('admin'), (req, res) => {
  const m = db.prepare('SELECT file FROM materials WHERE id=?').get(req.params.id);
  if (m) { fs.rmSync(path.resolve('uploads', m.file), { force: true }); db.prepare('DELETE FROM materials WHERE id=?').run(req.params.id); }
  res.json({ ok: true });
});

// ---- AI tutor
app.post('/api/chat', auth(), async (req, res) => {
  const { messages = [], materialId } = req.body;
  const msgs = messages.slice(-20).map(m => ({ role: m.role === 'assistant' ? 'assistant' : 'user', content: String(m.content).slice(0, 4000) }));
  while (msgs.length && msgs[0].role !== 'user') msgs.shift();
  if (!msgs.length || msgs[msgs.length - 1].role !== 'user') return res.status(400).json({ error: 'Ask a question first' });

  const rows = materialId
    ? db.prepare('SELECT title,course,text FROM materials WHERE id=?').all(materialId)
    : db.prepare('SELECT title,course,text FROM materials ORDER BY id DESC').all();
  let budget = 150000; const ctx = [];
  for (const r of rows) { if (budget <= 0) break; const t = r.text.slice(0, budget); budget -= t.length; ctx.push(`## ${r.title} (${r.course || 'General'})\n${t}`); }

  const system = `You are the study assistant for 100 Level students at Osun State University (UNIOSUN), Nigeria. Help with anything they ask: course content, assignments, study methods, campus life, general knowledge. Explain in clear, simple language with examples a first-year student can follow. When the course materials below cover the question, base your answer on them and name the material. If they don't cover it, say so, then answer from general knowledge. Never invent facts about school rules, dates or fees; tell students to confirm those with the school.\n\nCOURSE MATERIALS:\n${ctx.join('\n\n') || '(none uploaded yet)'}`;
  try {
    const r = await claude.messages.create({ model: MODEL, max_tokens: 1500, system, messages: msgs });
    res.json({ reply: r.content.filter(b => b.type === 'text').map(b => b.text).join('') });
  } catch (e) { console.error(e.message); res.status(502).json({ error: 'The AI is unavailable right now. Try again shortly.' }); }
});

app.listen(PORT, () => console.log(`Running on http://localhost:${PORT}`));
````


---

## 5. `public/index.html`

````html
<!doctype html>
<html lang="en"><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">
<title>UNIOSUN 100L Hub</title>
<link rel="preconnect" href="https://fonts.googleapis.com"><link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=Bricolage+Grotesque:wght@600;800&family=Figtree:wght@400;600&display=swap" rel="stylesheet">
<link rel="stylesheet" href="style.css">
</head><body>
<div id="toast" role="status" aria-live="polite"></div>

<section id="login" class="auth" hidden>
  <div class="hero">
    <img class="lg logo" alt="UNIOSUN" hidden>
    <h1>Your first year, made easier.</h1>
    <p>Course PDFs from your lecturers and an AI tutor that explains anything, all in one place.</p>
    <div class="spines" aria-hidden="true">
      <i style="--h:150;--n:62">GST 101</i><i style="--h:35;--n:88">MTH 101</i><i style="--h:205;--n:70">CSC 101</i><i style="--h:330;--n:96">BIO 101</i><i style="--h:265;--n:76">PHY 101</i><i style="--h:12;--n:58">CHM 101</i>
    </div>
  </div>
  <form id="loginForm" class="auth-card">
    <h2>Welcome back</h2>
    <p class="muted">Sign in with the details you were given.</p>
    <label>Matric number or email<input name="login" autocomplete="username" required></label>
    <label>Password<input name="password" type="password" autocomplete="current-password" required></label>
    <p class="err" id="loginErr" role="alert"></p>
    <button class="btn">Sign in</button>
    <!--DEMO-->
  </form>
</section>

<header id="bar" hidden>
  <div class="brand"><img class="lg" alt="" hidden><b>100L Hub</b></div>
  <div class="who"><span id="who"></span><button id="out" class="ghost">Sign out</button></div>
</header>

<main id="student" hidden data-tab="chat">
  <nav class="tabs"><button data-t="mats">Materials</button><button data-t="chat" class="on">Ask AI</button></nav>
  <aside>
    <h2>Materials</h2>
    <input id="find" type="search" placeholder="Search materials" aria-label="Search materials">
    <div id="matList" class="mats"></div>
  </aside>
  <section class="chat">
    <div id="focus" class="focus"></div>
    <div id="log" class="log"></div>
    <div id="chips" class="chips"></div>
    <form id="chatForm"><input id="q" placeholder="Ask anything about your courses…" autocomplete="off" required><button class="btn">Send</button></form>
  </section>
</main>

<main id="admin" hidden>
  <nav class="atabs"><button data-a="mats" class="on">Materials <span id="nM"></span></button><button data-a="sts">Students <span id="nS"></span></button></nav>
  <section id="a-mats" class="panel">
    <form id="upForm">
      <label class="drop" id="drop"><input type="file" name="file" accept="application/pdf" required>
        <b id="dropT">Drop a PDF here or tap to choose</b><small>Students see it as soon as you upload. Max 20 MB.</small></label>
      <div class="row"><label>Title<input name="title" required></label><label>Course code<input name="course" placeholder="e.g. GST 101"></label></div>
      <button class="btn">Upload and share</button>
    </form>
    <input id="findA" type="search" placeholder="Search uploaded PDFs" aria-label="Search uploaded PDFs">
    <div id="adminMat" class="mats"></div>
  </section>
  <section id="a-sts" class="panel" hidden>
    <form id="stForm">
      <div class="row"><label>Matric number<input name="login" required></label><label>Full name<input name="name" required></label></div>
      <label>Password (6+ characters)<input name="password" minlength="6" required></label>
      <button class="btn">Add student</button>
    </form>
    <div id="stList" class="mats"></div>
  </section>
</main>
<script src="app.js"></script>
</body></html>
````


---

## 6. `public/style.css`

````css
:root{--bh:152;--bs:82%;--ah:42;--onpri:#fff;--cl:36%;--hb:58px;--ink:hsl(var(--bh) 40% 12%);--pri:hsl(var(--bh) var(--bs) 27%);--pri2:hsl(var(--bh) var(--bs) 16%);--gold:hsl(var(--ah) 88% 57%);--bg:hsl(var(--bh) 30% 95%);--card:#fff;--line:hsl(var(--bh) 20% 84%);--mute:hsl(var(--bh) 12% 36%);--soft:hsl(var(--bh) 28% 91%);
 padding-top:env(safe-area-inset-top,0px);padding-bottom:env(safe-area-inset-bottom,0px)}
@media(prefers-color-scheme:dark){:root:not([data-theme="light"]){--ink:hsl(var(--bh) 30% 92%);--pri:hsl(var(--bh) var(--bs) 55%);--onpri:#06150e;--bg:hsl(var(--bh) 25% 7%);--card:hsl(var(--bh) 22% 10%);--line:hsl(var(--bh) 18% 20%);--mute:hsl(var(--bh) 12% 64%);--soft:hsl(var(--bh) 22% 13%);--cl:62%}}
:root[data-theme="dark"]{--ink:hsl(var(--bh) 30% 92%);--pri:hsl(var(--bh) var(--bs) 55%);--onpri:#06150e;--bg:hsl(var(--bh) 25% 7%);--card:hsl(var(--bh) 22% 10%);--line:hsl(var(--bh) 18% 20%);--mute:hsl(var(--bh) 12% 64%);--soft:hsl(var(--bh) 22% 13%);--cl:62%}
html{scroll-padding-top:env(safe-area-inset-top,0px)}
*{box-sizing:border-box}[hidden]{display:none!important}
body{margin:0;font:16px/1.6 Figtree,"Segoe UI",system-ui,sans-serif;color:var(--ink);background:var(--bg)}
h1,h2{font-family:"Bricolage Grotesque",Figtree,sans-serif;line-height:1.15;margin:0}
h2{font-size:1.25rem;margin-bottom:.8rem}.muted{color:var(--mute);margin:.3rem 0 1rem}
.err{color:#d4402f;min-height:1.4em;margin:.2rem 0 .6rem;font-weight:600}
label{display:block;font-weight:600;font-size:.92rem;margin:0 0 .9rem}
input{display:block;width:100%;margin-top:.3rem;padding:.7rem .85rem;border:1.5px solid var(--line);border-radius:10px;font:inherit;color:var(--ink);background:var(--card)}
input::placeholder{color:var(--mute)}
:focus-visible{outline:3px solid var(--gold);outline-offset:2px}
.btn{width:100%;padding:.8rem 1.2rem;border:0;border-radius:10px;background:var(--pri);color:var(--onpri);font:inherit;font-weight:700;cursor:pointer;transition:filter .15s}
.btn:hover{filter:brightness(1.1)}.btn:disabled{opacity:.6;cursor:wait}
.sm{padding:.4rem .8rem;border-radius:8px;font:inherit;font-size:.88rem;font-weight:600;cursor:pointer;border:1.5px solid var(--pri);background:transparent;color:var(--pri);text-decoration:none;white-space:nowrap}
.sm.del{border-color:#d4402f;color:#d4402f}

/* sign in */
.auth{display:grid;grid-template-columns:1.1fr 1fr;min-height:100vh}
.hero{background:linear-gradient(160deg,var(--pri2),hsl(var(--bh) var(--bs) 26%));color:#fff;padding:3rem clamp(1.5rem,5vw,4rem);display:flex;flex-direction:column;justify-content:center;gap:1rem}
.hero h1{font-size:clamp(2rem,4.5vw,3.4rem);font-weight:800;max-width:14ch}.hero p{max-width:38ch;margin:0;opacity:.9;font-size:1.05rem}
.logo{height:80px;width:80px;object-fit:contain;background:#fff;border-radius:18px;padding:6px}
.spines{display:flex;align-items:flex-end;gap:6px;height:170px;margin-top:1.5rem;border-bottom:4px solid var(--gold)}
.spines i{writing-mode:vertical-rl;font-style:normal;font-weight:700;font-size:.78rem;letter-spacing:.04em;padding:.7rem .4rem;border-radius:5px 5px 0 0;color:#fff;background:hsl(var(--h) 48% 40%);height:calc(var(--n)*1%)}
.auth-card{align-self:center;justify-self:center;width:min(400px,92%);padding:2rem 0}

/* header */
header{height:var(--hb);display:flex;justify-content:space-between;align-items:center;padding:0 1.2rem;background:var(--pri2);color:#fff;border-bottom:3px solid var(--gold)}
.brand{display:flex;align-items:center;gap:.6rem;font-family:"Bricolage Grotesque",sans-serif;font-size:1.1rem}.brand img{height:34px;width:34px;object-fit:contain;background:#fff;border-radius:8px}
.who{display:flex;align-items:center;gap:.8rem;font-size:.92rem}
.ghost{background:transparent;border:1px solid #ffffff80;color:#fff;border-radius:8px;padding:.3rem .8rem;font:inherit;cursor:pointer}

/* materials */
.mats{display:grid;gap:.6rem;margin-top:.9rem}
.mat{display:grid;grid-template-columns:1fr auto;gap:.4rem .8rem;align-items:center;padding:.8rem .9rem;background:var(--card);border:1px solid var(--line);border-left:6px solid hsl(var(--h) 50% var(--cl));border-radius:12px}
.mat .code{font-size:.78rem;font-weight:700;color:hsl(var(--h) 50% var(--cl))}.mat .t{font-weight:600;line-height:1.3;overflow-wrap:anywhere}
.mat .acts{display:flex;gap:.4rem;flex-wrap:wrap;justify-content:flex-end}.mat small{color:var(--mute)}
.empty{padding:1.4rem;text-align:center;color:var(--mute);border:1.5px dashed var(--line);border-radius:12px}

/* student */
#student{display:grid;grid-template-columns:360px 1fr;height:calc(100vh - var(--hb))}
.tabs,.atabs{display:none}
aside{padding:1.2rem;overflow:auto;background:var(--soft);border-right:1px solid var(--line)}
.chat{display:flex;flex-direction:column;padding:1rem 1.4rem;min-width:0}
.focus{min-height:2rem;font-size:.9rem;color:var(--mute)}
.focus b{background:var(--soft);color:var(--ink);padding:.25rem .5rem;border-radius:999px;font-weight:600}.focus button{border:0;background:none;color:var(--pri);font:inherit;cursor:pointer;font-weight:700}
.log{flex:1;overflow:auto;display:flex;flex-direction:column;gap:.8rem;padding:.4rem 0}
.msg{max-width:min(720px,94%);padding:.75rem 1rem;border-radius:16px;overflow-wrap:anywhere}
.msg.user{align-self:flex-end;background:var(--pri);color:var(--onpri);border-bottom-right-radius:4px;white-space:pre-wrap}
.msg.ai{align-self:flex-start;background:var(--card);border:1px solid var(--line);border-bottom-left-radius:4px}
.msg p{margin:0 0 .5rem}.msg p:last-child{margin:0}.msg ul{margin:.2rem 0 .5rem;padding-left:1.2rem}.msg code{background:var(--soft);padding:.1rem .3rem;border-radius:4px}
.dots span{display:inline-block;width:7px;height:7px;margin-right:4px;border-radius:50%;background:var(--mute);animation:b 1s infinite}.dots span:nth-child(2){animation-delay:.15s}.dots span:nth-child(3){animation-delay:.3s}
@keyframes b{50%{transform:translateY(-4px)}}
.chips{display:flex;gap:.5rem;flex-wrap:wrap;margin:.6rem 0}
.chips button{padding:.4rem .85rem;border-radius:999px;border:1.5px solid var(--line);background:var(--card);color:var(--ink);font:inherit;font-size:.9rem;cursor:pointer}
.chips button:hover{border-color:var(--pri)}
#chatForm{display:flex;gap:.5rem}#chatForm input{margin:0}#chatForm .btn{width:auto}

/* admin */
#admin{max-width:820px;margin:0 auto;padding:1.2rem}
.atabs{display:flex;gap:.5rem;margin-bottom:1rem}
.atabs button{padding:.55rem 1.1rem;border-radius:999px;border:1.5px solid var(--line);background:var(--card);color:var(--ink);font:inherit;font-weight:600;cursor:pointer}
.atabs button.on{background:var(--pri);border-color:var(--pri);color:var(--onpri)}.atabs span{opacity:.7;font-weight:400}
.panel form{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:1.2rem;margin-bottom:1rem}
.row{display:grid;grid-template-columns:1fr 1fr;gap:0 .9rem}
.drop{position:relative;display:grid;gap:.2rem;place-items:center;text-align:center;padding:1.6rem 1rem;margin-bottom:1rem;border:2px dashed var(--pri);border-radius:12px;background:var(--soft);cursor:pointer}
.drop input{position:absolute;inset:0;opacity:0;cursor:pointer;margin:0}.drop.over{background:var(--card)}.drop small{color:var(--mute);font-weight:400}

/* toast */
#toast{position:fixed;left:50%;bottom:calc(1.2rem + env(safe-area-inset-bottom,0px));transform:translate(-50%,150%);background:var(--ink);color:var(--bg);padding:.7rem 1.1rem;border-radius:10px;font-weight:600;transition:transform .25s;z-index:9;max-width:90vw}
#toast.show{transform:translate(-50%,0)}#toast.bad{background:#d4402f;color:#fff}

@media(max-width:820px){
 .auth{grid-template-columns:1fr}.hero{padding:1.5rem}.spines{height:90px;margin-top:.5rem}.hero h1{font-size:1.9rem}
 #student{grid-template-columns:1fr;grid-template-rows:auto 1fr}
 .tabs{display:flex;background:var(--card);border-bottom:1px solid var(--line)}
 .tabs button{flex:1;padding:.75rem;border:0;border-bottom:3px solid transparent;background:none;color:var(--mute);font:inherit;font-weight:700}
 .tabs button.on{color:var(--pri);border-color:var(--gold)}
 #student[data-tab=chat] aside,#student[data-tab=mats] .chat{display:none}
 aside{border-right:0}.row{grid-template-columns:1fr}.who #who{display:none}
}
@media(prefers-reduced-motion:reduce){*{transition:none!important;animation:none!important}}
````


---

## 7. `public/app.js`

````js
const $ = s => document.querySelector(s);
const h = (tag, props = {}, ...kids) => { const e = Object.assign(document.createElement(tag), props); kids.flat().forEach(k => e.append(k)); return e; };
const api = async (url, opts = {}) => {
  if (opts.body && !(opts.body instanceof FormData)) { opts.headers = { 'Content-Type': 'application/json' }; opts.body = JSON.stringify(opts.body); }
  const r = await fetch(url, opts); const d = await r.json().catch(() => ({}));
  if (!r.ok) throw new Error(d.error || 'Something went wrong'); return d;
};
const hue = c => { let n = 0; for (const ch of c || 'GEN') n = (n * 31 + ch.charCodeAt(0)) % 360; return n; };
const toast = (t, bad) => { const e = $('#toast'); e.textContent = t; e.className = 'show' + (bad ? ' bad' : ''); clearTimeout(toast.t); toast.t = setTimeout(() => e.className = '', 3200); };
const esc = s => s.replace(/[&<>]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;' }[c]));
const inl = s => s.replace(/\*\*(.+?)\*\*/g, '<b>$1</b>').replace(/`(.+?)`/g, '<code>$1</code>');
const md = s => { let out = '', list = false;
  for (const l of esc(s).split('\n')) { const m = l.match(/^\s*(?:[-*]|\d+\.)\s+(.*)/);
    if (m) { if (!list) { out += '<ul>'; list = true; } out += '<li>' + inl(m[1]) + '</li>'; }
    else { if (list) { out += '</ul>'; list = false; } if (l.trim()) out += '<p>' + inl(l) + '</p>'; } }
  return out + (list ? '</ul>' : ''); };
const CHIPS = ['Explain this in simple terms', 'Give me 5 practice questions', 'Summarize the key points', 'How should I study for exams?'];

// The site's colors come from public/logo.png: the most common bright color becomes the brand color, a contrasting one becomes the accent.
function theme(im) {
  const c = document.createElement('canvas'); c.width = c.height = 48; const x = c.getContext('2d'); x.drawImage(im, 0, 0, 48, 48);
  let d; try { d = x.getImageData(0, 0, 48, 48).data; } catch { return; }
  const bins = {};
  for (let i = 0; i < d.length; i += 4) {
    if (d[i + 3] < 200) continue;
    const R = d[i] / 255, G = d[i + 1] / 255, B = d[i + 2] / 255, mx = Math.max(R, G, B), mn = Math.min(R, G, B), l = (mx + mn) / 2, dl = mx - mn;
    if (!dl) continue; const s = dl / (1 - Math.abs(2 * l - 1));
    if (s < .3 || l < .12 || l > .88) continue;
    const hh = ((mx === R ? ((G - B) / dl) % 6 : mx === G ? (B - R) / dl + 2 : (R - G) / dl + 4) * 60 + 360) % 360;
    const k = Math.round(hh / 20) % 18; const e = bins[k] ||= { n: 0, s: 0 }; e.n++; e.s += s;
  }
  const ks = Object.keys(bins).sort((a, b) => bins[b].n - bins[a].n); if (!ks.length) return;
  const H = k => k * 20, p = ks[0], dist = (a, b) => Math.min(Math.abs(a - b), 360 - Math.abs(a - b));
  const a = ks.find(k => dist(H(k), H(p)) >= 50 && bins[k].n > bins[p].n * .08), st = document.documentElement.style;
  st.setProperty('--bh', H(p)); st.setProperty('--bs', Math.min(85, Math.max(45, Math.round(bins[p].s / bins[p].n * 100))) + '%'); st.setProperty('--ah', a ? H(a) : (H(p) + 40) % 360);
}
function applyLogo(src) {
  const im = new Image();
  im.onload = () => { document.querySelectorAll('.lg').forEach(i => { i.src = src; i.hidden = false; }); theme(im); };
  im.src = src;
}
let me, mats = [], sts = [], focus = null, history = [];

async function init() { try { me = await api('/api/me'); } catch { me = null; } render(); }
function render() {
  $('#login').hidden = !!me; $('#bar').hidden = !me;
  $('#student').hidden = !(me && me.role === 'student'); $('#admin').hidden = !(me && me.role === 'admin');
  if (!me) return; $('#who').textContent = me.name;
  me.role === 'admin' ? loadAdmin() : loadStudent();
}
$('#loginForm').onsubmit = async e => {
  e.preventDefault(); $('#loginErr').textContent = ''; const b = e.target.querySelector('.btn'); b.disabled = true;
  try { await api('/api/login', { method: 'POST', body: Object.fromEntries(new FormData(e.target)) }); e.target.reset(); await init(); }
  catch (x) { $('#loginErr').textContent = x.message; } b.disabled = false;
};
$('#out').onclick = async () => { await api('/api/logout', { method: 'POST' }); me = null; history = []; focus = null; $('#log').replaceChildren(); render(); };

const openUrl = id => `/api/materials/${id}/file`;
const card = (m, acts) => h('div', { className: 'mat', style: `--h:${hue(m.course)}` },
  h('div', {}, h('div', { className: 'code', textContent: m.course || 'General' }), h('div', { className: 't', textContent: m.title }), m.readable ? '' : h('small', { textContent: 'AI cannot read this PDF (scanned pages)' })),
  h('div', { className: 'acts' }, acts));
const match = (list, q) => list.filter(m => (m.title + ' ' + (m.course || '')).toLowerCase().includes(q.toLowerCase()));

// ---- student
async function loadStudent() { mats = await api('/api/materials'); drawStudent(); setFocus(null); if (!history.length) greet(); }
function drawStudent() {
  const l = match(mats, $('#find').value);
  $('#matList').replaceChildren(...(l.length ? l.map(m => card(m, [
    h('a', { className: 'sm', href: openUrl(m.id), target: '_blank', rel: 'noopener', textContent: 'Open' }),
    h('button', { className: 'sm', textContent: 'Ask AI', onclick: () => { setFocus(m); tab('chat'); $('#q').focus(); } })]))
    : [h('div', { className: 'empty', textContent: mats.length ? 'No match. Try another word.' : 'No materials yet. PDFs from your lecturers will show up here.' })]));
}
$('#find').oninput = drawStudent;
const tab = t => { $('#student').dataset.tab = t; document.querySelectorAll('.tabs button').forEach(b => b.classList.toggle('on', b.dataset.t === t)); };
document.querySelectorAll('.tabs button').forEach(b => b.onclick = () => tab(b.dataset.t));
function setFocus(m) {
  focus = m; $('#focus').replaceChildren(...(m ? [h('b', { textContent: m.title }), ' ', h('button', { textContent: 'Clear', onclick: () => setFocus(null) })] : ['Answering from all materials and general knowledge.']));
}
function say(role, text) { const d = h('div', { className: 'msg ' + role }); role === 'ai' ? d.innerHTML = text : d.textContent = text; $('#log').append(d); d.scrollIntoView({ block: 'end' }); return d; }
function greet() {
  say('ai', '<p>Hi! I can explain your course materials, quiz you, or help with study tips. What do you want to know?</p>');
  $('#chips').replaceChildren(...CHIPS.map(c => h('button', { textContent: c, onclick: () => ask(c) })));
}
async function ask(q) {
  $('#chips').replaceChildren(); say('user', q); history.push({ role: 'user', content: q });
  const w = say('ai', '<span class="dots"><span></span><span></span><span></span></span>');
  try { const { reply } = await api('/api/chat', { method: 'POST', body: { messages: history, materialId: focus?.id } }); w.innerHTML = md(reply); history.push({ role: 'assistant', content: reply }); }
  catch (x) { w.textContent = x.message; history.pop(); }
}
$('#chatForm').onsubmit = e => { e.preventDefault(); const q = $('#q').value.trim(); if (q) { $('#q').value = ''; ask(q); } };

// ---- admin
async function loadAdmin() { [mats, sts] = await Promise.all([api('/api/materials'), api('/api/students')]); drawAdmin(); }
function drawAdmin() {
  $('#nM').textContent = mats.length; $('#nS').textContent = sts.length;
  const l = match(mats, $('#findA').value);
  $('#adminMat').replaceChildren(...(l.length ? l.map(m => card(m, h('button', { className: 'sm del', textContent: 'Delete', onclick: async () => {
    if (confirm(`Delete "${m.title}"? Students will no longer see it.`)) { await api('/api/materials/' + m.id, { method: 'DELETE' }); toast('Deleted'); loadAdmin(); } } })))
    : [h('div', { className: 'empty', textContent: mats.length ? 'No match.' : 'Upload your first PDF above to share it with students.' })]));
  $('#stList').replaceChildren(...(sts.length ? sts.map(s => h('div', { className: 'mat', style: '--h:150' },
    h('div', {}, h('div', { className: 't', textContent: s.name }), h('small', { textContent: s.login })),
    h('button', { className: 'sm del', textContent: 'Remove', onclick: async () => { if (confirm(`Remove ${s.name}?`)) { await api('/api/students/' + s.id, { method: 'DELETE' }); toast('Student removed'); loadAdmin(); } } })))
    : [h('div', { className: 'empty', textContent: 'No students yet. Add one above so they can sign in.' })]));
}
$('#findA').oninput = drawAdmin;
document.querySelectorAll('.atabs button').forEach(b => b.onclick = () => {
  document.querySelectorAll('.atabs button').forEach(x => x.classList.toggle('on', x === b));
  $('#a-mats').hidden = b.dataset.a !== 'mats'; $('#a-sts').hidden = b.dataset.a !== 'sts'; });
const file = $('#upForm').file, drop = $('#drop');
file.onchange = () => { const f = file.files[0]; if (!f) return; $('#dropT').textContent = f.name; const t = $('#upForm').title; if (!t.value) t.value = f.name.replace(/\.pdf$/i, '').replace(/[_-]+/g, ' '); };
['dragenter', 'dragover'].forEach(v => drop.addEventListener(v, e => { e.preventDefault(); drop.classList.add('over'); }));
['dragleave', 'drop'].forEach(v => drop.addEventListener(v, () => drop.classList.remove('over')));
drop.addEventListener('drop', e => { e.preventDefault(); file.files = e.dataTransfer.files; file.onchange(); });
$('#upForm').onsubmit = async e => {
  e.preventDefault(); const b = e.target.querySelector('.btn'); b.disabled = true; b.textContent = 'Uploading…';
  try { const r = await api('/api/materials', { method: 'POST', body: new FormData(e.target) }); e.target.reset(); $('#dropT').textContent = 'Drop a PDF here or tap to choose';
    toast(r.readable ? 'Uploaded. Students can see it now.' : 'Uploaded, but the AI cannot read it (scanned pages).', !r.readable); loadAdmin(); }
  catch (x) { toast(x.message, true); } b.disabled = false; b.textContent = 'Upload and share';
};
$('#stForm').onsubmit = async e => {
  e.preventDefault();
  try { await api('/api/students', { method: 'POST', body: Object.fromEntries(new FormData(e.target)) }); e.target.reset(); toast('Student added'); loadAdmin(); }
  catch (x) { toast(x.message, true); }
};
applyLogo('logo.png');
init();
````


---

## 8. `README.md`

````markdown
# UNIOSUN 100L Hub

Study hub for 100 Level students. The admin uploads course PDFs and creates student accounts. Students sign in, open materials, and chat with an AI tutor that answers from those PDFs and general knowledge.

## Run locally
```bash
npm install
cp .env.example .env     # set JWT_SECRET, ADMIN_PASSWORD, ANTHROPIC_API_KEY
npm start                # http://localhost:3000
```
Sign in as the admin (`ADMIN_EMAIL` / `ADMIN_PASSWORD`), add students (matric number + password), upload PDFs. Put the UNIOSUN logo at `public/logo.png`. The site reads it and takes its colors from it automatically, so swap the file to re-theme.

## Push to GitHub
```bash
git init && git add . && git commit -m "Initial commit"
git branch -M main
git remote add origin https://github.com/<you>/uniosun-100l-hub.git
git push -u origin main
```
`.env`, `uploads/` and `data.db` are git-ignored, so keys and student data stay off GitHub.

## Deploy
Needs a host that runs Node and keeps a persistent disk (Render, Railway, Fly.io, a VPS). Set the `.env` values as environment variables, `NODE_ENV=production`, and use HTTPS. GitHub Pages cannot run this (it needs the server).

## Known limits
- The AI reads up to ~150k characters of PDF text per question. Past that, add retrieval (embeddings) so only relevant passages are sent.
- Scanned PDFs have no text; the admin panel flags them. OCR them first.
````
