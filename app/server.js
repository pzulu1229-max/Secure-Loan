/*
=========================  SECURELOANS WEB APP (single file)  =========================

STEP 1. In MySQL Workbench (as root), run this ONCE:

    USE secureloans;
    CREATE TABLE IF NOT EXISTS app_users (
      user_id INT AUTO_INCREMENT PRIMARY KEY,
      username VARCHAR(50) NOT NULL UNIQUE,
      password_hash VARCHAR(100) NOT NULL,
      role ENUM('officer','auditor') DEFAULT 'officer'
    );

STEP 2. Save this file as server.js in a new folder (e.g. D:\secureloans-app).
        Open Command Prompt in that folder and run:

    npm init -y
    npm install express mysql2 bcrypt
    node server.js

STEP 3. Open http://localhost:3000 in your browser.
        Register an "officer" and an "auditor", log in, and try everything.

(Optional env vars: DB_PASS for officer1's password, AES_KEY for the encryption key.)
=======================================================================================
*/
const express = require('express');
const mysql = require('mysql2/promise');
const bcrypt = require('bcrypt');
const crypto = require('crypto');

const AES_KEY = process.env.AES_KEY || 'MySecretKey123';
const pool = mysql.createPool({
  host: '127.0.0.1',
  user: 'officer1',                                   // least-privilege account, not root
  password: process.env.DB_PASS || 'Officer#2026',
  database: 'secureloans',
  multipleStatements: false                           // blocks stacked-query injection
});

const app = express();
app.use(express.json());
const sessions = new Map();                           // token -> {username, role}
const wrap = fn => (req, res) => fn(req, res).catch(e => {
  console.error(e.message);
  res.status(500).json({ error: e.code === 'ER_NO_SUCH_TABLE'
    ? 'A table is missing. Run the setup SQL from the top of server.js.' : e.message });
});

function auth(req, res, next) {
  const s = sessions.get(req.headers['x-token']);
  if (!s) return res.status(401).json({ error: 'Please log in' });
  req.user = s; next();
}
function officerOnly(req, res, next) {
  if (req.user.role !== 'officer')
    return res.status(403).json({ error: 'Auditors have read-only access' });
  next();
}

// ---------- Authentication ----------
app.post('/api/register', wrap(async (req, res) => {
  const { username, password, role } = req.body;
  if (!/^[A-Za-z0-9_]{3,30}$/.test(username || ''))
    return res.status(400).json({ error: 'Username: 3-30 letters, digits or _' });
  if (!password || password.length < 8)
    return res.status(400).json({ error: 'Password must be at least 8 characters' });
  if (!['officer', 'auditor'].includes(role))
    return res.status(400).json({ error: 'Role must be officer or auditor' });
  const hash = await bcrypt.hash(password, 10);       // salted hash, never plain text
  try {
    await pool.execute('INSERT INTO app_users (username, password_hash, role) VALUES (?,?,?)',
      [username, hash, role]);
  } catch (e) {
    if (e.code === 'ER_DUP_ENTRY') return res.status(409).json({ error: 'Username already taken' });
    throw e;
  }
  res.json({ message: 'Registered. You can log in now.' });
}));

app.post('/api/login', wrap(async (req, res) => {
  const { username, password } = req.body;
  const [rows] = await pool.execute(
    'SELECT password_hash, role FROM app_users WHERE username = ?', [username || '']);
  const ok = rows.length && await bcrypt.compare(password || '', rows[0].password_hash);
  if (!ok) return res.status(401).json({ error: 'Invalid username or password' });
  const token = crypto.randomUUID();
  sessions.set(token, { username, role: rows[0].role });
  res.json({ token, username, role: rows[0].role });
}));

// ---------- Customers (NRC encrypted in the database) ----------
const mask = n => (n ? '*'.repeat(Math.max(n.length - 2, 0)) + n.slice(-2) : '');
app.get('/api/customers', auth, wrap(async (req, res) => {
  const [rows] = await pool.execute(
    'SELECT customer_id, full_name, phone, CAST(AES_DECRYPT(nrc_number, ?) AS CHAR) AS nrc, created_at ' +
    'FROM customers ORDER BY customer_id DESC', [AES_KEY]);
  // Auditors only ever see a masked NRC
  res.json(rows.map(r => ({ ...r, nrc: req.user.role === 'officer' ? r.nrc : mask(r.nrc) })));
}));
app.post('/api/customers', auth, officerOnly, wrap(async (req, res) => {
  const { full_name, nrc, phone } = req.body;
  if (!full_name || !nrc) return res.status(400).json({ error: 'Name and NRC are required' });
  await pool.execute(
    'INSERT INTO customers (full_name, nrc_number, phone) VALUES (?, AES_ENCRYPT(?, ?), ?)',
    [full_name, nrc, AES_KEY, phone || null]);
  res.json({ message: 'Customer added (NRC stored encrypted)' });
}));

// ---------- Loans ----------
app.get('/api/loans', auth, wrap(async (req, res) => {
  const [rows] = await pool.execute(
    'SELECT l.loan_id, c.full_name, l.amount, l.interest_rate, l.status ' +
    'FROM loans l JOIN customers c ON c.customer_id = l.customer_id ORDER BY l.loan_id DESC');
  res.json(rows);
}));
app.post('/api/loans', auth, officerOnly, wrap(async (req, res) => {
  const customer_id = parseInt(req.body.customer_id, 10);
  const amount = Number(req.body.amount), rate = Number(req.body.interest_rate);
  if (!customer_id || !(amount > 0) || !(rate >= 0 && rate <= 100))
    return res.status(400).json({ error: 'Check customer, amount (>0) and rate (0-100)' });
  try {
    await pool.execute('INSERT INTO loans (customer_id, amount, interest_rate) VALUES (?,?,?)',
      [customer_id, amount, rate]);
  } catch (e) {
    if (e.code === 'ER_NO_REFERENCED_ROW_2') return res.status(400).json({ error: 'No such customer' });
    throw e;
  }
  res.json({ message: 'Loan created' });
}));
app.put('/api/loans/:id/status', auth, officerOnly, wrap(async (req, res) => {
  const status = req.body.status;
  if (!['pending', 'active', 'paid', 'defaulted'].includes(status))
    return res.status(400).json({ error: 'Invalid status' });
  await pool.execute('UPDATE loans SET status = ? WHERE loan_id = ?', [status, req.params.id]);
  res.json({ message: 'Status updated. The database trigger logged the change.' });
}));

// ---------- Audit log (filled by the MySQL trigger) ----------
app.get('/api/audit', auth, wrap(async (req, res) => {
  const [rows] = await pool.execute(
    'SELECT log_id, loan_id, old_status, new_status, changed_by, changed_at ' +
    'FROM audit_log ORDER BY log_id DESC LIMIT 50');
  res.json(rows);
}));

// ---------- SQL injection lab ----------
// INSECURE: the text is pasted straight into the SQL. Do not write code like this.
app.get('/api/search/insecure', wrap(async (req, res) => {
  const sql = "SELECT customer_id, full_name, phone, created_at FROM customers " +
              "WHERE full_name LIKE '%" + (req.query.name || '') + "%'";
  try {
    const [rows] = await pool.query(sql);
    res.json({ sql, rows });
  } catch (e) {
    res.json({ sql, error: e.message, rows: [] });
  }
}));
// SECURE: parameterized query + login required
app.get('/api/search/secure', auth, wrap(async (req, res) => {
  const sql = 'SELECT customer_id, full_name, phone, created_at FROM customers WHERE full_name LIKE ?';
  const param = '%' + (req.query.name || '') + '%';
  const [rows] = await pool.execute(sql, [param]);
  res.json({ sql, param, rows });
}));

// ---------- The web page ----------
const PAGE = String.raw`<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SecureLoans</title>
<style>
*{box-sizing:border-box}body{margin:0;font-family:Segoe UI,Arial,sans-serif;background:#0f1b2d;color:#f4f6f8}
header{display:flex;justify-content:space-between;align-items:center;padding:16px 28px;background:#17294a}
header h1{margin:0;font-size:22px}.badge{background:#2ec4b6;color:#0f1b2d;border-radius:20px;padding:4px 12px;font-weight:600;font-size:14px}
main{max-width:1000px;margin:24px auto;padding:0 16px}
.card{background:#17294a;border-radius:14px;padding:22px;margin-bottom:20px}
h2{margin:0 0 14px;font-size:20px}h3{margin:18px 0 8px;font-size:16px;color:#b8c4d4}
input,select,button{font:inherit;padding:9px 12px;border-radius:8px;border:1px solid #3a4f73;background:#0f1b2d;color:#f4f6f8}
button{background:#2ec4b6;color:#0f1b2d;border:0;font-weight:600;cursor:pointer}button.alt{background:#3a4f73;color:#f4f6f8}
button.warn{background:#ffb347}.row{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:12px}
.tabs{display:flex;gap:8px;margin-bottom:16px;flex-wrap:wrap}.tabs button{background:#17294a;color:#b8c4d4}.tabs button.on{background:#2ec4b6;color:#0f1b2d}
table{width:100%;border-collapse:collapse}th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #2b4068;font-size:15px}th{color:#2ec4b6}
.msg{padding:10px 14px;border-radius:8px;margin-bottom:12px;background:#0a1322}.ok{border-left:5px solid #2ec4b6}.err{border-left:5px solid #ffb347}
code,.sql{font-family:Consolas,monospace;background:#0a1322;padding:10px 12px;border-radius:8px;display:block;white-space:pre-wrap;word-break:break-all;margin:8px 0}
.two{display:grid;grid-template-columns:1fr 1fr;gap:16px}@media(max-width:760px){.two{grid-template-columns:1fr}}
.bad{color:#ffb347}.good{color:#2ec4b6}.hide{display:none}
</style></head><body>
<header><h1>SecureLoans</h1><div id="who"></div></header>
<main>
<div id="msg"></div>

<div id="authbox" class="card">
  <h2>Sign in</h2>
  <div class="row"><input id="u" placeholder="Username"><input id="p" type="password" placeholder="Password (8+ chars)">
  <select id="r"><option value="officer">officer</option><option value="auditor">auditor</option></select></div>
  <div class="row"><button id="login">Log in</button><button class="alt" id="register">Register (uses the role above)</button></div>
  <p style="color:#b8c4d4;margin:0">Officers can add customers and loans. Auditors are read-only and see masked national IDs. The Injection Lab works without login.</p>
</div>

<div id="app" class="hide">
  <div class="tabs" id="tabs"></div>

  <div id="t-customers" class="card">
    <h2>Customers</h2>
    <div class="row officer"><input id="cn" placeholder="Full name"><input id="cnrc" placeholder="NRC e.g. 123456/78/1"><input id="cph" placeholder="Phone"><button id="addc">Add customer</button></div>
    <div id="custtable"></div>
  </div>

  <div id="t-loans" class="card hide">
    <h2>Loans</h2>
    <div class="row officer"><input id="lc" placeholder="Customer ID" size="10"><input id="la" placeholder="Amount" size="10"><input id="lr" placeholder="Interest %" size="10"><button id="addl">Create loan</button></div>
    <div id="loantable"></div>
  </div>

  <div id="t-audit" class="card hide">
    <h2>Audit log</h2>
    <p style="color:#b8c4d4">Every loan status change is recorded automatically by a MySQL trigger.</p>
    <div id="audittable"></div>
  </div>
</div>

<div id="t-lab" class="card hide">
  <h2>SQL injection lab</h2>
  <p style="color:#b8c4d4">Search for a customer name. Then try the attack buttons on both versions.</p>
  <div class="row"><input id="q" placeholder="Customer name" size="40">
    <button class="warn" id="qa">Insecure search</button><button id="qb">Secure search (login needed)</button></div>
  <div class="row"><button class="alt" id="p1">Payload: show every customer</button><button class="alt" id="p2">Payload: steal user password hashes</button></div>
  <div class="two"><div><h3 class="bad">Insecure result</h3><div id="resA"></div></div><div><h3 class="good">Secure result</h3><div id="resB"></div></div></div>
</div>
</main>

<script>
var token = sessionStorage.getItem('token') || '', user = JSON.parse(sessionStorage.getItem('user') || 'null');
function $(id){return document.getElementById(id);}
function el(tag, text, cls){var e=document.createElement(tag); if(text!==undefined) e.textContent=text; if(cls) e.className=cls; return e;}
function say(text, ok){var m=el('div',text,'msg '+(ok?'ok':'err')); $('msg').replaceChildren(m); setTimeout(function(){m.remove();},6000);}
function api(method, url, body){
  var opt={method:method,headers:{'Content-Type':'application/json','x-token':token}};
  if(body) opt.body=JSON.stringify(body);
  return fetch(url,opt).then(function(r){return r.json().then(function(d){ if(!r.ok) throw new Error(d.error||'Request failed'); return d; });});
}
function table(rows, cols){
  if(!rows.length) return el('p','No records yet.');
  var t=el('table'), hr=el('tr'); cols.forEach(function(c){hr.appendChild(el('th',c));}); t.appendChild(hr);
  rows.forEach(function(r){var tr=el('tr'); cols.forEach(function(c){var v=r[c]; tr.appendChild(el('td', v===null||v===undefined?'':String(v)));}); t.appendChild(tr);});
  return t;
}
function show(tab){
  ['customers','loans','audit'].forEach(function(n){$('t-'+n).classList.toggle('hide', n!==tab);});
  Array.prototype.forEach.call($('tabs').children,function(b){b.classList.toggle('on', b.dataset.t===tab);});
  if(tab==='customers') loadCustomers(); if(tab==='loans') loadLoans(); if(tab==='audit') loadAudit();
}
function render(){
  var on=!!user;
  $('authbox').classList.toggle('hide', on); $('app').classList.toggle('hide', !on); $('t-lab').classList.remove('hide');
  $('who').replaceChildren();
  if(on){
    var b=el('span',user.username+' ('+user.role+')','badge'); $('who').appendChild(b);
    var lo=el('button','Log out'); lo.style.marginLeft='10px'; lo.onclick=function(){token='';user=null;sessionStorage.clear();render();}; $('who').appendChild(lo);
    $('tabs').replaceChildren();
    [['customers','Customers'],['loans','Loans'],['audit','Audit log']].forEach(function(x){var b=el('button',x[1]); b.dataset.t=x[0]; b.onclick=function(){show(x[0]);}; $('tabs').appendChild(b);});
    Array.prototype.forEach.call(document.querySelectorAll('.officer'),function(r){r.classList.toggle('hide', user.role!=='officer');});
    show('customers');
  }
}
function loadCustomers(){api('GET','/api/customers').then(function(d){$('custtable').replaceChildren(table(d,['customer_id','full_name','phone','nrc','created_at']));}).catch(function(e){say(e.message);});}
function loadLoans(){api('GET','/api/loans').then(function(d){
  var box=$('loantable'); box.replaceChildren(table(d,['loan_id','full_name','amount','interest_rate','status']));
  if(user.role==='officer' && d.length){
    var row=el('div',undefined,'row'); row.style.marginTop='14px';
    var id=el('input'); id.placeholder='Loan ID'; id.size=8;
    var st=el('select'); ['pending','active','paid','defaulted'].forEach(function(s){var o=el('option',s); o.value=s; st.appendChild(o);});
    var go=el('button','Change status'); go.onclick=function(){api('PUT','/api/loans/'+encodeURIComponent(id.value)+'/status',{status:st.value}).then(function(r){say(r.message,true);loadLoans();}).catch(function(e){say(e.message);});};
    row.append(id,st,go); box.appendChild(row);
  }}).catch(function(e){say(e.message);});}
function loadAudit(){api('GET','/api/audit').then(function(d){$('audittable').replaceChildren(table(d,['log_id','loan_id','old_status','new_status','changed_by','changed_at']));}).catch(function(e){say(e.message);});}

$('login').onclick=function(){api('POST','/api/login',{username:$('u').value,password:$('p').value}).then(function(d){token=d.token;user={username:d.username,role:d.role};sessionStorage.setItem('token',token);sessionStorage.setItem('user',JSON.stringify(user));render();}).catch(function(e){say(e.message);});};
$('register').onclick=function(){api('POST','/api/register',{username:$('u').value,password:$('p').value,role:$('r').value}).then(function(d){say(d.message,true);}).catch(function(e){say(e.message);});};
$('addc').onclick=function(){api('POST','/api/customers',{full_name:$('cn').value,nrc:$('cnrc').value,phone:$('cph').value}).then(function(d){say(d.message,true);loadCustomers();}).catch(function(e){say(e.message);});};
$('addl').onclick=function(){api('POST','/api/loans',{customer_id:$('lc').value,amount:$('la').value,interest_rate:$('lr').value}).then(function(d){say(d.message,true);loadLoans();}).catch(function(e){say(e.message);});};

function showResult(box, d){
  box.replaceChildren();
  if(d.sql) box.appendChild(el('div','SQL run:\n'+d.sql,'sql'));
  if(d.param!==undefined) box.appendChild(el('div','Parameter (plain text): '+d.param,'sql'));
  if(d.error) box.appendChild(el('div',d.error,'msg err'));
  if(d.rows) box.appendChild(table(d.rows, d.rows.length?Object.keys(d.rows[0]):[]));
}
$('qa').onclick=function(){fetch('/api/search/insecure?name='+encodeURIComponent($('q').value)).then(function(r){return r.json();}).then(function(d){showResult($('resA'),d);});};
$('qb').onclick=function(){api('GET','/api/search/secure?name='+encodeURIComponent($('q').value)).then(function(d){showResult($('resB'),d);}).catch(function(e){$('resB').replaceChildren(el('div',e.message,'msg err'));});};
$('p1').onclick=function(){$('q').value="' OR 1=1 -- ";};
$('p2').onclick=function(){$('q').value="zzz' UNION SELECT user_id, username, password_hash, role FROM app_users -- ";};
render();
</script></body></html>`;
app.get('/', (req, res) => res.type('html').send(PAGE));

app.listen(3000, () => console.log('SecureLoans running at http://localhost:3000'));
