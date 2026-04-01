#!/usr/bin/env node
/**
 * KEMET POS - Cloud Admin Dashboard
 * نسخة cloud - تشتغل على Railway/Render 24/7
 * الإعدادات للـ environment variables
 */

const express = require('express');
const crypto = require('crypto');
const https = require('https');

const app = express();
const PORT = process.env.PORT || 3300;

// ── Config from environment variables ──
const GITHUB_TOKEN = process.env.GITHUB_TOKEN || '';
const DEVICE_GIST_ID = process.env.DEVICE_GIST_ID || '0feb032572a9f3372b6c899a1c9d1b5a';
const BLOCKLIST_GIST_ID = process.env.BLOCKLIST_GIST_ID || 'fb57c1e7cc284105f807a5062868d0bc';
const PRIVATE_KEY_B64 = process.env.PRIVATE_KEY_B64 || '';

// ── Middleware ──
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// ── Helper: Get private key from env ──
function getPrivateKey() {
  if (!PRIVATE_KEY_B64) throw new Error('PRIVATE_KEY_B64 غير محدد في إعدادات السيرفر');
  const pem = Buffer.from(PRIVATE_KEY_B64, 'base64').toString('utf8');
  return crypto.createPrivateKey(pem);
}

// ── Helper: GitHub API ──
function githubAPI(method, endpoint, body) {
  return new Promise((resolve, reject) => {
    const data = body ? JSON.stringify(body) : null;
    const req = https.request({
      hostname: 'api.github.com',
      path: endpoint,
      method,
      headers: {
        'Authorization': 'token ' + GITHUB_TOKEN,
        'User-Agent': 'KEMET-Dashboard',
        'Content-Type': 'application/json',
        ...(data ? { 'Content-Length': Buffer.byteLength(data) } : {})
      }
    }, (res) => {
      let body = '';
      res.on('data', c => body += c);
      res.on('end', () => {
        try { resolve(JSON.parse(body)); } catch { resolve(body); }
      });
    });
    req.on('error', reject);
    if (data) req.write(data);
    req.end();
  });
}

// ── Helper: Generate Activation Code ──
function generateActivationCode(hwid, type, days, clientName) {
  const privateKey = getPrivateKey();
  const cleanHwid = hwid.trim().replace(/[\s\-]/g, '').toUpperCase();
  if (cleanHwid.length !== 32) throw new Error(`كود الجهاز لازم يكون 32 حرف (الحالي: ${cleanHwid.length})`);

  const payload = JSON.stringify({
    hwid: cleanHwid,
    type,
    expiryDays: type === 'lifetime' ? 0 : (days || 30),
    nonce: crypto.randomBytes(16).toString('hex'),
    createdAt: Date.now(),
    clientName: clientName || ''
  });

  const payloadBuf = Buffer.from(payload, 'utf8');
  const signature = crypto.sign(null, payloadBuf, privateKey);
  const lenBuf = Buffer.alloc(4);
  lenBuf.writeUInt32BE(payloadBuf.length);
  return Buffer.concat([lenBuf, payloadBuf, signature]).toString('base64');
}

// ── Blocklist via Gist ──
async function getBlocklist() {
  const gist = await githubAPI('GET', '/gists/' + BLOCKLIST_GIST_ID);
  if (gist.files && gist.files['blocklist.json']) {
    try { return JSON.parse(gist.files['blocklist.json'].content); } catch {}
  }
  return { blocked: [], messages: {} };
}

async function saveBlocklist(data) {
  await githubAPI('PATCH', '/gists/' + BLOCKLIST_GIST_ID, {
    files: { 'blocklist.json': { content: JSON.stringify(data, null, 2) } }
  });
}

// ════════════════════════════════════════
//  API Endpoints
// ════════════════════════════════════════

app.post('/api/activate', (req, res) => {
  try {
    const { hwid, type, months, days, hours, minutes, clientName } = req.body;
    if (!hwid) return res.json({ error: 'كود الجهاز مطلوب' });

    let totalDays = 0;
    if (type !== 'lifetime') {
      if (months) totalDays = parseFloat(months) * 30;
      else if (days) totalDays = parseFloat(days);
      else if (hours) totalDays = parseFloat(hours) / 24;
      else if (minutes) totalDays = parseFloat(minutes) / 1440;
      if (totalDays <= 0) return res.json({ error: 'لازم تحدد المدة' });
    }

    const code = generateActivationCode(hwid, type, totalDays, clientName);

    let durationLabel = 'مدى الحياة';
    if (type !== 'lifetime') {
      const d = totalDays;
      if (d >= 30 && d % 30 === 0) durationLabel = `${Math.round(d / 30)} شهر`;
      else if (d >= 1) durationLabel = `${Math.round(d)} يوم`;
      else if (d * 24 >= 1) durationLabel = `${Math.round(d * 24)} ساعة`;
      else durationLabel = `${Math.round(d * 1440)} دقيقة`;
    }

    const expiryDate = type === 'lifetime' ? 'لا ينتهي' :
      new Date(Date.now() + totalDays * 86400000).toLocaleDateString('ar-EG', {
        year: 'numeric', month: 'long', day: 'numeric'
      });

    res.json({ success: true, code, type, durationLabel, expiryDate, clientName });
  } catch (e) {
    res.json({ error: e.message });
  }
});

app.get('/api/devices', async (req, res) => {
  try {
    const gist = await githubAPI('GET', '/gists/' + DEVICE_GIST_ID);
    const devices = [];
    if (gist.files) {
      for (const [name, file] of Object.entries(gist.files)) {
        if (name.startsWith('device_') && name.endsWith('.json')) {
          try { devices.push(JSON.parse(file.content)); } catch {}
        }
      }
    }
    devices.sort((a, b) => new Date(b.lastOnline || 0) - new Date(a.lastOnline || 0));
    res.json({ success: true, devices });
  } catch (e) {
    res.json({ error: e.message });
  }
});

app.get('/api/blocklist', async (req, res) => {
  try {
    const data = await getBlocklist();
    res.json({ success: true, ...data });
  } catch (e) {
    res.json({ error: e.message });
  }
});

app.post('/api/block', async (req, res) => {
  try {
    const { hwid, message } = req.body;
    if (!hwid) return res.json({ error: 'كود الجهاز مطلوب' });
    const cleanHwid = hwid.replace(/[\s\-]/g, '').toUpperCase();
    const data = await getBlocklist();
    if (!data.blocked.includes(cleanHwid)) data.blocked.push(cleanHwid);
    data.messages[cleanHwid] = message || 'تم إيقاف الترخيص. تواصل مع المطور.';
    await saveBlocklist(data);
    res.json({ success: true, message: 'تم حظر الجهاز وتحديث السيرفر' });
  } catch (e) {
    res.json({ error: e.message });
  }
});

app.post('/api/unblock', async (req, res) => {
  try {
    const { hwid } = req.body;
    if (!hwid) return res.json({ error: 'كود الجهاز مطلوب' });
    const cleanHwid = hwid.replace(/[\s\-]/g, '').toUpperCase();
    const data = await getBlocklist();
    data.blocked = data.blocked.filter(h => h !== cleanHwid);
    delete data.messages[cleanHwid];
    await saveBlocklist(data);
    res.json({ success: true, message: 'تم فك الحظر وتحديث السيرفر' });
  } catch (e) {
    res.json({ error: e.message });
  }
});

// OTA push via GitHub API (no local files needed)
app.post('/api/push-update', async (req, res) => {
  try {
    const { version, changelog } = req.body;
    if (!version) return res.json({ error: 'رقم الإصدار مطلوب' });
    res.json({
      success: true,
      message: `لتحديث الإصدار على GitHub:
1. افتح https://github.com/Taherafifi/android-apk-last-update
2. عدّل update_info.json وغيّر "version" لـ "${version}"
3. ارفع index.html الجديد`
    });
  } catch (e) {
    res.json({ error: e.message });
  }
});

// ════════════════════════════════════════
//  Dashboard HTML
// ════════════════════════════════════════
app.get('/', (req, res) => {
  res.send(DASHBOARD_HTML);
});

const DASHBOARD_HTML = `<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>KEMET POS - لوحة التحكم</title>
<link href="https://fonts.googleapis.com/css2?family=Cairo:wght@400;600;700;900&display=swap" rel="stylesheet">
<style>
* { margin:0; padding:0; box-sizing:border-box; }
body { font-family:'Cairo',sans-serif; background:#0a0e1a; color:#e2e8f0; min-height:100vh; }
.header { background:linear-gradient(135deg,#1e1b4b,#0f172a); border-bottom:1px solid rgba(99,102,241,.3); padding:16px 24px; display:flex; align-items:center; gap:14px; }
.header .logo { width:42px; height:42px; background:linear-gradient(135deg,#6366f1,#8b5cf6); border-radius:12px; display:flex; align-items:center; justify-content:center; font-size:22px; }
.header h1 { font-size:18px; font-weight:900; }
.header .sub { font-size:12px; color:#94a3b8; }
.nav { display:flex; gap:4px; padding:12px 24px; background:#0f1629; border-bottom:1px solid rgba(255,255,255,.06); overflow-x:auto; }
.nav button { padding:10px 20px; border:none; border-radius:10px; background:transparent; color:#94a3b8; font-family:'Cairo',sans-serif; font-size:13px; font-weight:700; cursor:pointer; white-space:nowrap; transition:.2s; }
.nav button:hover { background:rgba(99,102,241,.1); color:#c7d2fe; }
.nav button.active { background:linear-gradient(135deg,#6366f1,#8b5cf6); color:#fff; }
.panel { display:none; padding:24px; max-width:1000px; margin:0 auto; }
.panel.active { display:block; }
.card { background:linear-gradient(160deg,#1a1f35,#151928); border:1px solid rgba(255,255,255,.06); border-radius:16px; padding:24px; margin-bottom:16px; }
.card h3 { font-size:15px; font-weight:800; margin-bottom:16px; color:#c7d2fe; display:flex; align-items:center; gap:8px; }
.form-group { margin-bottom:14px; }
.form-group label { display:block; font-size:12px; font-weight:700; color:#94a3b8; margin-bottom:6px; }
.form-group input, .form-group select, .form-group textarea {
  width:100%; padding:10px 14px; border:1.5px solid rgba(255,255,255,.1); border-radius:10px;
  background:rgba(255,255,255,.04); color:#e2e8f0; font-family:'Cairo',sans-serif; font-size:13px; outline:none; transition:.2s;
}
.form-group input:focus, .form-group select:focus { border-color:#6366f1; background:rgba(99,102,241,.06); }
.btn { padding:10px 24px; border:none; border-radius:10px; font-family:'Cairo',sans-serif; font-size:13px; font-weight:700; cursor:pointer; transition:.2s; display:inline-flex; align-items:center; gap:6px; }
.btn-primary { background:linear-gradient(135deg,#6366f1,#8b5cf6); color:#fff; }
.btn-success { background:linear-gradient(135deg,#10b981,#059669); color:#fff; }
.btn-danger { background:linear-gradient(135deg,#ef4444,#dc2626); color:#fff; }
.btn-ghost { background:rgba(255,255,255,.06); color:#94a3b8; border:1px solid rgba(255,255,255,.1); }
.code-box { background:#0a0e1a; border:1px solid rgba(99,102,241,.3); border-radius:12px; padding:16px; margin-top:12px; font-family:monospace; font-size:11px; word-break:break-all; line-height:1.7; color:#a5b4fc; position:relative; direction:ltr; text-align:left; }
.copy-btn { position:absolute; top:8px; right:8px; padding:4px 10px; border:none; border-radius:6px; background:rgba(99,102,241,.2); color:#a5b4fc; font-size:11px; cursor:pointer; font-family:'Cairo',sans-serif; }
.result { margin-top:12px; padding:14px; border-radius:10px; font-size:13px; display:none; }
.result.success { background:rgba(16,185,129,.1); border:1px solid rgba(16,185,129,.3); color:#6ee7b7; display:block; }
.result.error { background:rgba(239,68,68,.1); border:1px solid rgba(239,68,68,.3); color:#fca5a5; display:block; }
.device-grid { display:grid; gap:12px; }
.device-card { background:rgba(255,255,255,.03); border:1px solid rgba(255,255,255,.06); border-radius:14px; padding:16px; }
.device-card .name { font-size:14px; font-weight:800; }
.device-card .hwid { font-size:10px; font-family:monospace; color:#64748b; direction:ltr; }
.device-card .meta { display:flex; flex-wrap:wrap; gap:6px; margin-top:8px; }
.tag { padding:3px 8px; border-radius:6px; font-size:10.5px; font-weight:700; }
.tag-lifetime { background:rgba(16,185,129,.15); color:#6ee7b7; }
.tag-timed { background:rgba(245,158,11,.15); color:#fcd34d; }
.tag-trial { background:rgba(99,102,241,.15); color:#a5b4fc; }
.tag-online { background:rgba(16,185,129,.1); color:#4ade80; }
.tag-offline { background:rgba(239,68,68,.1); color:#fca5a5; }
.tag-blocked { background:rgba(239,68,68,.2); color:#f87171; }
.device-card .info { font-size:11.5px; color:#64748b; margin-top:6px; }
.device-card .info span { margin-left:12px; }
.device-card .actions { margin-top:10px; display:flex; gap:6px; flex-wrap:wrap; }
.row { display:flex; gap:12px; flex-wrap:wrap; }
.row .form-group { flex:1; min-width:140px; }
.loading { text-align:center; padding:40px; color:#64748b; }
.stats { display:grid; grid-template-columns:repeat(auto-fit,minmax(160px,1fr)); gap:12px; margin-bottom:20px; }
.stat { background:rgba(255,255,255,.03); border:1px solid rgba(255,255,255,.06); border-radius:14px; padding:16px; text-align:center; }
.stat .num { font-size:28px; font-weight:900; }
.stat .label { font-size:11px; color:#64748b; font-weight:700; }
</style>
</head>
<body>
<div class="header">
  <div class="logo">⚡</div>
  <div><h1>KEMET POS</h1><div class="sub">لوحة تحكم الإدارة ☁️</div></div>
</div>
<div class="nav">
  <button class="active" onclick="showTab('activate',this)">🔑 تفعيل</button>
  <button onclick="showTab('devices',this)">📱 الأجهزة</button>
  <button onclick="showTab('blocklist',this)">🚫 الحظر</button>
</div>

<!-- تفعيل -->
<div id="tab-activate" class="panel active">
  <div class="card">
    <h3>🔑 إنشاء كود تفعيل</h3>
    <div class="form-group">
      <label>كود الجهاز (HWID)</label>
      <input id="act-hwid" placeholder="XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX" dir="ltr" style="text-align:left">
    </div>
    <div class="row">
      <div class="form-group">
        <label>اسم العميل</label>
        <input id="act-name" placeholder="اختياري">
      </div>
      <div class="form-group">
        <label>نوع الترخيص</label>
        <select id="act-type" onchange="toggleDuration()">
          <option value="lifetime">مدى الحياة</option>
          <option value="timed">مؤقت</option>
          <option value="trial">تجريبي</option>
        </select>
      </div>
    </div>
    <div id="duration-row" class="row" style="display:none">
      <div class="form-group">
        <label>وحدة المدة</label>
        <select id="act-unit">
          <option value="months">شهور</option>
          <option value="days">أيام</option>
          <option value="hours">ساعات</option>
          <option value="minutes">دقائق</option>
        </select>
      </div>
      <div class="form-group">
        <label>القيمة</label>
        <input id="act-val" type="number" value="1" min="1">
      </div>
    </div>
    <button class="btn btn-primary" onclick="doActivate()">🔑 إنشاء الكود</button>
    <div id="act-result"></div>
    <div id="act-code-box" style="display:none">
      <div class="code-box">
        <button class="copy-btn" onclick="copyCode(this)">📋 نسخ</button>
        <div id="act-code"></div>
      </div>
      <div style="margin-top:12px">
        <button class="btn btn-success" onclick="sendWhatsApp()">💬 إرسال واتساب</button>
      </div>
    </div>
  </div>
</div>

<!-- الأجهزة -->
<div id="tab-devices" class="panel">
  <div id="devices-stats" class="stats"></div>
  <div class="card">
    <h3>📱 الأجهزة المتصلة <button class="btn btn-ghost" onclick="loadDevices()" style="margin-right:auto;font-size:11px">🔄</button></h3>
    <div id="devices-list" class="device-grid"><div class="loading">⏳ جارِ التحميل...</div></div>
  </div>
</div>

<!-- الحظر -->
<div id="tab-blocklist" class="panel">
  <div class="card">
    <h3>🚫 حظر جهاز</h3>
    <div class="row">
      <div class="form-group" style="flex:2">
        <label>كود الجهاز (HWID)</label>
        <input id="block-hwid" placeholder="XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX" dir="ltr" style="text-align:left">
      </div>
      <div class="form-group" style="flex:2">
        <label>سبب الحظر</label>
        <input id="block-msg" value="تم إيقاف الترخيص. تواصل مع المطور.">
      </div>
    </div>
    <button class="btn btn-danger" onclick="doBlock()">🔒 حظر</button>
    <div id="block-result"></div>
  </div>
  <div class="card">
    <h3>📋 الأجهزة المحظورة <button class="btn btn-ghost" onclick="loadBlocklist()" style="margin-right:auto;font-size:11px">🔄</button></h3>
    <div id="blocked-list"></div>
  </div>
</div>

<script>
function showTab(name, btn) {
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.nav button').forEach(b => b.classList.remove('active'));
  document.getElementById('tab-' + name).classList.add('active');
  btn.classList.add('active');
  if (name === 'devices') loadDevices();
  if (name === 'blocklist') loadBlocklist();
}
function toggleDuration() {
  document.getElementById('duration-row').style.display =
    document.getElementById('act-type').value === 'lifetime' ? 'none' : 'flex';
}
async function api(url, data) {
  try {
    const opts = data ? { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(data) } : {};
    const r = await fetch(url, opts);
    return r.json();
  } catch(e) { return { error: e.message }; }
}
function showResult(id, msg, isError) {
  const el = document.getElementById(id);
  el.className = 'result ' + (isError ? 'error' : 'success');
  el.textContent = msg; el.style.display = 'block';
}

let lastCode = '', lastClientName = '';
async function doActivate() {
  const hwid = document.getElementById('act-hwid').value.trim();
  const type = document.getElementById('act-type').value;
  const clientName = document.getElementById('act-name').value.trim();
  const unit = document.getElementById('act-unit').value;
  const val = document.getElementById('act-val').value;
  lastClientName = clientName;
  const body = { hwid, type, clientName }; body[unit] = val;
  const r = await api('/api/activate', body);
  if (r.error) { showResult('act-result','❌ '+r.error,true); document.getElementById('act-code-box').style.display='none'; return; }
  showResult('act-result','✅ '+r.durationLabel+' — ينتهي: '+r.expiryDate,false);
  lastCode = r.code;
  document.getElementById('act-code').textContent = r.code;
  document.getElementById('act-code-box').style.display = 'block';
}
function copyCode(btn) {
  navigator.clipboard.writeText(lastCode);
  btn.textContent = '✅ تم'; setTimeout(() => btn.textContent = '📋 نسخ', 1500);
}
function sendWhatsApp() {
  const msg = 'مرحباً ' + (lastClientName||'') + '\\n\\nكود تفعيل KEMET POS:\\n\\n' + lastCode + '\\n\\nالصق الكود في شاشة التفعيل.';
  window.open('https://wa.me/?text=' + encodeURIComponent(msg), '_blank');
}

async function loadDevices() {
  const list = document.getElementById('devices-list');
  list.innerHTML = '<div class="loading">⏳ جارِ التحميل...</div>';
  try {
    const [r, bl] = await Promise.all([api('/api/devices'), api('/api/blocklist')]);
    if (r.error) { list.innerHTML = '<div style="color:#fca5a5;padding:20px">❌ خطأ: '+r.error+'</div>'; return; }
  const blockedSet = new Set((bl.blocked||[]).map(h=>h.replace(/-/g,'').toUpperCase()));
  const devices = r.devices;
  const total=devices.length, lifetime=devices.filter(d=>d.licenseType==='lifetime').length;
  const timed=devices.filter(d=>d.licenseType==='timed'||d.licenseType==='monthly').length;
  const online=devices.filter(d=>d.lastOnline&&(Date.now()-new Date(d.lastOnline))<86400000).length;
  const blocked=devices.filter(d=>blockedSet.has((d.hwid||'').replace(/-/g,'').toUpperCase())).length;
  document.getElementById('devices-stats').innerHTML =
    '<div class="stat"><div class="num" style="color:#a5b4fc">'+total+'</div><div class="label">إجمالي</div></div>'+
    '<div class="stat"><div class="num" style="color:#6ee7b7">'+lifetime+'</div><div class="label">مدى الحياة</div></div>'+
    '<div class="stat"><div class="num" style="color:#fcd34d">'+timed+'</div><div class="label">مؤقت</div></div>'+
    '<div class="stat"><div class="num" style="color:#4ade80">'+online+'</div><div class="label">متصل اليوم</div></div>'+
    '<div class="stat"><div class="num" style="color:#f87171">'+blocked+'</div><div class="label">محظور</div></div>';
  if (!devices.length) { list.innerHTML='<div style="color:#64748b;text-align:center;padding:30px">لا توجد أجهزة</div>'; return; }
  list.innerHTML = devices.map(d => {
    const hwid=(d.hwid||'').replace(/-/g,'').toUpperCase();
    const isBlocked=blockedSet.has(hwid);
    const online=d.lastOnline&&(Date.now()-new Date(d.lastOnline))<86400000;
    const typeClass=d.licenseType==='lifetime'?'tag-lifetime':d.licenseType==='trial'?'tag-trial':'tag-timed';
    const typeLabel=d.licenseType==='lifetime'?'مدى الحياة':d.licenseType==='trial'?'تجريبي':'مؤقت';
    const daysRem=d.daysRemaining===-1?'':' ('+d.daysRemaining+' يوم)';
    const lastOn=d.lastOnline?new Date(d.lastOnline).toLocaleString('ar-EG'):'غير معروف';
    const loc=[d.city,d.country].filter(Boolean).join(', ');
    return '<div class="device-card"><div style="display:flex;justify-content:space-between;align-items:flex-start">'
      +'<div><div class="name">'+(d.clientName||d.computerName||'جهاز')+'</div>'
      +'<div class="hwid">'+(d.hwid||hwid)+'</div></div></div>'
      +'<div class="meta"><span class="tag '+typeClass+'">'+typeLabel+daysRem+'</span>'
      +(isBlocked?'<span class="tag tag-blocked">🔒 محظور</span>':'')
      +'<span class="tag '+(online?'tag-online':'tag-offline')+'">'+(online?'🟢 متصل':'🔴 غير متصل')+'</span></div>'
      +'<div class="info"><span>📱 '+(d.computerName||d.platform||'')+'</span>'
      +(loc?'<span>📍 '+loc+'</span>':'')
      +(d.ip?'<span>🌐 '+d.ip+'</span>':'')
      +'<span>🕒 '+lastOn+'</span></div>'
      +'<div class="actions">'
      +'<button class="btn btn-primary" onclick="activateFrom(\''+( d.hwid||'')+'\',\''+(d.clientName||'')+'\')" style="padding:5px 12px;font-size:11px">🔑 تفعيل</button>'
      +(isBlocked
        ?'<button class="btn btn-success" onclick="quickUnblock(\''+hwid+'\')" style="padding:5px 12px;font-size:11px">🔓 فك الحظر</button>'
        :'<button class="btn btn-danger" onclick="quickBlock(\''+hwid+'\')" style="padding:5px 12px;font-size:11px">🔒 حظر</button>')
      +'</div></div>';
  }).join('');
  } catch(e) { list.innerHTML = '<div style="color:#fca5a5;padding:20px">❌ خطأ: '+e.message+'</div>'; }
}

function activateFrom(hwid, name) {
  document.querySelectorAll('.panel').forEach(p=>p.classList.remove('active'));
  document.querySelectorAll('.nav button').forEach(b=>b.classList.remove('active'));
  document.getElementById('tab-activate').classList.add('active');
  document.querySelectorAll('.nav button')[0].classList.add('active');
  document.getElementById('act-hwid').value=hwid;
  document.getElementById('act-name').value=name;
}

async function quickBlock(hwid) {
  if(!confirm('حظر هذا الجهاز؟')) return;
  const r = await api('/api/block',{hwid,message:'تم إيقاف الترخيص. تواصل مع المطور.'});
  alert(r.message||r.error); loadDevices();
}
async function quickUnblock(hwid) {
  if(!confirm('فك الحظر؟')) return;
  const r = await api('/api/unblock',{hwid});
  alert(r.message||r.error); loadDevices();
}

async function loadBlocklist() {
  const list = document.getElementById('blocked-list');
  list.innerHTML = '<div class="loading">⏳ جارِ التحميل...</div>';
  try {
    const r = await api('/api/blocklist');
    if(r.error){list.innerHTML='<div style="color:#fca5a5;padding:20px">❌ خطأ: '+r.error+'</div>';return;}
    if(!r.blocked||!r.blocked.length){ list.innerHTML='<div style="color:#64748b;text-align:center;padding:16px">لا توجد أجهزة محظورة</div>'; return; }
    list.innerHTML = r.blocked.map(hwid=>{
    const msg=r.messages[hwid]||'';
    return '<div style="display:flex;align-items:center;justify-content:space-between;padding:10px 14px;border-bottom:1px solid rgba(255,255,255,.04)">'
      +'<div><div style="font-family:monospace;font-size:12px;color:#fca5a5;direction:ltr">'+hwid+'</div>'
      +'<div style="font-size:11px;color:#64748b">'+msg+'</div></div>'
      +'<button class="btn btn-success" onclick="doUnblock(\''+hwid+'\')" style="padding:5px 12px;font-size:11px">🔓 فك الحظر</button>'
      +'</div>';
  }).join('');
  } catch(e) { list.innerHTML='<div style="color:#fca5a5;padding:20px">❌ خطأ: '+e.message+'</div>'; }
}

async function doBlock() {
  const hwid=document.getElementById('block-hwid').value.trim();
  const msg=document.getElementById('block-msg').value.trim();
  if(!hwid){showResult('block-result','❌ ادخل كود الجهاز',true);return;}
  const r=await api('/api/block',{hwid,message:msg});
  showResult('block-result',r.error?'❌ '+r.error:'✅ '+r.message,!!r.error);
  if(r.success){document.getElementById('block-hwid').value='';loadBlocklist();}
}
async function doUnblock(hwid) {
  if(!confirm('فك الحظر عن '+hwid+'؟'))return;
  const r=await api('/api/unblock',{hwid});
  alert(r.message||r.error); loadBlocklist();
}
</script>
</body>
</html>`;

app.listen(PORT, '0.0.0.0', () => {
  console.log('KEMET Dashboard running on port ' + PORT);
});
