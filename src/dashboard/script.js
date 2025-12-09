const API_ROOT = '/api';
const token = localStorage.getItem('ps_token');
if (!token) { window.location.href = '/login'; }

function authHeaders() { return { 'Content-Type': 'application/json', 'x-auth-token': token }; }
function toast(msg, t=2000) { const el = document.getElementById('toast'); el.innerText = msg; el.style.display='block'; setTimeout(()=>el.style.display='none', t); }

function show(view) {
  document.querySelectorAll('.view').forEach(v=>v.classList.remove('active'));
  document.getElementById('view-' + view).classList.add('active');
}

async function loadData() {
  const r = await fetch(API_ROOT + '/data', { headers: authHeaders() });
  const j = await r.json();
  if (!j.ok) { alert('Auth error'); localStorage.removeItem('ps_token'); return window.location='/login'; }
  document.getElementById('totalUsers').innerText = Object.keys(j.lastActive||{}).length;
  document.getElementById('queueSize').innerText = j.adStats ? (j.adStats.totalSent || 0) : 0;
  document.getElementById('adsSent').innerText = j.adStats ? (j.adStats.totalSent || 0) : 0;
  document.getElementById('adsMessage').value = j.adsMessage || '';
  document.getElementById('adsMessage').value = j.adsMessage || '';
  document.getElementById('adsMessage').value = j.adsMessage || '';
  document.getElementById('adsMessage').value = j.adsMessage || '';
  document.getElementById('adsMessage').value = j.adsMessage || '';

  renderUsers(Object.keys(j.lastActive || {}));
  renderInactive(j.inactive || []);
  renderUploads(j.lastUploads || []);
  renderAdHistory(j.adStats || {});
}

function renderUsers(users) {
  const box = document.getElementById('usersList'); box.innerHTML='';
  users.forEach(u => { const el=document.createElement('div'); el.className='card'; el.innerText = u; box.appendChild(el); });
}
function renderInactive(list) {
  const box = document.getElementById('inactiveList'); box.innerHTML='';
  list.forEach(u => { const el=document.createElement('div'); el.className='card'; el.innerHTML=`${u} <button onclick="notify('${u}')">Notify</button>`; box.appendChild(el); });
}
async function notify(uid) {
  if (!confirm('Notify ' + uid + '?')) return;
  const res = await fetch(API_ROOT + '/sendto', { method:'POST', headers: authHeaders(), body: JSON.stringify({ userId: uid, text: document.getElementById('inactiveMessage').value || 'We miss you!' })});
  const j = await res.json();
  toast(j.ok ? 'Notified' : 'Failed');
}

async function refresh() { await loadData(); toast('Refreshed'); }
async function saveMessages() {
  const body = { adsMessage: document.getElementById('adsMessage').value, headerText: document.getElementById('headerText').value, footerText: document.getElementById('footerText').value, inactiveMessage: document.getElementById('inactiveMessage').value };
  await fetch(API_ROOT + '/save', { method:'POST', headers: authHeaders(), body: JSON.stringify(body) });
  toast('Saved');
}
async function sendAds() {
  const text = document.getElementById('adText').value;
  if (!text) return toast('Enter ad');
  await fetch(API_ROOT + '/sendads', { method:'POST', headers: authHeaders(), body: JSON.stringify({ text }) });
  toast('Queued');
}

async function uploadMedia() {
  const file = document.getElementById('mediaFile').files[0];
  if (!file) return toast('Choose file');
  const form = new FormData();
  form.append('media', file);
  const r = await fetch(API_ROOT + '/upload', { method:'POST', headers: { 'x-auth-token': token }, body: form });
  const j = await r.json();
  if (j.ok) { toast('Uploaded'); loadUploads(); } else toast('Upload failed');
}

async function loadUploads() {
  const r = await fetch(API_ROOT + '/lastuploads', { headers: authHeaders() });
  const j = await r.json();
  renderUploads(j.lastUploads || []);
}
function renderUploads(list) {
  const box = document.getElementById('uploads'); box.innerHTML='';
  list.forEach(f => {
    const el = document.createElement('div'); el.className='card';
    el.innerHTML = `<b>${f.original}</b><div><button onclick="sendMedia('${f.filename}','image')">Send as Image</button> <button onclick="sendMedia('${f.filename}','video')">Send as Video</button></div>`;
    box.appendChild(el);
  });
}
async function sendMedia(fileName, type) {
  const caption = document.getElementById('mediaCaption').value || '';
  const r = await fetch(API_ROOT + '/sendmedia', { method:'POST', headers: authHeaders(), body: JSON.stringify({ fileName, mediaType: type, caption }) });
  const j = await r.json();
  toast(j.ok ? 'Queued' : 'Failed');
}

async function sendToUser() {
  const id = document.getElementById('sendtoId').value.trim();
  const text = document.getElementById('sendtoText').value.trim();
  if (!id || !text) return toast('Missing');
  const r = await fetch(API_ROOT + '/sendto', { method:'POST', headers: authHeaders(), body: JSON.stringify({ userId: id, text }) });
  const j = await r.json();
  toast(j.ok ? 'Sent' : 'Failed');
}

async function sendInactiveNow() {
  const msg = prompt('Message to send to inactive users:', document.getElementById('inactiveMessage').value || '');
  if (!msg) return;
  await fetch(API_ROOT + '/sendads', { method:'POST', headers: authHeaders(), body: JSON.stringify({ text: msg }) });
  toast('Queued');
}

async function onSearch() {
  const q = document.getElementById('search').value.trim();
  const r = await fetch(API_ROOT + '/users?q=' + encodeURIComponent(q), { headers: authHeaders() });
  const j = await r.json();
  renderUsers(j.users || []);
}

async function renderAdHistory(stats) {
  // simple
}

loadData();
show('stats');
