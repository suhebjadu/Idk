// dashboard client logic
const API_ROOT = '/dashboard';
const toastEl = document.getElementById('toast');

function showToast(txt, time=2000) {
  toastEl.innerText = txt;
  toastEl.style.display = 'block';
  setTimeout(()=> toastEl.style.display='none', time);
}

function showTab(tab) {
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  document.getElementById('tab-'+tab).classList.add('active');
  document.querySelectorAll('.menu li').forEach(li=>li.classList.remove('active'));
  document.querySelector(`.menu li[data-tab="${tab}"]`).classList.add('active');
}

async function loadData() {
  try {
    const res = await fetch(API_ROOT + '/data');
    if (!res.ok) return showToast('Load failed');
    const j = await res.json();
    renderUsers(j.users);
    renderInactive(j.inactive);
    document.getElementById('adsMessage').value = j.adsMessage || '';
    document.getElementById('headerText').value = j.headerText || '';
    document.getElementById('footerText').value = j.footerText || '';
    document.getElementById('summary').innerText = `${j.users.length} users • ${j.adStats ? (j.adStats.totalDelivered||0) + ' delivered' : ''}`;
  } catch (e) { console.error(e); showToast('Error'); }
}

function renderUsers(users) {
  document.getElementById('total-users').innerText = users.length;
  const container = document.getElementById('usersContainer');
  container.innerHTML = '';
  users.forEach(u => {
    const el = document.createElement('div');
    el.className = 'user-item';
    el.innerHTML = `<div><strong>${u.id}</strong><div class="meta">${u.hasApi ? 'API: set' : 'API: not set'} • Last: ${timeAgo(u.lastActive)}</div></div>
                    <div><button onclick="sendMsg('${u.id}')">Msg</button></div>`;
    container.appendChild(el);
  });
}
function renderInactive(list) {
  document.getElementById('inactive-count').innerText = list.length;
  const c = document.getElementById('inactiveContainer');
  c.innerHTML = '';
  list.forEach(id => {
    const el = document.createElement('div');
    el.className = 'user-item';
    el.innerHTML = `<div><strong>${id}</strong></div><div><button onclick="notifySingle('${id}')">Notify</button></div>`;
    c.appendChild(el);
  });
}

function timeAgo(ts) {
  if (!ts) return 'never';
  const s = Math.floor((Date.now() - ts)/1000);
  if (s < 60) return s+'s';
  if (s < 3600) return Math.floor(s/60)+'m';
  if (s < 86400) return Math.floor(s/3600)+'h';
  return Math.floor(s/86400)+'d';
}

async function saveMessages() {
  const adtext = document.getElementById('adsMessage').value;
  const header = document.getElementById('headerText').value;
  const footer = document.getElementById('footerText').value;
  await fetch(API_ROOT + '/setads', { method: 'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ adtext })});
  await fetch(API_ROOT + '/sethf', { method: 'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ header, footer })});
  showToast('Saved');
}

async function sendAdsNow() {
  const txt = document.getElementById('sendAdText').value;
  if (!txt.trim()) return showToast('Enter ad');
  const res = await fetch(API_ROOT + '/sendad', { method: 'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ adtext: txt })});
  const j = await res.json();
  if (j.ok) showToast(`Sent: ${j.delivered} / failed: ${j.failed}`, 3000);
  else showToast('Send failed');
}

async function refresh() { await loadData(); showToast('Refreshed'); }
async function onSearch() {
  const q = document.getElementById('searchInput').value.trim();
  if (!q) return loadData();
  const res = await fetch(API_ROOT + `/users?q=${encodeURIComponent(q)}`);
  const j = await res.json();
  if (j.ok) renderUsers(j.users);
}

async function sendMsg(uid) {
  const txt = prompt("Type message to user " + uid);
  if (!txt) return;
  // For now save as ad and inform user to implement send single endpoint if needed
  await fetch(API_ROOT + '/setads', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ adtext: txt })});
  showToast('Saved as default ad (or implement direct send endpoint)');
}

async function notifySingle(id) {
  const conf = confirm("Send inactive notice to " + id + "?");
  if (!conf) return;
  const res = await fetch(API_ROOT + '/sendad', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({ adtext: '👋 We miss you! Please send a link to shorten.' , target: id })});
  const j = await res.json();
  if (j.ok) showToast('Notified');
  else showToast('Notify failed');
}

function showAdHistory() {
  fetch('/dashboard/data').then(r=>r.json()).then(j=>{
    const node = document.getElementById('adHistory');
    node.innerHTML = '';
    (j.adStats && j.adStats.history || []).slice(0,10).forEach(h=>{
      const el = document.createElement('div');
      el.className = 'user-item';
      el.innerHTML = `<div><strong>${new Date(h.id).toLocaleString()}</strong><div class="meta">${h.type} • delivered:${h.delivered} failed:${h.failed}</div></div>`;
      node.appendChild(el);
    });
  });
}

// init
showTab('users');
loadData();