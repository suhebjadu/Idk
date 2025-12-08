let token = localStorage.getItem("token");

if (!token) {
    window.location.href = "/login";
}

function showToast() {
    let t = document.getElementById("savedToast");
    t.style.display = "block";
    setTimeout(() => t.style.display = "none", 2000);
}

function switchTab(id) {
    document.querySelectorAll(".tab").forEach(t => t.style.display = "none");
    document.getElementById(id).style.display = "block";
}

async function loadData() {
    let res = await fetch("/api/data", {
        headers: { "x-auth-token": token }
    });

    let data = await res.json();
    if (!data.ok) return alert("Auth error");

    document.getElementById("adsBox").value = data.adsMessage;
    document.getElementById("msgAds").value = data.adsMessage;
    document.getElementById("msgHeader").value = data.headerText;
    document.getElementById("msgFooter").value = data.footerText;
    document.getElementById("msgInactive").value = data.inactiveMessage;

    document.getElementById("totalUsers").innerText = Object.keys(data.lastActive).length;
    document.getElementById("queueSize").innerText = data.queue || 0;
    document.getElementById("adsSent").innerText = data.adStats.totalSent;
    document.getElementById("adsDelivered").innerText = data.adStats.totalDelivered;
    document.getElementById("adsFailed").innerText = data.adStats.totalFailed;

    loadUsers();
    loadInactive();
    loadUploads();
}

async function loadUsers() {
    let res = await fetch("/api/users", { headers: { "x-auth-token": token } });
    let data = await res.json();
    let box = document.getElementById("usersList");
    box.innerHTML = "";
    data.users.forEach(u => {
        let li = document.createElement("li");
        li.innerText = u;
        box.appendChild(li);
    });
}

async function searchUsers() {
    let q = document.getElementById("userSearch").value.trim();
    let res = await fetch("/api/users?q=" + q, { headers: { "x-auth-token": token } });
    let data = await res.json();
    let box = document.getElementById("usersList");
    box.innerHTML = "";
    data.users.forEach(u => {
        let li = document.createElement("li");
        li.innerText = u;
        box.appendChild(li);
    });
}

async function loadInactive() {
    let res = await fetch("/api/inactive", { headers: { "x-auth-token": token } });
    let data = await res.json();
    let box = document.getElementById("inactiveList");
    box.innerHTML = "";
    data.inactive.forEach(u => {
        let li = document.createElement("li");
        li.innerText = u;
        box.appendChild(li);
    });
}

async function sendInactiveNow() {
    let msg = prompt("Message to send:");
    if (!msg) return;

    let res = await fetch("/api/sendads", {
        method: "POST",
        headers: { "Content-Type":"application/json", "x-auth-token": token },
        body: JSON.stringify({ text: msg })
    });

    alert("Queued!");
}

async function saveMessages() {
    let res = await fetch("/api/save", {
        method: "POST",
        headers: { "Content-Type":"application/json", "x-auth-token": token },
        body: JSON.stringify({
            adsMessage: document.getElementById("msgAds").value,
            headerText: document.getElementById("msgHeader").value,
            footerText: document.getElementById("msgFooter").value,
            inactiveMessage: document.getElementById("msgInactive").value
        })
    });
    showToast();
}

async function sendAds() {
    let text = document.getElementById("adsBox").value;
    await fetch("/api/sendads", {
        method: "POST",
        headers: { "Content-Type":"application/json", "x-auth-token": token },
        body: JSON.stringify({ text })
    });
    alert("Queued!");
}

async function uploadMedia() {
    let file = document.getElementById("mediaFile").files[0];
    if (!file) return alert("Choose file");

    let form = new FormData();
    form.append("media", file);

    let res = await fetch("/api/upload", {
        method: "POST",
        headers: { "x-auth-token": token },
        body: form
    });

    alert("Uploaded!");
    loadUploads();
}

async function loadUploads() {
    let res = await fetch("/api/lastuploads", {
        headers: { "x-auth-token": token }
    });

    let data = await res.json();
    let box = document.getElementById("uploadsList");
    box.innerHTML = "";

    data.lastUploads.forEach(f => {
        let li = document.createElement("li");
        li.innerHTML = `
            <b>${f.original}</b><br>
            <button onclick="sendMedia('${f.filename}', 'image')">Send as Image</button>
            <button onclick="sendMedia('${f.filename}', 'video')">Send as Video</button>
        `;
        box.appendChild(li);
    });
}

async function sendMedia(fileName, type) {
    let caption = document.getElementById("mediaCaption").value;
    await fetch("/api/sendmedia", {
        method: "POST",
        headers: { "Content-Type":"application/json", "x-auth-token": token },
        body: JSON.stringify({ fileName, mediaType: type, caption })
    });
    alert("Queued!");
}

async function sendToUser() {
    let userId = document.getElementById("sendToID").value.trim();
    let text = document.getElementById("sendToText").value.trim();
    if (!userId || !text) return alert("Missing fields");

    await fetch("/api/sendto", {
        method: "POST",
        headers: { "Content-Type":"application/json","x-auth-token": token },
        body: JSON.stringify({ userId, text })
    });

    alert("Sent!");
}

loadData();
switchTab("statsTab");
