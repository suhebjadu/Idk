// MENU SWITCHING
document.querySelectorAll(".menu-btn").forEach(btn => {
    btn.onclick = () => {
        document.querySelectorAll(".menu-btn").forEach(b => b.classList.remove("active"));
        btn.classList.add("active");

        let page = btn.dataset.page;

        document.querySelectorAll(".page").forEach(p => p.classList.remove("active"));
        document.getElementById(page).classList.add("active");
    };
});

function logout() {
    fetch("/logout").then(() => {
        location.href = "/login";
    });
}

// SHOW TOAST
function showToast(msg) {
    let t = document.getElementById("toast");
    t.innerText = msg;
    t.style.display = "block";
    setTimeout(() => t.style.display = "none", 2000);
}


// LOAD DASHBOARD DATA
async function loadDashboard() {
    let res = await fetch("/admin/data");
    let data = await res.json();

    totalUsers.innerText = data.totalUsers;
    inactiveUsers.innerText = data.inactiveUsers;
    premiumUsers.innerText = data.premiumUsers;
    serverStatus.innerText = "Online";
}


// LOAD USERS LIST
async function loadUsers() {
    let res = await fetch("/admin/users");
    let users = await res.json();

    usersList.innerHTML = "";
    users.forEach(u => {
        usersList.innerHTML += `<li>${u}</li>`;
    });
}

// SEARCH USERS
function searchUserList() {
    let term = searchUsers.value.toLowerCase();

    document.querySelectorAll("#usersList li").forEach(li => {
        li.style.display = li.innerText.toLowerCase().includes(term) ? "block" : "none";
    });
}


// LOAD INACTIVE USERS
async function loadInactive() {
    let res = await fetch("/admin/inactive");
    let users = await res.json();

    inactiveList.innerHTML = "";
    users.forEach(u => {
        inactiveList.innerHTML += `<li>${u}</li>`;
    });
}


// SEND INACTIVE MESSAGE NOW
async function sendInactiveNow() {
    let res = await fetch("/admin/sendInactiveNow");
    let data = await res.json();

    showToast(data.message);
}


// SEND TEXT ADS
async function sendTextAd() {
    let msg = textAd.value;

    let res = await fetch("/admin/sendAdsText", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ msg })
    });

    let data = await res.json();
    showToast(data.message);
}


// SENDTO FEATURE
async function sendToUser() {
    let chatId = sendToId.value.trim();
    let msg = sendToMsg.value.trim();

    let res = await fetch("/admin/sendTo", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ chatId, msg })
    });

    let data = await res.json();
    showToast(data.message);
}


// DEFAULT MESSAGES LOADING
async function loadMessages() {
    let res = await fetch("/admin/messages");
    let msgs = await res.json();

    messagesBox.innerHTML = "";

    for (let key in msgs) {
        messagesBox.innerHTML += `
            <div class="ads-box">
                <label>${key}</label>
                <textarea id="${key}">${msgs[key]}</textarea>
                <button onclick="saveMessage('${key}')" class="primary-btn">Save</button>
            </div>
        `;
    }
}


// SAVE SINGLE MESSAGE
async function saveMessage(key) {
    let value = document.getElementById(key).value;

    let res = await fetch("/admin/saveMessage", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ key, value })
    });

    showToast("Saved");
}


// LOAD PREMIUM USERS
async function loadPremium() {
    let res = await fetch("/admin/premium");
    let list = await res.json();

    premiumList.innerHTML = "";
    list.forEach(u => {
        premiumList.innerHTML += `<li>${u}</li>`;
    });
}


// ADD PREMIUM
async function addPremiumUser() {
    let id = premiumAddId.value.trim();

    let res = await fetch("/admin/premium/add", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id })
    });

    showToast("Added");
    loadPremium();
}


// REMOVE PREMIUM
async function removePremiumUser() {
    let id = premiumRemoveId.value.trim();

    let res = await fetch("/admin/premium/remove", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ id })
    });

    showToast("Removed");
    loadPremium();
}


// SAVE SETTINGS
async function saveSettings() {
    let data = {
        header: headerInput.value,
        footer: footerInput.value,
        inactiveDays: Number(inactiveDays.value)
    };

    await fetch("/admin/settings", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data)
    });

    showToast("Settings Updated");
}


// INIT
loadDashboard();
loadUsers();
loadInactive();
loadMessages();
loadPremium();
