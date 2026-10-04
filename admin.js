// Admin panel: list and delete accounts in the Google Drive user database.
// The admin password is checked by the backend, which returns a 30-minute admin token.
// Neither is ever stored: closing or reloading the page locks the panel again.

let adminToken = '';
let accounts = [];

function showMessage(id, text, type) {
    const box = document.getElementById(id);
    box.className = `admin-message ${type}`;
    box.textContent = text;
}

function clearMessage(id) {
    document.getElementById(id).className = 'admin-message';
}

async function unlock(event) {
    event.preventDefault();
    const button = document.getElementById('unlockButton');
    const input = document.getElementById('adminPassword');
    clearMessage('gateMessage');

    button.disabled = true;
    const result = await callAccountsApi({ action: 'adminLogin', password: input.value });
    button.disabled = false;
    input.value = '';

    if (!result.ok) {
        showMessage('gateMessage', result.error, 'error');
        return;
    }
    adminToken = result.token;
    document.getElementById('gate').hidden = true;
    document.getElementById('panel').hidden = false;
    document.getElementById('lockButton').hidden = false;
    loadAccounts();
}

function lockAdmin(message) {
    adminToken = '';
    accounts = [];
    document.getElementById('accountsBody').innerHTML = '';
    document.getElementById('panel').hidden = true;
    document.getElementById('lockButton').hidden = true;
    document.getElementById('gate').hidden = false;
    clearMessage('panelMessage');
    if (typeof message === 'string') {
        showMessage('gateMessage', message, 'error');
    } else {
        clearMessage('gateMessage');
    }
}

// Every admin request: if the token has expired, go back to the password screen
async function adminCall(payload) {
    const result = await callAccountsApi({ ...payload, token: adminToken });
    if (result.expired) lockAdmin(result.error);
    return result;
}

async function loadAccounts() {
    clearMessage('panelMessage');
    const result = await adminCall({ action: 'adminList' });
    if (!result.ok) {
        if (!result.expired) showMessage('panelMessage', result.error, 'error');
        return;
    }
    accounts = result.users;
    renderAccounts();
}

function renderAccounts() {
    const query = document.getElementById('search').value.trim().toLowerCase();
    const shown = accounts.filter(a =>
        a.username.toLowerCase().includes(query) || (a.real_name || '').toLowerCase().includes(query));

    document.getElementById('accountCount').textContent = `(${accounts.length})`;
    const body = document.getElementById('accountsBody');
    body.innerHTML = '';

    if (shown.length === 0) {
        const row = body.insertRow();
        const cell = row.insertCell();
        cell.colSpan = 4;
        cell.className = 'empty-row';
        cell.textContent = accounts.length ? 'No accounts match your search.' : 'No accounts yet.';
        return;
    }

    for (const account of shown) {
        const row = body.insertRow();
        // textContent, never innerHTML: usernames come from the public sign-up form
        row.insertCell().textContent = account.user_number ? `#${account.user_number}` : '-';
        row.insertCell().textContent = account.username;
        row.insertCell().textContent = account.real_name || '-';

        const button = document.createElement('button');
        button.className = 'admin-button danger';
        button.innerHTML = '<i class="fas fa-trash"></i> Delete';
        button.addEventListener('click', () => deleteAccount(account.username, button));
        row.insertCell().appendChild(button);
    }
}

async function deleteAccount(username, button) {
    if (!confirm(`Delete the account "${username}"?\n\nThey won't be able to log in to the website or the app. This can't be undone.`)) {
        return;
    }
    button.disabled = true;
    const result = await adminCall({ action: 'adminDelete', username });
    if (!result.ok) {
        button.disabled = false;
        if (!result.expired) showMessage('panelMessage', result.error, 'error');
        return;
    }
    accounts = accounts.filter(a => a.username !== username);
    renderAccounts();
    showMessage('panelMessage', `Deleted "${username}".`, 'success');
}

document.getElementById('gateForm').addEventListener('submit', unlock);
document.getElementById('lockButton').addEventListener('click', () => lockAdmin());
document.getElementById('refreshButton').addEventListener('click', loadAccounts);
document.getElementById('search').addEventListener('input', renderAccounts);
