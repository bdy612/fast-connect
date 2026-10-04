// Accounts: sign up / log in against the Google Drive user database (same accounts as the desktop app).
// The browser talks to the Apps Script backend in backend/Code.gs; its URL is set in config.js.
// The backend returns a signed session token; nothing here is trusted by the server without it.

// Never show these pages inside another site's frame (stops clickjacking)
if (window.top !== window.self) {
    document.documentElement.style.display = 'none';
}

const SESSION_KEY = 'fcSession';
let session = null;   // { token, user: { username, real_name, user_number } }

// Passwords travel to this URL, so it must be https (or the local test server, backend/dev_server.js)
const SAFE_API_URL = /^(https:\/\/|http:\/\/(localhost|127\.0\.0\.1)(:\d+)?\/)/;

async function callAccountsApi(payload) {
    if (typeof ACCOUNTS_API_URL === 'undefined' || !SAFE_API_URL.test(ACCOUNTS_API_URL)) {
        return { ok: false, error: 'Accounts are not set up on this site yet.' };
    }
    try {
        // text/plain keeps this a "simple" request, which Apps Script web apps accept cross-origin
        const response = await fetch(ACCOUNTS_API_URL, {
            method: 'POST',
            headers: { 'Content-Type': 'text/plain;charset=utf-8' },
            body: JSON.stringify(payload),
            credentials: 'omit',
            referrerPolicy: 'no-referrer',
        });
        return await response.json();
    } catch (error) {
        return { ok: false, offline: true, error: 'Could not reach the server. Check your connection and try again.' };
    }
}

function saveSession(result) {
    session = { token: result.token, user: result.user };
    try {
        localStorage.setItem(SESSION_KEY, JSON.stringify(session));
    } catch (e) { /* storage blocked - stays signed in for this page only */ }
}

function clearSession() {
    session = null;
    try {
        localStorage.removeItem(SESSION_KEY);
        localStorage.removeItem('currentUser');   // left over from the old accounts.json system
    } catch (e) { /* nothing stored */ }
}

function getSession() {
    if (!session) {
        try {
            const stored = JSON.parse(localStorage.getItem(SESSION_KEY));
            if (stored && typeof stored.token === 'string' && stored.user && typeof stored.user.username === 'string') {
                session = stored;
            }
        } catch (e) { /* no stored session */ }
    }
    return session;
}

// Is there a saved session? (For page layout only - the server decides what is really allowed.)
function checkAuth() {
    return getSession() !== null;
}

function getCurrentUser() {
    return getSession() ? getSession().user : null;
}

// Ask the server whether the saved session is still valid. Returns the user, or null if signed out.
async function verifySession() {
    if (!getSession()) return null;
    const result = await callAccountsApi({ action: 'me', token: session.token });
    if (result.ok) {
        session.user = result.user;
        return result.user;
    }
    if (result.offline) return session.user;   // can't check right now; keep showing the saved details
    clearSession();
    return null;
}

async function login(username, password) {
    const result = await callAccountsApi({ action: 'login', username, password });
    if (result.ok) saveSession(result);
    return { success: !!result.ok, user: result.user, message: result.error };
}

async function signup(username, realName, password) {
    const result = await callAccountsApi({ action: 'signup', username, real_name: realName, password });
    if (result.ok) saveSession(result);
    return { success: !!result.ok, user: result.user, message: result.error };
}

function logout() {
    clearSession();
    window.location.href = 'login.html';
}

// Same rules as the backend and the desktop app
function validateUsername(username) {
    return /^[A-Za-z0-9_.-]{3,32}$/.test(username);
}

function validatePassword(password) {
    return password.length >= 6 && password.length <= 128;
}
