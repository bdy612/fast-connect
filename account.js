// Account page: only for a session the server still accepts
function showUser(user) {
    // textContent, never innerHTML: these values were typed by a user
    document.getElementById('displayUsername').textContent = user.username;
    document.getElementById('displayRealName').textContent = user.real_name || '-';
    document.getElementById('displayUserNumber').textContent = user.user_number ? `#${user.user_number}` : '-';
}

(async () => {
    if (!checkAuth()) {
        window.location.href = 'login.html';
        return;
    }
    showUser(getCurrentUser());

    const user = await verifySession();
    if (!user) {
        window.location.href = 'login.html';   // deleted account or expired session
        return;
    }
    showUser(user);
})();

document.getElementById('logoutNav').addEventListener('click', event => {
    event.preventDefault();
    logout();
});
document.getElementById('logoutButton').addEventListener('click', logout);
document.getElementById('downloadButton').addEventListener('click', () => {
    window.location.href = 'download.html';
});
