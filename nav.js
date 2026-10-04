// Public pages: show "Account" instead of "Sign In" when someone is signed in
document.addEventListener('DOMContentLoaded', () => {
    const button = document.getElementById('navAuthButton');
    if (button && checkAuth()) {
        button.href = 'account.html';
        button.innerHTML = '<i class="fas fa-user"></i> Account';
    }
});
