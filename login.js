// Login page
if (checkAuth()) {
    window.location.href = 'account.html';
}

document.getElementById('loginForm').addEventListener('submit', async event => {
    event.preventDefault();

    const username = document.getElementById('username').value.trim();
    const password = document.getElementById('password').value;
    const errorDiv = document.getElementById('errorMessage');
    const successDiv = document.getElementById('successMessage');
    const button = document.getElementById('submitButton');

    errorDiv.style.display = 'none';
    successDiv.style.display = 'none';

    button.disabled = true;
    const label = button.innerHTML;
    button.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Logging in...';
    const result = await login(username, password);
    button.disabled = false;
    button.innerHTML = label;

    if (result.success) {
        successDiv.textContent = 'Login successful! Redirecting...';
        successDiv.style.display = 'block';
        setTimeout(() => {
            window.location.href = 'account.html';
        }, 1000);
    } else {
        errorDiv.textContent = result.message;
        errorDiv.style.display = 'block';
    }
});
