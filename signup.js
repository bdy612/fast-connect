// Sign-up page
if (checkAuth()) {
    window.location.href = 'account.html';
}

document.getElementById('signupForm').addEventListener('submit', async event => {
    event.preventDefault();

    const username = document.getElementById('username').value.trim();
    const realName = document.getElementById('realName').value.trim();
    const password = document.getElementById('password').value;
    const confirmPassword = document.getElementById('confirmPassword').value;

    const errorDiv = document.getElementById('errorMessage');
    const successDiv = document.getElementById('successMessage');
    const button = document.getElementById('submitButton');

    errorDiv.style.display = 'none';
    successDiv.style.display = 'none';

    const showError = message => {
        errorDiv.textContent = message;
        errorDiv.style.display = 'block';
    };

    // Same rules as the backend, which checks them again
    if (!validateUsername(username)) {
        return showError('Username must be 3-32 characters: letters, numbers, _ . or -');
    }
    if (!realName) {
        return showError('Please enter your real name');
    }
    if (!validatePassword(password)) {
        return showError('Password must be 6 to 128 characters long');
    }
    if (password !== confirmPassword) {
        return showError('Passwords do not match');
    }

    button.disabled = true;
    const label = button.innerHTML;
    button.innerHTML = '<i class="fas fa-spinner fa-spin"></i> Creating account...';
    const result = await signup(username, realName, password);
    button.disabled = false;
    button.innerHTML = label;

    if (result.success) {
        successDiv.textContent = `Account created! Your user number is #${result.user.user_number}. Redirecting...`;
        successDiv.style.display = 'block';
        setTimeout(() => {
            window.location.href = 'account.html';
        }, 1500);
    } else {
        showError(result.message);
    }
});
