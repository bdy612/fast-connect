// Download page: OS tabs and download feedback
document.addEventListener('DOMContentLoaded', () => {
    const tabs = document.querySelectorAll('.os-tab');
    const panels = document.querySelectorAll('.os-panel');

    const buttons = document.querySelector('.download-buttons');

    function selectOS(os) {
        tabs.forEach(tab => {
            const active = tab.dataset.os === os;
            tab.classList.toggle('active', active);
            tab.setAttribute('aria-selected', active);
        });
        panels.forEach(panel => { panel.hidden = panel.dataset.os !== os; });

        // Main download button for this OS first; the other one becomes a small secondary link
        document.querySelectorAll('.download-btn').forEach(btn => {
            const forThisOS = btn.dataset.for.split(' ').includes(os);
            btn.classList.toggle('download-alt', !forThisOS);
            if (forThisOS) buttons.prepend(btn);
        });
        document.querySelectorAll('.download-meta[data-for]').forEach(meta => {
            meta.hidden = !meta.dataset.for.split(' ').includes(os);
        });
    }

    tabs.forEach(tab => tab.addEventListener('click', () => selectOS(tab.dataset.os)));
    selectOS(detectOS());

    // Point people at the install steps once the download starts
    document.querySelectorAll('.download-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            selectOS(btn.dataset.for.split(' ').includes(detectOS()) ? detectOS() : btn.dataset.for.split(' ')[0]);
            showNotification('Download started! Follow the steps below to install.', 'success');
            setTimeout(() => {
                document.getElementById('install').scrollIntoView({ behavior: 'smooth' });
            }, 600);
        });
    });
});

function detectOS() {
    const platform = (navigator.userAgentData && navigator.userAgentData.platform) || navigator.platform || '';
    const ua = `${platform} ${navigator.userAgent}`.toLowerCase();
    // Phones can't run the desktop app; show the most common desktop steps
    if (/android|iphone|ipad|ipod/.test(ua)) return 'windows';
    if (ua.includes('mac')) return 'mac';
    if (ua.includes('linux') || ua.includes('x11') || ua.includes('cros')) return 'linux';
    return 'windows';
}

function showNotification(message, type = 'info') {
    // Create notification element
    const notification = document.createElement('div');
    notification.className = `notification notification-${type}`;

    let icon = 'info-circle';
    if (type === 'success') icon = 'check-circle';
    if (type === 'error') icon = 'exclamation-circle';

    notification.innerHTML = `
        <i class="fas fa-${icon}"></i>
        <span>${message}</span>
    `;

    // Add to page
    document.body.appendChild(notification);

    // Trigger animation
    setTimeout(() => notification.classList.add('show'), 10);

    // Remove after 4 seconds
    setTimeout(() => {
        notification.classList.remove('show');
        setTimeout(() => notification.remove(), 300);
    }, 4000);
}

// Add notification styles
const style = document.createElement('style');
style.textContent = `
.notification {
    position: fixed;
    top: 20px;
    right: 20px;
    max-width: calc(100vw - 40px);
    background: #1e293b;
    color: #f8fafc;
    padding: 1rem 1.5rem;
    border-radius: 8px;
    box-shadow: 0 10px 30px rgba(0,0,0,0.3);
    display: flex;
    align-items: center;
    gap: 0.75rem;
    transform: translateX(calc(100% + 40px));
    transition: transform 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    z-index: 10000;
    border-left: 4px solid #3b82f6;
}

.notification.show {
    transform: translateX(0);
}

.notification-success {
    border-left-color: #10b981;
}

.notification-error {
    border-left-color: #ef4444;
}

.notification-info {
    border-left-color: #3b82f6;
}

.notification i {
    font-size: 1.25rem;
}

.notification-success i {
    color: #10b981;
}

.notification-error i {
    color: #ef4444;
}

.notification-info i {
    color: #3b82f6;
}
`;
document.head.appendChild(style);
