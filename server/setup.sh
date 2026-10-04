#!/usr/bin/env bash
# Fast Connect chat server installer for an Ubuntu server (e.g. Oracle Cloud Always Free).
#
#   curl -fsSL https://bdy612.github.io/fast-connect/server/setup.sh | sudo bash
#
# Installs the server to /opt/fastconnect, runs it as a background service that starts on boot,
# and opens TCP port 9999. Run it again to update the server to the latest version.
set -euo pipefail

SITE="https://bdy612.github.io/fast-connect/server"
FILES="fast_connect.py server.py client.py main.py secure_channel.py accounts_api.py run_server_backend.py api_url.txt"
PORT=9999
DIR=/opt/fastconnect

if [ "$(id -u)" -ne 0 ]; then
    echo "Run this with sudo." >&2
    exit 1
fi

echo "== Installing Python =="
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3 python3-venv iptables-persistent >/dev/null

echo "== Downloading Fast Connect server =="
id fastconnect >/dev/null 2>&1 || useradd --system --home "$DIR" --shell /usr/sbin/nologin fastconnect
mkdir -p "$DIR"
for f in $FILES; do
    curl -fsSL "$SITE/$f" -o "$DIR/$f"
done
[ -x "$DIR/venv/bin/python" ] || python3 -m venv "$DIR/venv"
"$DIR/venv/bin/pip" install -q --upgrade pycryptodome
chown -R fastconnect:fastconnect "$DIR"

# Remote control password (same as your control panel's main password); asked only once
ENV_FILE=/etc/fastconnect.env
if [ ! -f "$ENV_FILE" ]; then
    echo
    echo "Choose the remote-control password (use your control panel's MAIN password, 8+ characters)."
    while true; do
        read -rsp "Password: " PW < /dev/tty; echo
        read -rsp "Again:    " PW2 < /dev/tty; echo
        if [ "$PW" != "$PW2" ]; then echo "They don't match, try again."; continue; fi
        if [ "${#PW}" -lt 8 ]; then echo "At least 8 characters, try again."; continue; fi
        break
    done
    printf 'FASTCONNECT_ADMIN_PASSWORD=%s\nPORT=%s\n' "$PW" "$PORT" > "$ENV_FILE"
    chmod 600 "$ENV_FILE"
    unset PW PW2
fi

echo "== Creating the service =="
cat > /etc/systemd/system/fastconnect.service <<EOF
[Unit]
Description=Fast Connect chat server
After=network-online.target
Wants=network-online.target

[Service]
User=fastconnect
WorkingDirectory=$DIR
EnvironmentFile=$ENV_FILE
ExecStart=$DIR/venv/bin/python -u $DIR/run_server_backend.py
Restart=always
RestartSec=3
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
ReadWritePaths=$DIR

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now fastconnect >/dev/null 2>&1
systemctl restart fastconnect

echo "== Opening port $PORT =="
if ! iptables -C INPUT -p tcp --dport "$PORT" -j ACCEPT 2>/dev/null; then
    iptables -I INPUT 6 -p tcp --dport "$PORT" -j ACCEPT 2>/dev/null || iptables -I INPUT -p tcp --dport "$PORT" -j ACCEPT
    netfilter-persistent save >/dev/null 2>&1 || true
fi

sleep 2
echo
systemctl --no-pager --lines=5 status fastconnect || true
echo
echo "Done. Fast Connect server is running on port $PORT."
echo "Public address: $(curl -fsS https://api.ipify.org 2>/dev/null || echo "this-server-ip"):$PORT"
