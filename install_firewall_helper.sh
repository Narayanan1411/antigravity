#!/usr/bin/env bash
# ============================================================
# Guardient Firewall Helper — one-time installation
#
# Run with:  sudo bash "poc Guardient/install_firewall_helper.sh"
#
# What it does:
#   1. Installs guardient_firewall_helper.py to /usr/local/lib/guardient/
#   2. Creates a systemd unit that runs it as root
#   3. Enables + starts the service immediately
#
# After install, the Guardient API can block/unblock hotspot devices
# without any further sudo configuration.
# ============================================================

set -e
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HELPER_SRC="$SCRIPT_DIR/guardient_firewall_helper.py"
INSTALL_DIR="/usr/local/lib/guardient"
UNIT="/etc/systemd/system/guardient-firewall.service"

if [[ $EUID -ne 0 ]]; then
    echo "Run with sudo:  sudo bash \"$0\""
    exit 1
fi

echo "[Install] Creating $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"
cp "$HELPER_SRC" "$INSTALL_DIR/guardient_firewall_helper.py"
chmod 755 "$INSTALL_DIR/guardient_firewall_helper.py"

PYTHON=$(which python3)

echo "[Install] Writing systemd unit..."
cat > "$UNIT" << EOF
[Unit]
Description=Guardient Firewall Helper
Documentation=https://github.com/guardient
After=network.target

[Service]
Type=simple
ExecStart=$PYTHON $INSTALL_DIR/guardient_firewall_helper.py
Restart=always
RestartSec=3
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

echo "[Install] Enabling and starting service..."
systemctl daemon-reload
systemctl enable guardient-firewall
systemctl restart guardient-firewall
sleep 2

if systemctl is-active --quiet guardient-firewall; then
    echo ""
    echo "✔  guardient-firewall service is running"
    echo "   Socket: /run/guardient-fw.sock"
    echo "   Logs:   journalctl -u guardient-firewall -f"
else
    echo "✘  Service failed to start"
    journalctl -u guardient-firewall --no-pager -n 20
    exit 1
fi
