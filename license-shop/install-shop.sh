#!/usr/bin/env bash
# Install the JojoNet monthly license shop (seller server only).
#   sudo bash license-shop/install-shop.sh
set -Eeuo pipefail

(( EUID == 0 )) || { echo "Run as root"; exit 1; }

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
DEST="/opt/jojonet-license-shop"
DATA="/var/lib/jojonet-license-shop"
ENVF="/etc/jojonet-license-shop.env"
SVC="jojonet-license-shop"

command -v python3 >/dev/null || { echo "python3 required"; exit 1; }
command -v openssl >/dev/null || { echo "openssl required"; exit 1; }

install -d -m755 "$DEST" "$DEST/static"
install -d -m700 "$DATA"
install -m644 "$SRC/app.py" "$DEST/app.py"
install -m644 "$SRC/requirements.txt" "$DEST/requirements.txt"
install -m644 "$SRC/static/"* "$DEST/static/"

if [[ ! -f "$DATA/private.pem" ]]; then
    if [[ -f "$SRC/secrets/private.pem" ]]; then
        install -m600 "$SRC/secrets/private.pem" "$DATA/private.pem"
    else
        echo "Copy your Ed25519 private.pem to $DATA/private.pem (must match the public key inside jojonet)."
        exit 1
    fi
fi

python3 -m venv "$DEST/venv"
"$DEST/venv/bin/pip" install -q -r "$DEST/requirements.txt"

if [[ ! -f "$ENVF" ]]; then
    ADMIN_PW="${JOJONET_SHOP_ADMIN_PASSWORD:-$(openssl rand -base64 12)}"
    cat > "$ENVF" <<EOF
JOJONET_SHOP_DATA=$DATA
JOJONET_LICENSE_PRIVATE_KEY=$DATA/private.pem
JOJONET_SHOP_HOST=0.0.0.0
JOJONET_SHOP_PORT=2083
JOJONET_SHOP_ADMIN_PASSWORD=$ADMIN_PW
EOF
    chmod 600 "$ENVF"
    echo "Admin password (save now): $ADMIN_PW"
else
    echo "Keeping existing $ENVF"
fi

if [[ ! -f "$DATA/shop.json" ]]; then
    cat > "$DATA/shop.json" <<'EOF'
{
  "monthly_usd": 15,
  "shop_name": "JojoNet",
  "support": "@B_KHANEMAN",
  "wallets": {
    "USDT-TRC20": "YOUR_USDT_TRC20_ADDRESS",
    "USDT-BEP20": "",
    "BTC": "",
    "TON": "",
    "TRX": ""
  }
}
EOF
    chmod 600 "$DATA/shop.json"
    echo "Edit wallets and price: $DATA/shop.json"
fi

cat > "/etc/systemd/system/${SVC}.service" <<EOF
[Unit]
Description=JojoNet license shop
After=network.target
[Service]
Type=simple
EnvironmentFile=$ENVF
WorkingDirectory=$DEST
ExecStart=$DEST/venv/bin/python $DEST/app.py
Restart=on-failure
User=root
[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable --now "$SVC"
echo "Shop: http://SERVER_IP:2083   Admin: http://SERVER_IP:2083/admin"
echo "Set JOJONET_SHOP_URL in jojonet to this URL before you ship the script."
