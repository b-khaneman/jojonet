#!/usr/bin/env bash
# JOJONET uninstall — removes units, runners, configs, optional binaries
set -Eeo pipefail
(( EUID == 0 )) || { echo "Run as root"; exit 1; }

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
log(){ echo -e "${GREEN}[+]${NC} $*"; }
warn(){ echo -e "${YELLOW}[!]${NC} $*"; }

read -r -p "Remove ALL JojoNet tunnels, configs, and services? [y/N]: " c
c=$(echo "$c" | tr '[:upper:]' '[:lower:]')
[[ "$c" == "y" ]] || { echo "Cancelled."; exit 0; }

shopt -s nullglob
for conf in /etc/jojonet/instances/*.conf; do
    name=$(grep -E '^Name=' "$conf" 2>/dev/null | head -1 | cut -d'"' -f2 || true)
    [[ -n "$name" ]] || continue
    for unit in "jojonet-u2r@${name}.service" \
                "jojonet@${name}.service" "jojonet-tcptun@${name}.service" \
                "jojonet-paqet@${name}.service" "jojonet-vxlan@${name}.service" \
                "jojonet-wg@${name}.service" "jojonet-hy2@${name}.service" \
                "jojonet-rathole@${name}.service" "jojonet-wstunnel@${name}.service" \
                "jojonet-xray@${name}.service" "jojonet-v6@${name}.service" \
                "jojonet-stream@${name}.service"; do
        systemctl stop "$unit" 2>/dev/null || true
        systemctl disable "$unit" 2>/dev/null || true
    done
    [[ -x /usr/local/bin/jojonet-run-u2r.sh ]] && /usr/local/bin/jojonet-run-u2r.sh stop "$name" >/dev/null 2>&1 || true
    [[ -x /usr/local/bin/jojonet-run-stream.sh ]] && /usr/local/bin/jojonet-run-stream.sh stop "$conf" >/dev/null 2>&1 || true
    ip link delete "$name" 2>/dev/null || true
    nft delete table ip "jojonet_$name" 2>/dev/null || true
done
for conf in /etc/jojonet/relays/*.conf; do
    name="${conf##*/}"
    name="${name%.conf}"
    [[ -n "$name" ]] || continue
    for unit in "jojonet-relay@${name}.service" "jojonet-relay-nat@${name}.service"; do
        systemctl stop "$unit" 2>/dev/null || true
        systemctl disable "$unit" 2>/dev/null || true
    done
    [[ -x /usr/local/bin/jojonet-run-relay.sh ]] && /usr/local/bin/jojonet-run-relay.sh stop "$conf" >/dev/null 2>&1 || true
done
shopt -u nullglob

systemctl stop jojonet-boot.service 2>/dev/null || true
systemctl disable jojonet-boot.service 2>/dev/null || true
for unit in jojonet-spoof.service jojonet-qs.service; do
    systemctl stop "$unit" 2>/dev/null || true
    systemctl disable "$unit" 2>/dev/null || true
done
if [[ -r /etc/jojonet/spoof/ufw.rules ]] && command -v ufw >/dev/null 2>&1; then
    while read -r proto port from; do
        [[ "$proto" =~ ^(tcp|udp)$ && "$port" =~ ^[0-9]{1,5}$ && "$from" =~ ^(any|[0-9.]{7,15})$ ]] || continue
        ufw delete allow proto "$proto" from "$from" to any port "$port" >/dev/null 2>&1 || true
    done < /etc/jojonet/spoof/ufw.rules
fi

rm -f /etc/systemd/system/jojonet@.service \
      /etc/systemd/system/jojonet-tcptun@.service \
      /etc/systemd/system/jojonet-paqet@.service \
      /etc/systemd/system/jojonet-vxlan@.service \
      /etc/systemd/system/jojonet-wg@.service \
      /etc/systemd/system/jojonet-hy2@.service \
      /etc/systemd/system/jojonet-rathole@.service \
      /etc/systemd/system/jojonet-wstunnel@.service \
      /etc/systemd/system/jojonet-u2r@.service \
      /etc/systemd/system/jojonet-xray@.service \
      /etc/systemd/system/jojonet-v6@.service \
      /etc/systemd/system/jojonet-stream@.service \
      /etc/systemd/system/jojonet-relay@.service \
      /etc/systemd/system/jojonet-relay-nat@.service \
      /etc/systemd/system/jojonet-spoof.service \
      /etc/systemd/system/jojonet-qs.service \
      /etc/systemd/system/jojonet-boot.service
rm -f /usr/local/bin/jojonet-run-instance.sh \
      /usr/local/bin/jojonet-run-tuntcp.sh \
      /usr/local/bin/jojonet-run-paqet.sh \
      /usr/local/bin/jojonet-run-vxlan.sh \
      /usr/local/bin/jojonet-run-wg.sh \
      /usr/local/bin/jojonet-run-hy2.sh \
      /usr/local/bin/jojonet-run-rathole.sh \
      /usr/local/bin/jojonet-run-wstunnel.sh \
      /usr/local/bin/jojonet-run-u2r.sh \
      /usr/local/bin/jojonet-run-xray.sh \
      /usr/local/bin/jojonet-run-v6.sh \
      /usr/local/bin/jojonet-run-stream.sh \
      /usr/local/bin/jojonet-run-relay.sh \
      /usr/local/bin/jojonet-boot-restore.sh \
      /usr/local/bin/jojonet \
      /usr/local/bin/jojonet-uninstall
rm -rf /usr/local/share/jojonet
rm -f /etc/sysctl.d/99-jojonet.conf
systemctl daemon-reload 2>/dev/null || true

read -r -p "Also delete /etc/jojonet (keys + configs)? [y/N]: " c2
c2=$(echo "$c2" | tr '[:upper:]' '[:lower:]')
if [[ "$c2" == "y" ]]; then
    rm -rf /etc/jojonet
    log "Removed /etc/jojonet"
else
    warn "Kept /etc/jojonet"
fi

read -r -p "Remove downloaded tun/paqet/hysteria/rathole/wstunnel/spoof/udp2raw/xray/gost/dnstt/pingtunnel binaries and managed QS runtime? [y/N]: " c3
c3=$(echo "$c3" | tr '[:upper:]' '[:lower:]')
if [[ "$c3" == "y" ]]; then
    rm -f /usr/local/bin/tun-server /usr/local/bin/tun-client \
          /usr/local/bin/paqet /usr/local/bin/hysteria /usr/local/bin/rathole \
          /usr/local/bin/wstunnel /usr/local/bin/spoof /usr/local/bin/udp2raw \
          /usr/local/bin/xray /usr/local/bin/gost \
          /usr/local/bin/dnstt-server /usr/local/bin/dnstt-client /usr/local/bin/pingtunnel
    rm -rf /opt/jojonet/qs-tunnel
fi

log "JojoNet uninstalled."
