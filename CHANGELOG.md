# Changelog

## 1.3.0
- **GRE matches proven manual setup**: no GRE key, fixed overlay `172.20.10.1/30` (Kharej) ↔ `.2` (Iran)
- MTU default **1436** for GRE
- **Iran**: `iptables` DNAT (tcp/443…) + full `POSTROUTING MASQUERADE` (replaces nftables for GRE)
- Auto-repair migrates old GRE configs to `172.20.10.x`

## 1.2.9
- Fix `ipv4_to_uint` crash (`unbound variable` with set -u)
- WireGuard Kharej: start listen-only when Iran keys not ready yet (no fake self-peer)
- WireGuard: detect UDP port / overlay IP conflicts with clear errors
- Safer rollback on failed tunnel deploy (no ERR trap crash)

## 1.2.8
- **Manage → Change peer IP**: replace tunnel with new Iran/Kharej peer (recomputes subnet, overlay, keys)
- CLI: `sudo jojonet --change-peer <NAME> <NEW_PEER_IP>`

## 1.2.7
- Fix `--list-tunnels --detail` crash (set -e + empty optional fields)
- Detail card shows suggested ping target (peer overlay IP)

## 1.2.6
- **Fix ping between tunnel endpoints**: `ip_forward=1` and `rp_filter=0` on both Iran and Kharej (GRE/VXLAN/WG)
- Global sysctl always applies `rp_filter=0` at runtime (fixes ICMP/GRE drops on eth0)
- Auto-repair overlay IPs in saved configs (`Tun_IP` .1 Kharej / .2 Iran)
- New CLI: `sudo jojonet --fix-tunnels` (repair configs + refresh templates + restart)

## 1.2.5
- Tunnel map uses **Kharej/خارج** instead of Foreign/peer for the foreign server IP

## 1.2.4
- Tunnel map shows explicit **Iran/ایران** and **Foreign/خارج** labels on every public IP
- Quick table columns: Iran IP | Foreign IP (instead of local/peer)

## 1.2.3
- **Tunnel Map**: manage menu shows `Local IP ──[METHOD]──► Peer IP` for every tunnel
- New CLI: `sudo jojonet --list-tunnels` / `--list-tunnels --detail`
- Manage menu: full detail cards, local IP column in table

## 1.2.2
- **Fix GRE/VXLAN/WireGuard tunnel IPs**: foreign server gets `.1`, Iran gets `.2` (aligned with TUN/TCP)
- **Fix ping/healthcheck targets** for foreign role after IP correction
- **Fix WireGuard**: server listens only; client initiates with endpoint
- **Fix VXLAN**: per-interface `rp_filter=0` (GRE-style)
- **Improve role detection**: fallback GeoIP APIs when ip-api is blocked

## 1.2.1
- Self-update runs **before** tunnel init (no more silent fail)
- Multi-mirror download (jsDelivr / gitmirror / ghproxy) for Iran networks
- CLI `--update` no longer asks Y/n
- Installer uses the same mirrors

## 1.2.0
- **Self-update** from GitHub: `sudo jojonet --update` / `--check-update` / menu 13
- Keeps `/etc/jojonet` configs; backs up previous binary

## 1.1.0
- Added **WireGuard** mode (`--wg`) — low latency / high stability
- Added **Hysteria2** mode (`--hy2`) — high speed on filtered paths
- Menu items 5 and 6 for WG / HY2

## 1.0.0 — First official public release
- GRE / TUN-TCP / Paqet / VXLAN
- One-liner install, systemd, healthcheck, uninstall
