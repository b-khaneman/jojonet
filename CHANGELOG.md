# Changelog

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
