# Changelog

## 1.6.0 / panel 1.3.45
- Registration has a clear owner control in مدیریت: open it for new signups, or close it so only existing accounts can log in.

## 1.6.0 / panel 1.3.44
- Main tabs follow the workflow order: status, servers, tunnels, relays, panels, outbound, monitor, guides, orders, wallet, support, management.

## 1.6.0 / panel 1.3.43
- With a Let's Encrypt certificate on port 443, HTTP on port 80 permanently redirects to the HTTPS panel URL so browsers no longer show "Not secure".
- Visiting `https://domain/` redirects to the panel entry path when the SSL domain is configured.

## 1.6.0 / panel 1.3.42
- Failed paid tunnel deploys refund the wallet charge; deposit approval is transactional.
- Order fulfill lets the owner supply SSH secrets and mode options (Spoof, DNSTT, Xray, ICMP).
- Panel SSH and the web terminal keep jojonet commands out of bash history with the same scrub patterns as the CLI.

## 1.6.0 / panel 1.3.41
- Tunnel type selection is a searchable technical picker with grouped protocols, stack badges, and a clear deployment brief.

## 1.6.0 / panel 1.3.40
- The owner can edit each guide article in the panel, including font family, size, color, and step text, and can reset it to the default.

## 1.6.0 / panel 1.3.39
- The panel has an آموزش tab: a right-aligned, step-by-step guide for every tunnel type, then the VPN panel, Reality outbound, and relay.

## 1.6.0 / panel 1.3.38
- An update reloads the panel process without closing the listen port, and the page retries a short network gap instead of looking disconnected.

## 1.6.0 / panel 1.3.37
- The owner can issue a Let's Encrypt certificate from the panel by entering a domain. The secure panel address is shown in a copyable card.

## 1.6.0 / panel 1.3.36
- The first page is an account overview: remaining subscription time, service health, and usage limits, for both the owner and customers.

## 1.6.0 / panel 1.3.35
- Outbound and routing JSON open in an editor on the page. Edits are what copy and download use, and the JSON status stays visible while typing.

## 1.6.0 / panel 1.3.34
- The outbound tab gives a Freedom JSON file that sends 3x-ui traffic out the tunnel IP, plus a matching VLESS Reality client config, 3x-ui inbound file, and routing rule. Keys stay the same across reloads.

## 1.6.0 / panel 1.3.33
- Tunnel cards keep each interface name, address, and timestamp on its own line, and the actions sit in an even grid.

## 1.6.0 / panel 1.3.32
- The header brand is only the mark and the name. Version, entry path, and the Telegram handle are no longer beside the title.

## 1.6.0 / panel 1.3.31
- The header account control is a menu: profile, username, password, and logout. The username text in the bar is a mark, and the signed-in account can rename itself.

## 1.6.0 / panel 1.3.30
- The live-scan note explains an unregistered tunnel in plain language. The badge says «ثبت‌نشده» instead of «یتیم».

## 1.6.0 / panel 1.3.29
- Customer cards show usage as three figures, permissions as separate on/off chips, and expiry on its own row.

## 1.6.0 / panel 1.3.28
- The panel no longer binds port 80 or 443 itself. systemd owns the listen socket and passes it to the locked-down service, so a privileged port stays up across updates.
- `jojonet-panel update` waits until the secret URL answers over HTTPS. If it does not, the previous unit, socket, and env are restored and the old service is started again.
- The owner can save port 80 or 443 from the مدیریت tab. The root helper rewrites the systemd socket and restarts it.

## 1.6.0 / panel 1.3.27
- Panel on port 80 or 443 can bind again. The service unit no longer sets NoNewPrivileges together with the low-port capability.
- Installer no longer aborts with `$2: unbound variable` while reading the saved panel path.
- Side terminals can be dragged by the title bar and resized from the corner or the edges. The size and place are remembered in this browser.

## 1.6.0 / panel 1.3.26
- Installer keeps an admin-chosen port across updates. `--port` still overrides it. Docs show the fixed entry path. Saving the same address no longer reloads the panel.

## 1.6.0 / panel 1.3.25
- Panel entry path is fixed at `/jojonet-panel-entry` (old random paths are replaced). The owner can change the path and the port from the مدیریت tab; the service restarts onto the new address.

## 1.6.0 / panel 1.3.24
- Panel is not served on the bare IP. A secret path (`JOJONET_PANEL_PATH`, or a random path saved in `web.path`) is required; anything else is an empty 404.
- Login lockout also counts per username. Request bodies over 1 MB are rejected. Extra browser isolation headers; public health no longer returns the version.
- Side terminals sit on their own edges, beside the lists: the left terminal opens on the left, the right terminal on the right.

## 1.6.0 / panel 1.3.23
- **Live tunnels on servers**: panel tab scans each host via `jojonet --list-tunnels --json`, matches panel DB or marks orphans, full delete, and reboot persistence (`--enable-boot`) per server or all.
- **Fix**: boot restore script starts DNSTT/ICMP with `jojonet-stream@NAME` (was wrongly `jojonet@`).
- CLI: `sudo jojonet --enable-boot` and `sudo jojonet --list-tunnels --json`.
- README install path is one command (`install.sh`); zip/`setup.sh` moved to optional/advanced.

## 1.6.0 / panel 1.3.22
- Topbar brand cleaned up: single panel version, Telegram @B_KHANEMAN, animated title.

## 1.6.0 / panel 1.3.21
- Content width slightly reduced; side terminals a bit larger for better balance.

## 1.6.0 / panel 1.3.20
- Main tab bar is centered.

## 1.6.0 / panel 1.3.19
- Larger, bolder UI type on the wider layout without breaking cards or grids.

## 1.6.0 / panel 1.3.18
- Day theme: terminal server dropdown IPs are readable. Side terminals stick under the topbar.

## 1.6.0 / panel 1.3.17
- Wider page content, cleaner topbar/tabs alignment, denser type scale, and tighter responsive breakpoints.

## 1.6.0 / panel 1.3.16
- VPN panels tab layout fixed: three install cards in one even row, clearer server field spacing.

## 1.6.0 / panel 1.3.15
- Side terminals sit under the header/tabs, have a close button, and no longer cover the top bar.

## 1.6.0 / panel 1.3.14
- Job report modal (test / install / deploy) is sectioned: summary cards, numbered steps, and readable grouped log cards.

## 1.6.0 / panel 1.3.13
- Page zoom is the original 100%. Side terminals overlay the page and no longer shrink the cards.

## 1.6.0 / panel 1.3.12
- Default page zoom is 67% again so the original card layout stays intact.

## 1.6.0 / panel 1.3.11
- Default page zoom is 100% again (the 67% shrink is gone).

## 1.6.0 / panel 1.3.10
- Owner can hide the main-page terminals for everyone, or turn them off for one customer.

## 1.6.0 / panel 1.3.9
- Two hacker-style SSH terminals on the left and right of the main page, plus default UI zoom of 67%.

## 1.6.0 / panel 1.3.8
- Jobs / install monitor restyled as a dark ops console (terminal chrome, live HUD, phosphor log feed).

## 1.6.0 / panel 1.3.7
- Owner header no longer shows the «مالک پنل» label under the username.

## 1.6.0 / panel 1.3.6
- Panel text uses Vazirmatn Medium/Bold and stronger muted contrast so labels and descriptions stay readable.

## 1.6.0 / panel 1.3.5
- Default theme is **شب**. Day theme uses an icy-white page, clearer contrast, and larger Vazirmatn type. Choice is stored as `jojonet-theme-2`.

## 1.6.0 / panel 1.3.4
- **Fix**: existing panel DBs still had a global unique `relays.name`. Two customers could not reuse the same relay name. Migration rebuilds `relays` and keeps uniqueness per owner.

## 1.6.0 / panel 1.3.3
- New **اوتباند** tab: after a tunnel is up, shows which server should get the X-UI / 3x-ui Freedom outbound and the exact Send Through / tag values (copy buttons). Tunnel cards have a shortcut.

## 1.6.0 / panel 1.3.2
- Tunnel form no longer offers the «سرور خارج / ایران‌اکسس» direction; new tunnels go ایران → خارج. Direct DNSTT/ICMP (checkbox) is unchanged.

## 1.6.0 / panel 1.3.1
- **Theme picker**: keep the current navy theme, plus selectable **روز** (white page / black text) and **شب** (black page / white text). Choice is saved in the browser.

## 1.6.0 / panel 1.3.0
- **Web panel 1.3.0**: multi-tenant accounts. Existing `admin` stays the owner. Owner creates customers with subscription days, server/tunnel/relay quotas, and VPN/relay/OS-update flags. Each customer sees only their own resources; owner sees all with an owner badge. License key `JN1` is no longer required to run `jojonet` (`--activate` / `--license` remain as no-op-safe flags). `private.pem` is not shipped in the customer zip.

## 1.6.0
- **DNSTT** (`--dnstt`): DNS tunnel with official bamsoftware dnstt (`v1.20260501.0`), Noise_NK, DoH/DoT/UDP on Iran, `dnstt-server` on Kharej UDP/53 (or 5300 + iptables REDIRECT). SOCKS auth from `dnstt.auth`. One DNSTT per server. Domain NS must point at Kharej (`JOJONET_DNSTT_DOMAIN`). Menu 28. Unit `jojonet-stream@NAME`.
- **ICMP / pingtunnel** (`--icmp`): standalone ICMP echo tunnel (pingtunnel **2.10**, sha256-pinned, ChaCha20). Distinct from `--wg-icmp` (udp2raw + WireGuard). One ICMP tunnel per host (raw socket). Kernel `icmp_echo_ignore_all=1` while running, restored on stop. Menu 29.
- **Monthly license**: JojoNet runs only with a signed `JN1` subscription key (`--activate` / `--license`). Buy on the web shop with crypto (USDT / BTC / TON / TRX); the seller confirms the TXID and the shop issues a 30-day key. Shop: `license-shop/install-shop.sh`. Set `JOJONET_SHOP_URL` before shipping.
- **Xray Dokodemo-door** (`--dokodemo` / `--doko`) and **Xray Reverse** (`--xray-reverse`): VLESS over tcp/ws/grpc, shared `xray.uuid`, unit `jojonet-xray@NAME`. Dokodemo: Iran dials Kharej. Reverse: Kharej dials the Iran portal — for Iran-access servers. Env: `JOJONET_XRAY_NET`, `JOJONET_XRAY_CTRL_PORT`, `JOJONET_FWD_PORTS`. Menu 22 / 23.
- **IPv6 tunnels**: 6to4 SIT (`--6to4` / `--sit`, ULA `fd6a:…::1/::2`), GRE6 (`--gre6`, overlay `172.22`), IPIP6 (`--ipip6`, overlay `172.23`). One v6 overlay per peer. Unit `jojonet-v6@NAME`. Menu 24.
- **Single-server relays** (hiddify-relay style): iptables DNAT, GOST, HAProxy (TCP only), Socat, Xray dokodemo with traffic stats. CLI `--relay ENGINE DEST PORTS [tcp|udp|both] [NAME]`, `--relay-list`, `--relay-remove`, `--relay-stats`. Units `jojonet-relay@` / `jojonet-relay-nat@`. Menu 25.
- **Server tools**: set DNS, ping test, OS package update. Menu 26 / `--dns` / `--ping-test` / `--update-server`.
- **Direct Kharej (no Iran VPS)**: DNSTT and ICMP can run on a single foreign server (`--direct dnstt|icmp`, omit peer IP, menu 30). Users run `dnstt-client` / `pingtunnel` on their own device; client card is saved to `/etc/jojonet/direct/`. Relays can be built on Iran **or** Kharej. Panel 1.2.1: checkbox «فقط سرور خارج» and relays on any server.
- **3x-ui / X-UI (separate section)**: official MHSanaei 3x-ui installer (GitHub + mirrors, `XUI_NONINTERACTIVE=1`). Menu 31, `jojonet --xui-install|--xui-status|--xui-uninstall`, `sudo bash setup.sh xui`. Not a JojoNet tunnel.
- **PasarGuard (one-click)**: official installer (SQLite, `--no-ssl`), GitHub + mirrors. Menu 31, `jojonet --pasarguard-install|--pasarguard-status`, `sudo bash setup.sh pasarguard`.
- **X-UI classic (Alireza)**: official `alireza0/x-ui` next to 3x-ui Sanaei. `--xui-classic-install`, `setup.sh xui-classic`. They share `x-ui.service` and cannot run together.
- **Web panel 1.2.4**: tab «پنل‌ها» asks for confirm, then shows a live install monitor. Cards: 3x-ui سنایی، X-UI اصلی، پاسارگارد.
- **VPN panel login**: after one-click install, JojoNet prints URL / username / password (or PasarGuard temp key). CLI `jojonet --vpn-panel-creds`, menu 31 item 10, saved at `/etc/jojonet/vpn-panel.creds`. Web panel 1.2.5 shows a dedicated credentials card with copy buttons.
- **Web panel 1.2.6**: install/job monitor turns raw logs into a Persian step-by-step report (noise hidden; technical dump behind «جزئیات فنی»).
- **VPN panel already-installed check**: before install, JojoNet detects 3x-ui / X-UI classic / PasarGuard (even if the service is stopped). Same panel is not reinstalled; a Persian message is shown. Conflicting X-UI flavors are refused. CLI `jojonet --vpn-panel-check`, menu 31 item 11. Web panel 1.2.7 asks first and can show existing login.
- **Fix**: `--list-tunnels` with zero tunnels no longer trips the ERR trap. TUN/TCP and Rathole auto-install `unzip`. LocalTun download uses GitHub mirrors + pinned amd64 sha256. VXLAN `srcport` is a MIN/MAX pair (Ubuntu 26 iproute2). Menu `press_enter` typos restored.
- **Fix**: WireGuard on Ubuntu 24+/26 — AppArmor `wg` profile only allows keys under `/etc/wireguard/`; runner copies the private key there before `wg set`.
- **Web panel 1.2.2**: choose whether users connect on Iran (tunnel ایران → خارج) or Kharej (خارج → ایران / ایران‌اکسس). Listen/DNAT follows that side.
- **Web panel 1.2.1**: Direct DNSTT/ICMP (one Kharej only) and relays on Iran or Kharej.
- **Web panel 1.2.0**: Xray and v6 modes (one v6 tunnel per Iran/Kharej pair), Relays tab, DNS / ping / OS-update buttons on each server card. DNSTT and ICMP modes (one of each per host).
- Uninstall stops xray/v6/relay/stream units and can remove the `xray`, `gost`, `dnstt-server`, `dnstt-client` and `pingtunnel` binaries.

## 1.5.9
- **New WireGuard over ICMP** (`--wg-icmp`) and **WireGuard over FakeTCP** (`--wg-faketcp`): WireGuard is carried by udp2raw 20230206.0 (sha256-pinned) inside ICMP echo or fake TCP segments, AES-128-CBC + HMAC-SHA1 with a shared `udp2raw.key`. Overlays `10.67.X.0/30` / `10.68.X.0/30`, MTU 1200, menu item 21.
- udp2raw runs as the sidecar `jojonet-u2r@NAME.service` (bound to `jojonet-wg@NAME`); peer-scoped iptables DROP rules tagged `jojonet-u2r-NAME` are added on start and removed on stop. The carrier port comes from the server pair (`JOJONET_WG_OBFS_PORT` overrides it); WireGuard listens on carrier port ± 10000.
- Healthcheck, repair, change-peer, boot restore, delete and uninstall all handle the udp2raw sidecar.
- Deploy refuses a udp2raw port that another program already holds, and treats a crash-looping udp2raw (systemd restarts during start-up) as a failed start.
- **Fix**: running without a terminal/`TERM` (cron, SSH automation) no longer aborts every mode at `clear`; a failing CLI command exits with its code without the misleading "Unexpected error" line.
- **New `--spoof-install`**: installs only the spoof binary (used by the panel's readiness test).
- **Web panel**: `wg_icmp` / `wg_faketcp` modes; **Spoof readiness check** (spoof tester in both directions over the chosen transports) before building a Spoof tunnel, plus a standalone "check servers" button (the test opens a temporary, tagged iptables rule for the peer's spoof IP and removes exactly that rule); valid existing WireGuard keys are reused so sibling WireGuard tunnels keep working.

### Web panel 1.1.0
- **Domain + trusted certificate**: `--domain NAME [--email ADDR]` gets a Let's Encrypt ECDSA certificate (certbot, HTTP-01 standalone) with a renewal hook that installs the new certificate and restarts the panel; `--no-domain` goes back to self-signed. `jojonet-panel url` shows the domain.
- **Speed**: gzip for pages, assets and API (not for SSE or responses carrying the CSRF token); versioned assets cached for a year (`immutable`), revalidated with ETag otherwise; asset hashing and `index.html` cached in memory; 65 s keep-alive so the browser reuses its TLS connection; uvloop + httptools when wheels are available.
- **Speed**: job log lines are written in batches (every 0.5 s or 200 lines) instead of one SQLite rewrite per line, so chatty installs no longer stall the panel; SQLite `synchronous=NORMAL` under WAL; tunnel list without a per-row server query.

## 1.5.8
- **Spoof Tunnel, fully non-interactive**: `JOJONET_SPOOF_IP`, `JOJONET_SPOOF_PEER_IP`, `JOJONET_SPOOF_LISTEN`, `JOJONET_SPOOF_FORWARD`, `JOJONET_SPOOF_REMOTE_PORT` / `_RECV_PORT`, `JOJONET_SPOOF_UP_TRANSPORT` / `_DOWN_TRANSPORT`. The same values on both sides give a matching pair.
- **Spoof**: IPv4 validation for spoof/peer/server IPs, a real `restart` on reconfigure, non-zero exit (with journal) if the service does not come up.
- **Spoof**: when UFW is active, opens the receive port (only from the peer's spoof IP) and the public Iran UDP listen port; the recorded rules are removed on reconfigure/remove.
- **New `--spoof-remove`**: stops/disables the service and removes its unit, config and UFW rule (binary kept).
- **Web panel**: Spoof Tunnel mode (deploy, verify with an end-to-end UDP probe, delete).

## 1.5.7
- **Key sync fix**: TUN/TCP and Paqet keys are synced into the shared `pair_<subnet>` dir on both servers (was the wrong remote path).
- **WireGuard**: pushes our public key as the peer's `wg_peer_public.key`, pulls the peer's key, drops a self-copy placeholder.
- **HY2 / Rathole / Wstunnel**: one `ensure_shared_secret` helper; hints go to stderr (no more polluted secrets).
- **`--export-keys` / `--import-keys`**: whitelisted files only, safe temp extraction (no owners/perms/symlinks), accept `SUBNET_ID` for TUN/TCP/Paqet.
- **New `--delete <NAME>`**: full non-interactive teardown; the menu delete and rollback use the same `teardown_tunnel_runtime`.
- **Fixes**: anchored `pkill` (deleting one wstunnel no longer kills the others); default interface detection without a gateway (`dev`/`src` tokens); `restart_tunnel` exit code propagated; three same-line `local` bugs; GRE name suggestion; invalid `JOJONET_HY2_HOP_RANGE` falls back with a warning; tunnel name / line-count validation for `--health` / `--logs`; `install.sh` no longer appends duplicate checksum lines.
- **Web panel** (Persian): `sudo bash panel/install-panel.sh`.

## 1.5.6
- **Auto deploy (type + peer IP)**: after choosing tunnel type, only ask for the other server's IP; ports/hop/TLS/forward use smart defaults.
- Menu asks once: Use automatic defaults? [Y/n] (default **Y**). CLI with peer IP skips the question.
- Env: JOJONET_AUTO=1 (force auto) / JOJONET_AUTO=0 (full advanced prompts). Other JOJONET_* overrides still apply.
- **HY2 auto**: Hop Port ON (20000-50000 / 30s); TLS self-signed unless JOJONET_HY2_DOMAIN (ACME) or TLS env set.
- **WG / Rathole / Wstunnel / TUN-TCP / Paqet / VXLAN**: default ports + auto Iran forward port.
- Spoof/QS: still ask required fields (spoof IPs / DNS domains / password); optional knobs use defaults in auto mode.
- **Fixes**: Wstunnel runner accepts `RatholeToml` in instance conf (was wrongly `WstunnelToml` → Bad config); pairing card uses `--wstunnel`; repair rebuilds HY2 server YAML missing `tls`/`acme`.


## 1.5.5
- **Spoof Tunnel v3.1.0-beta.0** به‌صورت standalone single-instance:
  - ایران = `local`، خارج = `remote`
  - دانلود `amd64`/`arm64` با mirror و بررسی اجباری `checksums.txt` رسمی upstream
  - کانفیگ JSON امن، سرویس `jojonet-spoof.service`
  - پشتیبانی `spoof_ip` یا `spoof_ip_file` و transportهای TCP/UDP/ICMP/ICMPv6
  - CLI: `--spoof-tunnel` / `--spoof`
  - هشدار صریح: هر دو provider باید source-IP spoofing را پشتیبانی کنند.
- **QS-Tunnel** روی commit `4497146ccc1e70ad510b68db5a483e0395782df4`:
  - ایران = client، خارج = server، mode=`1-1`
  - Python 3.12+، venv مدیریت‌شده، `aiohttp` + `numba`
  - آرایه‌های comma-separated با JSON escaping، سرویس `jojonet-qs.service`
  - CLI: `--qs-tunnel` / `--qs`
  - فقط UDP forwarder؛ نیازمند HY2/WG/xhttp-h3 و تابع محدودیت DNS/upload upstream.
- نمایش وضعیت سرویس‌های standalone در `--status`، بازسازی unitها در refresh/repair و cleanup محدود به فایل‌های مدیریت‌شده در uninstall.

## 1.5.4
- **Hysteria2 TLS روی دامنه شخصی** — انتخاب حالت گواهی موقع ساخت تانل:
  - `self-signed` (پیش‌فرض، بدون دامنه، `insecure: true`)
  - `ACME` خودکار Let's Encrypt روی دامنه شخصی (رکورد A → سرور خارج) + باز کردن TCP 80/443
  - `custom` گواهی دستی: `cert.pem` + `key.pem`
- سازگار کامل با **Hop Port** (رنج UDP روی داده، چلنج گواهی روی TCP جدا)
- کلاینت ایران با گواهی واقعی → `insecure: false` و SNI = دامنه
- Env: `JOJONET_HY2_TLS_MODE` / `JOJONET_HY2_DOMAIN` / `JOJONET_HY2_ACME_EMAIL` / `JOJONET_HY2_CERT` / `JOJONET_HY2_KEY`
- فیکس باگ `unbound variable` (`ws_cmd`) هنگام ساخت تانل‌های غیر-Wstunnel

## 1.5.3
- **Wstunnel Reverse WebSocket tunnel** (alternative to Rathole over WebSocket)
  - Iran = wstunnel **SERVER** (`--restrict-http-upgrade-path-prefix`)
  - Kharej = wstunnel **CLIENT** with `-R tcp://0.0.0.0:PORT:127.0.0.1:PORT`
  - Menu item 8 + CLI: `sudo jojonet --wstunnel <PEER_IP>` (alias `--ws`)
  - Default control port **8080**, forward **443**
  - Token: `$keydir/wstunnel.token` | runtime: `$WSTUNNEL_CONFIG_DIR/${name}.cmd.sh`
  - Binary pin: wstunnel **v10.1.9** (GitHub + ghproxy mirrors)
  - Repair, firewall, rollback, uninstall wired like Rathole

## 1.5.2
- **دیباگ Rathole**: repair برای toml گم‌شده/کهنه، فایروال UFW/firewalld روی ایران، دانلود با mirrorهای ghproxy
- Pre-flight: اعتبارسنجی control port + هشدار پورت فوروارد
- Rollback تمیز: kill رات‌هول + حذف toml/yaml
- Uninstall کامل برای WG / HY2 / Rathole (unit + runner + باینری)
- راهنمای `--export-keys` / `--import-keys` اگر sync توکن با SSH نشد

## 1.5.1
- **راهنما**: اعلام تغییرات هر نسخه در `sudo jojonet --help` و `sudo jojonet --changelog`
- بعد از `--update` خلاصهٔ What's new نمایش داده می‌شود
- README به‌روز با Rathole و تاریخچه نسخه‌ها

## 1.5.0
- **Rathole Reverse TCP tunnel** (alternative to GRE when UDP/GRE is blocked)
  - Iran = rathole **SERVER** (users hit public ports)
  - Kharej = rathole **CLIENT** (dials Iran control port, exposes local panel)
  - Menu item 7 + CLI: `sudo jojonet --rathole <PEER_IP>`
  - Asks for control port + forward ports at setup
  - Token sync via SSH/SCP (same pattern as HY2/Paqet)

## 1.4.3
- **Hysteria2 Hop Port hardened / debug pass**
  - Require `nft` or `iptables` on Kharej before hop deploy (hard fail)
  - Auto-open UDP hop range in UFW / firewalld when active
  - Pre-flight: large-range warning, first-port busy warning
  - Random hop interval option (`15s-45s` → minHopInterval/maxHopInterval)
  - Repair rebuilds stale YAML if hop range/interval missing
  - Runner refuses start without firewall tools when hop enabled
  - Healthcheck + pairing card show hop status
  - Env: `JOJONET_HY2_HOP_RANGE`, `JOJONET_HY2_HOP_INTERVAL`
  - Fix interval normalize under `set -e` (`((sec<5))` edge case)

## 1.4.2
- **Hysteria2 Hop Port** (native): UDP port range hopping so traffic is not stuck on one filtered port
  - Prompt at setup (default range `20000-50000`, interval `30s`)
  - Kharej: `listen: :START-END` (HY2 auto DNAT via nft/iptables)
  - Iran: `server: peer:START-END` + `transport.udp.hopInterval`
  - Stored as `HyHopRange` / `HyHopInterval` in instance config

## 1.4.1
- **All tunnel modes**: auto forward port on Iran (not only GRE)
- **Pairing card**: correct CLI per mode (`--wg`, `--tun-tcp`, …) + subnet prefix per mode
- **Healthcheck**: Hysteria2 process check; ping for TUN/TCP and WireGuard
- **Pre-flight**: forward port warning for all Iran modes

## 1.4.0
- **Pre-flight check** before deploy (wg0 port, GRETun, overlay IP conflicts)
- **Auto forward port** on Iran when 443 is taken (8443, 2053, …)
- **`sudo jojonet --status`** — ping latency + forward reachability + tunnel summary
- **Pairing card** after successful deploy (exact peer command + subnet ID)
- **`--import-gretun`** migrate manual GRETun into JojoNet
- **`--export-config` / `--import-config`** backup & restore all tunnels
- **`--logs <NAME>`** tunnel journal from CLI
- **Webhook** notify on tunnel up/down (`JOJONET_WEBHOOK_URL`)
- Menu: backup/restore + import GRETun

## 1.3.1
- **Multi-tunnel GRE**: each peer pair gets its own subnet (`172.20.X.1` Kharej / `.2` Iran), auto from IP pair hash
- Interface names include subnet hint (`gr…b11`) — unique per peer + subnet
- Second tunnel on same server no longer reuses `172.20.10.2` if another peer already owns that subnet

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
