<div align="center">

# 🏠📡 Home Monitor

**One self-hosted place to watch, alert on and automate your homelab.**

Monitoring, uptime pages, alerts on your phone and SSH automation in a single small app,
with no database server, no containers inside containers and no `pip install`.

![Licence: MIT](https://img.shields.io/badge/licence-MIT-blue)
![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-3776ab)
![Dependencies: stdlib only](https://img.shields.io/badge/dependencies-stdlib%20%2B%20cryptography-success)
![Built with Claude Code](https://img.shields.io/badge/built%20with-Claude%20Code-d97757)

</div>

---

## ✨ Why it exists

Most homelabs end up with one tool for uptime, another for SNMP graphs, another for automation
and a notification bot glued on the side. Each is good at its job, but that is several things to
install, update and back up. Home Monitor brings the everyday parts together in one app that
installs with one file and backs itself up.

## 🧰 What it does

| | |
| :--- | :--- |
| 📈 **Monitoring** | Ping, SNMP (CPU, memory, disks, interfaces, temperatures, UPS, printers, NAS), port and web checks. Templates for common homelab gear, with custom OIDs for anything else. |
| 🟢 **Availability** | Status pages and uptime history per device, in the style of Uptime Kuma. |
| 🚨 **Alerts** | Rules with thresholds, durations and severities. Problems group sensibly (a switch going down does not page you for everything behind it). Quiet hours, maintenance windows and acknowledgements. |
| 📱 **Telegram** | Alerts with your own message texts, plus a read-only bot you can ask for status. |
| 🤖 **Automation** | A visual workflow builder: SSH commands on your hosts, waits, conditions and schedules, or a trigger when something happens. Ready-made host actions for common Linux chores. |
| 🗺️ **Map and dashboards** | A network map that understands upstream links, and several dashboards built from tiles. |
| 🔌 **Integrations** | Proxmox (guests, storage, start and stop), UniFi (clients, Wi-Fi, switch ports) and Pi-hole. |
| 👥 **Users** | Roles and per-device access, two-factor authentication and an audit log. |
| 💾 **Backups** | A daily backup with everything a rebuild needs, kept locally or synced to your NAS with Syncthing. Restore in place from the installer. |
| 🔄 **Updates** | Settings, Updates installs new signed releases, keeps a backup and lets you undo the update for two days. |

## 🚀 Getting started

### On Proxmox (the main way)

1. Download `infra.sh` from the [latest release](../../releases/latest) to your Proxmox host.
2. Have a look at the settings block at the top (container ID, storage, address), then run:
   ```bash
   bash infra.sh
   ```
   A menu offers install, upgrade, check, restore and a preview that changes nothing.
3. Open the address it prints, create your administrator account with the one-time setup code,
   and let the setup guide scan your network.

The installer makes a small container (Ubuntu 24.04), with an outbound firewall that only reaches
package sources and Telegram, plus an inbound one that only lets in SSH and the web page from your
own network.

### On a VM or a spare machine

```bash
sudo bash infra.sh --local
```
Ubuntu 22.04 or newer, or Debian 12 or newer. Best on a machine of its own.

### Just looking? Try demo mode

No network to point it at? Demo mode fills the app with sixteen made-up devices and believable
readings, so you can click around safely:

```bash
export MONITOR_DB_PATH=$PWD/demo-data/monitor.db MONITOR_KEY_FILE=$PWD/demo-data/vault.key MONITOR_DEMO=1
python3 demo.py seed
python3 server.py      # then open http://127.0.0.1:8080
```
On Windows PowerShell, set the same three variables with `$env:NAME = "..."`.

## 🔄 Updating

- **From the app:** Settings, Updates, then *Check for updates*. An update is installed only if its
  signature matches the release key built into your copy. It backs up first, and it puts the old
  version back by itself if the new one does not start. For two days you can go back, either to
  the previous version with today's data or to the data from before the update.
- **From the Proxmox host:** `bash infra.sh --upgrade` with a newer `infra.sh`. It works without
  internet access on the box, too.

## 🔐 Security

Stored passwords, SSH keys and tokens are encrypted (AES-256-GCM) and never sent to the browser.
The web interface uses HTTPS by default, sessions are HttpOnly and SameSite, sensitive actions ask
for your password again and the service runs as its own unprivileged user in a systemd sandbox.
The whole design was reviewed before the first public release.

Found a problem? Please report it privately: see [SECURITY.md](SECURITY.md).

## 🧪 Development

Plain Python 3.10+ (standard library plus `cryptography`) and vanilla JavaScript. No build step.

```bash
python3 tests/run_all.py             # unit, API and installer tests
python3 tests/browser_checks.py      # browser checks (needs Chrome or Edge)
```
`TESTING.md` explains the test layers, and `deploy/build.py` turns the source into `infra.sh`.

## 💛 About this project

Home Monitor is a hobby project, built for a homelab and shared in case it is useful for yours.
It is maintained in spare time, and new versions arrive as features are ready. It is not meant for
mission-critical systems, and it comes as is, under the MIT licence.

**Built with [Claude Code](https://claude.com/claude-code).** Most of the code, the tests and this
page were written with Claude Code as the development partner, with a person deciding what to build
and testing it on real hardware.

Ideas, fixes and pull requests are very welcome: see [CONTRIBUTING.md](CONTRIBUTING.md).

### 🙏 Inspiration

Home Monitor's ideas owe a lot to some excellent projects: [Uptime Kuma](https://github.com/louislam/uptime-kuma)
(status pages), [LibreNMS](https://www.librenms.org/) and [Zabbix](https://www.zabbix.com/) (device
pages and problem handling) and [n8n](https://n8n.io/) (visual workflows). No code from them is
used, and Home Monitor is not affiliated with them. If you need any of those things done really
well, they are worth a look.
