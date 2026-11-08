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
| 🟢 **Availability** | Status pages and uptime history for every device. |
| 🚨 **Alerts** | Rules with thresholds, durations and severities. Problems group sensibly (a switch going down does not page you for everything behind it). Quiet hours, maintenance windows and acknowledgements. |
| 📱 **Telegram** | Alerts with your own message texts, plus a read-only bot you can ask for status. |
| 🤖 **Automation** | A visual workflow builder: SSH commands on your hosts, waits, conditions and schedules, or a trigger when something happens. Ready-made host actions for common Linux chores. |
| 🗺️ **Map and dashboards** | A network map that understands upstream links, and several dashboards built from tiles. |
| 🔌 **Integrations** | Proxmox (guests, storage, start and stop), UniFi (clients, Wi-Fi, switch ports) and Pi-hole. |
| 👥 **Users** | Roles and per-device access, two-factor authentication and an audit log. |
| 💾 **Backups** | A daily backup with everything a rebuild needs, kept locally or synced to your NAS with Syncthing. Restore in place from the installer. |
| 🔄 **Updates** | Settings, Updates installs new signed releases, keeps a backup and lets you undo the update for two days. |

## 🚀 Getting started

Everything comes in one file, `home_monitor.sh`. You download it, make it runnable and start it. It
asks a few questions and does the rest. You do not need to know Linux: copying the commands below
is enough.

### On Proxmox (recommended)

1. **Open a shell on your Proxmox host.** In the Proxmox web interface, click your server's name
   under *Datacenter*, then **Shell**. (Or connect with SSH: `ssh root@<your Proxmox address>`.)
2. **Download the installer:**
   ```bash
   curl -fsSLO https://github.com/The-Flying-Pancake/Home_Monitor/releases/latest/download/home_monitor.sh
   ```
3. **Make it runnable, then start it:**
   ```bash
   chmod +x home_monitor.sh
   ./home_monitor.sh
   ```
   `chmod +x` marks the file as a program you are allowed to run. You only need it once.
4. **Choose 1, Install**, then answer the questions. Pressing Enter keeps the answer shown in
   [brackets]: the container's number, its name, its address (DHCP is fine) and whether to start
   with demo data. Then choose a root password for the new container.
5. **Open the address it shows at the end** in your browser. Type the one-time setup code it prints,
   create your administrator account and let the setup guide find the devices on your network.

The installer makes a small container for the monitor (Ubuntu 24.04 with 2 cores, 1 GB of memory and
a 20 GB disk) and tags it `homelab-monitor`, so it can find it again for upgrades. Only your own
network can reach its web page and SSH. The container itself can reach your network, package updates
and Telegram, and nothing else.

### On a spare computer or a virtual machine

Any computer or VM with Ubuntu 22.04 or newer, or Debian 12 or newer, will do. A fresh, minimal
install is best: the monitor sets up the firewall of the whole machine.

1. Log in to it, at its own screen or with `ssh <you>@<its address>`.
2. Make sure `curl` is installed:
   ```bash
   sudo apt update && sudo apt install -y curl
   ```
3. Download the installer, make it runnable and install with `--local`:
   ```bash
   curl -fsSLO https://github.com/The-Flying-Pancake/Home_Monitor/releases/latest/download/home_monitor.sh
   chmod +x home_monitor.sh
   sudo ./home_monitor.sh --local
   ```
4. Type `INSTALL` when it asks, then open the address it shows, as above.

### Just looking? Start with demo data

Answer **yes** to *Start with demo data* (or run `./home_monitor.sh --demo`) and the new monitor
fills itself with sixteen made-up devices and a week of history: graphs, a network map, a few
problems and all. Their readings are invented on the monitor, so nothing is sent to those addresses.
When you are ready for the real thing, **Settings, Demo data, Remove the demo data** takes them away
and the setup guide starts on your own network.

### Changing the defaults (optional)

The top of `home_monitor.sh` holds its settings, each with a note: storage, CPU and memory, the
network bridge and VLAN, a fixed address, backups to a NAS and more. Most people never need them. To
change one, open the file with `nano home_monitor.sh`, edit, save with **Ctrl+O** then **Enter**,
leave with **Ctrl+X** and run it again.

### Is my download genuine? (optional)

Every release is signed. The `SHA256SUMS` file next to it lists the checksums, so after downloading it
too, `sha256sum -c SHA256SUMS --ignore-missing` should say `OK`. The release notes show how to check
the signature itself.

## 🔄 Updating

- **From the app:** the monitor looks for a new version once a day and shows a red number on
  Settings when one is ready. Settings, Updates shows what is new in it, and *Update now* does the
  rest while you watch. An update is installed only if its signature matches the release key built
  into your copy. It backs up first and puts the old version back by itself if the new one does not
  start. For two days you can still go back, and the update history keeps the log of every update.
- **From the Proxmox host:** download the newest `home_monitor.sh` as above, then run
  `./home_monitor.sh --upgrade`. This works without internet access on the monitor, too.

Before version 0.10.0 the installer was called `infra.sh`. It is the same file with a new name, and
both names work for upgrading.

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
`TESTING.md` explains the test layers, and `deploy/build.py` turns the source into `home_monitor.sh`.

## 💛 About this project

Home Monitor is a hobby project, built for a homelab and shared in case it is useful for yours.
It is maintained in spare time, and new versions arrive as features are ready. It is not meant for
mission-critical systems, and it comes as is, under the MIT licence.

**Built with [Claude Code](https://claude.com/claude-code).** Most of the code, the tests and this
page were written with Claude Code as the development partner, with a person deciding what to build
and testing it on real hardware.

Ideas, fixes and pull requests are very welcome: see [CONTRIBUTING.md](CONTRIBUTING.md).

### 🙏 Good company

Home Monitor is its own app, written from scratch for this project. It sits alongside some excellent
open-source tools that many homelabs already run happily, such as
[Uptime Kuma](https://github.com/louislam/uptime-kuma), [LibreNMS](https://www.librenms.org/),
[Zabbix](https://www.zabbix.com/) and [n8n](https://n8n.io/). Each of them goes much deeper into its
own job than Home Monitor tries to, so if you need one of those jobs done really well, they are well
worth a look. Home Monitor is not affiliated with any of them.
