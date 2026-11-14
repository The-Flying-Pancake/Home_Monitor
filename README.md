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
| 📈 **Monitoring** | Ping, SNMP v2c and v3 (CPU, memory, disks, interfaces, temperatures, UPS, printers, NAS), port and web checks. Templates for common homelab gear, with custom OIDs for anything else. |
| 🟢 **Availability** | Status pages and uptime history for every device. |
| 🚨 **Alerts** | Rules with thresholds, durations and severities. Problems group sensibly (a switch going down does not page you for everything behind it). Quiet hours, maintenance windows and acknowledgements. |
| 📱 **Telegram** | Alerts with your own message texts, plus a read-only bot you can ask for status. |
| 🤖 **Automation** | A visual workflow builder: SSH commands on your hosts, waits, conditions and schedules, or a trigger when something happens. Ready-made host actions for common Linux chores. |
| 🗺️ **Map and dashboards** | A network map that understands upstream links and shows Wi-Fi devices and link traffic, plus several dashboards built from tiles. |
| 📄 **Reports** | Ready-made reports you can adjust (availability, problems, device health, storage, Wi-Fi, Pi-hole and more), downloaded as a PDF or a CSV file. Save one to run every day, week or month and have it sent to Telegram. |
| 🔌 **Integrations** | Proxmox (guests, storage, start and stop), UniFi (clients, Wi-Fi, switch ports) and Pi-hole. |
| 👥 **Users** | Roles and per-device access, two-factor authentication and an audit log. |
| 💾 **Backups** | A daily backup with everything a rebuild needs, kept locally or synced to your NAS with Syncthing. Set a backup passphrase and each backup is sealed and can prove it was not changed. Restore in place from the installer. |
| 🔄 **Updates** | Settings, System, Updates installs new signed releases, keeps a backup and lets you undo the update for two days. |

## 🚀 Getting started

Everything comes in one file, `home_monitor.sh`. You download it, make it runnable and start it. It
asks a few questions and does the rest. You do not need to know Linux: copying the commands below
is enough.

> **Please read this before you install.** Home Monitor is a hobby project and comes as is, with no
> warranty and no promise of support. It isn't built or tested for business or enterprise use, so
> please don't rely on it for that. The installer runs as root on your Proxmox host and the app can run
> commands on the machines you connect to it, so a mistake or a bug could damage your setup. Try it
> somewhere you can afford to lose, keep your own backups and use it at your own discretion. If
> something goes wrong, I may not be able to help you recover it.

### On Proxmox (recommended)

1. **Open a shell on your Proxmox host.** In the Proxmox web interface, click your server's name
   under *Datacenter*, then **Shell**. (Or connect with SSH: `ssh root@<your Proxmox address>`.)
2. **Download the installer and check that it is the real one.** Copy this whole block and paste it:
   ```bash
   U=https://github.com/The-Flying-Pancake/Home_Monitor/releases/latest/download
   curl -fsSLO $U/home_monitor.sh
   curl -fsSLO $U/home_monitor.sh.sig
   echo 'release@home-monitor namespaces="home-monitor-release" ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKQPTSJq7103aQVXEseRIWBM/Rtm/z8tiJyBboEcd0lz' > release-signers
   ssh-keygen -Y verify -f release-signers -I release@home-monitor -n home-monitor-release -s home_monitor.sh.sig < home_monitor.sh
   ```
   You should see a line starting with `Good "home-monitor-release" signature`. If you see anything
   else, please don't run the file: download it again, and if it still fails,
   [let us know](../../issues/new?template=problem.yml). Please check the file before you change
   anything in it, because an edited copy no longer matches its signature.
3. **Make it runnable, then start it:**
   ```bash
   chmod +x home_monitor.sh
   ./home_monitor.sh
   ```
   `chmod +x` marks the file as a program you are allowed to run. You only need it once.
4. **Choose 1, Install**, then answer the questions. Pressing Enter keeps the answer shown in
   [brackets]: the container's number, its name, its address (DHCP is fine), whether to start with
   demo data and the kind of container. Then choose a root password for the new container.
5. **Open the address it shows at the end** in your browser. Type the one-time setup code it prints,
   create your administrator account and let the setup guide find the devices on your network.

The installer makes a small container for the monitor (Ubuntu 24.04 with 2 cores, 1 GB of memory and
a 20 GB disk) and tags it `homelab-monitor`, so it can find it again for upgrades. Only your own
network can reach its web page and SSH. The container itself can reach your network, package updates
and Telegram, and nothing else.

**Two things the installer will point out.** A *privileged* container is the default, and it is only
needed if the container mounts NFS shares itself. If someone ever broke into a privileged container
they could get close to root on your Proxmox host, so *unprivileged* is the safer pick when your
Proxmox host can do the NFS work instead. And unless you give it an SSH key, root can log in to the
container with a password from your own network. You can paste a public key right there to switch
that off. If you are happy with what it shows, type `ACCEPT` and it carries on.

### On a spare computer or a virtual machine

Any computer or VM with Ubuntu 22.04 or newer, or Debian 12 or newer, will do. A fresh, minimal
install is best: the monitor limits what the whole machine can reach on the internet. It doesn't add a
firewall for traffic coming in, so its web page and SNMP port can be reached by anything on your
network. If that matters to you, a firewall of your own in front of it is a good idea.

1. Log in to it, at its own screen or with `ssh <you>@<its address>`.
2. Make sure `curl` and `ssh-keygen` are installed:
   ```bash
   sudo apt update && sudo apt install -y curl openssh-client
   ```
3. Download the installer and check it with the block in step 2 above, then make it runnable and
   install with `--local`:
   ```bash
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

### What the signature check does for you

The check above proves the file is exactly what the project signed, so it catches a download that
was changed on the way and a release file that was swapped. It can't protect you if someone takes
over the project's GitHub account, because they could change this page and the key on it too. If
you'd like that extra bit of safety, save this fingerprint of the release key somewhere of your own
and compare it from time to time:

`SHA256:VfgS3MkxWYcs7WXOVRScDX29tjA3pWXCf5d4VwDByQQ`

The `SHA256SUMS` file only spots a damaged download, as it isn't signed. Once installed, the monitor
checks the signature by itself before every update.

## 🔄 Updating

- **From the app:** the monitor looks for a new version once a day and shows a red number on
  Settings when one is ready. Settings, System, Updates shows what is new in it, and *Update now* does the
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

Found a security problem? Please report it privately: see [SECURITY.md](SECURITY.md).

## 🐞 Something not working?

Please [open an issue](../../issues/new?template=problem.yml) and say what happened. A report from your
monitor makes it much easier to help: in the app, **Settings, System, Report a problem**, then *Copy*
and paste it into the issue. If the web page will not open, run `./home_monitor.sh --report` on the
Proxmox host instead (it changes nothing). Addresses, names and passwords in the report are masked,
and you see all of it before it goes anywhere.

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

### 🙏 Thank you

Home Monitor owes a lot to some excellent open-source projects.
[Uptime Kuma](https://github.com/louislam/uptime-kuma) inspired its status pages and uptime history,
[LibreNMS](https://www.librenms.org/) and [Zabbix](https://www.zabbix.com/) shaped its device pages
and problem handling and [n8n](https://n8n.io/) inspired its visual workflows. The ideas came from
admiring those tools, while the code was written for this project and none of it comes from them.
Each one goes much deeper into its own job than Home Monitor tries to, so if you need that job done
really well, they are well worth a look. Home Monitor is not affiliated with any of them.
