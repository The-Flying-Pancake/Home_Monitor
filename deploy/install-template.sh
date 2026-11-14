#!/usr/bin/env bash
# ================================ Home Monitor: the installer ================================
# On the Proxmox host as root (its Shell in the web interface, or SSH in), get it and start it:
#   curl -fsSLO https://github.com/The-Flying-Pancake/Home_Monitor/releases/latest/download/home_monitor.sh
#   chmod +x home_monitor.sh
#   ./home_monitor.sh             a menu: install, upgrade, check, restore, rebuild or preview (each
#                                 confirmed first); without a terminal it installs a new container
# Or straight to one of them:
#   ./home_monitor.sh --upgrade   check, back up, then replace the app in place (rolls back if it fails)
#   ./home_monitor.sh --check     only the upgrade check: can it be upgraded? changes nothing
#   ./home_monitor.sh --restore   keep the container, wipe the app and its data, restore a backup you pick
#   ./home_monitor.sh --rebuild   destroy the container and install again with its own settings
#   ./home_monitor.sh --preview   show what the installer looks like; changes nothing
#   ./home_monitor.sh --demo      a new install filled with made-up devices to look around (removable)
#   ./home_monitor.sh --report    a problem report to paste into a GitHub issue (changes nothing)
# No Proxmox, or inside a VM: sudo ./home_monitor.sh --local installs on the machine itself (Ubuntu
# 22.04+ or Debian 12+); use --local --upgrade or --local --check later. No container is made.
# Upgrade, check, restore and rebuild find the container by its Proxmox tag homelab-monitor.
# (Called infra.sh before 0.10.0: the same file, renamed.)
# App version __VERSION__, built __BUILT__. Regenerate with: py -3.15 deploy/build.py
# ============================================================================================
# Saved with Windows line endings (an editor or a text-mode copy on Windows)? Then every line ends
# in a carriage return and nothing below would parse: this one line strips them from this file (or,
# when it cannot be written, from a copy) and starts it again. It parses either way: with Windows
# endings the carriage return lands in the trailing comment. ./home_monitor.sh cannot be helped (Linux
# rejects the first line before any of this runs): use bash home_monitor.sh.
if [ -z "${HM_CRLF_FIXED-}" ] && grep -qU $'\r' "$0" 2>/dev/null; then echo "  home_monitor.sh had Windows line endings: fixing them and starting again." >&2; if sed -b -i 's/\r$//' "$0" 2>/dev/null; then HM_CRLF_FIXED=1 exec bash "$0" "$@"; else HM_CRLF_COPY="$(mktemp)"; tr -d '\r' < "$0" > "$HM_CRLF_COPY"; HM_CRLF_FIXED=1 exec bash "$HM_CRLF_COPY" "$@"; fi; fi #

# >>> SETTINGS: change these for your Proxmox host. deploy/build.py keeps this block as you
# leave it when it regenerates home_monitor.sh (delete the block to get the defaults back).

CTID=201                      # container ID for a new install (upgrades find theirs by its tag)
HOSTNAME="Monitor"            # container hostname (also accepted in the browser address bar)

# Storage. Leave blank to pick automatically: templates go to "local" if it holds templates,
# the disk goes to the storage with the most free space that holds containers.
# See yours with:  pvesm status -content vztmpl   and   pvesm status -content rootdir
TEMPLATE_STORAGE=""           # where the Ubuntu template is downloaded, e.g. local
DISK_STORAGE=""               # where the container disk lives, e.g. local-lvm or data
DISK_SIZE=20                  # GiB
CORES=2
MEMORY=1024                   # MiB
SWAP=512                      # MiB

# Network
BRIDGE="vmbr0"
VLAN_TAG=""                   # blank for none
MAC_ADDRESS=""                # blank lets Proxmox pick one (set a DHCP reservation for it)
IP_ADDRESS="dhcp"             # dhcp, or a fixed address such as 192.168.1.51/24
GATEWAY=""                    # with a fixed address, e.g. 192.168.1.1
DNS_SERVER=""                 # blank: the host's resolver settings
TIMEZONE=""                   # blank: same as this Proxmox host (workflow schedules use it)

# SNMP inside the container, so the monitor can watch its own host
SNMP_COMMUNITY="public"
SNMP_ALLOW=""                 # blank: only the container itself (its own address and 127.0.0.1)
# SNMP_ALLOW: addresses or networks, IPv4 or IPv6, separated by spaces.

PORT=8080                     # web interface port

# yes: a new install starts with made-up devices and a week of history, to look around before
# pointing it at your network. Settings, Demo data removes them when you are ready (the installer
# also asks on a first install).
DEMO="no"

# Only with --local (installed on a VM or another machine, not in a container): a time server on
# your network, e.g. 192.168.1.1. The outbound firewall blocks internet time servers, and 2FA codes
# need a correct clock. Blank: leave the machine's time settings as they are.
NTP_SERVER=""

# Unattended restore (a rebuild that comes back as it was).
#   RESTORE="no"      fresh install: you create the first account in the browser
#   RESTORE="latest"  restore the newest backup from the source below while installing
RESTORE="no"
# yes: RESTORE="latest" may restore a backup that cannot be proven unchanged. Leave this at no unless
# you are restoring older backups on purpose.
RESTORE_UNVERIFIED="no"
# Backups through Syncthing: the NFS export holding this container's Syncthing identity
# (cert.pem, key.pem, config.xml) and the folder Syncthing keeps the backups in.
SYNCTHING_KEYS_NFS=""         # e.g. 192.168.1.10:/Share/SyncThingKeys/Monitor
SYNCTHING_FOLDER="/mnt/Syncthing/Monitor"
# Or backups on a plain NFS share (used when SYNCTHING_KEYS_NFS is blank)
BACKUP_NFS=""                 # e.g. 192.168.1.10:/Share/Backups/Monitor
# A passphrase that seals the vault key inside every backup and proves each backup unchanged
# (12 characters or more). Blank: backups that leave the container (Syncthing, a share) go without
# the key, so a rebuild from them cannot use the stored passwords, and no backup can be proven
# unchanged. Set: a restore needs it (a rebuild with RESTORE="latest" takes it from here). It is kept
# on the container for the daily backup, readable by root only. On an installed box, set or change
# it with /root/backup-passphrase.sh.
BACKUP_PASSPHRASE=""

# Who may reach the container's SSH and web page. Blank on a new install: any private address (10.x,
# 172.16-31.x, 192.168.x and local IPv6). Or a list such as "192.168.1.0/24 192.168.10.5". Everything
# else coming in is dropped, apart from Syncthing and DHCP. Not used with --local.
# On an upgrade a blank value keeps what this box already uses. A different value is asked about.
# To go back to every private address after setting a list, write them out:
# 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 fc00::/7 fe80::/10
ADMIN_NET=""
# Root SSH login with a key instead of the password: a public key line, or a file on this host such
# as /root/.ssh/id_ed25519.pub. Set: password logins over SSH are switched off (the Proxmox console
# still takes the password). Blank: at a terminal the installer offers to take one. Not used with --local.
# On an upgrade a blank value keeps what this box already uses. A different value is asked about.
ROOT_SSH_KEY=""
# 1: an unprivileged container, the safer kind: root inside it is not root on this host. It cannot
# mount NFS itself, so this host copies the Syncthing identity and backups in, and other NFS shares
# are passed in as mount points (see the guide). 0: privileged, the container mounts NFS itself.
# The installer asks at a terminal, with this as the answer Enter keeps.
UNPRIVILEGED=0

# <<< SETTINGS

set -euo pipefail

TEMPLATE_SERIES="ubuntu-24.04-standard"
# nesting: systemd sandboxing in Ubuntu 24.04 containers; mount=nfs only for a privileged one.
set_features() { FEATURES="nesting=1,mount=nfs"; [[ "${UNPRIVILEGED:-0}" == 1 ]] && FEATURES="nesting=1"; return 0; }
set_features
APP_DIR="/opt/homelab-monitor"
DATA_DIR="/var/lib/homelab-monitor"
KEY_DIR="/etc/homelab-monitor"
INSTALL_DIR="/etc/homelab-monitor-install"   # root's own: install.conf, layout and the backup passphrase
SAFE_DIR="/var/lib/homelab-monitor-safe"      # root only: the safety copies made before an upgrade, restore or undo
NEW_DIR="/root/.hm-new"                       # the new build while upgrading or restoring (root only)
PAYLOAD_SHA256="__PAYLOAD_SHA256__"
SERVICE_USER="homelab-monitor"
VERSION="__VERSION__"
# What the container itself looks like (packages, users, units, folders), apart from the app. Raised
# when an installer change needs a fresh container; an upgrade from an older layout is checked
# item by item and repaired where it can be, otherwise it stops and says to rebuild and restore.
LAYOUT=1
HEALTH_TRIES="${HM_HEALTH_TRIES:-45}"   # 2 s each: how long a new version gets to answer

MODE="install"
RUN_HERE=""
TARGET="container"                   # --local: this machine itself, no container
HM_ARGS=$#                           # none: the menu asks what to do
for arg in "$@"; do
  case "$arg" in
    --local) TARGET="local" ;;
    --rebuild) MODE="rebuild" ;;
    --upgrade) MODE="upgrade" ;;
    --preview) MODE="preview" ;;
    --check) MODE="check" ;;
    --restore) MODE="restore" ;;
    --demo) DEMO="yes" ;;
    --report) MODE="report" ;;
    # Used by Update in the web page (updatectl.py, as root on the box): upgrade the machine this runs
    # on, with the settings recorded there at install time instead of the ones in this file.
    --update-here) MODE="upgrade"; RUN_HERE=1 ;;
    -h|--help) sed -n '2,/^# App version/p' "$0"; exit 0 ;;
    *) echo "Unknown option $arg (use --local, --rebuild, --upgrade, --check, --restore, --preview, --demo, --report or --help)" >&2; exit 1 ;;
  esac
done
# The box's own settings (settings.env, written by every install and upgrade): only these names, plain characters.
set_re='^(CTID|HOSTNAME|PORT|ADMIN_NET|SNMP_ALLOW|SSH_KEY_LINE|UNPRIVILEGED|SYNCTHING_KEYS_NFS|SYNCTHING_FOLDER|BACKUP_NFS|TARGET)="([A-Za-z0-9 ._:/@+=,-]*)"$'
if [[ -n "$RUN_HERE" ]]; then
  SETTINGS_ENV="${HM_SETTINGS_ENV:-/etc/homelab-monitor-install/settings.env}"
  [[ -f "$SETTINGS_ENV" ]] || { echo "No recorded settings at $SETTINGS_ENV: upgrade once with home_monitor.sh from the Proxmox host first." >&2; exit 1; }
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" =~ $set_re ]] && printf -v "${BASH_REMATCH[1]}" '%s' "${BASH_REMATCH[2]}"
  done < "$SETTINGS_ENV"
  ROOT_SSH_KEY="${SSH_KEY_LINE-}"
  [[ "$TARGET" == local || "$TARGET" == container ]] || TARGET="container"
fi
if [[ "$TARGET" == "local" ]]; then
  if [[ "$MODE" == "rebuild" ]]; then
    echo "--rebuild destroys and remakes a container; with --local there is none. To start again on this machine:" >&2
    echo "reinstall its system (or make a fresh VM), run bash $(basename "$0") --local, then /root/restore.sh." >&2
    exit 1
  fi
  [[ -n "$RUN_HERE" ]] || HOSTNAME="$(hostname 2>/dev/null || echo monitor)"
  WHERE="this machine"; FLAG=" --local"
elif [[ -n "$RUN_HERE" ]]; then
  WHERE="this container"; FLAG=""
else
  WHERE="CT ${CTID}"; FLAG=""
fi
# Security settings, checked before anything is done.
bad_setting() { echo "$1" >&2; exit 1; }
[[ -z "$BACKUP_PASSPHRASE" || ${#BACKUP_PASSPHRASE} -ge 12 ]] || bad_setting "BACKUP_PASSPHRASE: 12 characters or more, or blank."
[[ "$UNPRIVILEGED" == 0 || "$UNPRIVILEGED" == 1 ]] || bad_setting "UNPRIVILEGED: 0 or 1."
RESTORE_UNVERIFIED="${RESTORE_UNVERIFIED,,}"
[[ "$RESTORE_UNVERIFIED" == yes || "$RESTORE_UNVERIFIED" == no ]] || bad_setting "RESTORE_UNVERIFIED: yes or no."
DEMO="${DEMO,,}"
[[ "$DEMO" == yes || "$DEMO" == no ]] || bad_setting "DEMO: yes or no."
# ADMIN_NET and SNMP_ALLOW go into the firewall rules and snmpd.conf: strict IPv4 or IPv6 addresses
# or networks only, in plain bash (Python may not be on the machine yet).
# >>> net checks
valid_net4() {
  local a="$1" o
  if [[ "$a" == */* ]]; then [[ "${a#*/}" =~ ^(0|[1-9]|[12][0-9]|3[0-2])$ ]] || return 1; a="${a%/*}"; fi
  [[ "$a" =~ ^([0-9]{1,3})[.]([0-9]{1,3})[.]([0-9]{1,3})[.]([0-9]{1,3})$ ]] || return 1
  for o in "${BASH_REMATCH[@]:1}"; do [[ "$o" =~ ^(0|[1-9][0-9]{0,2})$ ]] && (( o <= 255 )) || return 1; done
}
valid_net6() {
  local a="$1" body g n=0 IFS=:; local -a groups
  if [[ "$a" == */* ]]; then [[ "${a#*/}" =~ ^(0|[1-9][0-9]{0,2})$ ]] && (( ${a#*/} <= 128 )) || return 1; a="${a%/*}"; fi
  [[ "$a" =~ ^[0-9A-Fa-f:]+$ && "$a" == *:* && "$a" != *:::* ]] || return 1
  body="${a//::/}"; (( ${#a} - ${#body} <= 2 )) || return 1
  [[ "$a" != :[!:]* && "$a" != *[!:]: ]] || return 1
  read -r -a groups <<<"$a"
  for g in "${groups[@]}"; do [[ -z "$g" ]] && continue; (( ${#g} <= 4 )) || return 1; n=$((n + 1)); done
  if [[ "$a" == *::* ]]; then (( n <= 7 )); else (( n == 8 )); fi
}
valid_net() { if [[ "$1" == *:* ]]; then valid_net6 "$1"; else valid_net4 "$1"; fi; }
net_words() {   # a list by spaces or commas, one per line; a value of several lines can never pass
  local w; local -a t
  [[ "$1" != *$'\n'* ]] || { echo "(several lines)"; return 0; }
  read -r -a t <<<"${1//,/ }"
  for w in "${t[@]}"; do printf '%s\n' "$w"; done
}
# <<< net checks
check_nets() {  # name, value: a setting in this file is refused at its first bad entry
  local w
  while IFS= read -r w; do
    valid_net "$w" || bad_setting "$1: addresses or networks such as 192.168.1.0/24 or fd00::/8, separated by spaces ($w is not one)."
  done < <(net_words "$2")
  return 0
}
keep_valid_nets() {  # name, value: the good entries, single spaces; bad ones are named on stderr and left out
  local w; local -a good=()
  while IFS= read -r w; do
    if valid_net "$w"; then good+=("$w"); else echo "Ignoring $w in the recorded $1: it is not an address or network." >&2; fi
  done < <(net_words "$2")
  printf '%s' "${good[*]}"
}
if [[ -n "$RUN_HERE" ]]; then
  # Recorded by an older, looser build: a bad entry is dropped rather than stopping Update in the app.
  ADMIN_NET="$(keep_valid_nets ADMIN_NET "$ADMIN_NET")"; SNMP_ALLOW="$(keep_valid_nets SNMP_ALLOW "$SNMP_ALLOW")"
else
  check_nets ADMIN_NET "$ADMIN_NET"; check_nets SNMP_ALLOW "$SNMP_ALLOW"
  ADMIN_NET="$(keep_valid_nets ADMIN_NET "$ADMIN_NET")"; SNMP_ALLOW="$(keep_valid_nets SNMP_ALLOW "$SNMP_ALLOW")"
fi
key_re='^(ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(256|384|521)|sk-ssh-ed25519@openssh[.]com|sk-ecdsa-sha2-nistp256@openssh[.]com) [A-Za-z0-9+/=]+( [ A-Za-z0-9@._+:-]*)?$'
# A public key line, or a file on this host holding one: sets SSH_KEY_LINE, or returns 1 and leaves it.
# The setting and the key pasted at the installer's question are checked by this one function.
parse_key() {
  local line
  if [[ -f "$1" ]]; then line="$(grep -m1 -E '^(ssh-|ecdsa-|sk-)' "$1" || true)"; else line="$1"; fi
  [[ "$line" =~ $key_re ]] || return 1
  SSH_KEY_LINE="$line"
}
SSH_KEY_LINE=""
if [[ -n "$ROOT_SSH_KEY" ]]; then
  parse_key "$ROOT_SSH_KEY" || bad_setting "ROOT_SSH_KEY: a public key line (ssh-ed25519 AAAA... you@pc) or a file on this host holding one."
fi

# ------------------------------------------------------------------ look and feel
if [[ ( -t 1 || -n "${FORCE_COLOR-}" ) && -z "${NO_COLOR-}" ]]; then
  B=$'\033[1m'; D=$'\033[2m'; R=$'\033[0m'; GRN=$'\033[32m'; RED=$'\033[31m'; CYN=$'\033[36m'
  YEL=$'\033[33m'; BLU=$'\033[34m'; K=$'\033[K'; FANCY=1
else
  B=""; D=""; R=""; GRN=""; RED=""; CYN=""; YEL=""; BLU=""; K=""; FANCY=0
fi
LOG="/var/log/homelab-monitor-install-$(date +%Y%m%d-%H%M%S).log"
[[ "$MODE" == "preview" || ! -w /var/log ]] && LOG="$(mktemp /tmp/homelab-monitor-install-XXXX.log)"
# Update in the app (updatectl.py, root) keeps the log beside the download, for the update history.
[[ -n "$RUN_HERE" && "${HM_LOG_FILE-}" == /root/hm-update-*/install.log ]] && LOG="$HM_LOG_FILE"
( umask 077; : >> "$LOG" ) 2>/dev/null || true      # root only: it records what was installed and where
STATE="$(mktemp -d)"
DRAWER=""

banner() {
  # Block-letter wordmark over a heartbeat trace: what the monitor does, drawn with characters
  # every terminal font has. While installing, the trace scrolls (frame number in $1).
  # An array, not a string: slicing a string cuts multibyte characters when the shell is not
  # in a UTF-8 locale (common over SSH).
  local beat=(▁ ▁ ▁ ▁ ▁ ▁ ▁ ▁ ▂ ▃ ▁ ▇ █ ▁ ▂ ▁ ▁ ▁ ▁ ▁ ▁ ▁ ▁ ▁ ▁ ▁ ▁ ▁ ▃ ▅ ▁ ▂ ▁ ▁ ▁ ▁ ▁ ▁) n=${1:-0} i trace=""
  for ((i = 0; i < 24; i++)); do trace+="${beat[$(( (i + n) % ${#beat[@]} ))]}"; done
  printf '%s\n' \
    "" \
    "   ${B}█ █ █▀█ █▀▄▀█ █▀▀ █   █▀█ █▀▄${R}   ${CYN}${B}█▀▄▀█ █▀█ █▄ █ █ ▀█▀ █▀█ █▀█${R}" \
    "   ${B}█▀█ █ █ █ ▀ █ █▀▀ █   █▀█ █▀▄${R}   ${CYN}${B}█ ▀ █ █ █ █ ▀█ █  █  █ █ █▀▄${R}" \
    "   ${B}▀ ▀ ▀▀▀ ▀   ▀ ▀▀▀ ▀▀▀ ▀ ▀ ▀▀ ${R}   ${CYN}${B}▀   ▀ ▀▀▀ ▀  ▀ ▀  ▀  ▀▀▀ ▀ ▀${R}" \
    "   ${GRN}${trace}${R}  ${D}network monitor and automation  v${VERSION}${R}" \
    ""
}

fmt_time() { local s=$1; (( s >= 60 )) && printf '%dm %02ds' $((s / 60)) $((s % 60)) || printf '%ds' "$s"; }

say()  { printf '  %s\n' "$*"; }
die()  {
  stop_drawer
  printf '\n  %s✖  %s%s\n' "$RED$B" "$*" "$R" >&2
  if [[ -s "$LOG" ]]; then
    printf '\n  %sLast lines of the log:%s\n' "$D" "$R" >&2
    tail -n 12 "$LOG" | sed 's/^/    /' >&2
    printf '\n  Full log: %s\n' "$LOG" >&2
  fi
  exit 1
}

# Steps: id|label|weight|typical seconds. The bar moves by weight; a running step creeps
# toward its share by elapsed / typical time so it never sits still. Defined just before the
# progress screen starts, once the mode, container ID and name are settled (the menu, the
# first-install questions and the tag can each change them).
# Unprivileged container with an NFS source: this host copies from the share (see host_share_copy).
share_needed() {
  [[ "$TARGET" == container && "$UNPRIVILEGED" == 1 ]] || return 1
  [[ -n "$SYNCTHING_KEYS_NFS" || ( "$RESTORE" == latest && -n "$BACKUP_NFS" ) ]]
}
# Demo data: only on a new install that does not restore a backup.
demo_wanted() { [[ "$DEMO" == yes && "$RESTORE" != latest && ( "$MODE" == install || "$MODE" == preview ) ]]; }
ask_demo() {
  local a
  read -r -p "  Start with demo data, made-up devices to look around first? yes or no [${DEMO}]: " a || a=""
  a="${a,,}"; [[ "$a" == yes || "$a" == y ]] && DEMO="yes"; [[ "$a" == no || "$a" == n ]] && DEMO="no"
  return 0
}
STEPS=()
define_steps() {
  case "$MODE" in
    upgrade|check)
      STEPS=(
        "ready|Starting ${WHERE} and finding the monitor|2|10"
        "copy|Copying the new build in|2|5"
        "check|Checking the install and your data with the new build|10|30"
      )
      [[ "$MODE" == "check" ]] && return 0
      STEPS+=(
        "repair|Installing what was missing|8|60"
        "backup|Backing up before the upgrade|6|15"
        "replace|Replacing the app|8|20"
        "health|Waiting for the new version to answer|6|20"
      ) ;;
    restore)
      STEPS=(
        "verify|Checking the backup with the new build|6|20"
        "safety|Keeping a copy of what is there now|6|15"
        "wipe|Clearing the app and its data|2|5"
        "app|Fresh copy of Homelab Monitor ${VERSION}|6|15"
        "restore|Restoring the backup|8|30"
        "web|Starting the web interface|4|20"
      ) ;;
    *)
      if [[ "$TARGET" == "local" ]]; then
        STEPS=("here|Checking this machine|2|3")
      else
        STEPS=(
          "host|Checking the Proxmox host|2|3"
          "template|Ubuntu 24.04 template|8|30"
          "create|Creating container ${CTID}|6|15"
          "boot|Starting the container|4|15"
        )
      fi
      STEPS+=(
        "packages|Updating system packages|26|150"
        "tools|Python, cryptography, SSH, SNMP and NFS|14|60"
        "syncthing|Syncthing|8|30"
        "app|Homelab Monitor ${VERSION}|4|5"
        "services|Service, firewall and daily backups|8|20"
      )
      share_needed && STEPS+=("share|Copying from your NFS share through this host|4|20")
      [[ "$RESTORE" == "latest" ]] && STEPS+=("restore|Restoring the latest backup|10|90")
      STEPS+=("web|Starting the web interface|4|10")
      demo_wanted && STEPS+=("demo|Filling it with demo data|8|45") ;;
  esac
  return 0
}

step_field() { local IFS='|'; read -r -a f <<<"$1"; printf '%s' "${f[$2]}"; }

progress_title() {
  case "$MODE" in
    upgrade) printf '  %sUpgrading %s to %s%s  %s(data, key and settings are kept)%s%s\n\n' "$B" "$WHERE" "$VERSION" "$R" "$D" "$R" "$K" ;;
    check)   printf '  %sChecking %s for an upgrade to %s%s  %s(nothing is changed)%s%s\n\n' "$B" "$WHERE" "$VERSION" "$R" "$D" "$R" "$K" ;;
    restore) printf '  %sRestoring %s%s  %s(from %s)%s%s\n\n' "$B" "$WHERE" "$R" "$D" "${PICKED_NAME-a backup}" "$R" "$K" ;;
    *) if [[ "$TARGET" == "local" ]]; then
         printf '  %sInstalling on this machine%s  %s(%s, no container)%s%s\n\n' "$B" "$R" "$D" "$HOSTNAME" "$R" "$K"
       else
         printf '  %sInstalling into CT %s%s  %s(%s, %s GiB on %s)%s%s\n\n' "$B" "$CTID" "$R" "$D" "$HOSTNAME" "$DISK_SIZE" "${DISK_STORAGE:-auto}" "$R" "$K"
       fi ;;
  esac
}

render_progress() {
  local now total=0 done_w=0 cur_frac=0 i=0 line id label w typ st icon dur
  now=$(date +%s)
  local started; started=$(cat "$STATE/started" 2>/dev/null || echo "$now")
  banner "$(( $(date +%s%N 2>/dev/null | cut -c1-11 || echo 0) % 1000 ))"
  progress_title
  local spin=(⠋ ⠙ ⠹ ⠸ ⠼ ⠴ ⠦ ⠧ ⠇ ⠏)
  for line in "${STEPS[@]}"; do
    [[ -z "$line" ]] && continue
    id=$(step_field "$line" 0); label=$(step_field "$line" 1); w=$(step_field "$line" 2); typ=$(step_field "$line" 3)
    total=$((total + w))
    st=$(cat "$STATE/$id.status" 2>/dev/null || echo pending)
    dur=""
    printf -v label '%-52s' "$label"
    case "$st" in
      ok)      icon="${GRN}✔${R}"; done_w=$((done_w + w)); dur=$(fmt_time "$(cat "$STATE/$id.secs")") ;;
      skip)    icon="${D}–${R}"; done_w=$((done_w + w)); dur="skipped" ;;
      fail)    icon="${RED}✖${R}"; dur=$(fmt_time "$(cat "$STATE/$id.secs")") ;;
      run)     local t0; t0=$(cat "$STATE/$id.t0"); local el=$((now - t0))
               icon="${CYN}${spin[$(( $(date +%s%N 2>/dev/null | cut -c1-11 || echo 0) % 10 ))]}${R}"
               cur_frac=$(( w * (el < typ ? el : typ) * 90 / 100 / (typ > 0 ? typ : 1) ))
               dur=$(fmt_time "$el"); label="${B}${label}${R}" ;;
      *)       icon="${D}·${R}"; label="${D}${label}${R}" ;;
    esac
    printf '   %s  %s %s%10s%s%s\n' "$icon" "$label" "$D" "$dur" "$R" "$K"
  done
  local pct=$(( (done_w * 100 + cur_frac * 100) / (total > 0 ? total : 1) ))
  (( pct > 100 )) && pct=100
  local width=44 fill=$(( pct * 44 / 100 ))
  local on="" off="" j
  for ((j = 0; j < width; j++)); do (( j < fill )) && on+="━" || off+="━"; done
  printf '\n   %s%s%s%s%s  %s%3d%%%s   %s%s%s\n' "$CYN" "$on" "$R$D" "$off" "$R" "$B" "$pct" "$R" "$D" "$(fmt_time $((now - started)))" "$R$K"
  local last; last=$(grep -v '^\s*$' "$LOG" 2>/dev/null | tail -n 1 | tr -d '\r' | cut -c1-66)
  printf '   %s› %s%s%s\n' "$D" "$last" "$R" "$K"
}

start_drawer() {
  date +%s > "$STATE/started"
  [[ "$FANCY" == 1 ]] || { progress_title; return 0; }
  tput smcup 2>/dev/null || true
  tput civis 2>/dev/null || true
  printf '\033[2J'
  ( while :; do printf '\033[H%s\033[J' "$(render_progress)"; sleep 0.12; done ) &
  DRAWER=$!
}

stop_drawer() {
  if [[ -n "$DRAWER" ]]; then
    kill "$DRAWER" 2>/dev/null || true
    wait "$DRAWER" 2>/dev/null || true
    DRAWER=""
    tput cnorm 2>/dev/null || true
    tput rmcup 2>/dev/null || true
  fi
}

cleanup() { stop_drawer; rm -rf "$STATE" "${PAYLOAD-}"; }
trap cleanup EXIT
if [[ "$TARGET" == "local" ]]; then
  trap 'die "Stopped (Ctrl+C). The install on this machine may be half done: see the log, then run again."' INT
else
  trap 'die "Stopped (Ctrl+C). The container may be half built: run again with --rebuild."' INT
fi

# run_step id function: runs it with errexit in a subshell, output to the log, status to $STATE.
# Values a step must hand on are written to $STATE/<name> (a subshell cannot set variables here).
# A step may write the reason it failed to $STATE/why (shown instead of "... failed"). With a third
# argument (soft) a failed step returns 1 instead of stopping the script, for steps that roll back.
run_step() {
  local id=$1 fn=$2 soft=${3-} t0 rc
  rm -f "$STATE/why"
  t0=$(date +%s); echo "$t0" > "$STATE/$id.t0"; echo run > "$STATE/$id.status"
  printf '\n===== %s: %s =====\n' "$(date +'%F %T')" "$id" >> "$LOG"
  [[ "$FANCY" == 1 ]] || printf '  ... %s\n' "$id"
  set +e
  ( set -euo pipefail; "$fn" ) >> "$LOG" 2>&1
  rc=$?
  set -e
  echo $(( $(date +%s) - t0 )) > "$STATE/$id.secs"
  if (( rc != 0 )); then
    echo fail > "$STATE/$id.status"
    sleep 0.3
    [[ -n "$soft" ]] && return 1
    die "$(cat "$STATE/why" 2>/dev/null || echo "$(step_label "$id") failed.")"
  fi
  echo ok > "$STATE/$id.status"
}
skip_step() {
  echo 0 > "$STATE/$1.secs"; echo skip > "$STATE/$1.status"
  [[ "$FANCY" == 1 ]] || printf '  ... %s (skipped)\n' "$1"
  return 0
}

# ------------------------------------------------------------------ finding the monitor's container
# Upgrade, check and rebuild find the container by its Proxmox tag, set when it was installed. Only
# Proxmox's own config files on this host are read (/etc/pve/lxc/<id>.conf): nothing runs inside
# any other guest. Without a tagged container they stop and say how to tag it.
HM_TAG="homelab-monitor"
PVE_LXC_DIR="${HM_PVE_LXC_DIR:-/etc/pve/lxc}"

ct_conf() {  # id, key: the value from the container's own section (snapshots below are ignored)
  awk -v k="$2" '/^\[/ {exit} index($0, k ": ") == 1 {print substr($0, length(k) + 3); exit}' "$PVE_LXC_DIR/$1.conf" 2>/dev/null
}

tagged_cts() {  # the IDs of containers carrying the tag
  local f id
  for f in "$PVE_LXC_DIR"/*.conf; do
    [[ -e "$f" ]] || continue
    id="$(basename "$f" .conf)"
    [[ "$id" =~ ^[0-9]+$ ]] || continue
    ct_conf "$id" tags | tr ';, ' '\n\n\n' | grep -qx "$HM_TAG" && echo "$id"
  done | sort -n
}

no_tag_help() {
  stop_drawer 2>/dev/null || true
  {
    printf '\n  %s✖  No container on this host has the tag %s, so there is nothing to %s.%s\n\n' "$RED$B" "$HM_TAG" "$MODE" "$R"
    printf '  The tag is how this script finds the monitor. Containers installed by an older home_monitor.sh\n'
    printf '  do not have it yet. Tag yours once (it keeps any tags it already has):\n\n'
    printf '    %spct list%s                       # find the monitor'"'"'s container ID\n' "$B" "$R"
    printf '    %sID=201; T=$(pct config $ID | awk '"'"'/^tags:/ {print $2}'"'"'); pct set $ID --tags "%s${T:+;$T}"%s\n\n' "$B" "$HM_TAG" "$R"
    printf '  (Use your ID instead of 201.) Or in the Proxmox web interface: the container, Summary,\n'
    printf '  the pencil beside its tags, add %s. Then run this again.\n\n' "$HM_TAG"
  } >&2
  exit 1
}

find_monitor_ct() {  # sets CTID from the tag; asks when several have it
  local ids=() i n
  mapfile -t ids < <(tagged_cts)
  (( ${#ids[@]} )) || no_tag_help
  if (( ${#ids[@]} == 1 )); then
    CTID="${ids[0]}"
  else
    [[ -t 0 && -z "${HM_FAKE_HOST-}" ]] || die "Several containers have the tag ${HM_TAG} (${ids[*]}). Run this at a terminal to pick one, or take the tag off the ones that are not the monitor."
    printf '\n  Several containers have the tag %s:\n\n' "$HM_TAG"
    for i in "${!ids[@]}"; do printf '    %s%d%s  CT %s  %s\n' "$B" $((i + 1)) "$R" "${ids[$i]}" "$(ct_conf "${ids[$i]}" hostname)"; done
    echo
    while :; do
      read -r -p "  Which one? " n || exit 1
      [[ "$n" =~ ^[0-9]+$ ]] && (( n >= 1 && n <= ${#ids[@]} )) && break
    done
    CTID="${ids[$((n - 1))]}"
  fi
  WHERE="CT ${CTID}"
  say "The monitor's container, found by its tag: CT ${CTID} ($(ct_conf "$CTID" hostname))."
}

adopt_ct() {  # a rebuild keeps the container's own settings, not the ones at the top of this file
  local v s
  v="$(ct_conf "$CTID" hostname)"; [[ -n "$v" ]] && HOSTNAME="$v"
  v="$(ct_conf "$CTID" cores)"; [[ -n "$v" ]] && CORES="$v"
  v="$(ct_conf "$CTID" memory)"; [[ -n "$v" ]] && MEMORY="$v"
  v="$(ct_conf "$CTID" swap)"; [[ -n "$v" ]] && SWAP="$v"
  v="$(ct_conf "$CTID" nameserver)"; [[ -n "$v" ]] && DNS_SERVER="$v"
  v="$(ct_conf "$CTID" rootfs)"
  if [[ -n "$v" ]]; then
    DISK_STORAGE="${v%%:*}"
    s="$(sed -n 's/.*size=\([0-9][0-9]*\)G.*/\1/p' <<<"$v")"; [[ -n "$s" ]] && DISK_SIZE="$s"
  fi
  v="$(ct_conf "$CTID" net0)"; [[ -n "$v" ]] && KEEP_NET0="$v"
  # The kind too: a rebuild never turns an unprivileged container into a privileged one by itself.
  v="$(ct_conf "$CTID" unprivileged)"; [[ "$v" == 1 ]] && UNPRIVILEGED=1
  set_features
  return 0
}

# ------------------------------------------------------------------ menu (bash home_monitor.sh with no options)
# A person at the terminal without options gets a numbered menu; the choice is confirmed before
# anything happens. The options themselves (--upgrade and the rest) skip it.
if [[ "$HM_ARGS" -eq 0 && -t 0 && -t 1 && -z "${HM_FAKE_HOST-}" && -z "${HM_NO_ASK-}" ]]; then
  clear 2>/dev/null || true
  banner
  if command -v pct >/dev/null 2>&1; then
    ON="this Proxmox host"
    OPTS=("install|Install the monitor in a new container"
          "upgrade|Upgrade the monitor (found by its tag ${HM_TAG})"
          "check|Check whether an upgrade would work (changes nothing)"
          "restore|Restore a backup: wipe the app, keep the container"
          "rebuild|Rebuild: destroy its container, install it again"
          "preview|Preview the install screens (changes nothing)"
          "report|Make a problem report to paste on GitHub (changes nothing)")
  else
    ON="this machine"; TARGET="local"
    OPTS=("install|Install the monitor on this machine"
          "upgrade|Upgrade the monitor on this machine"
          "check|Check whether an upgrade would work (changes nothing)"
          "restore|Restore a backup: wipe the app, then put a backup back"
          "report|Make a problem report to paste on GitHub (changes nothing)")
  fi
  printf '  %s+----------------------------------------------------------------+%s\n' "$D" "$R"
  printf '  %s|%s %-62s %s|%s\n' "$D" "$R" "What would you like to do on ${ON}?" "$D" "$R"
  printf '  %s+----------------------------------------------------------------+%s\n' "$D" "$R"
  for i in "${!OPTS[@]}"; do printf '  %s|%s  %s%d%s  %-58s %s|%s\n' "$D" "$R" "$B" $((i + 1)) "$R" "${OPTS[$i]#*|}" "$D" "$R"; done
  printf '  %s|%s  %s0%s  %-58s %s|%s\n' "$D" "$R" "$B" "$R" "Quit" "$D" "$R"
  printf '  %s+----------------------------------------------------------------+%s\n\n' "$D" "$R"
  while :; do
    read -r -p "  Choose a number: " n || exit 0
    [[ "$n" == "0" ]] && { echo "  Nothing done."; exit 0; }
    [[ "$n" =~ ^[0-9]+$ ]] && (( n >= 1 && n <= ${#OPTS[@]} )) && break
    echo "  Type one of the numbers shown."
  done
  PICK="${OPTS[$((n - 1))]}"
  read -r -p "  ${PICK#*|}: type yes to go ahead: " ok || ok=""
  [[ "${ok,,}" == "yes" ]] || { echo "  Nothing done."; exit 0; }
  MODE="${PICK%%|*}"
  if [[ "$TARGET" == "local" ]]; then
    HOSTNAME="$(hostname 2>/dev/null || echo monitor)"; WHERE="this machine"; FLAG=" --local"
  fi
  [[ "$MODE" == "preview" ]] && LOG="$(mktemp /tmp/homelab-monitor-install-XXXX.log)"
fi

# ------------------------------------------------------------------ --local: no container
# Every step talks to its target through pct exec and pct push. With --local the target is this
# machine: these stand-ins run the same commands here instead, so both paths share one set of steps
# and one set of checks. (The test suite routes them through a stub, hm-fake-local, that logs them.)
if [[ "$TARGET" == "local" || -n "$RUN_HERE" ]]; then
  pct() {
    local run=()
    [[ -n "${HM_FAKE_HOST-}" ]] && run=(hm-fake-local)
    case "$1" in
      status) "${run[@]}" test -f /etc/systemd/system/homelab-monitor.service && echo "status: running" ;;
      start) return 0 ;;
      exec) shift 2; [[ "${1-}" == "--" ]] && shift; "${run[@]}" "$@" ;;
      push) "${run[@]}" install -m 0600 "$3" "$4" ;;
      *) echo "pct $1 is not used with --local" >&2; return 1 ;;
    esac
  }
fi

step_label() { local l; for l in "${STEPS[@]}"; do [[ "$(step_field "$l" 0)" == "$1" ]] && step_field "$l" 1; done; }

show_summary() {
  if [[ "$TARGET" == "local" ]]; then
    printf '   %sMachine%s    %-22s %sSystem%s   %s\n' "$D" "$R" "$HOSTNAME" "$D" "$R" "${OS_NAME:-Ubuntu or Debian}"
    printf '   %sContainer%s  %-22s %sTime%s     %s\n' "$D" "$R" "none (--local)" "$D" "$R" "${NTP_SERVER:-as it is now}"
    printf '   %sRestore%s    %s\n' "$D" "$R" \
      "$([[ "$RESTORE" == latest ]] && echo "newest backup from ${SYNCTHING_KEYS_NFS:+Syncthing, identity }${SYNCTHING_KEYS_NFS:-$BACKUP_NFS}" || echo "no, fresh install")"
    demo_wanted && printf '   %sDemo%s       %s\n' "$D" "$R" "made-up devices to look around (Settings, Demo data removes them)"
    return 0
  fi
  printf '   %sContainer%s  %-22s %sNetwork%s  %s\n' "$D" "$R" "${CTID} ${HOSTNAME}" "$D" "$R" "${BRIDGE}${VLAN_TAG:+ VLAN $VLAN_TAG}, ${IP_ADDRESS}${MAC_ADDRESS:+, $MAC_ADDRESS}"
  printf '   %sDisk%s       %-22s %sTemplate%s %s\n' "$D" "$R" "${DISK_SIZE} GiB on ${DISK_STORAGE:-auto}" "$D" "$R" "Ubuntu 24.04 on ${TEMPLATE_STORAGE:-auto}"
  printf '   %sCPU, RAM%s   %-22s %sRestore%s  %s\n' "$D" "$R" "${CORES} cores, ${MEMORY} MiB" "$D" "$R" \
    "$([[ "$RESTORE" == latest ]] && echo "newest backup from ${SYNCTHING_KEYS_NFS:+Syncthing, identity }${SYNCTHING_KEYS_NFS:-$BACKUP_NFS}" || echo "no, fresh install")"
  printf '   %sKind%s       %-22s %sSSH%s      %s\n' "$D" "$R" "$([[ "$UNPRIVILEGED" == 1 ]] && echo unprivileged || echo privileged)" "$D" "$R" \
    "$([[ -n "$SSH_KEY_LINE" ]] && echo "root with your key only" || echo "root with the password")"
  printf '   %sReach%s      %s\n' "$D" "$R" "SSH and the web page from ${ADMIN_NET:-private addresses}; other incoming traffic dropped"
  demo_wanted && printf '   %sDemo%s       %s\n' "$D" "$R" "made-up devices to look around (Settings, Demo data removes them)"
  return 0
}

# ------------------------------------------------------------------ the container's kind and root SSH
# A person at the terminal is asked; anyone else gets the same warnings printed, in the log and on
# the last screen, and is never asked. HM_TEST_ASK lets the test suite answer on a pipe.
hm_interactive() {
  [[ -z "${HM_NO_ASK-}" ]] || return 1
  [[ -n "${HM_TEST_ASK-}" ]] && return 0
  [[ -t 0 && -z "${HM_FAKE_HOST-}" ]]
}
SEC_NOTES=()            # one line each under "Good to know" on the last screen
# Printed to the terminal and kept in the log as plain text (a log problem never stops the install).
warn_head() { printf '\n  %s⚠  %s%s\n' "$YEL$B" "$1" "$R"; { printf '\n⚠  %s\n' "$1" >> "$LOG"; } 2>/dev/null || true; }
warn_line() { printf '    %s\n' "$1"; { printf '    %s\n' "$1" >> "$LOG"; } 2>/dev/null || true; }
warn_privileged() {  # new or upgrade
  warn_head "This container is privileged."
  warn_line "Root inside a privileged container is close to root on this Proxmox host, so if someone broke"
  warn_line "into the monitor's container they could reach the host too."
  warn_line "Privileged is only needed so the container can mount NFS shares itself."
  warn_line "With an unprivileged container this host mounts the NFS shares and copies backups and the"
  warn_line "Syncthing identity in instead."
  if [[ "$1" == upgrade ]]; then
    warn_line "To change it: set UNPRIVILEGED=1 at the top of this file, then run --rebuild with RESTORE=\"latest\"."
  elif ! hm_interactive; then
    warn_line "Set UNPRIVILEGED=1 at the top of this file to use it."
  fi
  return 0
}
warn_password() {  # new or upgrade
  warn_head "Root can log in to the container over SSH with a password."
  warn_line "It is allowed from: ${ADMIN_NET:-every private address}."
  warn_line "Each connection gets 3 tries (MaxAuthTries 3) and each address can open 10 new connections a minute."
  warn_line "To use a key instead, set ROOT_SSH_KEY at the top of this file to your public key."
  [[ "$1" == upgrade ]] && warn_line "Then run the upgrade again: password logins over SSH are switched off."
  return 0
}
choose_kind() {  # Enter (or the end of the input) keeps the kind from the settings
  local a def=1
  [[ "$UNPRIVILEGED" == 1 ]] && def=2
  echo
  say "What kind of container?"
  say "  1  Privileged (default; the container mounts NFS shares itself)"
  say "  2  Unprivileged (safer; this Proxmox host mounts NFS shares and copies backups and the Syncthing identity in)"
  while :; do
    read -r -p "  Kind, 1 or 2 [${def}]: " a || a=""
    a="${a%$'\r'}"; a="${a:-$def}"
    case "$a" in
      1) UNPRIVILEGED=0; break ;;
      2) UNPRIVILEGED=1; break ;;
    esac
    say "${YEL}Type 1 or 2.${R}"
  done
  set_features
}
# A new install or a rebuild: after the questions, before the summary. One typed ACCEPT covers both
# warnings; a pasted key takes the password warning away.
container_choices() {
  local a need=0
  hm_interactive && choose_kind
  if [[ "$UNPRIVILEGED" != 1 ]]; then
    warn_privileged new; need=1
    SEC_NOTES+=("Privileged container: root in it is close to root on the Proxmox host.")
  fi
  if [[ -z "$SSH_KEY_LINE" ]]; then
    warn_password new
    if hm_interactive; then
      while :; do
        read -r -p "  Paste a public key to use it instead, or press Enter to keep the password: " a || a=""
        a="${a%$'\r'}"
        [[ -z "$a" ]] && break
        if parse_key "$a"; then ROOT_SSH_KEY="$a"; say "${GRN}Root will log in over SSH with that key only.${R}"; break; fi
        say "${YEL}That is not a public key line (ssh-ed25519 AAAA... you@pc) or a file holding one.${R}"
      done
    fi
    if [[ -z "$SSH_KEY_LINE" ]]; then
      need=1
      SEC_NOTES+=("Root can log in over SSH with a password from ${ADMIN_NET:-every private address}.")
    fi
  fi
  if (( need )) && hm_interactive; then
    echo
    read -r -p "  Type ACCEPT to carry on with the above: " a || a=""
    [[ "$a" == "ACCEPT" ]] || die "Cancelled. Nothing was changed."
  fi
  echo
  return 0
}
# An upgrade only prints the warnings: the kind was chosen at install and an upgrade cannot change it.
# The container's own sshd_config is read, as the owner may have changed it by hand.
upgrade_warnings() {
  local kind="$UNPRIVILEGED"
  [[ "$TARGET" == container ]] || return 0
  [[ -n "$RUN_HERE" ]] || kind="$(ct_conf "$CTID" unprivileged)"
  [[ "$kind" == 1 ]] || warn_privileged upgrade
  if [[ -z "$SSH_KEY_LINE" ]] && pct exec "$CTID" -- grep -qE '^\s*PermitRootLogin\s+yes' /etc/ssh/sshd_config 2>/dev/null; then
    warn_password upgrade
  fi
  return 0
}
print_sec_notes() {
  local n
  for n in "${SEC_NOTES[@]}"; do printf '      %-9s %s\n' "Security" "$n"; done
  return 0
}

# ------------------------------------------------------------------ preview (changes nothing)
if [[ "$MODE" == "preview" ]]; then
  clear 2>/dev/null || true
  banner
  say "${D}Preview only: nothing is created. This is what an install looks like.${R}"
  echo
  DISK_STORAGE="${DISK_STORAGE:-local-lvm}"; TEMPLATE_STORAGE="${TEMPLATE_STORAGE:-local}"
  show_summary
  if [[ "$TARGET" == container ]]; then
    [[ "$UNPRIVILEGED" == 1 ]] || warn_privileged new
    [[ -n "$SSH_KEY_LINE" ]] || warn_password new
  fi
  echo
  if [[ "$TARGET" == "local" ]]; then
    say "${D}With --local nothing asks for a password: your own logins stay as they are.${R}"
  elif [[ -t 0 ]]; then
    read -r -s -p "  Root password for the new container (preview, not used): " _ || true; echo; unset _
  else
    printf '  Root password for the new container (your SSH login to it): ••••••••••\n  Once more: ••••••••••\n'
    sleep 1
  fi
  fake() { local n; for n in 1 2 3 4 5 6; do echo "Setting up package-$RANDOM (1.$n) ..."; sleep 0.4; done; }
  define_steps
  start_drawer
  for line in "${STEPS[@]}"; do [[ -n "$line" ]] && run_step "$(step_field "$line" 0)" fake; done
  sleep 0.6
  stop_drawer
  IP="192.168.1.51"; SETUP_TOKEN="preview-code-1234"
fi

# ------------------------------------------------------------------ embedded application
PAYLOAD="$(mktemp)"
sed -n '/^__PAYLOAD_BEGIN__$/,/^__PAYLOAD_END__$/p' "$0" | sed '1d;$d' | base64 -d > "$PAYLOAD" 2>/dev/null \
  || { [[ "$MODE" == "preview" ]] || die "The embedded application is damaged; copy home_monitor.sh to the host again"; }
# The application must be exactly what build.py packed (a damaged or changed copy is never installed).
if [[ "$MODE" != "preview" ]] && command -v sha256sum >/dev/null; then
  [[ "$(sha256sum "$PAYLOAD" | awk '{print $1}')" == "$PAYLOAD_SHA256" ]] \
    || die "The embedded application does not match its checksum; copy home_monitor.sh to the host again"
fi

wait_for_ct() {
  for _ in {1..120}; do
    pct exec "${CTID}" -- bash -lc 'test -r /etc/os-release' >/dev/null 2>&1 && return 0
    sleep 2
  done
  return 1
}

# ------------------------------------------------------------------ the box's own settings win
# An upgrade, a restore or a rebuild from the Proxmox host rewrites the firewall and settings.env from
# this file. A freshly downloaded file has these blank, so they must never silently widen who may
# reach the box: what the box recorded (settings.env) is read first. Blank here keeps it. A different
# value is asked about at a terminal, and otherwise the recorded one is kept with a note. The record
# was written by root in the container, so it is checked like any other input.
note_line() { say "$1"; { printf '%s\n' "$1" >> "$LOG"; } 2>/dev/null || true; }
same_form() {  # two lists with the same entries in any order
  [[ "$(net_words "$1" | sort -u | tr '\n' ' ')" == "$(net_words "$2" | sort -u | tr '\n' ' ')" ]]
}
settle() {  # name shown, value in this file, recorded value -> SETTLED
  local name="$1" file="$2" rec="$3" a
  SETTLED="$rec"
  [[ -z "$file" ]] && return 0
  if [[ "$name" == ROOT_SSH_KEY ]]; then [[ "$file" == "$rec" ]] && { SETTLED="$file"; return 0; }
  else same_form "$file" "$rec" && { SETTLED="$file"; return 0; }; fi
  if hm_interactive; then
    echo
    printf '  %-34s %s\n' "${name} in this file:" "$file" "${name} this box was set with:" "${rec:-(blank)}"
    read -r -p "  Type yes to use the value from this file. Press Enter to keep the one on the box: " a || a=""
    if [[ "${a,,}" == yes ]]; then SETTLED="$file"; return 0; fi
    note_line "${name}: kept the value this box uses."
  else
    note_line "${name}: this file differs from what the box uses, so the box's value was kept. Run this at a terminal to change it."
    SEC_NOTES+=("${name}: this file differs from what the box uses, so the box's value was kept.")
  fi
  return 0
}
reconcile_recorded() {
  local line rec_admin="" rec_snmp="" rec_key="" have=0 v
  [[ "$TARGET" == container && -z "$RUN_HERE" ]] || return 0
  if [[ "$MODE" != rebuild ]]; then
    # An upgrade and a restore never change the kind: the container's own config is the truth.
    v="$(ct_conf "$CTID" unprivileged)"
    if [[ "$v" != 1 && "$UNPRIVILEGED" == 1 ]]; then
      note_line "This container is privileged and UNPRIVILEGED=1 in this file does not change that. An upgrade never changes the kind of a container: use --rebuild."
      SEC_NOTES+=("UNPRIVILEGED=1 in this file was not applied: an upgrade never changes the kind (use --rebuild).")
    fi
    if [[ "$v" == 1 ]]; then UNPRIVILEGED=1; else UNPRIVILEGED=0; fi
    set_features
    pct status "${CTID}" 2>/dev/null | grep -q running || pct start "${CTID}" >> "$LOG" 2>&1 || true
    wait_for_ct || true
  elif ! pct status "${CTID}" 2>/dev/null | grep -q running; then
    note_line "CT ${CTID} is not running, so its recorded settings could not be read: the values in this file are used."
    return 0
  fi
  while IFS= read -r line || [[ -n "$line" ]]; do
    [[ "$line" =~ $set_re ]] || continue
    have=1
    case "${BASH_REMATCH[1]}" in
      ADMIN_NET) rec_admin="$(keep_valid_nets ADMIN_NET "${BASH_REMATCH[2]}")" ;;
      SNMP_ALLOW) rec_snmp="$(keep_valid_nets SNMP_ALLOW "${BASH_REMATCH[2]}")" ;;
      SSH_KEY_LINE) v="${BASH_REMATCH[2]}"; [[ "$v" =~ $key_re ]] && rec_key="$v" ;;
    esac
  done < <(pct exec "${CTID}" -- cat "${INSTALL_DIR}/settings.env" 2>/dev/null || true)
  (( have )) || return 0          # installed before 0.8.0: no record, the file's values apply
  settle ADMIN_NET "$ADMIN_NET" "$rec_admin"; ADMIN_NET="$SETTLED"
  settle SNMP_ALLOW "$SNMP_ALLOW" "$rec_snmp"; SNMP_ALLOW="$SETTLED"
  settle ROOT_SSH_KEY "$SSH_KEY_LINE" "$rec_key"; SSH_KEY_LINE="$SETTLED"; ROOT_SSH_KEY="$SETTLED"
  return 0
}

push_app() {
  # Files go through /root (root only) in the container, never a shared /tmp another user could prepare.
  pct push "${CTID}" "$PAYLOAD" /root/.hm-app.tar.gz
  pct exec "${CTID}" -- bash -lc "set -e; rm -rf ${APP_DIR}.new; mkdir -p ${APP_DIR}.new; tar -xzf /root/.hm-app.tar.gz -C ${APP_DIR}.new; rm -f /root/.hm-app.tar.gz; rm -rf ${APP_DIR}.old; [ -d ${APP_DIR} ] && mv ${APP_DIR} ${APP_DIR}.old || true; mv ${APP_DIR}.new ${APP_DIR}; chown -hR root:root ${APP_DIR}; chmod -R go-w ${APP_DIR}"
}

# ------------------------------------------------------------------ upgrade
if [[ "$MODE" == "upgrade" || "$MODE" == "check" || "$MODE" == "restore" || "$MODE" == "report" ]]; then
  if [[ "$TARGET" == "local" || -n "$RUN_HERE" ]]; then
    [[ $EUID -eq 0 || -n "${HM_FAKE_HOST-}" ]] || die "Run as root: sudo bash $(basename "$0") --local --${MODE}"
    pct status "${CTID}" >/dev/null 2>&1 || die "The monitor is not installed on this machine; run bash $(basename "$0") --local to install it."
  else
    command -v pct >/dev/null || die "Not a Proxmox host (pct not found). Installed on this machine with --local? Then run bash $(basename "$0") --local --${MODE}"
    find_monitor_ct
    pct status "${CTID}" >/dev/null 2>&1 || die "CT ${CTID} has the tag ${HM_TAG} but Proxmox does not know it (pct status)."
    if [[ "$MODE" == upgrade || "$MODE" == restore ]]; then reconcile_recorded; fi
  fi
  # The rest happens after the helper files below are written (see "run the upgrade").
fi

# ------------------------------------------------------------------ problem report (changes nothing)
# The report.py of this build is copied in (the installed app may be older than the report), run as
# root so it can add the service's state and log, then removed. It masks addresses, names and secrets
# itself. The result is printed and kept beside this file for pasting into a GitHub issue.
if [[ "$MODE" == "report" ]]; then
  REPORT_PY="$(mktemp)"
  tar -xzf "$PAYLOAD" -O report.py > "$REPORT_PY" 2>/dev/null && [[ -s "$REPORT_PY" ]] || die "This file has no report.py (an older build)."
  pct push "${CTID}" "$REPORT_PY" /root/.hm-report.py
  rm -f "$REPORT_PY"
  OUT="$(pwd)/home-monitor-report-$(date +%Y%m%d-%H%M%S).txt"
  {
    echo "Made by home_monitor.sh ${VERSION} --report on $([[ "$TARGET" == local ]] && echo "the monitor machine (--local)" || echo "the Proxmox host ($(pveversion 2>/dev/null | head -n 1 | cut -d/ -f1-2))")."
    echo "Container: $([[ "$TARGET" == local ]] && echo none || pct status "${CTID}" 2>/dev/null)"
    echo
    pct exec "${CTID}" -- python3 /root/.hm-report.py --db "${DATA_DIR}/monitor.db" --app "${APP_DIR}" --install "${INSTALL_DIR}" --journal \
      || echo "The report could not be made inside ${WHERE} (is python3 there?)."
  } | tee "$OUT"
  pct exec "${CTID}" -- rm -f /root/.hm-report.py >/dev/null 2>&1 || true
  printf '\n  %sSaved as %s%s\n  Paste it into a new issue: %s\n\n' "$B" "$OUT" "$R" "https://github.com/The-Flying-Pancake/Home_Monitor/issues/new?template=problem.yml"
  exit 0
fi

# ------------------------------------------------------------------ install / rebuild
if [[ "$TARGET" == "local" && "$MODE" == "install" ]]; then
  [[ $EUID -eq 0 || -n "${HM_FAKE_HOST-}" ]] || die "Run as root on this machine: sudo bash $(basename "$0") --local"
  ! command -v pveversion >/dev/null || die "This is a Proxmox host: run bash $(basename "$0") without --local, and the monitor gets a container of its own."
  for b in apt-get systemctl base64 tar; do command -v "$b" >/dev/null || die "--local needs Ubuntu or Debian with systemd ($b not found)."; done
  OS_RELEASE="${HM_FAKE_OS_RELEASE:-/etc/os-release}"
  OS_ID="$(. "$OS_RELEASE" 2>/dev/null; echo "${ID-}")"
  OS_VER="$(. "$OS_RELEASE" 2>/dev/null; echo "${VERSION_ID-0}")"
  OS_NAME="$(. "$OS_RELEASE" 2>/dev/null; echo "${PRETTY_NAME-unknown}")"
  case "$OS_ID" in
    ubuntu) OS_MIN="22.04" ;;
    debian) OS_MIN="12" ;;
    *) die "--local supports Ubuntu 22.04 or newer and Debian 12 or newer; this is ${OS_NAME}." ;;
  esac
  [[ "$(printf '%s\n' "$OS_MIN" "$OS_VER" | sort -V | head -n 1)" == "$OS_MIN" ]] \
    || die "--local needs ${OS_ID^} ${OS_MIN} or newer (for Python 3.10); this is ${OS_NAME}."
  [[ -z "$NTP_SERVER" || "$NTP_SERVER" =~ ^[A-Za-z0-9.:-]+( [A-Za-z0-9.:-]+)*$ ]] \
    || die "NTP_SERVER should be one or more addresses or names separated by spaces."
  if [[ "$RESTORE" == "latest" && -z "$SYNCTHING_KEYS_NFS" && -z "$BACKUP_NFS" ]]; then
    die "RESTORE=\"latest\" needs SYNCTHING_KEYS_NFS or BACKUP_NFS in the settings at the top of this file."
  fi
  pct status "${CTID}" >/dev/null 2>&1 \
    && die "The monitor is already installed on this machine. Use --local --upgrade to update it (or --local --check first)."
  clear 2>/dev/null || true
  banner
  show_summary
  echo
  say "${YEL}${B}This machine becomes the monitor.${R} Best on a VM of its own (2 cores, 1 GiB, 8 GiB disk)."
  say "  • Outbound internet is limited to package sources and Telegram, for the whole machine."
  say "    Your local network stays reachable, and SSH sessions in keep working."
  say "  • Installed: the monitor service, snmpd (read-only, this machine only), nftables, Syncthing"
  say "    (off until you use it) and a daily backup. The system journal is capped at 200 MB."
  say "  • Your logins, passwords and SSH settings are left as they are."
  say "  • ${YEL}No inbound firewall:${R} --local does not add one. The web page (port ${PORT}) and SNMP (UDP 161)"
  say "    can be reached by anything that can reach this machine.$([[ -z "$SNMP_ALLOW" ]] && echo " SNMP only answers this machine itself.")"
  [[ -n "$NTP_SERVER" ]] || say "  • ${YEL}Time:${R} internet time servers are blocked too. Unless this machine already uses one on your"
  [[ -n "$NTP_SERVER" ]] || say "    network, set NTP_SERVER at the top of this file first (2FA codes need a correct clock)."
  echo
  if [[ -t 0 && -z "${HM_FAKE_HOST-}" && -z "${HM_NO_ASK-}" && "$RESTORE" != latest ]]; then ask_demo; echo; fi
  read -r -p "  Type INSTALL to continue: " ok || ok=""
  [[ "$ok" == "INSTALL" ]] || die "Cancelled. Nothing was changed."
  SETUP_TOKEN="$(head -c 18 /dev/urandom | base64 | tr -d '/+=' | cut -c1-20)"
  s_here() {
    cat "$OS_RELEASE"
    uname -a
    df -h / || true
    getent hosts api.telegram.org || echo "Note: api.telegram.org does not resolve yet"
  }
fi

if [[ "$TARGET" == "container" && ( "$MODE" == "install" || "$MODE" == "rebuild" ) ]]; then
  # HM_FAKE_HOST: the test suite runs the install against stub pct, pveam and pvesm commands.
  [[ $EUID -eq 0 || -n "${HM_FAKE_HOST-}" ]] || die "Run as root on the Proxmox host."
  for b in pct pveam pvesm base64; do
    command -v "$b" >/dev/null || die "Not a Proxmox host ($b not found). To install on this machine itself (a VM, for example): bash $(basename "$0") --local"
  done
  clear 2>/dev/null || true
  banner
  KEEP_NET0=""
  if [[ "$MODE" == "rebuild" ]]; then
    find_monitor_ct
    adopt_ct
    reconcile_recorded
  else
    existing="$(tagged_cts | tr '\n' ' ')"
    if [[ -n "${existing// }" ]]; then
      printf '  %sA monitor container is already on this host: CT %s(tag %s). Upgrade updates it.%s\n' "$YEL" "$existing" "$HM_TAG" "$R"
      [[ -t 0 && -z "${HM_FAKE_HOST-}" ]] || die "Not installing a second monitor without a person to confirm it. To update the existing one: bash $(basename "$0") --upgrade"
      read -r -p "  Install a second monitor anyway? Type yes: " ok || ok=""
      [[ "${ok,,}" == "yes" ]] || die "Cancelled."
    fi
  fi

  # Storage: validate what was set, or pick.
  pick_storage() {  # content kind, preferred name
    pvesm status -content "$1" 2>/dev/null | awk 'NR > 1 && $3 == "active" {print $1, $6}' > "$STATE/stores.$1"
    if grep -q "^$2 " "$STATE/stores.$1"; then echo "$2"; else sort -k2 -nr "$STATE/stores.$1" | awk 'NR == 1 {print $1}'; fi
  }
  check_storage() {  # name content kind, human kind
    pvesm status -content "$2" 2>/dev/null | awk 'NR > 1 {print $1}' | grep -qx "$1" && return 0
    die "Storage \"$1\" cannot hold $3. Storages that can: $(pvesm status -content "$2" 2>/dev/null | awk 'NR > 1 {printf "%s ", $1}')"
  }
  if [[ -n "$TEMPLATE_STORAGE" ]]; then check_storage "$TEMPLATE_STORAGE" vztmpl "container templates"; else TEMPLATE_STORAGE=$(pick_storage vztmpl local); fi
  if [[ -n "$DISK_STORAGE" ]]; then check_storage "$DISK_STORAGE" rootdir "container disks"; else DISK_STORAGE=$(pick_storage rootdir local-lvm); fi
  [[ -n "$TEMPLATE_STORAGE" && -n "$DISK_STORAGE" ]] || die "No storage found for templates or container disks (pvesm status)."
  if [[ "$RESTORE" == "latest" && -z "$SYNCTHING_KEYS_NFS" && -z "$BACKUP_NFS" ]]; then
    die "RESTORE=\"latest\" needs SYNCTHING_KEYS_NFS or BACKUP_NFS in the settings at the top of this file."
  fi

  # A first install, run by a person at the terminal: ask for the container ID, its name and its
  # address in a framed box, with the settings above as the answers Enter keeps. Not asked with
  # --rebuild (the container already has them), --local, or when nobody is at the terminal
  # (piped, or HM_NO_ASK=1): then the settings above are used as they are.
  if [[ "$MODE" == "install" && -t 0 && -z "${HM_FAKE_HOST-}" && -z "${HM_NO_ASK-}" ]]; then
    hm_line() { printf '  %s|%s %-62s %s|%s\n' "$D" "$R" "$1" "$D" "$R"; }
    hm_rule() { printf '  %s+%s+%s\n' "$D" "----------------------------------------------------------------" "$R"; }
    hm_ask() {  # prompt, default -> REPLY
      local a; read -r -p "  $1 [$2]: " a || a=""; REPLY="${a:-$2}"
    }
    if pct status "${CTID}" >/dev/null 2>&1; then
      CTID="$(pvesh get /cluster/nextid 2>/dev/null || echo "$CTID")"
    fi
    hm_rule
    hm_line "HOMELAB MONITOR  :  new container on this Proxmox host"
    hm_line ""
    hm_line "New container. Press Enter to keep the answer in [brackets]."
    hm_rule
    while :; do
      hm_ask "Container ID" "$CTID"
      if [[ ! "$REPLY" =~ ^[1-9][0-9]{2,8}$ ]]; then printf '  %sA number from 100 up.%s\n' "$YEL" "$R"; continue; fi
      if pct status "$REPLY" >/dev/null 2>&1 || qm status "$REPLY" >/dev/null 2>&1; then
        printf '  %sID %s is already in use. Free: %s%s\n' "$YEL" "$REPLY" "$(pvesh get /cluster/nextid 2>/dev/null || echo '?')" "$R"; continue
      fi
      CTID="$REPLY"; break
    done
    while :; do
      hm_ask "Container name" "$HOSTNAME"
      [[ "$REPLY" =~ ^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?$ ]] && { HOSTNAME="$REPLY"; break; }
      printf '  %sLetters, digits and hyphens; no hyphen at either end.%s\n' "$YEL" "$R"
    done
    while :; do
      hm_ask "Address: dhcp, or a fixed one with its prefix (e.g. 192.168.1.51/24)" "$IP_ADDRESS"
      if [[ "${REPLY,,}" == "dhcp" ]]; then IP_ADDRESS="dhcp"; GATEWAY=""; break; fi
      if [[ "$REPLY" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([0-9]|[12][0-9]|3[0-2])$ ]]; then
        IP_ADDRESS="$REPLY"
        while :; do
          hm_ask "Gateway for ${IP_ADDRESS}" "${GATEWAY:-${IP_ADDRESS%.*}.1}"
          [[ "$REPLY" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] && { GATEWAY="$REPLY"; break; }
          printf '  %sAn address such as 192.168.1.1.%s\n' "$YEL" "$R"
        done
        break
      fi
      printf '  %sType dhcp, or an address with its prefix such as 192.168.1.51/24.%s\n' "$YEL" "$R"
    done
    if [[ -n "$MAC_ADDRESS" ]]; then
      hm_ask "Network card MAC (none: Proxmox picks one)" "$MAC_ADDRESS"
      if [[ "${REPLY,,}" == "none" ]]; then MAC_ADDRESS=""; elif [[ "$REPLY" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]]; then MAC_ADDRESS="$REPLY"; fi
    fi
    [[ "$RESTORE" != latest ]] && ask_demo
    hm_rule
    echo
  fi

  NET0="name=eth0,bridge=${BRIDGE},ip=${IP_ADDRESS},firewall=1"
  [[ -n "$GATEWAY" ]] && NET0+=",gw=${GATEWAY}"
  [[ -n "$MAC_ADDRESS" ]] && NET0+=",hwaddr=${MAC_ADDRESS}"
  [[ -n "$VLAN_TAG" ]] && NET0+=",tag=${VLAN_TAG}"
  # A rebuild comes back with the network card it had (address, MAC, bridge, VLAN).
  if [[ -n "$KEEP_NET0" ]]; then
    NET0="$KEEP_NET0"
    IP_ADDRESS="$(sed -n 's/.*ip=\([^,]*\).*/\1/p' <<<"$NET0")"; MAC_ADDRESS="$(sed -n 's/.*hwaddr=\([^,]*\).*/\1/p' <<<"$NET0")"
    BRIDGE="$(sed -n 's/.*bridge=\([^,]*\).*/\1/p' <<<"$NET0")"; VLAN_TAG="$(sed -n 's/.*tag=\([^,]*\).*/\1/p' <<<"$NET0")"
  fi

  container_choices
  show_summary
  echo

  if pct status "${CTID}" >/dev/null 2>&1; then
    [[ "$MODE" == "rebuild" ]] || die "CT ${CTID} already exists. Use --upgrade to update the app, or --rebuild to destroy and reinstall it."
    printf '  %s%sThis DESTROYS CT %s and everything in it.%s\n' "$RED" "$B" "$CTID" "$R"
    read -r -p "  Type REBUILD to continue: " ok
    [[ "$ok" == "REBUILD" ]] || die "Cancelled."
  fi

  while :; do
    read -r -s -p "  Root password for the new container (your SSH login to it): " PW1; echo
    read -r -s -p "  Once more: " PW2; echo
    [[ "$PW1" == "$PW2" ]] && (( ${#PW1} >= 12 )) && break
    printf '  %sThe two did not match or are shorter than 12 characters. Try again.%s\n\n' "$YEL" "$R"
  done
  ROOT_PASSWORD="$PW1"; unset PW1 PW2
  SETUP_TOKEN="$(head -c 18 /dev/urandom | base64 | tr -d '/+=' | cut -c1-20)"

  # --- steps (each runs in its own subshell; see run_step) ---
  s_host() {
    pveversion
    pvesm status
    if pct status "${CTID}" >/dev/null 2>&1; then pct stop "${CTID}" || true; pct destroy "${CTID}" --purge; fi
  }
  s_template() {
    pveam update || true
    local t
    t="$(pveam available --section system | awk '{print $2}' | grep "^${TEMPLATE_SERIES}" | sort -V | tail -n1)"
    [[ -n "$t" ]] || t="$(pveam list "${TEMPLATE_STORAGE}" | awk '{print $1}' | sed 's|.*/||' | grep "^${TEMPLATE_SERIES}" | sort -V | tail -n1)"
    [[ -n "$t" ]] || { echo "No ${TEMPLATE_SERIES} template available"; return 1; }
    pveam list "${TEMPLATE_STORAGE}" | awk '{print $1}' | grep -q "${t}$" || pveam download "${TEMPLATE_STORAGE}" "${t}"
    echo "$t" > "$STATE/template"
  }
  s_create() {
    local extra=()
    [[ -n "$DNS_SERVER" ]] && extra+=(-nameserver "$DNS_SERVER")
    if [[ -n "$SSH_KEY_LINE" ]]; then
      printf '%s\n' "$SSH_KEY_LINE" > "$STATE/root-key.pub"
      extra+=(-ssh-public-keys "$STATE/root-key.pub")
    fi
    # The root password is set after the start, on stdin (a command line shows in ps on this host).
    echo "pct create ${CTID}"
    pct create "${CTID}" "${TEMPLATE_STORAGE}:vztmpl/$(cat "$STATE/template")" \
      -hostname "${HOSTNAME}" -cores "${CORES}" -memory "${MEMORY}" -swap "${SWAP}" \
      -rootfs "${DISK_STORAGE}:${DISK_SIZE}" -net0 "${NET0}" -unprivileged "${UNPRIVILEGED}" \
      -features "${FEATURES}" -timezone "${TIMEZONE:-host}" -onboot 1 -tty 2 \
      -tags "${HM_TAG}" -description "Homelab Monitor, installed by home_monitor.sh ${VERSION} on $(date +%Y-%m-%d). The tag ${HM_TAG} is how home_monitor.sh --upgrade finds this container." \
      "${extra[@]}"
  }
  s_boot() {
    pct start "${CTID}"
    wait_for_ct
    printf 'root:%s\n' "$ROOT_PASSWORD" | pct exec "${CTID}" -- chpasswd || { echo "Could not set the root password"; return 1; }
    for _ in {1..60}; do pct exec "${CTID}" -- bash -lc 'getent hosts archive.ubuntu.com' && return 0; sleep 2; done
    echo "The container has no working DNS or network yet"; return 1
  }
fi

if [[ "$MODE" == "install" || "$MODE" == "rebuild" ]]; then
  # Steps shared by both targets (pct is the stand-in above with --local).
  s_packages() { pct exec "${CTID}" -- bash /root/.hm-bootstrap.sh packages; }
  s_tools() { printf '%s\n' "$SNMP_COMMUNITY" | pct exec "${CTID}" -- bash /root/.hm-bootstrap.sh tools "$SNMP_ALLOW" "$TARGET" "$NTP_SERVER" "${SSH_KEY_LINE:+key}"; }
  s_syncthing() { pct exec "${CTID}" -- bash /root/.hm-bootstrap.sh syncthing; }
  s_share() { host_share_copy; }
  s_app() { push_app; }
  s_services() { install_services; }
  s_restore() {
    local unverified=0; [[ "$RESTORE_UNVERIFIED" == yes ]] && unverified=1
    pct exec "${CTID}" -- env HM_RESTORE_UNVERIFIED="$unverified" /root/restore.sh --latest
    pct exec "${CTID}" -- cat /var/lib/homelab-monitor/restored-from > "$STATE/restored" 2>/dev/null || true
  }
  s_web() {
    for _ in {1..45}; do
      pct exec "${CTID}" -- bash -lc "curl -fsS http://127.0.0.1:${PORT}/api/auth/status" && break
      sleep 2
    done
    pct exec "${CTID}" -- bash -lc "curl -fsS http://127.0.0.1:${PORT}/api/auth/status >/dev/null"
    pct exec "${CTID}" -- hostname -I | awk '{print $1}' > "$STATE/ip"
  }
  # The made-up devices, written as the monitor's own user into its database; the running monitor
  # sees demo mode switch on by itself. Settings, Demo data takes them away again.
  s_demo() {
    pct exec "${CTID}" -- runuser -u "${SERVICE_USER}" -- env MONITOR_DB_PATH="${DATA_DIR}/monitor.db" \
      MONITOR_KEY_FILE="${KEY_DIR}/vault.key" MONITOR_INSTALL_CONF="${INSTALL_DIR}/install.conf" \
      python3 "${APP_DIR}/demo.py" seed
  }
fi

# ------------------------------------------------------------------ files pushed into the container
# Upgrade check, run in the container by --upgrade and --check before anything is changed. One line
# per finding: OK|text, FIX|text|what the upgrade does about it, PKG|package, BLOCK|text,
# NOTE|text; the last line is HM_CHECK_DONE. The data check uses the NEW build's compat.py: a
# trial migration of a copy of the database with the new code.
PRECHECK="$(mktemp)"
cat > "$PRECHECK" <<"EOF"
#!/usr/bin/env bash
set -uo pipefail
APP="$1" DATA="$2" KEYDIR="$3" SVC="$4" NEW="$5" WANT_LAYOUT="$6"
ok(){ echo "OK|$*"; }; block(){ echo "BLOCK|$*"; }; note(){ echo "NOTE|$*"; }
# shellcheck disable=SC1091
. /etc/os-release 2>/dev/null || true
case "${ID-}" in
  ubuntu|debian) ok "System: ${PRETTY_NAME-}" ;;
  *) block "Unsupported system (${PRETTY_NAME-unknown}): the container must be Ubuntu or Debian" ;;
esac
command -v systemctl >/dev/null || block "No systemd in the container"
if command -v python3 >/dev/null; then
  v="$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
  if python3 -c 'import sys; sys.exit(sys.version_info < (3, 10))'; then ok "Python $v"; else block "Python $v is too old (3.10 or newer is needed)"; fi
else
  block "python3 is missing"
fi
python3 -c 'import cryptography' 2>/dev/null && ok "python3-cryptography" || { echo "FIX|python3-cryptography is missing|installs it"; echo "PKG|python3-cryptography"; }
for pair in nft:nftables ssh:openssh-client mount.nfs:nfs-common snmpd:snmpd curl:curl sqlite3:sqlite3 ping:iputils-ping dig:dnsutils; do
  cmd="${pair%%:*}" pkg="${pair#*:}"
  if command -v "$cmd" >/dev/null || [[ -x "/usr/sbin/$cmd" || -x "/sbin/$cmd" ]]; then ok "$pkg"; else echo "FIX|$pkg is missing|installs it"; echo "PKG|$pkg"; fi
done
id "$SVC" >/dev/null 2>&1 && ok "Service user $SVC" || block "The service user $SVC does not exist: this container was not built by this installer"
[[ -f /etc/systemd/system/homelab-monitor.service ]] && ok "Monitor service" || block "The homelab-monitor service is not installed"
[[ -d "$APP" ]] && ok "App folder $APP" || block "No app at $APP"
[[ -d /etc/homelab-monitor-egress ]] && ok "Outbound firewall folder" || echo "FIX|The outbound firewall folder is missing|creates it"
if [[ -f "$DATA/monitor.db" ]]; then ok "Database $DATA/monitor.db"; else block "No database at $DATA/monitor.db: there is nothing to upgrade (install fresh instead)"; fi
if [[ -s "$KEYDIR/vault.key" ]]; then ok "Vault key"
else block "No vault key at $KEYDIR/vault.key (an install from before key files): rebuild and restore, the restore asks for the old passphrase"; fi
LAYOUT=0
for f in /etc/homelab-monitor-install/layout "$KEYDIR/layout"; do
  [[ -f "$f" ]] && { LAYOUT="$(sed -n 's/^LAYOUT=//p' "$f")"; break; }
done
if [[ "${LAYOUT:-0}" -gt "$WANT_LAYOUT" ]]; then block "This container was set up by a newer installer (layout $LAYOUT, this one knows $WANT_LAYOUT): use the newer home_monitor.sh"
elif [[ "${LAYOUT:-0}" -eq 0 ]]; then note "Built before layout markers: checked item by item above"
else ok "Container layout $LAYOUT"; fi
if [[ -f "$DATA/monitor.db" ]]; then
  size_k=$(( $(stat -c %s "$DATA/monitor.db") / 1024 ))
  free_k=$(df -Pk "$DATA" | awk 'NR == 2 {print $4}')
  need_k=$(( size_k * 3 + 102400 ))
  if (( free_k >= need_k )); then ok "Free space $((free_k / 1024)) MB"
  else block "Not enough free space in $DATA: $((free_k / 1024)) MB free, $((need_k / 1024)) MB needed for the backup and the trial"; fi
fi
if [[ -f "$DATA/monitor.db" && -f "$NEW/compat.py" ]] && command -v python3 >/dev/null; then
  report="$(python3 "$NEW/compat.py" check --db "$DATA/monitor.db" --key "$KEYDIR/vault.key" --trial --json 2>&1)"
  python3 - "$report" <<'PY'
import json, sys
try:
    r = json.loads(sys.argv[1].strip().splitlines()[-1])
except (ValueError, IndexError):
    print("BLOCK|The data check could not run: " + sys.argv[1].strip()[-300:].replace(chr(10), " "))
    sys.exit(0)
print(("OK|" if r["exit"] == 0 else "BLOCK|") + "Data: " + r["message"])
if r.get("trial") and r["exit"] == 0:
    print("OK|" + r["trial"]["message"])
for n in r.get("notes", []):
    print("NOTE|" + n)
PY
fi
echo HM_CHECK_DONE
EOF
BOOT="$(mktemp)"
cat > "$BOOT" <<"EOF"
#!/usr/bin/env bash
# Container bootstrap, run in phases by home_monitor.sh: packages | tools <snmp allow list> | syncthing
set -euo pipefail
export DEBIAN_FRONTEND=noninteractive
APT=(-o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold)
backup_file(){ local f="$1"; [[ -f "$f" ]] && cp -a "$f" "${f}.bak.$(date +'%s')" || true; }

case "$1" in
packages)
  apt-get update -y
  apt-get "${APT[@]}" full-upgrade -y
  ;;
tools)
  read -r community
  target="${3:-container}" ntp="${4:-}"
  pkgs=(python3 python3-cryptography openssh-client iputils-ping nfs-common snmpd nftables dnsutils ca-certificates curl gnupg sqlite3 tar)
  # In a container the installer sets up SSH; with --local the machine keeps its own (none is added).
  [[ "$target" == "local" ]] || pkgs+=(openssh-server)
  apt-get "${APT[@]}" install -y --no-install-recommends "${pkgs[@]}"
  apt-get autoremove -y --purge; apt-get autoclean -y

  # journald size caps
  backup_file /etc/systemd/journald.conf
  printf '[Journal]\nStorage=auto\nSystemMaxUse=200M\nRuntimeMaxUse=200M\nSystemMaxFileSize=50M\n' > /etc/systemd/journald.conf
  systemctl restart systemd-journald || true

  if [[ "$target" != "local" ]]; then
    # SSH: root with the key from ROOT_SSH_KEY only (prohibit-password), or else with the password
    # set by the installer. Either way at most 3 tries per connection; the inbound firewall limits
    # new connections per address.
    login="yes"; [[ "${5:-}" == key ]] && login="prohibit-password"
    backup_file /etc/ssh/sshd_config
    if grep -qE '^\s*#?\s*PermitRootLogin' /etc/ssh/sshd_config; then
      sed -i "s/^\s*#\?\s*PermitRootLogin.*/PermitRootLogin ${login}/" /etc/ssh/sshd_config
    else
      echo "PermitRootLogin ${login}" >> /etc/ssh/sshd_config
    fi
    grep -qE '^\s*MaxAuthTries' /etc/ssh/sshd_config || echo "MaxAuthTries 3" >> /etc/ssh/sshd_config
    systemctl enable ssh >/dev/null 2>&1 || true
    systemctl restart ssh || true
  elif [[ -n "$ntp" ]]; then
    # --local: a time server on the LAN (the outbound firewall blocks internet ones). A container
    # takes its clock from the Proxmox host and needs none.
    if command -v chronyd >/dev/null; then
      install -d -m 0755 /etc/chrony/conf.d
      printf 'server %s iburst\n' $ntp > /etc/chrony/conf.d/homelab-monitor.conf
      systemctl restart chrony || true
    else
      install -d -m 0755 /etc/systemd/timesyncd.conf.d
      printf '[Time]\nNTP=%s\n' "$ntp" > /etc/systemd/timesyncd.conf.d/homelab-monitor.conf
      systemctl restart systemd-timesyncd || true
    fi
  fi

  # SNMP: read-only, the container itself only (the monitor polls its own host). Same layout as
  # Fix SNMP writes on other hosts. The community comes on stdin, never on a command line.
  # The own address is the source of the default route (no packet is sent); with DHCP keep a
  # reservation for the container, or the entry no longer matches after an address change.
  allow="${2:-}"
  if [[ -z "$allow" ]]; then
    allow="$(ip -4 -o route get 1.1.1.1 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "src") print $(i + 1)}')"
    [[ -n "$allow" ]] && allow="${allow}/32"
  fi
  backup_file /etc/snmp/snmpd.conf
  # IPv6 entries (with a colon) need rocommunity6 and an agent listening on udp6 too.
  read -r -a nets <<<"$allow"
  agent="udp:161"
  for net in "${nets[@]}"; do [[ "$net" == *:* ]] && agent="udp:161,udp6:161"; done
  {
    echo "# Written by the Homelab Monitor installer: read-only SNMP for this container itself"
    echo "agentAddress ${agent}"
    echo "view   hmmonitor  included   .1"
    for net in "${nets[@]}"; do
      if [[ "$net" == *:* ]]; then echo "rocommunity6 ${community} ${net} -V hmmonitor"; else echo "rocommunity  ${community} ${net} -V hmmonitor"; fi
    done
    echo "rocommunity  ${community} 127.0.0.1 -V hmmonitor"
    echo "sysName $(hostname)"
    echo "sysServices 72"
    echo "includeAllDisks 10%"
  } > /etc/snmp/snmpd.conf
  chmod 600 /etc/snmp/snmpd.conf
  systemctl enable snmpd >/dev/null 2>&1 || true
  systemctl restart snmpd
  ;;
syncthing)
  install -d -m 0755 /usr/share/keyrings
  # Syncthing's release key, carried in this file (fingerprint FBA2E162F2F44657B38F0309E5665F9BD5970C47,
  # from https://syncthing.net/release-key.txt, November 2024) rather than downloaded at install time.
  gpg --dearmor --yes -o /usr/share/keyrings/syncthing-archive-keyring.gpg <<'STKEY'
-----BEGIN PGP PUBLIC KEY BLOCK-----

mQINBGdCz4IBEACqA2UybPzUDw81EG0nXNUJ4Fk64pRkKqC5FwWUg7dPA4rtdMao
6uPTxJdRj+TZlEwYAUUtG18E6Yfrp1l0p4s1p5c57YGu95E24osHsAYbbRL+57oA
boyxKgbCxayd168r0jdKqyEPWAChPDul+Q+CkHLeh6VmFQxT82EJ2bkUFWU0rCRJ
qu1ZeSozdjVSx6pXUaqCdlSHIK4GH6ryqNyGXjwF8W6OgWCUa09ky+BbgWlorhED
/owmbe2/yNjVEdTdqZ029n4AswIfBLmDmZDw0/hHLn5QV/7D6DF/mJ3E3DAfozOM
o6PSqRgj+dIPfPO9VBFjjVrRfb77vU2n6twIsvKHU88XMF3ETruv3eCysUkvuOqY
CKzs9yhavQiR/xwn+yEaoQcJKapJdjM7MvFqZ8XDRxaBsySQukQ1XrhqnzmpXaDP
kgnqdzOKbWjG81bWSdkfkXgQENMEPzwG7tWovLEL3mQAZ7lcQoMHCY7joIcRRHIv
Ofy/B4fCrBG+PYHtMgfAfRCxoVqskqkp4Wf6nJ24H9stdXGwaIzko2vgCUgA43KU
D/M+i3NqvDIVQiNJiFzfSjov//GrjRuQTdJPv9CcMHU9ClStXthBYE+j4x01SGEQ
gLu+am/rjfPNz3JweFJTc26k1t7gYevCX5bgmrTeDkw80KX6vznT9mxqzQARAQAB
tDRTeW5jdGhpbmcgUmVsZWFzZSBNYW5hZ2VtZW50IDxyZWxlYXNlQHN5bmN0aGlu
Zy5uZXQ+iQJRBBMBCAA7FiEE+6LhYvL0RlezjwMJ5WZfm9WXDEcFAmdCz4ICGwMF
CwkIBwICIgIGFQoJCAsCBBYCAwECHgcCF4AACgkQ5WZfm9WXDEc1qQ/8C0ikLGWe
q3mCXsf+ZVi03dHfK/WXGheGhF8WedzGByt95Hfg4lLeDP+tjkEXSjhjhdAutE+4
QC6Q0kOsoyjO6Yr3lBOJYVurL8d9cyAb64o73vqLBX4rEShagQFlL5X4ZDrOixVU
CttOqlVQ4R97zNivs1klxLLiOnMexEGw1oTnazvbadtc0Fm+whuocjID/5wZIYVi
UrfyAwXYtLuuLPrYDPq26wrqwh3/VweqMpJtdwyRj3h9Va5hb5kLuee+wcc/kVYz
t3lgXzzI7usAUK2E7r4jXeclzzfJdZaW5bvBVLSsXcfr4eIvZ1T3gq1Z333k/T08
5qSiEhRu+8JNfQXgG7bpzcj+DPEEriOB7Jlg9jPpvowGKHdOwWQ/2/ua50Oy9+pO
lmkBtAaTKgGgedJ/6m2f3IPwsJRy2IvR1XyOtmnjp6Uur6VrJjkpxLWrtH1rGSiF
NKL7BHwt7pIVP0jKAR5xCybH0gYJuryk6h3NQxai4lse8n/GUrzUG5sFaKpQ9Ley
VrZxfF6X4cPgCcme/fEy4zmzW6pM6NCE3w8SC37MrO7q+tR9Ry1tsT/WxD6PQJXM
ThaMv1dE5d5Hgf2XH5oZj+zQSlUEtlWRs55EdgyAt8924lcoYolgVxa+sPYUmrPu
L6D4QRPQVJmA4HaP/NntoE0fMQYXiwjCNgmJATMEEAEIAB0WIQQ3yEVU5+CiYeT3
bh7Sbm7QAGVKPgUCZ0NMiAAKCRDSbm7QAGVKPtoVB/4iPlyyXlV962yHxKt9axzI
7jr4gpStMcdtcUdnl1iJ0LaoH5jlOLMfUnIs+gX1yXE5X0xAB0NJ0FSxwIkrlXtL
AyDoTehFb6Kwe3sacKT4my1B+Bm7hY+iwA/AGLbm8luq9hejQXGPUwmphS6Qxa0W
HBAe3gKMRPgqq4l1aVLLAlebtN9Sr+V1503P/Bv0bK3tBG3Sf3OsQ/B9zU+nqH3g
spq6r1Irv7OpMSXy0n2Z0S7/GcfSBmzeNqjNKGOJK+JlxzXFkv6FDoJDypZajXYV
+kdtTNdJ13UOpaixtI7MmrlMbJHcv3MBz/cdeJuPfX8dmpVvUJVXRgxhf+56/Yye
uQINBGdCz4IBEACmL+wL5ExN4BbCHP5TkS9mWB+nPp0icjBZ0d9MoP+O9twJFsn5
r1vx0hRhFhN9Z6v+FF4UbqUZJK0sQPfQjBfgWV280mSz+et8doA6x2liNFyk26iy
A8oiQmyWxqSMITpBJpRKEJFFg7iRKxWhYbY+/SLKDJpmFP3yfj1nTWL6xOZuqOGb
uCZF29Ztzcwc1u1JaNSwUxx2up3IjIxwIC9MABF30L/KeZFC2Mo7FnOeD7LB5jgu
Zux7Z6utqP+f2SMFtl3BHH4UYWu1AODqj7SazX+GpT7xSRz/U4LmpEd9frS0mOhi
P3DjY2xMzfmJ1ywWoT8PxZtmZE1cAQmSj4MCGdJ/41hlFSUaAadeW5JddDrLs5Fu
nbASMNC3Z/NdLcdbBjD03scw6dh0NOprDoIHQ2rghOVe52Ti5xtStwyuteIsKfXx
NkgKTtw0pMB//lXzEf0i9nAS7/M1JO8AR7h34EIXyA8258/FU3P8QC8WntAOVIu5
BALfjr/6ZS5GEVHvaZe47AU8gBw2ePwQ32ZFUmmgIx7eNSDJ+K31U85HegRU0UnW
RLYLdFr00af3PBJh1urSblRx/r5bAzV/RhYV7FJeSB9q8hCfRpvxjopcNP42GSzi
VmwS6Bx8JRetTYXIFDle7Pegfm/p3ILBt1BQYB/mnW+SLtPfDNbuPfBxzwARAQAB
iQI2BBgBCAAgFiEE+6LhYvL0RlezjwMJ5WZfm9WXDEcFAmdCz4ICGwwACgkQ5WZf
m9WXDEcKJA//SxfoLXb/qoGCLYGqpKJgVCrSbBFsBKRsrGYfN0bRy0QdEj98t25u
k4TpxVpbfylv154P0LMjoIjCte0imTjxCaXyNfG2gPuGsQibc7ZlTi6EnEmSUECq
VocOtbLahuixV/NZcaMCIuoMy9TvSvtHkFDiK9FRn9MmJ0iFs32wMLNaYzzWJvxy
0WCTTusEr+ElrXHRhSgwQiFxjcHqXdhloA8D6QmPoXaDBB/p8X8u/V/vg6LLG5+Z
gxxYfGO+Qi+7rUdT+yXozYVHk1QTq1SpGSZ2WneI0ssNM1YBznQpVELCKqwDKUIP
wRNzmFi/ZeoPBIqCOxDTz024dZTk/KJuIMGpv6VPZxP7GZpPH5CL18aivCmpm86q
BXLPWYUjW1/+8BGOBkQvAXcDAkpmhf5mEp5Tn39eitOsdYjP+95pCotFqv/EkFB4
pPsHlZY5qI84Jp3l3+Q2fqO5EouSk5uqY9NZ6BC8jiabJ2gleh/XrT2OUyIHkxhH
EBhXkS7YDiihj01h5GkfG0zC/ZYiMpmjrmGHbJL1iD0KFcvlJ6NpZIED7fJ27CYC
f2j9erXWl0nbIaBKPQd6PT5g+zG76Ndf5u3IgSBJihV7buSOO3aKTobn0QaOE5xP
EdXK0FhTStybyYKkNy2Xsx0pFU4A8XFM1ZpsaqIxSqL089Ub+WdiFT0=
=VBZG
-----END PGP PUBLIC KEY BLOCK-----
STKEY
  echo "deb [signed-by=/usr/share/keyrings/syncthing-archive-keyring.gpg] https://apt.syncthing.net/ syncthing stable" > /etc/apt/sources.list.d/syncthing.list
  apt-get update -y
  apt-get "${APT[@]}" install -y syncthing
  getent group syncthing >/dev/null || groupadd --system syncthing
  id syncthing >/dev/null 2>&1 || useradd --system --create-home --home-dir /var/lib/syncthing --shell /usr/sbin/nologin --gid syncthing syncthing
  # Off until setup or a restore turns it on with an identity.
  systemctl disable --now syncthing@syncthing >/dev/null 2>&1 || true
  id homelab-monitor >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin homelab-monitor
  install -d -m 0700 -o homelab-monitor -g homelab-monitor /var/lib/homelab-monitor /etc/homelab-monitor
  install -d -m 0755 /opt/homelab-monitor
  ;;
esac
EOF

FILES="$(mktemp -d)"

cat > "$FILES/homelab-monitor.service" <<UNIT
[Unit]
Description=Homelab Monitor
After=network-online.target
Wants=network-online.target
[Service]
User=${SERVICE_USER}
Group=${SERVICE_USER}
WorkingDirectory=${APP_DIR}
Environment=MONITOR_DB_PATH=${DATA_DIR}/monitor.db
# A random key, created on first start. Backups carry it, so a restore needs nothing typed.
Environment=MONITOR_KEY_FILE=${KEY_DIR}/vault.key
Environment=MONITOR_INSTALL_CONF=${INSTALL_DIR}/install.conf
Environment=MONITOR_LISTEN=0.0.0.0
Environment=MONITOR_PORT=${PORT}
Environment=MONITOR_HOSTNAMES=${HOSTNAME,,}
# A fresh database starts on HTTPS with a certificate made here; an upgraded one keeps its choice.
Environment=MONITOR_TLS_DEFAULT=self-signed
EnvironmentFile=-${KEY_DIR}/setup.env
ExecStart=/usr/bin/python3 ${APP_DIR}/server.py
Restart=on-failure
RestartSec=5
# Sized for the default 1 GB container. A larger install can raise these with systemctl edit.
MemoryHigh=640M
MemoryMax=768M
TasksMax=512
# ping needs a raw socket; nothing else is granted.
AmbientCapabilities=CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_RAW
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictNamespaces=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
LockPersonality=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
SystemCallArchitectures=native
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
UMask=0077
ReadWritePaths=${DATA_DIR} ${KEY_DIR}
[Install]
WantedBy=multi-user.target
UNIT

# Where restore.sh and the Settings page find the backup sources chosen in the settings block.
cat > "$FILES/install.conf" <<CONF
# Written by home_monitor.sh ${VERSION}. Read (never run) by /root/restore.sh and the Settings, System page.
CTID="${CTID}"
TARGET="${TARGET}"
SYNCTHING_KEYS_NFS="${SYNCTHING_KEYS_NFS}"
SYNCTHING_FOLDER="${SYNCTHING_FOLDER}"
BACKUP_NFS="${BACKUP_NFS}"
UNPRIVILEGED="${UNPRIVILEGED}"
INSTALLED="$(date +'%F %T')"
CONF
# The backup passphrase (root only on the container). Written only when set: a blank setting leaves
# the container's copy alone, so backups sealed with it can still be put back.
if [[ -n "$BACKUP_PASSPHRASE" ]]; then
  ( umask 077; printf '%s\n' "$BACKUP_PASSPHRASE" > "$FILES/backup-passphrase" )
fi
[[ -n "$SSH_KEY_LINE" ]] && printf '%s\n' "$SSH_KEY_LINE" > "$FILES/root-key.pub"

# The settings an Update from the web page needs to keep (it runs a clean release whose own settings
# block holds the defaults). Root only on the box; rewritten by every install and upgrade.
{
  echo "# Written by home_monitor.sh ${VERSION}. Read (never run) by home_monitor.sh --update-here."
  for name in CTID HOSTNAME PORT ADMIN_NET SNMP_ALLOW SSH_KEY_LINE UNPRIVILEGED SYNCTHING_KEYS_NFS SYNCTHING_FOLDER BACKUP_NFS TARGET; do
    printf '%s="%s"\n' "$name" "${!name-}"
  done
} > "$FILES/settings.env"

# Update from the web page: the app asks (a file in DATA/requests), root acts (updatectl.py).
cat > "$FILES/hm-update.path" <<UNIT
[Unit]
Description=Check for, install or undo an update when the monitor asks
[Path]
PathChanged=${DATA_DIR}/requests/update-check
PathChanged=${DATA_DIR}/requests/update-install
PathChanged=${DATA_DIR}/requests/rollback-code
PathChanged=${DATA_DIR}/requests/rollback-all
Unit=hm-update.service
[Install]
WantedBy=multi-user.target
UNIT

cat > "$FILES/hm-update.service" <<UNIT
[Unit]
Description=Homelab Monitor update (from the project's signed releases)
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 ${APP_DIR}/updatectl.py requests --data ${DATA_DIR}
TimeoutStartSec=45min
NoNewPrivileges=yes
LockPersonality=yes
RestrictRealtime=yes
UNIT

# At boot, before the monitor starts: an update or undo that a restart cut short is closed (the app
# folder put in one piece, the result recorded), so the page does not wait for it for ever. It runs
# the updater from the app folder, or from the one beside it when the app folder is missing.
cat > "$FILES/hm-update-recover.service" <<UNIT
[Unit]
Description=Close an update that a restart cut short
After=local-fs.target
Before=homelab-monitor.service hm-update.path
[Service]
Type=oneshot
ExecStart=/bin/bash /root/.hm-update-recover.sh ${APP_DIR} ${DATA_DIR}
TimeoutStartSec=5min
[Install]
WantedBy=multi-user.target
UNIT
cat > "$FILES/update-recover.sh" <<'EOF'
#!/usr/bin/env bash
# hm-update-recover.service: $1 the app folder, $2 the data folder.
for d in "$1" "$1.old" "$1.rolledback"; do
  if [[ -f "$d/updatectl.py" ]]; then exec /usr/bin/python3 "$d/updatectl.py" recover --data "$2"; fi
done
echo "No updatectl.py beside $1: nothing to recover with"
EOF

# Root SSH with a key, for containers made before ROOT_SSH_KEY or when it changes: the key is added
# and password logins over SSH are switched off. Run by an upgrade or a restore when the key is set.
cat > "$FILES/ssh-key.sh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
key="$(cat "$1")"
install -d -m 0700 /root/.ssh
touch /root/.ssh/authorized_keys
grep -qxF "$key" /root/.ssh/authorized_keys || printf '%s\n' "$key" >> /root/.ssh/authorized_keys
chmod 0600 /root/.ssh/authorized_keys
if grep -qE '^\s*#?\s*PermitRootLogin' /etc/ssh/sshd_config; then
  sed -i 's/^\s*#\?\s*PermitRootLogin.*/PermitRootLogin prohibit-password/' /etc/ssh/sshd_config
else
  echo "PermitRootLogin prohibit-password" >> /etc/ssh/sshd_config
fi
grep -qE '^\s*MaxAuthTries' /etc/ssh/sshd_config || echo "MaxAuthTries 3" >> /etc/ssh/sshd_config
systemctl reload ssh 2>/dev/null || systemctl restart ssh 2>/dev/null || true
EOF

# Inbound firewall (a container only): SSH and the web page from ADMIN_NET (blank: private
# addresses), Syncthing and DHCP from the LAN, SNMP from SNMP_ALLOW; everything else coming in is
# dropped. New SSH connections are limited to 10 a minute per address.
ADMIN4=(); ADMIN6=()
if [[ -n "${ADMIN_NET// }" ]]; then
  for net in ${ADMIN_NET//,/ }; do if [[ "$net" == *:* ]]; then ADMIN6+=("$net"); else ADMIN4+=("$net"); fi; done
else
  ADMIN4=(10.0.0.0/8 172.16.0.0/12 192.168.0.0/16); ADMIN6=(fc00::/7 fe80::/10)
fi
# SNMP from SNMP_ALLOW: IPv6 entries only ever go under ip6 saddr.
SNMP4=(); SNMP6=()
read -r -a SNMP_NETS <<<"$SNMP_ALLOW"
for net in "${SNMP_NETS[@]}"; do if [[ "$net" == *:* ]]; then SNMP6+=("$net"); else SNMP4+=("$net"); fi; done
nft_list() { local IFS=,; printf '%s' "$*"; }
{
  echo "# Written by home_monitor.sh ${VERSION}: what may reach this container. Loaded by hm-ingress.service."
  echo "table inet hm_ingress"
  echo "delete table inet hm_ingress"
  echo "table inet hm_ingress {"
  echo "  set ssh4 { type ipv4_addr; flags dynamic, timeout; timeout 1m; }"
  echo "  set ssh6 { type ipv6_addr; flags dynamic, timeout; timeout 1m; }"
  echo "  chain input {"
  echo "    type filter hook input priority 0; policy drop;"
  echo "    iifname \"lo\" accept"
  echo "    ct state established,related accept"
  echo "    ct state invalid drop"
  echo "    meta l4proto { icmp, ipv6-icmp } accept"
  echo "    udp dport { 68, 546 } accept"
  echo "    ip saddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 } meta l4proto { tcp, udp } th dport { 22000, 21027 } accept"
  echo "    ip6 saddr { fc00::/7, fe80::/10 } meta l4proto { tcp, udp } th dport { 22000, 21027 } accept"
  if (( ${#ADMIN4[@]} )); then
    echo "    ip saddr { $(nft_list "${ADMIN4[@]}") } tcp dport 22 ct state new update @ssh4 { ip saddr limit rate over 10/minute } drop"
    echo "    ip saddr { $(nft_list "${ADMIN4[@]}") } tcp dport { 22, ${PORT} } accept"
  fi
  if (( ${#ADMIN6[@]} )); then
    echo "    ip6 saddr { $(nft_list "${ADMIN6[@]}") } tcp dport 22 ct state new update @ssh6 { ip6 saddr limit rate over 10/minute } drop"
    echo "    ip6 saddr { $(nft_list "${ADMIN6[@]}") } tcp dport { 22, ${PORT} } accept"
  fi
  if (( ${#SNMP4[@]} )); then echo "    ip saddr { $(nft_list "${SNMP4[@]}") } udp dport 161 accept"; fi
  if (( ${#SNMP6[@]} )); then echo "    ip6 saddr { $(nft_list "${SNMP6[@]}") } udp dport 161 accept"; fi
  echo "    limit rate 6/minute log prefix \"hm-ingress-drop \" counter drop"
  echo "  }"
  echo "}"
} > "$FILES/ingress.nft"

cat > "$FILES/hm-ingress.service" <<'UNIT'
[Unit]
Description=Homelab Monitor inbound firewall
After=network-pre.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f /etc/homelab-monitor-egress/ingress.nft
ExecStop=/usr/sbin/nft delete table inet hm_ingress
[Install]
WantedBy=multi-user.target
UNIT

# Outbound firewall: LAN, package sources and Telegram only.
cat > "$FILES/egress-hosts" <<'HOSTS'
# Internet hosts the container may reach. Everything on the LAN is always allowed.
archive.ubuntu.com
security.ubuntu.com
ports.ubuntu.com
apt.syncthing.net
syncthing.net
api.telegram.org
HOSTS

# GitHub, for root only (Update): the app's own user stays without internet.
cat > "$FILES/github-hosts" <<'HOSTS'
api.github.com
github.com
objects.githubusercontent.com
release-assets.githubusercontent.com
HOSTS

cat > "$FILES/egress-refresh.sh" <<'REFRESH'
#!/usr/bin/env bash
# Resolves the allowed internet hosts into the firewall sets. Run on a timer: CDN addresses change.
set -uo pipefail
v4=(); v6=()
while read -r host; do
  [[ -z "$host" || "$host" == \#* ]] && continue
  while read -r ip; do [[ -n "$ip" ]] && v4+=("$ip"); done < <(dig +short A "$host" | grep -E '^[0-9.]+$')
  while read -r ip; do [[ -n "$ip" ]] && v6+=("$ip"); done < <(dig +short AAAA "$host" | grep -E '^[0-9a-fA-F:]+$')
done < <(cat /etc/homelab-monitor-egress/hosts
         # Plus the hosts this machine's own apt sources name (a local mirror, Debian, extra repos).
         cat /etc/apt/sources.list /etc/apt/sources.list.d/*.list /etc/apt/sources.list.d/*.sources 2>/dev/null \
           | grep -v '^[[:space:]]*#' | grep -oE 'https?://[^/[:space:]]+' | sed -E 's#^https?://##; s#^[^@]*@##; s#:[0-9]+$##' | sort -u)
nft flush set inet hm_egress allow4
nft flush set inet hm_egress allow6
(( ${#v4[@]} )) && nft add element inet hm_egress allow4 "{ $(IFS=,; echo "${v4[*]}") }"
(( ${#v6[@]} )) && nft add element inet hm_egress allow6 "{ $(IFS=,; echo "${v6[*]}") }"
g4=(); g6=()
while read -r host; do
  [[ -z "$host" || "$host" == \#* ]] && continue
  while read -r ip; do [[ -n "$ip" ]] && g4+=("$ip"); done < <(dig +short A "$host" | grep -E '^[0-9.]+$')
  while read -r ip; do [[ -n "$ip" ]] && g6+=("$ip"); done < <(dig +short AAAA "$host" | grep -E '^[0-9a-fA-F:]+$')
done < <(cat /etc/homelab-monitor-egress/github-hosts 2>/dev/null)
nft flush set inet hm_egress github4 2>/dev/null || true
nft flush set inet hm_egress github6 2>/dev/null || true
(( ${#g4[@]} )) && nft add element inet hm_egress github4 "{ $(IFS=,; echo "${g4[*]}") }"
(( ${#g6[@]} )) && nft add element inet hm_egress github6 "{ $(IFS=,; echo "${g6[*]}") }"
exit 0
REFRESH

cat > "$FILES/egress.nft" <<'NFT'
table inet hm_egress {
  set allow4 { type ipv4_addr; flags interval; }
  set allow6 { type ipv6_addr; flags interval; }
  set github4 { type ipv4_addr; flags interval; }
  set github6 { type ipv6_addr; flags interval; }
  chain output {
    type filter hook output priority 0; policy drop;
    oifname "lo" accept
    ct state established,related accept
    ip daddr { 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 169.254.0.0/16, 224.0.0.0/4, 255.255.255.255 } accept
    ip6 daddr { fc00::/7, fe80::/10, ff00::/8 } accept
    ip daddr @allow4 tcp dport { 80, 443 } accept
    ip6 daddr @allow6 tcp dport { 80, 443 } accept
    meta skuid 0 ip daddr @github4 tcp dport 443 accept
    meta skuid 0 ip6 daddr @github6 tcp dport 443 accept
    limit rate 6/minute log prefix "hm-egress-drop " counter drop
  }
}
NFT

cat > "$FILES/hm-egress.service" <<'UNIT'
[Unit]
Description=Homelab Monitor outbound firewall
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/sbin/nft -f /etc/homelab-monitor-egress/egress.nft
ExecStartPost=/etc/homelab-monitor-egress/refresh.sh
ExecStop=/usr/sbin/nft delete table inet hm_egress
[Install]
WantedBy=multi-user.target
UNIT

cat > "$FILES/hm-egress-refresh.service" <<'UNIT'
[Unit]
Description=Refresh allowed internet addresses
[Service]
Type=oneshot
ExecStart=/etc/homelab-monitor-egress/refresh.sh
UNIT

cat > "$FILES/hm-egress-refresh.timer" <<'TMR'
[Unit]
Description=Refresh allowed internet addresses every 15 minutes
[Timer]
OnBootSec=2min
OnUnitActiveSec=15min
[Install]
WantedBy=timers.target
TMR

cat > "$FILES/backup.sh" <<"EOF"
#!/usr/bin/env bash
# Backs up the monitor: a consistent database copy, the vault key and salt, and the site settings
# (NFS mounts, Syncthing) as site.json, so a restore brings everything back without questions.
# Destination: the Syncthing folder chosen in setup, else /var/lib/homelab-monitor/backups.
#   /root/backup.sh            run now (also run daily by homelab-monitor-backup.timer)
#   RETENTION=14 /root/backup.sh
set -euo pipefail
RETENTION=${RETENTION:-7}
out="$(python3 /opt/homelab-monitor/sitectl.py backup --data /var/lib/homelab-monitor --key /etc/homelab-monitor/vault.key --keep "$RETENTION")"
id syncthing >/dev/null 2>&1 && chown -h syncthing:syncthing "$out" 2>/dev/null || true
echo "Backup written: $out"
# Copies kept for two days after an Update (and before a rollback) are removed once they expire.
python3 /opt/homelab-monitor/updatectl.py prune --data /var/lib/homelab-monitor || true
EOF

cat > "$FILES/restore.sh" <<"EOF"
#!/usr/bin/env bash
# Restores a Homelab Monitor backup into this container.
#   /root/restore.sh            asks where the backups are (the source set in home_monitor.sh first) and which one
#   /root/restore.sh --latest   no questions: the newest backup from the source set in home_monitor.sh
# The backup is copied somewhere private first and checked against the backup passphrase: one
# that cannot be proven unchanged shows its accounts and needs UNVERIFIED typed (--latest refuses it
# unless HM_RESTORE_UNVERIFIED=1, which RESTORE_UNVERIFIED="yes" in home_monitor.sh sets). One
# whose key is nowhere needs FORGET typed: its stored secrets are cleared. Then the site settings
# are applied (NFS mounts, Syncthing identity) and the service starts. Older backups made with a
# vault passphrase ask for it once.
set -Eeuo pipefail
DATA=/var/lib/homelab-monitor
APP=/opt/homelab-monitor
KEY=/etc/homelab-monitor/vault.key
SAFE=/var/lib/homelab-monitor-safe
CONF=/etc/homelab-monitor-install/install.conf
[[ -f "$CONF" ]] || CONF=/etc/homelab-monitor/install.conf      # before 0.7.0
log(){ printf '  %s\n' "$*"; }
[[ $EUID -eq 0 ]] || { echo "Run as root"; exit 1; }
SYNCTHING_KEYS_NFS=""; SYNCTHING_FOLDER="/mnt/Syncthing/Monitor"; BACKUP_NFS=""; UNPRIVILEGED=0
# install.conf is read as NAME="value" lines, never run: only these names and plain characters.
conf() { sed -n "s/^$1=\"\([A-Za-z0-9._:/ -]*\)\"\$/\1/p" "$CONF" 2>/dev/null | tail -n 1; }
if [[ -f "$CONF" ]]; then
  SYNCTHING_KEYS_NFS="$(conf SYNCTHING_KEYS_NFS)"; BACKUP_NFS="$(conf BACKUP_NFS)"
  v="$(conf SYNCTHING_FOLDER)"; [[ -n "$v" ]] && SYNCTHING_FOLDER="$v"
  [[ "$(conf UNPRIVILEGED)" == 1 ]] && UNPRIVILEGED=1
fi
LATEST=0; [[ "${1-}" == "--latest" ]] && LATEST=1
human(){ numfmt --to=iec-i --suffix=B "$1" 2>/dev/null || echo "$1 B"; }

from_syncthing() {
  local keys="$1" folder="$2" site
  site="$(mktemp)"
  python3 -c 'import json, sys; json.dump({"syncthing": {"enabled": True, "keys_source": sys.argv[1], "data_folder": sys.argv[2]}, "nfs": {"enabled": False}}, open(sys.argv[3], "w"))' "$keys" "$folder" "$site"
  python3 $APP/sitectl.py apply-site "$site" || { rm -f "$site"; exit 1; }
  rm -f "$site"
  log "Waiting for Syncthing to bring the backups down (up to 15 minutes)…"
  for _ in $(seq 1 180); do
    ls "$folder"/monitor-backup-*.tar.gz >/dev/null 2>&1 && { sleep 20; break; }
    sleep 5
  done
  BACKUP_DIR="$folder"
}

from_nfs() {
  if [[ "$UNPRIVILEGED" == 1 ]]; then
    # An unprivileged container cannot mount NFS: the Proxmox host copied the newest backup in.
    BACKUP_DIR="$SAFE/from-share"
    log "Unprivileged container: using the backups the Proxmox host copied into $BACKUP_DIR"
    return
  fi
  mkdir -p /mnt/hm-restore
  mountpoint -q /mnt/hm-restore || mount -t nfs -o ro,nosuid,nodev,noexec "$1" /mnt/hm-restore
  BACKUP_DIR=/mnt/hm-restore
}

choose_source() {
  local configured=""
  [[ -n "$SYNCTHING_KEYS_NFS" ]] && configured="Syncthing (identity from $SYNCTHING_KEYS_NFS, folder $SYNCTHING_FOLDER)"
  [[ -z "$configured" && -n "$BACKUP_NFS" ]] && configured="NFS share $BACKUP_NFS"
  if (( LATEST )); then
    [[ -n "$SYNCTHING_KEYS_NFS" ]] && { from_syncthing "$SYNCTHING_KEYS_NFS" "$SYNCTHING_FOLDER"; return; }
    [[ -n "$BACKUP_NFS" ]] && { from_nfs "$BACKUP_NFS"; return; }
    echo "No backup source is set in home_monitor.sh (SYNCTHING_KEYS_NFS or BACKUP_NFS)."; exit 1
  fi
  echo; echo "  Where are the backups?"
  [[ -n "$configured" ]] && echo "    0) $configured  (from home_monitor.sh)"
  echo "    1) Syncthing: restore this container's Syncthing identity from an NFS share, then sync"
  echo "    2) An NFS share"
  echo "    3) A folder already in this container"
  read -rp "  Choose: " src
  case "$src" in
    0) [[ -n "$SYNCTHING_KEYS_NFS" ]] && from_syncthing "$SYNCTHING_KEYS_NFS" "$SYNCTHING_FOLDER" || from_nfs "$BACKUP_NFS" ;;
    1) read -rp "  NFS export holding cert.pem, key.pem, config.xml: " keys
       read -rp "  Backup folder Syncthing syncs [$SYNCTHING_FOLDER]: " folder
       from_syncthing "$keys" "${folder:-$SYNCTHING_FOLDER}" ;;
    2) read -rp "  NFS export with the backups: " share; from_nfs "$share" ;;
    3) read -rp "  Folder [/var/lib/homelab-monitor/backups]: " folder; BACKUP_DIR="${folder:-/var/lib/homelab-monitor/backups}" ;;
    *) echo "  Cancelled."; exit 0 ;;
  esac
}

choose_backup() {
  # Plain backup names only (letters, digits, dot, dash and underscore).
  mapfile -t items < <(find "$BACKUP_DIR" -maxdepth 1 -type f -name 'monitor-backup-*.tar.gz' -printf '%T@ %s %f\n' 2>/dev/null \
    | grep -E ' monitor-backup-[A-Za-z0-9._-]+[.]tar[.]gz$' | sort -nr)
  (( ${#items[@]} )) || { echo "  No backups found in $BACKUP_DIR (if Syncthing is still syncing, run this again shortly)."; exit 1; }
  if (( LATEST )); then ARCHIVE="$BACKUP_DIR/$(awk '{print $3}' <<<"${items[0]}")"; return; fi
  echo; echo "  Backups in $BACKUP_DIR:"
  local i=1
  for line in "${items[@]}"; do
    read -r ts size name <<<"$line"
    printf "    %d) %s  %s  %s\n" "$i" "$name" "$(date -d "@${ts%.*}" '+%F %H:%M')" "$(human "$size")"
    ((i++))
  done
  read -rp "  Choice: " pick
  [[ "$pick" =~ ^[0-9]+$ ]] && (( pick >= 1 && pick < i )) || { echo "  Cancelled."; exit 0; }
  ARCHIVE="$BACKUP_DIR/$(awk '{print $3}' <<<"${items[$((pick-1))]}")"
}

choose_source
choose_backup
NAME="$(basename "$ARCHIVE")"
# Everything below works on a private copy: the file cannot change between the checks and the restore.
WORK="$(mktemp -d /root/.hm-restore.XXXXXX)"
trap 'rm -rf "$WORK"' EXIT
COPY="$WORK/backup.tar.gz"
python3 $APP/sitectl.py take "$ARCHIVE" --to "$COPY" >/dev/null || { log "This backup could not be copied. Nothing was restored."; exit 1; }
pass=""; FLAGS=()
sitectl_pass() {  # sitectl with the typed passphrase on stdin when there is one, else the one kept here
  if [[ -n "$pass" ]]; then printf '%s\n' "$pass" | python3 $APP/sitectl.py "$@" --passphrase-stdin
  else python3 $APP/sitectl.py "$@"; fi
}
check() { set +e; out="$(sitectl_pass check-auth "$COPY" --key "$KEY" "${FLAGS[@]}" 2>&1)"; rc=$?; set -e; }
show() { grep -v '^HM_AUTH=' <<<"$out" | sed 's/^ERROR: //; s/^/  /' || true; }
ask_pass() {
  (( rc == 4 )) || return 0
  if (( LATEST )); then show; log "The backup passphrase kept here does not open this backup. Nothing was restored."; exit 1; fi
  for attempt in 1 2 3; do
    read -rsp "  Backup passphrase for this backup: " pass; echo
    check
    (( rc == 4 )) || return 0
  done
}
check
ask_pass
if (( rc == 7 && ! LATEST )) && grep -q '^HM_AUTH=unverified-tagged' <<<"$out"; then
  # Made before the passphrase was changed? The older one proves it.
  echo "  This backup's tag does not match the passphrase. It may be from before the passphrase was changed."
  read -rsp "  An older backup passphrase (or press Enter to skip): " older; echo
  if [[ -n "$older" ]]; then
    before="$pass"; pass="$older"; check
    if (( rc == 7 )); then pass="$before"; check; fi
  fi
  unset older
fi
if (( rc == 7 )); then
  echo; show; echo
  if (( LATEST )); then
    if [[ "${HM_RESTORE_UNVERIFIED-0}" != 1 ]]; then
      log 'RESTORE="latest" refused this backup because it cannot be proven unchanged. Nothing was restored. To use it'
      log 'anyway, set RESTORE_UNVERIFIED="yes" at the top of home_monitor.sh and run it again, or run /root/restore.sh at a terminal.'
      exit 1
    fi
    log 'RESTORE_UNVERIFIED is yes: restoring it anyway.'
  else
    read -rp "  Type UNVERIFIED to restore it anyway: " confirm
    [[ "$confirm" == "UNVERIFIED" ]] || { echo "  Cancelled."; exit 0; }
  fi
  FLAGS+=(--accept-unverified); check; ask_pass
fi
if (( rc == 8 )); then
  echo; show; echo
  if (( LATEST )); then
    [[ "${HM_RESTORE_UNVERIFIED-0}" == 1 ]] || { log "Nothing was restored: no usable key for this backup."; exit 1; }
  else
    read -rp "  Type FORGET to restore it without them: " confirm
    [[ "$confirm" == "FORGET" ]] || { echo "  Cancelled."; exit 0; }
  fi
  FLAGS+=(--forget-secrets); check; ask_pass
fi
if (( rc != 0 )); then
  show; log "Nothing was restored; the monitor runs on the data it had. See the reason above."; exit 1
fi
if (( ! LATEST )); then
  echo; echo "  You chose: $NAME"
  echo "  Site settings in it (applied after the restore; a line starting with ! is refused):"
  python3 $APP/sitectl.py site-of "$COPY" | sed 's/^/    /' || true
  read -rp "  Type RESTORE to replace this monitor's data with it: " confirm
  [[ "$confirm" == "RESTORE" ]] || { echo "  Cancelled."; exit 0; }
fi

systemctl stop homelab-monitor || true
# The restore checks the backup against this build first (a newer, damaged or unmigratable one is
# refused with the current data untouched): then the monitor simply starts again on what it had.
set +e
sitectl_pass restore "$COPY" --data "$DATA" --key "$KEY" --record-name "$NAME" "${FLAGS[@]}"; rc=$?
set -e
pass=""
if (( rc != 0 )); then
  [[ -f "$DATA/monitor.db" ]] && systemctl start homelab-monitor || true
  log "Nothing was restored; the monitor runs on the data it had. See the reason above."
  exit 1
fi
if [[ ! -s "$KEY" ]]; then
  # A backup from before keys were included: it was made with a vault passphrase or a key file.
  if (( LATEST )); then
    log "This backup has no vault key: stored credentials stay locked until /root/restore.sh is run by hand."
  else
    for attempt in 1 2 3; do
      read -rsp "  This older backup needs its vault passphrase, or paste the key line from vault.key: " pass; echo
      if [[ "$pass" =~ ^[A-Za-z0-9+/]{43}=$ ]]; then
        printf '%s\n' "$pass" | python3 $APP/sitectl.py put-key --key "$KEY" >/dev/null && { unset pass; break; }
      fi
      if printf '%s\n' "$pass" | python3 $APP/sitectl.py derive-key --data "$DATA" --key "$KEY"; then unset pass; break; fi
    done
    unset pass
  fi
fi
chown -hR homelab-monitor:homelab-monitor "$DATA" /etc/homelab-monitor
if [[ -f "$DATA/site-restored.json" ]]; then
  log "Applying the site settings from the backup (NFS mounts, Syncthing)…"
  python3 $APP/sitectl.py apply-site "$DATA/site-restored.json" || log "Some site settings could not be applied; see above."
fi
# A restored install is already set up: no setup code needed.
rm -f /etc/homelab-monitor/setup.env
systemctl start homelab-monitor
log "Restore complete. Log in with the account from the backup."
EOF

cat > "$FILES/backup-passphrase.sh" <<"EOF"
#!/usr/bin/env bash
# backup-passphrase.sh: sets or changes the backup passphrase. With one, every backup carries a tag
# that proves it unchanged and the vault key travels sealed with it, so backups that leave this box
# keep the key. Read hidden, passed on stdin (never on a command line), kept in
# /etc/homelab-monitor-install/backup-passphrase (root only). A sealed backup is made straight away.
set -Eeuo pipefail
DATA=/var/lib/homelab-monitor
APP=/opt/homelab-monitor
[[ $EUID -eq 0 ]] || { echo "Run as root"; exit 1; }
. /root/.hm-look.sh
hm_banner "Backup passphrase"
printf '  Keep this passphrase in a password manager, apart from the backups. Without it a sealed\n'
printf '  backup cannot be opened.\n\n'
while :; do
  read -rsp "  New backup passphrase (12 or more characters): " p1; echo
  read -rsp "  Once more: " p2; echo
  if [[ "$p1" != "$p2" ]]; then printf '  %sThey did not match. Try again.%s\n' "$YEL" "$R"; continue; fi
  if (( ${#p1} < 12 )); then printf '  %sAt least 12 characters, please.%s\n' "$YEL" "$R"; continue; fi
  break
done
if ! printf '%s\n' "$p1" | python3 "$APP/sitectl.py" set-passphrase --data "$DATA"; then
  unset p1 p2; hm_fail "The passphrase was not saved (see the message above)."
fi
unset p1 p2
/root/backup.sh || hm_fail "The passphrase is saved, but the first sealed backup failed: run /root/backup.sh to see why."
hm_box "$GRN" "✔  Backup passphrase set and a sealed backup made"
printf '  Backups you already have stay as they are until the daily clean-up removes them, with the\n'
printf "  newest 7 kept. Copies on your NAS or in Syncthing's history may still hold the key in the\n"
printf '  clear, so remove them there if you want them gone now.\n\n'
EOF

# Shared look for the two account helpers below (same wordmark as the installer).
cat > "$FILES/hm-look.sh" <<"EOF"
# Sourced by /root/reset-admin.sh and /root/setup-code.sh.
if [[ -t 1 && -z "${NO_COLOR-}" ]]; then
  B=$'\033[1m'; D=$'\033[2m'; R=$'\033[0m'; GRN=$'\033[32m'; RED=$'\033[31m'; CYN=$'\033[36m'; YEL=$'\033[33m'
else
  B=""; D=""; R=""; GRN=""; RED=""; CYN=""; YEL=""
fi
hm_banner() {
  clear 2>/dev/null || true
  printf '%s\n' "" \
    "   ${B}█ █ █▀█ █▀▄▀█ █▀▀ █   █▀█ █▀▄${R}   ${CYN}${B}█▀▄▀█ █▀█ █▄ █ █ ▀█▀ █▀█ █▀█${R}" \
    "   ${B}█▀█ █ █ █ ▀ █ █▀▀ █   █▀█ █▀▄${R}   ${CYN}${B}█ ▀ █ █ █ █ ▀█ █  █  █ █ █▀▄${R}" \
    "   ${B}▀ ▀ ▀▀▀ ▀   ▀ ▀▀▀ ▀▀▀ ▀ ▀ ▀▀ ${R}   ${CYN}${B}▀   ▀ ▀▀▀ ▀  ▀ ▀  ▀  ▀▀▀ ▀ ▀${R}" \
    "   ${D}$1${R}" ""
}
hm_box() {  # colour, text
  local line; line="$(printf '─%.0s' $(seq 1 64))"
  printf '  %s╭%s╮%s\n  %s│%s  %-62s%s│%s\n  %s╰%s╯%s\n\n' "$1" "$line" "$R" "$1" "$R" "$2" "$1" "$R" "$1" "$line" "$R"
}
hm_fail() { printf '\n  %s✖  %s%s\n\n' "$RED$B" "$*" "$R" >&2; exit 1; }
hm_ip() { hostname -I 2>/dev/null | awk '{print $1}'; }
# The address to open, with https when the monitor serves it (it answers plain HTTP on 127.0.0.1).
hm_url() {
  local s=http
  curl -fsS "http://127.0.0.1:__PORT__/api/auth/status" 2>/dev/null | grep -q '"https": true' && s=https
  printf '%s://%s:__PORT__' "$s" "$(hm_ip)"
}
EOF

cat > "$FILES/reset-admin.sh" <<"EOF"
#!/usr/bin/env bash
# reset-admin.sh: a new password for a web login, from the container shell (root on the container
# is the final authority when the login is lost). Optionally turns that account's 2FA off.
# Nothing is typed on a command line: the password is read hidden and passed on stdin.
set -Eeuo pipefail
DATA=/var/lib/homelab-monitor
APP=/opt/homelab-monitor
[[ $EUID -eq 0 ]] || { echo "Run as root"; exit 1; }
. /root/.hm-look.sh
hm_banner "Reset a web login"
mapfile -t users < <(python3 "$APP/sitectl.py" accounts --data "$DATA")
(( ${#users[@]} )) || hm_fail "No accounts exist yet. Open the web page and create the first one (a new setup code: /root/setup-code.sh)."
printf '  %sAccounts%s\n' "$B" "$R"
i=1
for u in "${users[@]}"; do
  IFS=$'\t' read -r name role state mfa <<<"$u"
  printf '    %d) %-20s %s%-8s %-8s %s%s\n' "$i" "$name" "$D" "$role" "$state" "${mfa/no-2fa/no 2FA}" "$R"
  ((i++))
done
echo
read -rp "  Which account? " pick
[[ "$pick" =~ ^[0-9]+$ ]] && (( pick >= 1 && pick < i )) || hm_fail "Cancelled."
IFS=$'\t' read -r name role state mfa <<<"${users[$((pick-1))]}"
while :; do
  read -rsp "  New password for $name (12 or more characters): " pw1; echo
  read -rsp "  Once more: " pw2; echo
  [[ "$pw1" == "$pw2" ]] && break
  printf '  %sThey did not match. Try again.%s\n' "$YEL" "$R"
done
extra=()
if [[ "$mfa" == "2fa" ]]; then
  read -rp "  Also turn off 2FA for $name (lost phone and recovery codes)? [y/N] " off
  [[ "${off,,}" == y* ]] && extra=(--reset-2fa)
fi
rule_off=0
if [[ "$(python3 "$APP/sitectl.py" require-2fa --data "$DATA" 2>/dev/null)" != "off" ]]; then
  read -rp "  Also stop requiring 2FA for everyone on this monitor (no phone to set it up with)? [y/N] " stop
  [[ "${stop,,}" == y* ]] && { extra+=(--no-2fa-rule); rule_off=1; }
fi
# Stopped while the database is written as root, then ownership put back: the service user must
# own every database file (including the WAL) or it cannot open them.
systemctl stop homelab-monitor
if printf '%s\n' "$pw1" | python3 "$APP/sitectl.py" reset-password --data "$DATA" --user "$name" "${extra[@]}"; then ok=1; else ok=0; fi
unset pw1 pw2
chown -hR homelab-monitor:homelab-monitor "$DATA"
systemctl start homelab-monitor
(( ok )) || hm_fail "The password was not changed (see the message above)."
hm_box "$GRN" "✔  Password reset for $name"
printf '  Log in at %s%s%s with the new password.%s\n' "$CYN$B" "$(hm_url)" "$R" "$R"
[[ " ${extra[*]} " == *" --reset-2fa "* ]] && printf '  2FA is off for %s: set it up again in Settings, Account.\n' "$name"
(( rule_off )) && printf '  2FA is no longer required. Turn it on again in Settings, Users and sign-in.\n'
printf '  %sEvery open session was logged out. The change is in the audit log.%s\n\n' "$D" "$R"
EOF

cat > "$FILES/setup-code.sh" <<"EOF"
#!/usr/bin/env bash
# setup-code.sh: a new setup code for creating the first account, if the one the installer showed
# was lost. Refused once any account exists: the code is then useless, and refusing means it can
# never be used to take over an install that is set up.
set -Eeuo pipefail
DATA=/var/lib/homelab-monitor
APP=/opt/homelab-monitor
ENV=/etc/homelab-monitor/setup.env
[[ $EUID -eq 0 ]] || { echo "Run as root"; exit 1; }
. /root/.hm-look.sh
hm_banner "New setup code"
err="$(mktemp)"
set +e
code="$(python3 "$APP/sitectl.py" new-setup-code --data "$DATA" --env "$ENV" 2>"$err")"
rc=$?
set -e
if (( rc != 0 )); then
  msg="$(sed 's/^ERROR: //' "$err")"; rm -f "$err"
  hm_fail "${msg:-Could not make a new setup code.}"
fi
rm -f "$err"
systemctl restart homelab-monitor
hm_box "$GRN" "✔  New setup code ready"
printf '  Setup code   %s%s%s\n' "$YEL$B" "$code" "$R"
printf '  Open         %s%s%s and create your account with it.\n\n' "$CYN$B" "$(hm_url)" "$R"
printf '  %sThe old code no longer works. This code is shown once; run this again if you lose it,%s\n' "$D" "$R"
printf '  %suntil the first account exists.%s\n\n' "$D" "$R"
EOF

cat > "$FILES/update.sh" <<"EOF"
#!/usr/bin/env bash
# update.sh: menu-driven updates. The monitor app itself is upgraded with home_monitor.sh:
#   bash home_monitor.sh --upgrade            from the Proxmox host (a container)
#   bash home_monitor.sh --local --upgrade    on this machine (installed with --local)
set -Eeuo pipefail
[[ $EUID -eq 0 ]] || { echo "Run as root"; exit 1; }
log(){ printf '\n[%s] %s\n' "$(date +'%F %T')" "$*"; }
update_system() {
  log "Refreshing allowed package addresses, then apt full-upgrade…"
  /etc/homelab-monitor-egress/refresh.sh || true
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -y && apt-get -o Dpkg::Options::=--force-confdef -o Dpkg::Options::=--force-confold full-upgrade -y \
    && apt-get autoremove -y --purge && apt-get autoclean -y
  systemctl restart homelab-monitor
  log "System update complete."
}
while :; do
  cat <<'M'

==== Monitor Updater ====
1) System packages (includes Python, cryptography, Syncthing)
2) System packages + reboot
3) Restart the monitor service
4) Show monitor status
5) Back up now
6) Switch the web interface to plain HTTP (certificate trouble)
7) Set or change the backup passphrase
q) Quit
M
  read -rp "Select: " opt
  case "${opt,,}" in
    1) update_system ;;
    2) update_system; log "Rebooting…"; reboot ;;
    3) systemctl restart homelab-monitor; log "Restarted." ;;
    4) systemctl --no-pager status homelab-monitor | head -15 ;;
    5) /root/backup.sh ;;
    6) systemctl stop homelab-monitor
       python3 /opt/homelab-monitor/sitectl.py tls-off --data /var/lib/homelab-monitor \
         && chown -hR homelab-monitor:homelab-monitor /var/lib/homelab-monitor
       systemctl start homelab-monitor; log "Plain HTTP now. Switch HTTPS back on in Settings, HTTPS." ;;
    7) /root/backup-passphrase.sh ;;
    q|quit|exit) exit 0 ;;
    *) echo "Invalid choice." ;;
  esac
done
EOF

cat > "$FILES/homelab-monitor-backup.service" <<'UNIT'
[Unit]
Description=Homelab Monitor backup
After=homelab-monitor.service
[Service]
Type=oneshot
ExecStart=/root/backup.sh
# Writes only the data folder and the backup folder (below /mnt or /srv).
ProtectSystem=strict
ReadWritePaths=-/var/lib/homelab-monitor -/var/lib/homelab-monitor-safe -/mnt -/srv -/var/lib/syncthing
ProtectHome=read-only
PrivateTmp=yes
NoNewPrivileges=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
Nice=10
IOSchedulingClass=best-effort
IOSchedulingPriority=7
UNIT

cat > "$FILES/homelab-monitor-backup.timer" <<'TMR'
[Unit]
Description=Run Homelab Monitor backup daily at 03:30
[Timer]
OnCalendar=*-*-* 03:30:00
Persistent=true
RandomizedDelaySec=10m
[Install]
WantedBy=timers.target
TMR

# Requests from the web app, run as root. The app (an unprivileged user) writes a file into
# DATA/requests; these path units fire on it. Only these fixed actions exist: applying the site
# settings stored in the database (Syncthing, NFS) and running a backup now.
cat > "$FILES/hm-site.path" <<UNIT
[Unit]
Description=Apply site settings when the monitor asks
[Path]
PathChanged=${DATA_DIR}/requests/site
Unit=hm-site.service
[Install]
WantedBy=multi-user.target
UNIT

cat > "$FILES/hm-site.service" <<UNIT
[Unit]
Description=Apply Homelab Monitor site settings (Syncthing, NFS)
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 ${APP_DIR}/sitectl.py site-request --data ${DATA_DIR}
# It mounts shares for the whole container, so no private mount namespace (PrivateTmp,
# ProtectSystem): only the restrictions that leave mounting alone.
NoNewPrivileges=yes
LockPersonality=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
SystemCallArchitectures=native
UNIT

# Settings, Backups, Set backup passphrase: the app leaves the passphrase sealed with the vault key;
# root saves it beside install.conf, removes the request and starts a sealed backup.
cat > "$FILES/hm-passphrase.path" <<UNIT
[Unit]
Description=Save the backup passphrase when the monitor asks
[Path]
PathChanged=${DATA_DIR}/requests/backup-passphrase
Unit=hm-passphrase.service
[Install]
WantedBy=multi-user.target
UNIT

cat > "$FILES/hm-passphrase.service" <<UNIT
[Unit]
Description=Save the Homelab Monitor backup passphrase
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 ${APP_DIR}/sitectl.py passphrase-request --data ${DATA_DIR} --key ${KEY_DIR}/vault.key
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=read-only
ProtectKernelTunables=yes
ProtectKernelModules=yes
LockPersonality=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
SystemCallArchitectures=native
UNIT

cat > "$FILES/hm-backup-now.path" <<UNIT
[Unit]
Description=Back up when the monitor asks
[Path]
PathChanged=${DATA_DIR}/requests/backup
Unit=homelab-monitor-backup.service
[Install]
WantedBy=multi-user.target
UNIT

install_services() {
  printf 'MONITOR_SETUP_TOKEN=%s\n' "$SETUP_TOKEN" > "$FILES/setup.env"
  sed -i "s/__PORT__/${PORT}/g" "$FILES/reset-admin.sh" "$FILES/setup-code.sh"
  ( umask 077; tar -C "$FILES" -czf "$FILES.tgz" . )
  pct push "${CTID}" "$FILES.tgz" /root/.hm-files.tgz
  rm -f "$FILES.tgz" "$FILES/setup.env"
  pct exec "${CTID}" -- bash -lc "set -e
    d=\$(mktemp -d) && tar -xzf /root/.hm-files.tgz -C \$d && cd \$d
    $(files_into_place layout)
    install -m 0600 -o ${SERVICE_USER} -g ${SERVICE_USER} setup.env ${KEY_DIR}/setup.env
    cd / && rm -rf \$d /root/.hm-files.tgz
    systemctl daemon-reload
    systemctl enable --now hm-egress.service hm-egress-refresh.timer homelab-monitor.service homelab-monitor-backup.timer hm-site.path hm-backup-now.path hm-passphrase.path hm-update.path
    systemctl enable hm-update-recover.service"
  load_ingress
}

# The inbound firewall (a container only): the new rules are checked with nft -c before they replace
# the ones in force. A failed check or load never stops the install or upgrade (the monitor itself
# works), but it is written to $STATE/ingress so the last screen says the firewall is NOT active
# (off), or that the previous rules are still in force (kept). Arguments only, no shell string.
load_ingress() {
  local d=/etc/homelab-monitor-egress
  [[ "$TARGET" == container ]] || return 0
  if ! pct exec "${CTID}" -- /usr/sbin/nft -c -f "$d/ingress.nft.new"; then
    echo "The inbound firewall rules did not pass the check (nft -c)."
    if pct exec "${CTID}" -- systemctl is-active --quiet hm-ingress.service; then echo kept > "$STATE/ingress"; else echo off > "$STATE/ingress"; fi
    return 0
  fi
  pct exec "${CTID}" -- mv -f "$d/ingress.nft.new" "$d/ingress.nft" || { echo off > "$STATE/ingress"; return 0; }
  pct exec "${CTID}" -- systemctl enable hm-ingress.service || true
  pct exec "${CTID}" -- systemctl restart hm-ingress.service && return 0
  echo "The inbound firewall did not load (see journalctl -u hm-ingress)"
  echo off > "$STATE/ingress"
  return 0
}

# Shared by an install, an upgrade and a restore: units, firewall, helper scripts and root's own
# folder for install.conf and layout (read by root, so the app's user cannot change them).
files_into_place() {
  cat <<CMDS
    install -m 0644 homelab-monitor.service hm-egress.service hm-egress-refresh.service hm-egress-refresh.timer hm-ingress.service homelab-monitor-backup.service homelab-monitor-backup.timer hm-site.path hm-site.service hm-backup-now.path hm-passphrase.path hm-passphrase.service hm-update.path hm-update.service hm-update-recover.service /etc/systemd/system/
    install -d -m 0755 /etc/homelab-monitor-egress
    install -m 0644 egress-hosts /etc/homelab-monitor-egress/hosts
    install -m 0644 github-hosts /etc/homelab-monitor-egress/github-hosts
    install -d -m 0750 -o root -g ${SERVICE_USER} ${INSTALL_DIR}
    install -m 0600 -o root -g root settings.env ${INSTALL_DIR}/settings.env
    install -m 0644 egress.nft /etc/homelab-monitor-egress/egress.nft
    if [ '${TARGET}' = container ]; then install -m 0644 ingress.nft /etc/homelab-monitor-egress/ingress.nft.new; else install -m 0644 ingress.nft /etc/homelab-monitor-egress/ingress.nft; fi
    install -m 0755 egress-refresh.sh /etc/homelab-monitor-egress/refresh.sh
    install -m 0700 backup.sh restore.sh update.sh reset-admin.sh setup-code.sh backup-passphrase.sh /root/
    install -d -m 0700 -o root -g root ${SAFE_DIR}
    install -m 0600 hm-look.sh /root/.hm-look.sh
    install -m 0700 update-recover.sh /root/.hm-update-recover.sh
    if [ -f install.conf ]; then install -m 0640 -o root -g ${SERVICE_USER} install.conf ${INSTALL_DIR}/install.conf;
    elif [ -f ${KEY_DIR}/install.conf ] && [ ! -L ${KEY_DIR}/install.conf ] && [ ! -f ${INSTALL_DIR}/install.conf ]; then install -m 0640 -o root -g ${SERVICE_USER} ${KEY_DIR}/install.conf ${INSTALL_DIR}/install.conf; fi
    rm -f ${KEY_DIR}/install.conf ${KEY_DIR}/layout
    if [ -f backup-passphrase ]; then install -m 0600 -o root -g root backup-passphrase ${INSTALL_DIR}/backup-passphrase; fi
    if [ -f root-key.pub ] && [ '${TARGET}' = container ]; then bash ssh-key.sh root-key.pub; fi
    if [ -L ${DATA_DIR}/requests ]; then rm -f ${DATA_DIR}/requests; fi
    install -d -m 0700 -o ${SERVICE_USER} -g ${SERVICE_USER} ${DATA_DIR}/requests
CMDS
  # The layout marker: written here by an install only (an upgrade writes it once the new version answers).
  [[ "${1-}" == layout ]] && cat <<CMDS
    printf 'LAYOUT=%s\nVERSION=%s\n' ${LAYOUT} ${VERSION} > ${INSTALL_DIR}/layout
CMDS
}

# ------------------------------------------------------------------ run the upgrade
# Each part is a step on the same progress screen as an install:
# 1. ready, copy, check: the container, then the data with the new build (on a copy). Anything
#    blocking: stop with nothing changed and say how to rebuild and restore instead. --check
#    stops here.
# 2. repair: what the check found missing (packages, folders).
# 3. backup: the new build's sitectl, into SAFE_DIR/pre-upgrade (root only), the newest 3 kept.
# 4. replace: new app code plus the current helper scripts, units and firewall. Data, the vault
#    key, the setup code and install.conf stay as they are.
# 5. health: the new version must answer within HEALTH_TRIES x 2 s. If it does not: the previous
#    code and the backup from step 3 are put back and started, and the upgrade reports the failure.
ct() { pct exec "${CTID}" -- bash -lc "$1"; }
# Shell lines for the container that wait until nothing holds the web port any more, at most three
# minutes. Versions before 0.11.1 opened the port without address reuse: the connections they leave
# behind when stopped keep the port from the next version (and from them) for a minute or two.
port_free_cmd() {
  [[ "$PORT" =~ ^[0-9]{1,5}$ ]] || return 0
  echo "if command -v ss >/dev/null; then for i in \$(seq 1 90); do [ -z \"\$(ss -Htan '( sport = :${PORT} )' 2>/dev/null)\" ] && break; sleep 2; done; fi"
}
rebuild_help() {
  say ""
  if [[ "$TARGET" == "local" ]]; then
    say "${B}This install cannot be upgraded in place.${R} Nothing was changed. To move to ${VERSION}:"
    say "  1. Make sure a recent backup exists: ${B}/root/backup.sh${R}, and copy it off this machine"
    say "     (with Syncthing on, it lands in the synced folder)."
    say "  2. Reinstall this machine's system (or make a fresh VM) and run ${B}bash $(basename "$0") --local${R}."
    say "  3. Before the first visit run ${B}/root/restore.sh${R}: it checks the backup against the new build first."
    return 0
  fi
  say "${B}This container cannot be upgraded in place.${R} Nothing was changed. To move to ${VERSION}:"
  say "  1. Make sure a recent backup exists: in the container run ${B}/root/backup.sh${R}"
  say "     (with Syncthing on, it lands in the synced folder; otherwise copy it off the container)."
  say "  2. At the top of this file set ${B}RESTORE=\"latest\"${R} and ${B}SYNCTHING_KEYS_NFS${R} or ${B}BACKUP_NFS${R}."
  say "  3. Run ${B}bash $(basename "$0") --rebuild${R}: a fresh container, then the backup is restored into it."
  say "     The restore checks the backup against the new build first and refuses one it cannot run."
}

# A framed one-line heading for the end of an upgrade, check or restore (same look as the install).
result_box() {  # colour, icon, title (up to 58 characters)
  local line; line="$(printf '─%.0s' $(seq 1 64))"
  printf '  %s╭%s╮%s\n' "$1" "$line" "$R"
  printf '  %s│%s  %s%s  %-58s%s %s│%s\n' "$1" "$R" "$B$1" "$2" "$3" "$R" "$1" "$R"
  printf '  %s╰%s╯%s\n\n' "$1" "$line" "$R"
}
# The inbound firewall did not load ($STATE/ingress is off): said under the heading of the last screen.
ingress_help() {
  local look="pct exec ${CTID} -- systemctl status hm-ingress"
  [[ -n "$RUN_HERE" ]] && look="systemctl status hm-ingress"
  say "The firewall that limits who can reach SSH and the web page is not running, so anything on"
  say "your network can reach them. The reason is in the log named at the end of this screen."
  say "Check ADMIN_NET and SNMP_ALLOW at the top of this file, then run bash $(basename "$0") --upgrade."
  say "To look inside: ${look}"
  echo
}
# The new rules failed their check while the previous ones still run: one line under "Good to know".
ingress_kept_note() {
  [[ "$(cat "$STATE/ingress" 2>/dev/null || true)" == kept ]] || return 0
  printf '      %-9s %s\n' "Firewall" "the new rules failed their check, so the previous rules are still in force (see the log)"
}
show_findings() {  # what the upgrade check found, one line each
  local kind text what
  while IFS='|' read -r kind text what; do
    case "$kind" in
      OK) printf '      %s✔%s  %s\n' "$GRN" "$R" "$text" ;;
      FIX) printf '      %s●%s  %s %s(the upgrade %s)%s\n' "$YEL" "$R" "$text" "$D" "$what" "$R" ;;
      NOTE) printf '      %si  %s%s\n' "$D" "$text" "$R" ;;
      BLOCK) printf '      %s✖  %s%s\n' "$RED" "$text" "$R" ;;
    esac
  done < "$STATE/precheck"
}
# No backup passphrase on the box: backups that leave it go without the key, and none can be proven
# unchanged. Said at the end of an install, an upgrade and a restore, with the command that fixes it.
passphrase_note() {
  [[ "$MODE" == preview ]] && return 0
  pct exec "${CTID}" -- test -f "${INSTALL_DIR}/backup-passphrase" >/dev/null 2>&1 && return 0
  printf '  %sNo backup passphrase is set.%s Backups that leave this box go without the key that opens the
' "$YEL$B" "$R"
  printf '  stored passwords, and backups cannot be proven unchanged. To set one, run %s/root/backup-passphrase.sh%s
' "$B" "$R"
  printf '  in the %s, then keep the passphrase in your password manager.

' "${TARGET/local/monitor machine}"
}
end_screen() {  # after the progress screen: a clean page with the wordmark
  stop_drawer
  clear 2>/dev/null || true
  banner
}

# The helper scripts, units and firewall from this build, put in place by an upgrade and a restore.
# install.conf and setup.env stay as they are. $1: start the monitor afterwards (yes or no).
install_helpers() {
  sed -i "s/__PORT__/${PORT}/g" "$FILES/reset-admin.sh" "$FILES/setup-code.sh"
  ( umask 077; tar -C "$FILES" -czf "$FILES.tgz" --exclude=install.conf --exclude=setup.env . )
  pct push "${CTID}" "$FILES.tgz" /root/.hm-files.tgz
  rm -f "$FILES.tgz"
  pct exec "${CTID}" -- bash -lc "set -e
    d=\$(mktemp -d) && tar -xzf /root/.hm-files.tgz -C \$d && cd \$d
    $(files_into_place)
    cd / && rm -rf \$d /root/.hm-files.tgz
    systemctl daemon-reload
    systemctl restart hm-egress.service
    systemctl enable --now hm-site.path hm-backup-now.path hm-passphrase.path hm-update.path
    systemctl enable hm-update-recover.service     # at boot only: an update from the app may be running now
    if [ '$1' = yes ]; then systemctl start homelab-monitor; fi"
  load_ingress
}
# An unprivileged container cannot mount NFS. This host mounts the share read-only for a moment and
# copies in what is needed: the Syncthing identity (into /root/.hm-stkeys, where sitectl takes it
# from) and, for RESTORE="latest" from BACKUP_NFS, the newest backup.
ct_unprivileged() {
  [[ "$TARGET" == container ]] || return 1
  if pct config "${CTID}" >/dev/null 2>&1; then pct config "${CTID}" 2>/dev/null | grep -q '^unprivileged: 1'; else [[ "$UNPRIVILEGED" == 1 ]]; fi
}
host_share_copy() {
  local m f newest
  m="$(mktemp -d)"
  if [[ -n "$SYNCTHING_KEYS_NFS" ]]; then
    mount -t nfs -o ro,nosuid,nodev,noexec "$SYNCTHING_KEYS_NFS" "$m" || { rmdir "$m"; echo "This host could not mount $SYNCTHING_KEYS_NFS" > "$STATE/why"; return 1; }
    pct exec "${CTID}" -- install -d -m 0700 /root/.hm-stkeys
    for f in cert.pem key.pem config.xml; do
      [[ -f "$m/$f" ]] || { umount "$m"; rmdir "$m"; echo "$SYNCTHING_KEYS_NFS has no $f" > "$STATE/why"; return 1; }
      pct push "${CTID}" "$m/$f" "/root/.hm-stkeys/$f" --perms 0600
    done
    umount "$m"
    echo "Syncthing identity copied in from $SYNCTHING_KEYS_NFS"
  fi
  if [[ "$RESTORE" == latest && -z "$SYNCTHING_KEYS_NFS" && -n "$BACKUP_NFS" ]]; then
    mount -t nfs -o ro,nosuid,nodev,noexec "$BACKUP_NFS" "$m" || { rmdir "$m"; echo "This host could not mount $BACKUP_NFS" > "$STATE/why"; return 1; }
    # The name carries the date, so the last one sorted is the newest.
    newest="$(ls -1 "$m" 2>/dev/null | grep -E '^monitor-backup-[A-Za-z0-9._-]+[.]tar[.]gz$' | sort | tail -n 1 || true)"
    if [[ -n "$newest" ]]; then
      pct exec "${CTID}" -- install -d -m 0700 "${SAFE_DIR}" "${SAFE_DIR}/from-share"
      pct push "${CTID}" "$m/$newest" "${SAFE_DIR}/from-share/$newest" --perms 0600
      echo "Copied $newest in from $BACKUP_NFS"
    fi
    umount "$m"
  fi
  rmdir "$m"
}

healthy() {
  for _ in $(seq 1 "$HEALTH_TRIES"); do
    ct "systemctl is-active --quiet homelab-monitor && curl -fsS http://127.0.0.1:${PORT}/api/auth/status >/dev/null" && return 0
    sleep 2
  done
  return 1
}
# Getting the container going and the new build into it: the first steps of upgrade, check and restore.
s_ready() {
  pct status "${CTID}" | grep -q running || pct start "${CTID}"
  wait_for_ct || { echo "${WHERE^} did not become ready." > "$STATE/why"; return 1; }
  # The tag says where; the app itself must be there too. Nothing about the container (CPU, memory,
  # disk, network, start at boot) is changed by an upgrade or a restore: only the files inside it.
  if pct exec "${CTID}" -- test -f "${APP_DIR}/server.py"; then
    # The version that runs now, for the update history (a plain version number or nothing).
    local fv; fv="$(pct exec "${CTID}" -- grep -m1 '^APP_VERSION = ' "${APP_DIR}/server.py" 2>/dev/null || true)"
    fv="${fv#*\"}"; fv="${fv%%\"*}"
    [[ "$fv" =~ ^[0-9]{1,4}[.][0-9]{1,4}[.][0-9]{1,4}$ ]] && echo "$fv" > "$STATE/from_version"
    return 0
  fi
  if [[ "$MODE" == "restore" ]]; then
    # A restore can also mend an install whose app is gone, as long as this installer set it up.
    pct exec "${CTID}" -- bash -lc "id ${SERVICE_USER} && test -f /etc/systemd/system/homelab-monitor.service" && return 0
    echo "${WHERE^} was not set up by this installer (no monitor service or user in it). Rebuild it instead, with RESTORE=\"latest\" at the top of this file." > "$STATE/why"
  else
    echo "${WHERE^} has the tag ${HM_TAG} but the monitor is not installed in it. Take the tag off it, or install with bash $(basename "$0")." > "$STATE/why"
  fi
  return 1
}
s_copy() {
  pct push "${CTID}" "$PAYLOAD" /root/.hm-new.tar.gz || { echo "Could not copy the new build into ${WHERE}." > "$STATE/why"; return 1; }
  if [[ "$MODE" != "restore" ]]; then
    pct push "${CTID}" "$PRECHECK" /root/.hm-precheck.sh || { echo "Could not copy the check into ${WHERE}." > "$STATE/why"; return 1; }
  fi
  ct "rm -rf ${NEW_DIR} && mkdir -m 0700 ${NEW_DIR} && tar -xzf /root/.hm-new.tar.gz -C ${NEW_DIR}"
}
tidy_new() { ct "rm -rf ${NEW_DIR} /root/.hm-new.tar.gz /root/.hm-precheck.sh /root/hm-restore.tar.gz" >> "$LOG" 2>&1 || true; }
# An upgrade run from here goes into the box's update history (Settings, Updates) with this log, so it
# can be read in the app. Update in the app records its own. $1: 1 or 0, $2: blocked, replace, health or none.
record_history() {
  [[ -n "${HM_FROM_UPDATER-}" ]] && return 0
  local fv; fv="$(cat "$STATE/from_version" 2>/dev/null || true)"
  [[ "$fv" =~ ^[0-9]{1,4}[.][0-9]{1,4}[.][0-9]{1,4}$ ]] || fv=""
  pct push "${CTID}" "$LOG" /root/.hm-upgrade.log >> "$LOG" 2>&1 || return 0
  ct "python3 ${NEW_DIR}/updatectl.py record --data ${DATA_DIR} --kind upgrade --source host --from '${fv}' --to ${VERSION} --ok $1 --why $2 --log /root/.hm-upgrade.log; rm -f /root/.hm-upgrade.log" >> "$LOG" 2>&1 || true
}

if [[ "$MODE" == "upgrade" || "$MODE" == "check" ]]; then
  s_check() {
    ct "bash /root/.hm-precheck.sh ${APP_DIR} ${DATA_DIR} ${KEY_DIR} ${SERVICE_USER} ${NEW_DIR} ${LAYOUT}" > "$STATE/precheck" || true
    cat "$STATE/precheck"
    grep -q '^HM_CHECK_DONE' "$STATE/precheck" || { echo "The upgrade check did not finish (see the log)." > "$STATE/why"; return 1; }
  }
  s_repair() {
    ct "DEBIAN_FRONTEND=noninteractive apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ${PKGS}" \
      || { echo "Could not install ${PKGS}; nothing else was changed." > "$STATE/why"; return 1; }
  }
  s_backup() {
    local f sum
    # Root's own folder: the app cannot read or change the copy, and it carries the key in the clear,
    # so putting it back never depends on the backup passphrase.
    local into="pre-upgrade" keep=3
    [[ "${HM_UPDATE_BACKUP-}" == pre-update ]] && { into="pre-update"; keep=20; }   # Update: kept two days, by age
    f="$(ct "install -d -m 0700 -o root -g root ${SAFE_DIR} && python3 ${NEW_DIR}/sitectl.py backup --data ${DATA_DIR} --key ${KEY_DIR}/vault.key --dest ${SAFE_DIR}/${into} --keep ${keep} --safety --safe-dir ${SAFE_DIR}" | tail -n 1)"
    echo "$f"
    [[ "$f" =~ ^[A-Za-z0-9._/:-]+/monitor-backup-[A-Za-z0-9._-]+[.]tar[.]gz$ ]] || { echo "The backup before the upgrade failed; nothing was changed." > "$STATE/why"; return 1; }
    echo "$f" > "$STATE/backup_file"
    # Its checksum: putting it back checks the file is still the one made here.
    sum="$(pct exec "${CTID}" -- sha256sum -- "$f" 2>/dev/null | awk '{print $1}')" || sum=""
    [[ "$sum" =~ ^[0-9a-f]{64}$ ]] && echo "$sum" > "$STATE/backup_sha"
    # Update in the app: root records the copy for Undo in its own folder (the app cannot change it).
    if [[ "${HM_UPDATE_BACKUP-}" == pre-update ]]; then
      pct exec "${CTID}" -- python3 "${NEW_DIR}/updatectl.py" note-backup --data "${DATA_DIR}" --file "$f" --to "${VERSION}" \
        || { echo "The copy for undo could not be recorded; nothing was changed." > "$STATE/why"; return 1; }
    fi
    return 0
  }
  s_replace() {
    # app.old must mean "the code that was running": a leftover from an earlier upgrade goes first.
    ct "rm -rf ${APP_DIR}.old ${APP_DIR}.rolledback"
    pct exec "${CTID}" -- systemctl stop homelab-monitor
    ct "$(port_free_cmd)" || true
    push_app
    install_helpers yes
    # Unprivileged: the Syncthing identity comes in through this host, then the site settings are applied again.
    if ct_unprivileged && [[ -n "$SYNCTHING_KEYS_NFS" ]]; then
      host_share_copy && ct "python3 ${APP_DIR}/sitectl.py ask --kind site --data ${DATA_DIR}" || echo "The Syncthing identity could not be copied in (see above)"
    fi
  }
  s_health() { healthy; }

  define_steps
  start_drawer
  run_step ready s_ready
  run_step copy s_copy
  run_step check s_check
  PKGS="$(sed -n 's/^PKG|//p' "$STATE/precheck" | tr '\n' ' ')"
  if grep -q '^BLOCK|' "$STATE/precheck"; then
    [[ "$MODE" == "upgrade" ]] && record_history 0 blocked
    tidy_new
    end_screen
    result_box "$RED" "✖" "${WHERE^} cannot be upgraded in place"
    printf '  %sWhat the check found%s\n' "$B" "$R"
    show_findings
    rebuild_help
    echo
    exit 1
  fi
  if [[ "$MODE" == "check" ]]; then
    tidy_new
    end_screen
    result_box "$GRN" "✔" "${WHERE^} can be upgraded in place"
    printf '  %sWhat the check found%s\n' "$B" "$R"
    show_findings
    printf '\n  Nothing was changed. To upgrade: %sbash %s%s --upgrade%s\n\n' "$B" "$(basename "$0")" "$FLAG" "$R"
    exit 0
  fi
  if [[ -n "${PKGS// /}" ]]; then run_step repair s_repair; else skip_step repair; fi
  run_step backup s_backup
  BACKUP_FILE="$(cat "$STATE/backup_file")"
  BACKUP_SHA="$(cat "$STATE/backup_sha" 2>/dev/null || true)"
  if ! run_step replace s_replace soft; then
    UPGRADE_FAILED="the new files could not be installed"
    skip_step health
  elif ! run_step health s_health soft; then
    UPGRADE_FAILED="the new version did not start (see journalctl -u homelab-monitor in the container)"
  fi
  if [[ -n "${UPGRADE_FAILED-}" ]]; then
    end_screen
    result_box "$RED" "✖" "Upgrade failed: putting the previous version back"
    say "Why: ${UPGRADE_FAILED}."
    say "Putting the previous code and the data from just before back…"
    {
      ct "systemctl stop homelab-monitor || true
        if [ -d ${APP_DIR}.old ]; then rm -rf ${APP_DIR}.failed; [ -d ${APP_DIR} ] && mv ${APP_DIR} ${APP_DIR}.failed; mv ${APP_DIR}.old ${APP_DIR}; fi
        python3 ${NEW_DIR}/sitectl.py restore ${BACKUP_FILE} --data ${DATA_DIR} --key ${KEY_DIR}/vault.key ${BACKUP_SHA:+--expect-sha256 ${BACKUP_SHA}} \
          || { echo 'The new build could not restore the backup: using the previous version for it'
               if grep -q -- --expect-sha256 ${APP_DIR}/sitectl.py; then python3 ${APP_DIR}/sitectl.py restore ${BACKUP_FILE} --data ${DATA_DIR} --key ${KEY_DIR}/vault.key ${BACKUP_SHA:+--expect-sha256 ${BACKUP_SHA}}
               else python3 ${APP_DIR}/sitectl.py restore ${BACKUP_FILE} --data ${DATA_DIR} --key ${KEY_DIR}/vault.key; fi; }
        chown -hR ${SERVICE_USER}:${SERVICE_USER} ${DATA_DIR} ${KEY_DIR}
        $(port_free_cmd)
        systemctl start homelab-monitor"
    } >> "$LOG" 2>&1
    if healthy >> "$LOG" 2>&1; then
      say "${YEL}●${R}  Rolled back: the previous version is running on the data from before the upgrade."
      say "${D}The failed build is kept in ${APP_DIR}.failed; log: ${LOG}${R}"
    else
      say "${RED}✖${R}  The rollback did not come up either. Rebuild and restore ${BACKUP_FILE}."
      rebuild_help
    fi
    [[ "$UPGRADE_FAILED" == *installed* ]] && record_history 0 replace || record_history 0 health
    tidy_new
    echo
    exit 1
  fi
  ct "printf 'LAYOUT=%s\nVERSION=%s\n' ${LAYOUT} ${VERSION} > ${INSTALL_DIR}/layout" >> "$LOG" 2>&1
  # Before the history is recorded, so the warnings are in the log that goes with it.
  upgrade_warnings > "$STATE/warnings"
  record_history 1 none
  tidy_new
  rm -f "$BOOT" "$PRECHECK"; rm -rf "$FILES"
  end_screen
  if [[ "$(cat "$STATE/ingress" 2>/dev/null || true)" == off ]]; then
    result_box "$YEL" "⚠" "Upgraded to ${VERSION}, inbound firewall NOT active"
    ingress_help
  else
    result_box "$GRN" "✔" "Upgraded to ${VERSION} and answering"
  fi
  printf '  %sWhat the check found%s\n' "$B" "$R"
  show_findings
  cat "$STATE/warnings"
  printf '\n  %sGood to know%s\n' "$B" "$R"
  printf '      %-9s %s\n' "Backup" "${BACKUP_FILE} (made just before)"
  printf '      %-9s %s\n' "Previous" "the code that ran before is kept in ${APP_DIR}.old until the next upgrade"
  printf '      %-9s %s\n' "Built" "__BUILT__"
  ingress_kept_note
  print_sec_notes
  printf '      %-9s %s\n\n' "Log" "$LOG"
  passphrase_note
  exit 0
fi

# ------------------------------------------------------------------ run a restore (the container is kept)
# Finds every backup the container can see (its own folder, the Syncthing folder, mounted shares,
# /root), lets the person pick one, then: checks it with the new build, keeps a copy of what is
# there now, wipes the app and its data, puts a fresh copy of the app in, restores the backup and
# waits for it to answer. If any of that fails after the wipe, the copy of what was there is put
# back. Nothing about the container itself (CPU, memory, disk, network) is changed.
if [[ "$MODE" == "restore" ]]; then
  clear 2>/dev/null || true
  banner
  say "Getting ${WHERE} ready and looking for backups…"
  ( set -euo pipefail; s_ready ) >> "$LOG" 2>&1 || die "$(cat "$STATE/why" 2>/dev/null || echo "${WHERE^} did not become ready.")"
  ( set -euo pipefail; s_copy ) >> "$LOG" 2>&1 || die "$(cat "$STATE/why" 2>/dev/null || echo "Could not copy the new build into ${WHERE}.")"
  ct "python3 ${NEW_DIR}/sitectl.py find-backups --data ${DATA_DIR} --also /root --also /mnt/hm-restore" > "$STATE/backups" 2>> "$LOG" || true
  mapfile -t FOUND < <(grep '|' "$STATE/backups" || true)
  if (( ${#FOUND[@]} == 0 )); then
    tidy_new
    {
      printf '\n  %s✖  No backups were found, so there is nothing to restore. Nothing was changed.%s\n\n' "$RED$B" "$R"
      printf '  Looked in %s: %s/backups, the Syncthing folder, every mounted share\n' "$WHERE" "$DATA_DIR"
      printf '  and /root. A backup is a file named monitor-backup-<date>.tar.gz. To use one:\n\n'
      if [[ "$TARGET" == "local" ]]; then
        printf '    copy it to %s/backups/ on this machine, or mount the share that holds it,\n' "$DATA_DIR"
      else
        printf '    %spct push %s monitor-backup-<date>.tar.gz %s/backups/monitor-backup-<date>.tar.gz%s\n' "$B" "$CTID" "$DATA_DIR" "$R"
        printf '    (from this host), or mount the share that holds it inside the container,\n'
      fi
      printf '  then run this again.\n\n'
    } >&2
    exit 1
  fi
  human_size() { awk -v b="$1" 'BEGIN { split("B KB MB GB", u); i = 1; while (b >= 1024 && i < 4) { b /= 1024; i++ } printf (i == 1 ? "%d %s" : "%.1f %s"), b, u[i] }'; }
  when() { date -d "@$1" '+%F %H:%M' 2>/dev/null || echo "$1"; }
  printf '\n  %sBackups %s can see, newest first%s\n\n' "$B" "$WHERE" "$R"
  printf '  %s  #  Made              Version     Size      Where%s\n' "$D" "$R"
  for i in "${!FOUND[@]}"; do
    IFS='|' read -r f_path f_time f_size f_ver f_key f_where f_tag <<<"${FOUND[$i]}"
    kind=""
    case "$f_path" in */pre-upgrade/*) kind=", before an upgrade" ;; */pre-update/*) kind=", before an update" ;; */pre-restore/*) kind=", before a restore" ;; esac
    nokey=""; [[ "$f_key" == "no key" || "$f_key" == "withheld" ]] && nokey=" ${YEL}(no key)${R}"; [[ "$f_key" == "sealed key" ]] && nokey=" ${D}(passphrase)${R}"
    printf '  %s%3d%s  %-16s  %-10s  %-8s  %s%s%s\n' "$B" $((i + 1)) "$R" "$(when "$f_time")" "${f_ver:-?}" "$(human_size "$f_size")" "$f_where" "$kind" "$nokey"
  done
  printf '  %s  0  Cancel%s\n\n' "$D" "$R"
  while :; do
    read -r -p "  Restore which one? " n || { tidy_new; echo "  Nothing done."; exit 0; }
    [[ "$n" == "0" ]] && { tidy_new; echo "  Nothing done."; exit 0; }
    [[ "$n" =~ ^[0-9]+$ ]] && (( n >= 1 && n <= ${#FOUND[@]} )) && break
    echo "  Type one of the numbers shown."
  done
  IFS='|' read -r PICKED f_time f_size f_ver f_key f_where f_tag <<<"${FOUND[$((n - 1))]}"
  PICKED_NAME="$(basename "$PICKED")"
  echo
  printf '  %sThis wipes the monitor in %s (its app and all its data) and puts back%s\n' "$RED$B" "$WHERE" "$R"
  printf '  %s%s, made %s by version %s.%s\n' "$RED$B" "$PICKED_NAME" "$(when "$f_time")" "${f_ver:-?}" "$R"
  printf '  A copy of what is there now is kept first, in %s/pre-restore.\n' "$SAFE_DIR"
  [[ "$TARGET" == "local" ]] || printf '  The container itself (CPU, memory, disk, network) is not changed.\n'
  [[ "$f_key" == "no key" ]] && printf '  %sThis older backup has no vault key: stored passwords stay locked until /root/restore.sh\n  is run with its passphrase.%s\n' "$YEL" "$R"
  # What the backup's site settings would do (shares, Syncthing), so nothing is applied unseen.
  # The path goes to the container as an argument, never inside a shell command.
  mapfile -t SITE_LINES < <(pct exec "${CTID}" -- python3 "${NEW_DIR}/sitectl.py" site-of "$PICKED" 2>/dev/null || true)
  if (( ${#SITE_LINES[@]} )); then
    printf '  Site settings in it, applied after the restore:\n'
    for l in "${SITE_LINES[@]}"; do
      if [[ "$l" == '!'* ]]; then printf '    %sRefused, not applied: %s%s\n' "$YEL" "${l#!}" "$R"; else printf '    %s\n' "$l"; fi
    done
  fi
  # Before any question: a private copy, then can it be proven unchanged, and is there a key for it?
  # The path goes to the container as an argument, never inside a shell command.
  if ! pct exec "${CTID}" -- python3 "${NEW_DIR}/sitectl.py" take "$PICKED" --to /root/hm-restore.tar.gz >> "$LOG" 2>&1; then
    tidy_new; printf '\n  %s✖  This backup could not be copied for the restore. Nothing was changed.%s\n\n' "$RED$B" "$R" >&2; exit 1
  fi
  AUTH=()
  if [[ "$PICKED" == "${SAFE_DIR}/"* ]]; then
    # Root's own folder: trusted by where it is (the app cannot write there).
    sum="$(pct exec "${CTID}" -- sha256sum -- /root/hm-restore.tar.gz 2>/dev/null | awk '{print $1}')" || sum=""
    [[ "$sum" =~ ^[0-9a-f]{64}$ ]] && AUTH=(--expect-sha256 "$sum")
  fi
  RESTORE_PASS="$BACKUP_PASSPHRASE"
  pp=(); [[ -n "$RESTORE_PASS" ]] && pp=(--passphrase-stdin)
  check_auth() {
    if AUTH_OUT="$(printf '%s\n' "$RESTORE_PASS" | pct exec "${CTID}" -- python3 "${NEW_DIR}/sitectl.py" check-auth /root/hm-restore.tar.gz \
        --key "${KEY_DIR}/vault.key" "${pp[@]}" "${AUTH[@]}" 2>&1)"; then AUTH_RC=0; else AUTH_RC=$?; fi
  }
  show_auth() { grep -v '^HM_AUTH=' <<<"$AUTH_OUT" | sed 's/^ERROR: //; s/^/  /' || true; }
  ask_pass() {
    local attempt
    for attempt in 1 2 3; do
      (( AUTH_RC == 4 )) || return 0
      read -r -s -p "  Backup passphrase for this backup: " RESTORE_PASS || RESTORE_PASS=""; echo
      pp=(--passphrase-stdin); check_auth
    done
  }
  check_auth
  ask_pass
  if (( AUTH_RC == 7 )) && grep -q '^HM_AUTH=unverified-tagged' <<<"$AUTH_OUT"; then
    echo "  This backup's tag does not match the passphrase. It may be from before the passphrase was changed."
    read -r -s -p "  An older backup passphrase (or press Enter to skip): " older || older=""; echo
    if [[ -n "$older" ]]; then
      before="$RESTORE_PASS"; RESTORE_PASS="$older"; pp=(--passphrase-stdin); check_auth
      if (( AUTH_RC == 7 )); then RESTORE_PASS="$before"; pp=(); [[ -n "$RESTORE_PASS" ]] && pp=(--passphrase-stdin); check_auth; fi
    fi
    unset older
  fi
  if (( AUTH_RC == 7 )); then
    echo; show_auth; echo
    read -r -p "  Type UNVERIFIED to restore it anyway: " ok || ok=""
    [[ "$ok" == "UNVERIFIED" ]] || { tidy_new; echo "  Nothing done."; exit 0; }
    AUTH+=(--accept-unverified); check_auth; ask_pass
  fi
  if (( AUTH_RC == 8 )); then
    echo; show_auth; echo
    read -r -p "  Type FORGET to restore it without them: " ok || ok=""
    [[ "$ok" == "FORGET" ]] || { tidy_new; echo "  Nothing done."; exit 0; }
    AUTH+=(--forget-secrets); check_auth; ask_pass
  fi
  if (( AUTH_RC != 0 )); then
    show_auth; tidy_new; printf '\n  %s✖  This backup cannot be restored. Nothing was changed.%s\n\n' "$RED$B" "$R" >&2; exit 1
  fi
  read -r -p "  Type RESTORE to go ahead: " ok || ok=""
  [[ "$ok" == "RESTORE" ]] || { tidy_new; echo "  Nothing done."; exit 0; }

  s_verify() {
    local out
    if ! out="$(printf '%s\n' "$RESTORE_PASS" | pct exec "${CTID}" -- python3 "${NEW_DIR}/sitectl.py" verify /root/hm-restore.tar.gz \
        --key "${KEY_DIR}/vault.key" "${pp[@]}" "${AUTH[@]}" 2>&1)"; then
      echo "$out"
      echo "$(grep '^ERROR' <<<"$out" | tail -n 1 | sed 's/^ERROR: //'). Nothing was changed." > "$STATE/why"
      return 1
    fi
    echo "$out"
  }
  s_safety() {
    local out f sum
    out="$(ct "systemctl stop homelab-monitor || true
      install -d -m 0700 -o root -g root ${SAFE_DIR} ${SAFE_DIR}/pre-restore
      if [ -f ${DATA_DIR}/monitor.db ]; then
        python3 ${NEW_DIR}/sitectl.py backup --data ${DATA_DIR} --key ${KEY_DIR}/vault.key --dest ${SAFE_DIR}/pre-restore --keep 3 --safety --safe-dir ${SAFE_DIR} \
          || { f=${SAFE_DIR}/pre-restore/files-\$(date +%Y%m%d-%H%M%S).tar.gz; tar -czf \$f --exclude=./backups -C ${DATA_DIR} . && echo \$f; }
      else echo none; fi")"
    echo "$out"
    f="$(tail -n 1 <<<"$out")"
    echo "$f" > "$STATE/safety"
    if [[ "$f" =~ ^[A-Za-z0-9._/:-]+/monitor-backup-[A-Za-z0-9._-]+[.]tar[.]gz$ ]]; then
      sum="$(pct exec "${CTID}" -- sha256sum -- "$f" 2>/dev/null | awk '{print $1}')" || sum=""
      [[ "$sum" =~ ^[0-9a-f]{64}$ ]] && echo "$sum" > "$STATE/safety_sha"
    fi
    return 0
  }
  s_wipe() {
    ct "systemctl stop homelab-monitor || true
      find ${DATA_DIR} -mindepth 1 -maxdepth 1 ! -name backups -exec rm -rf {} +
      rm -f ${KEY_DIR}/vault.key ${KEY_DIR}/setup.env
      rm -rf ${APP_DIR} ${APP_DIR}.old ${APP_DIR}.new ${APP_DIR}.failed"
  }
  s_rapp() { push_app; install_helpers no; }
  s_rrestore() {
    printf '%s\n' "$RESTORE_PASS" | pct exec "${CTID}" -- python3 "${APP_DIR}/sitectl.py" restore /root/hm-restore.tar.gz \
      --data "${DATA_DIR}" --key "${KEY_DIR}/vault.key" --record-name "$PICKED_NAME" "${pp[@]}" "${AUTH[@]}"
    ct "set -e
      chown -hR ${SERVICE_USER}:${SERVICE_USER} ${DATA_DIR} ${KEY_DIR}
      if [ -f ${DATA_DIR}/site-restored.json ]; then python3 ${APP_DIR}/sitectl.py apply-site ${DATA_DIR}/site-restored.json || echo 'Some site settings could not be applied'; fi
      printf 'LAYOUT=%s\nVERSION=%s\n' ${LAYOUT} ${VERSION} > ${INSTALL_DIR}/layout
      systemctl start homelab-monitor"
  }
  s_rweb() {
    healthy || return 1
    pct exec "${CTID}" -- hostname -I | awk '{print $1}' > "$STATE/ip"
  }

  define_steps
  start_drawer
  run_step verify s_verify
  run_step safety s_safety
  SAFETY="$(cat "$STATE/safety" 2>/dev/null || echo none)"
  SAFETY_SHA="$(cat "$STATE/safety_sha" 2>/dev/null || true)"
  RESTORE_FAILED=""
  run_step wipe s_wipe soft || RESTORE_FAILED="the old app and data could not be cleared"
  if [[ -z "$RESTORE_FAILED" ]]; then run_step app s_rapp soft || RESTORE_FAILED="the fresh copy of the app could not be installed"; else skip_step app; fi
  if [[ -z "$RESTORE_FAILED" ]]; then run_step restore s_rrestore soft || RESTORE_FAILED="the backup could not be restored"; else skip_step restore; fi
  if [[ -z "$RESTORE_FAILED" ]]; then run_step web s_rweb soft || RESTORE_FAILED="the monitor did not answer after the restore"; else skip_step web; fi
  if [[ -n "$RESTORE_FAILED" ]]; then
    end_screen
    result_box "$RED" "✖" "Restore failed: putting back what was there"
    say "Why: ${RESTORE_FAILED}."
    if [[ "$SAFETY" == *monitor-backup-*.tar.gz ]]; then
      {
        ct "systemctl stop homelab-monitor || true
          [ -f ${APP_DIR}/server.py ] || { rm -rf ${APP_DIR}; cp -a ${NEW_DIR} ${APP_DIR}; chown -hR root:root ${APP_DIR}; }
          python3 ${NEW_DIR}/sitectl.py restore ${SAFETY} --data ${DATA_DIR} --key ${KEY_DIR}/vault.key ${SAFETY_SHA:+--expect-sha256 ${SAFETY_SHA}}
          chown -hR ${SERVICE_USER}:${SERVICE_USER} ${DATA_DIR} ${KEY_DIR}
          systemctl start homelab-monitor"
      } >> "$LOG" 2>&1
      if healthy >> "$LOG" 2>&1; then
        say "${YEL}●${R}  Put back: the monitor runs on the data it had before (${SAFETY})."
      else
        say "${RED}✖${R}  Putting it back did not come up either. The copy is ${SAFETY}: rebuild and restore it."
      fi
    elif [[ "$SAFETY" == none ]]; then
      say "There was no data before the restore, so there is nothing to put back. Try another backup, or rebuild."
    else
      say "The data from before is kept as plain files in ${SAFETY} (it could not be backed up the usual way)."
    fi
    say "${D}Log: ${LOG}${R}"
    tidy_new
    echo
    exit 1
  fi
  tidy_new
  stop_drawer
  IP="$(cat "$STATE/ip" 2>/dev/null || true)"
  RESTORED="${PICKED_NAME}"
fi

# ------------------------------------------------------------------ run the install
if [[ "$MODE" == "install" || "$MODE" == "rebuild" ]]; then
  define_steps
  start_drawer
  if [[ "$TARGET" == "local" ]]; then
    run_step here s_here
  else
    run_step host s_host
    run_step template s_template
    run_step create s_create
    run_step boot s_boot
    unset ROOT_PASSWORD
  fi
  pct push "${CTID}" "$BOOT" /root/.hm-bootstrap.sh >> "$LOG" 2>&1 || die "Could not copy the bootstrap into ${WHERE}."
  run_step packages s_packages
  run_step tools s_tools
  run_step syncthing s_syncthing
  run_step app s_app
  run_step services s_services
  share_needed && run_step share s_share
  [[ "$RESTORE" == "latest" ]] && run_step restore s_restore
  run_step web s_web
  demo_wanted && run_step demo s_demo
  pct exec "${CTID}" -- rm -f /root/.hm-bootstrap.sh >> "$LOG" 2>&1 || true
  sleep 0.6
  stop_drawer
  IP="$(cat "$STATE/ip" 2>/dev/null || true)"
  RESTORED="$(cat "$STATE/restored" 2>/dev/null || true)"
fi
rm -f "$BOOT"; rm -rf "$FILES"

# ------------------------------------------------------------------ done
SCHEME=http
if [[ "$MODE" != "preview" ]] && pct exec "${CTID}" -- curl -fsS "http://127.0.0.1:${PORT}/api/auth/status" 2>/dev/null | grep -q '"https": true'; then
  SCHEME=https
fi
URL="${SCHEME}://${IP:-<container ip>}:${PORT}"
clear 2>/dev/null || true
banner
INGRESS="$(cat "$STATE/ingress" 2>/dev/null || true)"
if [[ "$INGRESS" == off ]]; then
  result_box "$YEL" "⚠" "Running, but the inbound firewall is NOT active"
  ingress_help
else
  line="$(printf '─%.0s' $(seq 1 64))"
  printf '  %s╭%s╮%s\n' "$GRN" "$line" "$R"
  printf '  %s│%s  %s✔  Your monitor is up and running%s%29s%s│%s\n' "$GRN" "$R" "$B" "$R" "" "$GRN" "$R"
  printf '  %s╰%s╯%s\n\n' "$GRN" "$line" "$R"
fi
printf '  %sOpen it in your browser%s\n' "$B" "$R"
printf '      %s%s%s\n' "$CYN$B" "$URL" "$R"
if [[ "$SCHEME" == https ]]; then
  printf '      %sThe browser warns once: the certificate was made by the monitor, not a public authority.%s\n' "$D" "$R"
  printf '      %sContinue, or trust it (Settings, HTTPS shows its fingerprint and a download).%s\n' "$D" "$R"
fi
printf '\n'
if [[ -n "${RESTORED-}" ]]; then
  printf '  %sRestored%s from %s\n' "$B" "$R" "$RESTORED"
  printf '      Log in with your usual username and password. Devices, history, credentials,\n'
  printf '      workflows and settings came back with it.\n\n'
else
  printf '  %sFirst visit%s\n' "$B" "$R"
  if demo_wanted; then
    printf '      Choose the administrator username and password. The demo devices are waiting for\n'
    printf '      you; Settings, Demo data removes them when you want to use it for real.\n'
  else
    printf '      Choose the administrator username and password, then the setup guide walks\n'
    printf '      you through scanning your network.\n'
  fi
  printf '      Setup code  %s%s%s  %s(asked once, on that page)%s\n' "$YEL$B" "$SETUP_TOKEN" "$R" "$D" "$R"
  printf '      %s⚠  Copy the setup code now: it is shown only this once.%s\n' "$YEL$B" "$R"
  if [[ "$TARGET" == "local" ]]; then
    printf '      %sLost it? As root on this machine run /root/setup-code.sh (works until the first account exists).%s\n\n' "$D" "$R"
  else
    printf '      %sLost it? ssh root@%s then /root/setup-code.sh (works until the first account exists).%s\n\n' "$D" "${IP:-<container ip>}" "$R"
  fi
  printf '  %sRestoring a backup instead?%s  Do it before the first visit:\n' "$B" "$R"
  if [[ "$TARGET" == "local" ]]; then
    printf '      on this machine, as root:   /root/restore.sh\n\n'
  else
    printf '      ssh root@%s   then   /root/restore.sh\n' "${IP:-<container ip>}"
    printf '      %s(or from this host: pct enter %s)%s\n\n' "$D" "$CTID" "$R"
  fi
fi
printf '  %sGood to know%s\n' "$B" "$R"
if [[ "$TARGET" == "local" ]]; then
  printf '      %-9s as before: your own login, unchanged; the helpers below are in /root (run as root)\n' "SSH"
elif [[ "$MODE" == "restore" ]]; then
  printf '      %-9s root@%s as before (the container was kept)\n' "SSH" "${IP:-<container ip>}"
elif [[ -n "$SSH_KEY_LINE" ]]; then
  printf '      %-9s root@%s with your SSH key only (password logins over SSH are off)\n' "SSH" "${IP:-<container ip>}"
else
  printf '      %-9s root@%s with the container password you just set\n' "SSH" "${IP:-<container ip>}"
fi
printf '      %-9s daily at 03:30; Settings, System shows where they go and what to sync\n' "Backups"
printf '      %-9s bash %s%s --upgrade  %s(keeps everything)%s;  system packages: /root/update.sh\n' "Updates" "$(basename "$0")" "$FLAG" "$D" "$R"
printf '      %-9s /root/reset-admin.sh on the %s  %s(lost web password or 2FA)%s\n' "Login" "${TARGET/local/monitor machine}" "$D" "$R"
printf '      %-9s Settings, HTTPS; /root/update.sh option 6 goes back to plain HTTP from the shell\n' "HTTPS"
if [[ "$TARGET" == "local" ]]; then
  printf '      %-9s none added for incoming traffic: port %s (the web page) and UDP 161 (SNMP) are open\n' "Firewall" "$PORT"
fi
ingress_kept_note
print_sec_notes
printf '      %-9s %s\n\n' "Log" "$LOG"
passphrase_note
[[ "$MODE" == "preview" ]] && printf '  %sThat was a preview. Nothing was created.%s\n\n' "$D" "$R"
exit 0

__PAYLOAD_BEGIN__
__PAYLOAD__
__PAYLOAD_END__
