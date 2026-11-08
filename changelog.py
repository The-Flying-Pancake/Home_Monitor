"""What's changed: release notes in plain words, shown once to each user after an upgrade.

Each release has an id (counting up), a date, a title and a few sentences written for the
person using the monitor, not for whoever built it. The list starts with the round that
replaced Uptime Kuma (2026-11-02); earlier builds were before the first upgrade.

Who has seen what: one internal setting, {username: highest id seen}. The key "*" is the
default for a user not in the map: a database that already had accounts when this build first
started gets no default, so everyone sees every note once; a fresh install sets it to the
newest id, so a new install starts with nothing to read. Accounts made later are marked as
having seen everything up to then.
"""

import json
from typing import Any, Dict, List

import database

SEEN_KEY = "changes_seen"

RELEASES: List[Dict[str, Any]] = [
    {"id": 1, "date": "2026-11-02", "title": "Security, availability and checks for websites", "items": [
        "Two-step login: each user can add an authenticator app, with recovery codes for a lost phone.",
        "Sensitive actions ask for your password again; the most sensitive ones (credentials, users) also ask for your authenticator code.",
        "Forgot your password? Reset it with your authenticator and a code sent to Telegram. From the container, /root/reset-admin.sh does it too.",
        "A new Availability page shows uptime over 24 hours, 7, 30 and 90 days, with response times and incidents, like a status page.",
        "Website checks: watch a page by its address, the answer it should give and text it must contain.",
        "A Proxmox dashboard: nodes, VMs, containers, storage, backups and failed tasks, read only.",
        "Graphs: drag across one to zoom in. Enlarge opens it in its own window.",
        "Telegram messages wait and try again while the internet is down; a message editor with ready-made texts; newly added devices stay quiet at first.",
        "Automation can send a Telegram message. Workflows can also start by themselves when something happens: a value crosses a line, a device goes offline, a service stops or a problem opens.",
        "Custom SNMP values: poll values a device's template does not read, found by browsing what the device answers.",
        "Fix SNMP rewrites a device's SNMP settings cleanly and shows you exactly what it will change first.",
        "Adding devices: scan several networks at once and look for services on a range of ports.",
        "Buttons that delete or change a lot wait a moment before they can be pressed.",
    ]},
    {"id": 2, "date": "2026-11-02", "title": "Backups and quieter notifications", "items": [
        "With Syncthing on, backups go straight into the synced folder, so your NAS holds them.",
        "The audit log can be searched and filtered by category and time.",
        "A quiet window for Telegram: messages still arrive, without a sound, between the times you choose. Serious problems still ring.",
        "Notification settings are split into Delivery, When and Messages.",
    ]},
    {"id": 3, "date": "2026-11-02", "title": "Proxmox and Fix SNMP, fixed", "items": [
        "Proxmox is switched on in Settings and gets its own page in the menu once it is connected.",
        "Click a Proxmox node, VM or container to see its CPU, memory, network and disk graphs.",
        "When a Proxmox token lacks permissions, the page says which ones instead of showing almost nothing.",
        "Fix SNMP now works on hosts and containers where it failed before.",
        "While you are in Settings its own menu replaces the main one, with Back to where you came from.",
        "Tables and settings line up properly.",
    ]},
    {"id": 4, "date": "2026-11-04", "title": "Availability ranges and smoother graphs", "items": [
        "Availability shows 24 hours, 7, 30 or 90 days, on its page and on each device.",
        "Graph lines are smooth curves; busy graphs show an average with a faint band up to the peaks.",
        "The setup guide only appears the first time and is no longer in the menu.",
        "The readout when you hover over an enlarged graph is no longer hidden behind the window.",
    ]},
    {"id": 5, "date": "2026-11-04", "title": "Safer upgrades", "items": [
        "An upgrade first checks your data with the new version and takes a backup. If the new version does not start, it puts everything back by itself.",
        "Restoring a backup checks it against this version first.",
        "An installer that was edited on Windows repairs itself instead of failing.",
    ]},
    {"id": 6, "date": "2026-11-04", "title": "Ping only devices, port scans and a clearer Add window", "items": [
        "Add something that only answers ping, with no SNMP needed. Scans suggest this for hosts without SNMP.",
        "Service scans check common ports, the ports you choose or all 65,535 (with a warning first). A running scan can be stopped.",
        "The Add window starts by asking what you are adding: something to ping, a device with statistics or a service.",
        "Setup can add any host as ping only. A new step looks for services on the devices you picked.",
    ]},
    {"id": 7, "date": "2026-11-04", "title": "Groups, tags and a guide", "items": [
        "Make your own groups, rename any group and choose the order.",
        "Tags label devices (office, critical) with a colour and a description. The Devices, Availability and Events pages filter by tag.",
        "Alert rules per tag: for example everything tagged critical can alert sooner.",
        "Dashboard tiles can show just one group or one tag.",
        "A Guide page in the menu explains every part of the monitor, with search.",
    ]},
    {"id": 8, "date": "2026-11-04", "title": "A clearer map", "items": [
        "The map is redrawn: each device is a card with its state, icon, address and kind. Lines run neatly from box to box with the switch ports marked on them.",
        "A box you drop snaps into place. Everything connected below it moves along.",
        "Zoom buttons, Fit and a key sit on the map itself.",
        "The monitor is no longer drawn on the map; the side panel says where it connects.",
        "On graphs with several lines, click a name under the graph to hide or show that line.",
    ]},
    {"id": 9, "date": "2026-11-04", "title": "HTTPS", "items": [
        "The monitor can be served over HTTPS, so passwords cannot be read off the network: with a certificate it makes itself or with your own (Settings, HTTPS).",
        "Old http:// links and bookmarks are sent on to https:// automatically.",
        "Certificates are kept in backups. You are warned before your own certificate expires.",
    ]},
    {"id": 10, "date": "2026-11-04", "title": "Custom SNMP values that do something; your own Overview", "items": [
        "Custom SNMP values have their own tab on each device, with a graph for each value and the SNMP browser built in.",
        "A custom value can go on the Overview, open a problem at a threshold and start a workflow. Automation lists them by the names you gave them.",
        "Choose which graphs a device's Overview shows (Choose graphs). Or press Add to overview on any graph in the Graphs tab.",
        "Tags are easier to reach: + tag beside every device on the Devices page. The tag filter is always there.",
        "Adding a dashboard tile asks which devices it covers: all of them, a group or a tag.",
        "This window: after an upgrade, your next login shows what changed.",
    ]},
    {"id": 11, "date": "2026-11-04", "title": "Fewer surprises", "items": [
        "One alert for one failure: when a switch goes down you get one message for it, listing the devices behind it, instead of one for each.",
        "Maintenance windows: start one on a device page; Settings sets one for a group, a tag or everything. Problems still show but no messages are sent. The downtime counts as planned.",
        "Forecasts: the Storage tab says when a volume or disk will be full at the rate it is growing; an alert rule warns two weeks ahead.",
        "Website checks on https:// addresses warn 21 days before the site's certificate runs out.",
        "A new Inventory page lists every device seen on the network, where it is plugged in and when it first appeared. A device never seen before is announced.",
        "Pi-hole: queries, blocking and a real DNS check every minute, on the Pi-hole's own DNS tab. DNS that is down or slow opens a problem.",
        "UniFi: signal, speed, roaming and experience for every Wi-Fi device, on each access point's Wireless tab.",
        "An optional daily or weekly summary on Telegram (Settings, Notifications, When).",
    ]},
    {"id": 12, "date": "2026-11-04", "title": "Wi-Fi and Pi-hole pages; a map that knows", "items": [
        "With UniFi connected, the map uses UniFi's own layout: which port each switch and access point is plugged into. Devices on Wi-Fi hang off the access point they are on.",
        "A Wi-Fi page: every access point side by side and every Wi-Fi device in one list, weakest signal first.",
        "Reconnect a device stuck on a far access point, from the Wi-Fi page or with the workflow step Reconnect weak Wi-Fi. At most once an hour per device; a never-reconnect list keeps printers and gadgets out of it.",
        "A Pi-hole page: today's figures, where queries go and what is blocked most. Pause blocking for 5, 30 or 60 minutes; it comes back on by itself. A pause raises no alert.",
        "UniFi accepts the site by its name (Home) or its id (default).",
    ]},
    {"id": 13, "date": "2026-11-04", "title": "More from Proxmox; a tidier Inventory", "items": [
        "The map places every monitored VM and container on the Proxmox node that runs it.",
        "New alert rules: a guest that starts at boot but is not running, one that keeps restarting, memory or a container's disk nearly full.",
        "Proxmox storage pools get forecasts: the node's Storage tab says when each one will be full.",
        "Monitor buttons on the Proxmox page and on the Inventory open the Add window with the name and address filled in.",
        "With a second token that may make changes: start, shut down and reboot guests from the Proxmox page. The workflow step Snapshot a Proxmox guest takes a snapshot before an update.",
        "The Inventory shows each device once. Access points and other UniFi gear used to appear once for every network card and radio.",
    ]},
    {"id": 14, "date": "2026-11-04", "title": "Ask the Telegram bot", "items": [
        "Send your bot /status, /problems, /device NAME or /changes and it answers: what is down, what is wrong, one device's figures and the last 24 hours.",
        "The commands only read. Only your own chat gets answers; any other is ignored and noted in the audit log.",
        "Write the replies your way: Settings, Notifications, Commands has a text for each one, with placeholders and a preview of your own figures.",
        "Switch it off with Answer commands in Settings, Notifications, Delivery.",
    ]},
    {"id": 15, "date": "2026-11-04", "title": "Your own Telegram commands", "items": [
        "Settings, Notifications, Commands is now a command builder: the built-in commands with their replies and Add command for your own.",
        "A command of your own shows what you choose: devices (picked one by one, by tag or by group), Wi-Fi networks, access points or devices, Proxmox guests, nodes or storage, Pi-hole, problems or storage forecasts.",
        "Write a header, a line repeated for each item and a footer, with placeholders: dozens per source plus any figure a device records. The preview is the real reply, from your data now.",
        "Filters such as only down, only running or only weak. A word after the command narrows the list: /wifi guest.",
        "Any command can be switched off, the built-in ones too. Telegram's command menu (type /) lists exactly what is on.",
    ]},
    {"id": 16, "date": "2026-11-04", "title": "Smarter message texts", "items": [
        "Every Telegram text understands conditions: {if down > 0} ... {else} ... {end}. Notifications, workflow messages and command replies alike.",
        "Arithmetic with {= up / total * 100 | round:1} and filters such as round, default, plural, bar, truncate, sort, first and join.",
        "Your own commands can be sorted by any of their placeholders (highest first if you like) and kept to at most so many lines.",
        "Up to 95 commands of your own.",
        "The message editors are wider and list these tricks to click in. Their preview uses the real engine.",
    ]},
    {"id": 17, "date": "2026-11-04", "title": "Fewer messages, quieter restarts, a better guide", "items": [
        "Messages that come at once are grouped: restart four access points and you get one message listing them, not one for each device. Settings, Notifications, When.",
        "A workflow step Suppress notifications keeps Telegram quiet for the devices it restarts until the run ends (plus a few minutes), without hiding the problems.",
        "Send Telegram in a workflow can send quietly, without a sound.",
        "The restart templates suppress notifications by default. New templates: snapshot, update and restart Proxmox guests; restart a service; free disk space; a health check; update Pi-hole; reconnect weak Wi-Fi.",
        "More command templates: free disk space, restart a service, a quick health check, Pi-hole updates and listing Proxmox guests.",
        "The guide has chapters, numbered topics and a proper search box. It fits the window.",
    ]},
    {"id": 18, "date": "2026-11-05", "title": "Install without a container", "items": [
        "The installer can skip the Proxmox container: infra.sh --local installs the monitor on the machine it runs on, a VM for example. Upgrades work the same way with --local --upgrade.",
    ]},
    {"id": 19, "date": "2026-11-07", "title": "A calmer inventory and fewer shutdown alerts", "items": [
        "Edit and Forget in the Inventory work again (they failed with Endpoint not found). Known on a row marks a device known straight away, online or not.",
        "Add a device puts in an address as known before it is ever seen.",
        "A Wi-Fi network column shows the SSID each Wi-Fi device last joined.",
        "Quiet networks: devices on a tenant's or guest SSID are kept but never announced or counted as new. One device can be made quiet too.",
        "A device that is always weak on Wi-Fi can be left out of the weak-signal problem from its Edit window. It can also get a lower line of its own.",
        "Shutting a machine down sends one offline message: its SNMP warning waits a minute and a half and is dropped once the device is offline.",
    ]},
    {"id": 20, "date": "2026-11-07", "title": "Host actions for Linux machines", "items": [
        "Host actions: 30 fixed maintenance jobs for Linux hosts, run once over SSH from the host's page or from one of its problems (Fix...).",
        "A problem lists the actions that suit it first. Storage filling up starts with Disk space: what is using it.",
        "Checks change nothing and run at one click. Clean-ups show what they would remove before they run.",
        "Restarts ask for the host's name and can take a Proxmox snapshot first. Restarting the whole machine mutes its notifications until it is back.",
        "Make this a workflow saves an action as a workflow on that host, to repeat on a schedule. The same jobs are in the workflow command templates.",
        "Every run is kept with its output on the Automation page and in the audit log.",
    ]},
    {"id": 21, "date": "2026-11-07", "title": "Quieter nights and better grouping", "items": [
        "Back online and resolved messages never ring in the silent window. They used to carry the outage's critical severity and rang.",
        "Grouping waits until messages stop coming, so machines shut down one after another arrive as one message (at most four times Wait to group).",
        "Grouped messages list Proxmox messages in their own section.",
        "A problem on a device that is already offline is not sent: the offline message covers it. A Proxmox guest stopped on a machine you shut down no longer sends a second message.",
        "Send silent test (Settings, Notifications) sends a message without a sound and shows the monitor's clock.",
        "Device restarted leaves Active problems after a minute instead of 30.",
    ]},
    {"id": 22, "date": "2026-11-08", "title": "Several dashboards, tags you can see, a calmer Edit device", "items": [
        "Several dashboards: + Add dashboard starts a blank one or one of 20 ready-made ones (Proxmox, Wi-Fi, Morning check, Wall screen and more). Switch between them from the list beside the title; each is saved for everyone.",
        "Edit dashboard can rename the dashboard and each tile (Rename on the tile) and delete a dashboard.",
        "New tiles: Offline now, Proxmox guests, Pi-hole, Disks filling up, Host actions, Workflow runs, Maintenance windows, New devices and a Note.",
        "Tags on the Devices page: + tag shows how many tags a device has; hover over it to see them. Clicking it opens a tag manager: the applied tags (click to remove), the other tags (click to add) and a box for a new one. Adding or removing tags for several devices uses the same window.",
        "Edit device is wider and split in two: the device (name, address, group, tags) and how it is watched (template, ping, SNMP as one optional part).",
        "Automation: the steps on the left are grouped and coloured by what they do, the same colours as on the canvas. Templates are a second tab on the left; the right side shows what you picked.",
        "Eight new workflow templates made of host actions: weekly tidy-up, disk filling up, security report, updates then restart outdated services, Docker tidy-up, disk health, Proxmox host check and clearing failed services.",
        "Signed out, the login screen is the whole page: refreshing never shows the page behind it. You still return to where you were after logging in.",
        "Going into Settings and back slides the menu instead of switching it at once.",
    ]},
    {"id": 23, "date": "2026-11-08", "title": "Accurate groups, quicker all-clears, SSH in one paste", "items": [
        "A grouped offline message lists the devices behind each one and counts them: Offline (6): switch-01 (+ nas-01, web-app), media-server (+ downloads), test.",
        "Guest is stopped clears within a minute of Proxmox reporting the guest running. It used to wait out Resolve after as well.",
        "Volume or disk filling up warns only from 80% full. A disk at 57% that grows quickly is no longer a warning.",
        "Fix SNMP and Host actions: when SSH does not let the monitor in, Copy console commands gives one line to paste into the host's root shell. It installs SSH when missing, lets the monitor's address log in with a password or key (root too, from that address only) and restarts SSH. Then try again.",
        "The installer: a new container gets a 20 GB disk. A first install asks for the container ID, its name and DHCP or a fixed address (with gateway), in a framed box with your settings as the answers Enter keeps.",
        "Running bash infra.sh without options shows a menu (install, upgrade, check, rebuild, preview); the choice is confirmed with yes. --upgrade and the other options skip it.",
        "Upgrade, check and rebuild find the monitor's container by its Proxmox tag homelab-monitor, set on new installs. Without the tag they stop and show the command that adds it. Upgrades never change the container's CPU, memory, disk or network; a rebuild keeps them too.",
    ]},
    {"id": 24, "date": "2026-11-08", "title": "Restore in place, upgrade screens, phones", "items": [
        "The installer menu has Restore a backup (also bash infra.sh --restore). It keeps the container, lists every backup it can see (the container's own folder, the Syncthing folder, mounted shares and /root) with date, version and size. It restores the one you pick: a copy of what is there now is kept first, the app and its data are wiped, a fresh copy of the app goes in and the backup is restored. No backups found: it stops and says where to put one.",
        "If a restore fails after the wipe, the copy of what was there is put back. The container's CPU, memory, disk and network are never changed.",
        "Upgrade and the upgrade check use the same progress screen as an install (steps, a bar and the time), then end on a framed summary with what the check found.",
        "Phones: the menu is a drawer behind the menu button at the top left, pages fit the screen instead of zooming out, tables scroll sideways inside their panel, dashboard tiles and grids drop to one column and windows fill the screen.",
        "Phones: fields use larger text, so the phone no longer zooms in when you tap one. The Devices list shows status, name, address and ping; the device's page has the rest.",
    ]},
    {"id": 25, "date": "2026-11-08", "title": "Security hardening", "items": [
        "Stronger protection all round, after a full security review of the app and of how it is installed. Nothing changes in day to day use; a few actions now ask a little more.",
        "The Test buttons for Pi-hole, UniFi and Proxmox ask for the password again when the address or certificate changes, so a stored password is only ever sent to the place it was saved for. They also ask for your password first, like saving.",
        "Users who may manage users can no longer make anyone an administrator, give permissions they do not have themselves, change an administrator or change their own rights. Workflow run logs need workflow rights and show only the devices you can see.",
        "Workflows: saving one asks for your password and checks your device access; a scheduled run is skipped when the person who saved it no longer has the rights. Changing a device's address forgets its approved SSH host key; using a password credential in an action needs Manage credentials.",
        "Find my chat now listens only while you search and shows the chat's name for you to confirm. Logins, password checks and 2FA codes are limited per account as well as per address, a code can be used only once even when sent twice at the same moment. Turning 2FA on or off logs out your other sessions.",
        "Web checks no longer follow redirects or reach the monitor's own addresses. Browsers are told to stay on HTTPS once they have used it.",
        "The container: only SSH and the web page can be reached from outside, from private addresses or the ones in ADMIN_NET; new SSH connections are limited per address. ROOT_SSH_KEY switches root to key logins only.",
        "Backups can seal their key with a passphrase (BACKUP_PASSPHRASE), so a copy of the backup share opens nothing without it. Restore shows the shares and Syncthing settings a backup will apply and only lists backups with plain file names.",
        "Shares and the Syncthing folder must sit below /mnt or /srv and are mounted so nothing on them can run as a program. The container checks this itself before mounting, whatever the database or a backup says.",
        "New setting UNPRIVILEGED=1 makes the safer kind of container, where the Proxmox host copies files in from NFS shares. The installer checks the app it carries against a checksum, sets the root password without showing it to other programs and carries Syncthing's signing key instead of downloading it.",
    ]},
    {"id": 26, "date": "2026-11-08", "title": "Update from the app", "items": [
        "Settings, Updates checks the project's releases and installs a new version in place. A release is installed only when its signature matches the key built into your copy and it is newer than what runs now.",
        "Every update backs up first and keeps that backup with the previous version for two days. If the new version does not start, the previous one is put back by itself.",
        "For those two days the update can be undone: back to the previous version with today's data (when the data still suits it) or with the data from just before the update. The state at that moment is backed up first.",
        "Updating keeps the settings the monitor was installed with, such as its port and who may reach it. Only root on the box can reach GitHub; the monitor itself stays offline. bash infra.sh --upgrade still works without internet access.",
    ]},
    {"id": 27, "date": "2026-11-08", "title": "Friendlier updates and a fixed upgrade", "items": [
        "Upgrading to 0.8.0 could fail and put the previous version back: the new version was missing a file it needs to start. 0.9.0 has everything it needs. The tests now check that every part of the app is packed into infra.sh.",
        "The upgrade also stopped early on installs made before 0.8.0 because a folder was created too late. Its data check could crash instead of reporting what it found. Both are fixed. When the new version cannot put the old data back after a failed upgrade, the previous version now does it.",
        "The monitor looks for a new version once a day by itself. When one is out, a red number appears on Settings in the menu and on Updates. Check for updates every day can be turned off in the Updates card.",
        "The Updates card shows what is new in every version between yours and the newest, so nothing is missed. Skip this version hides the red number until a newer version comes out.",
        "Updating shows its progress step by step, waits while the monitor restarts and reconnects by itself. It ends with the new version running or with what went wrong while the previous version runs again.",
        "Update history lists every update, upgrade and undo with its result. View log shows the full log of each one in the page, with Copy and Save as a file. Upgrades run from the Proxmox host are listed too. Passwords and tokens in a log are masked.",
    ]},
    {"id": 28, "date": "2026-11-08", "title": "A new name for the installer, demo data to look around", "items": [
        "The installer is now called home_monitor.sh (it was infra.sh). It is the same file: installs made with the old name upgrade as before. Each release carries both names so every installed copy can update.",
        "Getting started is easier: open the Proxmox shell, download home_monitor.sh with one curl line, make it runnable with chmod +x and run it. The project page walks through it step by step, on Proxmox or on a spare computer.",
        "New installs can start with demo data: sixteen made-up devices with a week of history, to look around before pointing the monitor at your network. Their readings are invented on the monitor, so nothing is sent to them.",
        "Settings, Demo data appears only on a monitor with demo data. Remove the demo data deletes exactly what it added and keeps your account, settings and your own devices. With nothing left the setup guide opens to find your network.",
    ]},
    {"id": 29, "date": "2026-11-08", "title": "Report a problem", "items": [
        "Settings, System, Report a problem makes a short report to attach to an issue on the project's GitHub page: the version, how the monitor was installed, device counts, recent updates and recent warnings.",
        "Addresses, device and user names and anything that looks like a password are masked. Stored passwords are never read. You see the whole report first and copy it yourself: the monitor sends nothing.",
        "When the web page will not open, ./home_monitor.sh --report on the Proxmox host makes the same report with the end of the service log. It changes nothing.",
        "After an update, Settings, Updates no longer says you skipped the version you just installed.",
    ]},
    {"id": 30, "date": "2026-11-08", "title": "Updates that are cut short", "items": [
        "Fixed: an update could fail with the new version unable to start, because the web port was still held by connections the old version had just closed. The new version now takes the port as soon as the old one has stopped. While it waits, the monitor no longer restarts over and over, which kept the processor busy.",
        "An update cut short by a restart (or a power cut) no longer leaves Settings, Updates waiting for ever with its buttons locked. When the monitor starts again it puts the app in one piece, records what happened in the update history and lets you try again.",
        "When the new version was already in place but not yet checked, Undo stays open for two days to put the previous version and its data back.",
        "The problem report from the Proxmox host also shows the updater's own log.",
    ]},
    {"id": 31, "date": "2026-11-08", "title": "Acknowledged problems have their own place", "items": [
        "A problem you acknowledge has been seen to. It now leaves the dashboard and Current problems and waits under Acknowledged problems on the Devices page, with its note and an Unacknowledge button, until its cause clears.",
    ]},
]
LATEST = max(r["id"] for r in RELEASES)


def _seen_map() -> Dict[str, int]:
    try:
        value = json.loads(database.get_all_settings().get(SEEN_KEY) or "")
        return value if isinstance(value, dict) else {}
    except ValueError:
        return {}


def first_run(existing: Dict[str, str], has_accounts: bool) -> None:
    """The first start of this build on a database: upgraded installs read every note once,
    a fresh install starts with nothing unread."""
    if SEEN_KEY in existing:
        return
    database.set_internal_setting(SEEN_KEY, json.dumps({} if has_accounts else {"*": LATEST}))


def seen(username: str) -> int:
    m = _seen_map()
    return int(m.get(username, m.get("*", 0)) or 0)


def mark_seen(username: str, upto: int = LATEST) -> None:
    m = _seen_map()
    m[username] = max(int(m.get(username, 0) or 0), upto)
    database.set_internal_setting(SEEN_KEY, json.dumps(m))


def view(username: str) -> Dict[str, Any]:
    """Every release, newest first, and which of them this user has not read yet."""
    s = seen(username)
    return {"releases": sorted(RELEASES, key=lambda r: -r["id"]), "latest": LATEST,
            "unseen": [r["id"] for r in RELEASES if r["id"] > s]}
