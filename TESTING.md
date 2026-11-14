# Testing

How the application is tested, what is covered, and the latest recorded result of every suite. Update the snapshot (section 3) after each test run, so later work only re-tests what it touched (section 4).

## 1. How to run

```
py -3.15 tests/run_parallel.py       # the full run: unit and browser tests in 9 shards side by side
py -3.15 -m unittest tests.test_lan  # one test file, while working on what it covers
HM_ONLY=t_users,t_shell py -3.15 tests/browser_checks.py   # some browser checks (login always runs first)
py -3.15 tests/run_all.py            # unit + API tests in one process
py -3.15 tests/run_all.py --browser  # + browser tests in headless Edge/Chrome (isolated server)
py -3.15 tests/run_all.py --live     # + live checks against the running server and real devices
py -3.15 tests/run_all.py --all      # everything
```

**When to run what.** While working, run only the tests for the files you changed. Run the full set
(`run_parallel.py`) once at the end of a round, after the last code change, and once when shipping,
after the version is set. After a fix to a test file only, rerun that file or check, not everything.

**Shards.** `run_all.py --shard N/M` and `browser_checks.py --shard N/M` each run part of the tests;
shards 1 to M together run all of them. Each shard has its own database, key and port. They are
balanced by the time each test file and browser check took last time (`tests/shard_weights.json`;
`run_parallel.py --save-weights` updates it). The default of 9 shards uses about a third of the
development PC's 24 threads; keep it at half at most so the PC stays usable.

- Set `HM_TEST_SSH_HOST=<ip>` to include SSH host key and task run checks. A dummy credential is used, so the target logs one failed login per run.
- Live checks log in to the web UI: set `HM_TEST_USER` and `HM_TEST_PASSWORD`. Without them only the login gate is checked and the run is reported as skipped. To run them without your own password, start the app on a copy of the database (SQLite backup API, real vault key through `MONITOR_KEY_FILE`, its own port, a throwaway account) and point `MONITOR_URL`, `MONITOR_DB_PATH` and the two login variables at it. That is how the 2026-10-31 snapshot was taken.
- Unit, API and browser tests run against a throwaway database, vault key and port (`tests/_env.py`). They never touch `monitor.db`, the real vault key or the server on 8080.
- Live checks read the real database and query real devices. They decrypt community strings in-process only to confirm they are absent from the raw file, and never print them.
- Results land in `tests/results/unit.json`, `browser.json` and `live.json` (excluded from packaging); a sharded run writes `unit-shardNofM.json` and `browser-shardNofM.json`, with each shard's output in `tests/results/logs/`.
- Add `-W error::ResourceWarning` to treat leaked files or database connections as failures.

## 2. Coverage

| Area | What is verified | Suite |
| :--- | :--- | :--- |
| **Encryption at rest** | AES-256-GCM (256-bit key, 96-bit nonce, 128-bit tag), fresh nonce per encryption, context binding (a community token cannot decrypt as a credential), tamper detection, key file created private and never overwritten, wrong key or passphrase locks the vault, passphrase mode, legacy key rotation (old key decrypts nothing afterwards), default key path outside the data folder | `test_vault.py` |
| **Secrets in the database file** | Community strings, the default community, passwords and SSH keys never appear in raw `monitor.db` / WAL bytes. Plaintext migrated from before encryption leaves no residue after compaction. Columns hold `enc1:` tokens | `test_vault.py`, `live_checks.py` (real database) |
| **Secrets over the API** | No secret in any of 10 endpoints. Settings report `__set` flags only. Empty community on edit keeps the stored value; on add it uses the default. Secrets not written to logs or the audit log | `test_vault.py`, browser "Settings" |
| **HTTP security** | CSP / frame / nosniff headers, Host check (DNS rebinding), cross-origin mutations rejected, form posts (text/plain) rejected, body size and shape limits, no inline handlers or styles in the frontend | `test_api.py` |
| **Input validation** | Device address (non-resolving names, bad IPs, option injection), port, intervals, profile, duplicate IP, linear-time hostname check, missing ids, settings ranges and cross-field rule, dashboard layout, credentials, tasks (cron, targets, credential) | `test_api.py` |
| **SNMP protocol** | BER OID and integer encoding, truncated input rejected, response parsing including noSuchObject, binary strings as MACs | `test_protocol.py` |
| **Metric parsing and templates** | Typed values with units (QNAP), derived memory and CPU, counter wrap / reset / above-link-speed, profile auto-detection for every real device type, every profile well formed, interface classification (UniFi, MediaTek, Proxmox) | `test_protocol.py`, `live_checks.py` (re-runs auto-detect per device) |
| **Storage policy** | raw / change / hourly / none modes, hourly heartbeat, hourly rollup with exclusions, retention purge, previous-period comparison window | `test_storage.py` |
| **Problem engine** | Triggers (unreachable, CPU, memory, SMART, disk temperature, volume state and fullness, radio utilisation, port errors, restricted SNMP view), resolve delay, acknowledgement kept while open and cleared on recurrence | `test_storage.py`, browser "Acknowledge" |
| **SSH runner** | `shell=False`, password never in argv (askpass + env only), host key pinning (`StrictHostKeyChecking=yes`, approved key in per-run known_hosts), key file written private and deleted, temp dir removed, exit codes, timeout, 64 KB output cap, cron parser and validation | `test_ssh.py`, `test_protocol.py` |
| **SSH against a real host** | Host key fetch without authenticating; approval in the dialog; run reaches the host, password is sent via askpass and refused (dummy credential), output shown | browser "Host key", "Run a task", `live_checks.py` |
| **Dashboard UI** | Tiles render; corner drag resizes width and height; header drag moves; grid width change scales tiles; Graph tile add + configure dialog; chart redraws to the new tile size | `browser_checks.py` |
| **Other UI** | Column sorting asc/desc, collapsible groups, acknowledge from the devices page, LIVE badge, settings edit / unsaved count / save / invalid value blocks save, credential add / edit / delete, task create, no JavaScript errors | `browser_checks.py` |
| **Login** | scrypt hash format and production cost, per-hash salt, password rules, every API route refuses without a session, forged cookie refused, static files reachable, account created once only, setup token enforced when configured, cookie flags (HttpOnly, SameSite=Strict, Path), logout ends the session, server keeps only a token hash, same error for wrong user and wrong password, rate limit lockout, failed logins audited without the password, confirmation required on the sensitive routes, password change ends other sessions and leaves no plaintext in the file | `test_auth.py`, browser "Login", "Log out" |
| **Host data** | Windows memory from hrStorageRam, lm-sensors parsing and threshold, physical disk filter (no partitions, loop, dm), sensor name slugs, software name / version / architecture split, install / remove / update events and the batch summary, kernel threads left out of process lists | `test_protocol.py`, `test_storage.py`, live (a Proxmox host and a Windows PC) |
| **Watches** | Missing process or stopped service opens a problem, running one does not, nothing reported while the table is missing, watch API validation | `test_storage.py` |
| **WAN peaks** | A 10 s burst at 900 Mbit/s survives as the peak while the 5-minute average would show a fraction; peaks written and reset on flush | `test_storage.py` |
| **Network map** | Direct links only (a device behind a second switch is not linked to the first), ports on both ends, Proxmox guests behind their host, unmonitored hosts counted on edge ports only, downstream sets, hiding a link cuts the subtree, objects / links / positions API, input validation, device delete cleans map rows | `test_topology.py`, browser "Map" |
| **Workflows** | Step validation and normalisation, host order kept, restart sequence order of calls (command, ping down, ping up, next host), stop / carry on / retry policies, ping wait timeout, cancel, one run per workflow, credentials not in the run log, API CRUD, confirmation required to run | `test_workflows.py`, browser "Workflow" |
| **Fix SNMP** | View block placed before the first community line, localhost-only agent opened, idempotent rewrite, appended when no community line exists, communities masked in the diff and in errors, community sent on stdin and never in a command line, stale preview refused, automatic rollback when verification fails, Linux hosts only, confirmation required | `test_snmpfix.py` |
| **Setup wizard** | Subnet rules (private, at most /22), scan finds ping-only and SNMP-only hosts and marks monitored ones, community not kept after a scan, site settings validation (NFS sources and targets, mount options, Syncthing, Telegram token), preview writes nothing and never echoes secrets, apply once only and needs confirmation, existing installs count as set up, bulk add with duplicates and dry run, bulk delete | `test_setup.py`, browser "Setup preview", "Devices: tick boxes" |
| **Notifications** | Template placeholders, no attribute access, defaults use known placeholders, quiet hours across midnight, event filtering, held messages summarised, problem to event mapping, settings validation (time, chat ID, template length), token encrypted and never returned, Telegram errors without the token | `test_notify.py` |
| **Fix SNMP install** | snmpd missing: install planned, new file written, backup none; no apt-get refused; stopped service reported | `test_snmpfix.py` |
| **Device profiles** | Vendor OID beats plain Linux (Synology, TrueNAS); UPS, printer, MikroTik, pfSense, switch, Cisco, ESXi, EdgeOS identified from MIB-style samples; every profile well formed (alerts name real metrics, tables valid); Synology disk and RAID rows; printer supply levels including "some remaining"; unknown states shown, not alarmed; UPS alerts and health problems; byte and percent memory | `test_profiles.py` |
| **Alert rules** | Override chain and sources; validation; thresholds, severity, off and waits applied by the trigger set; pending problems; Telegram minimum severity, per-rule never, reminders; API; migration | `test_alerts.py` |
| **Deployment** | Installer payload holds the app and no data, keys or tests; fixed params (CT 201, MAC, Ubuntu 24.04, privileged, DHCP, root SSH, Telegram host); passphrase only on stdin; key derivation round trip with the server's vault; wrong passphrase refused; backup members, retention, restore over changed data, Syncthing folder default, path-traversal archive refused, site apply idempotent in dry run; every embedded script passes `bash -n` | `test_deploy.py`, `deploy/build.py` |
| **LAN listening** | Host header rules with `MONITOR_LISTEN=0.0.0.0`: IP literals, own and configured names pass; other domains, wrong port, no port fail | `test_api.py` |
| **HTML escaping** | Every value in an HTML template or sink in `web/*.js` is escaped or proved safe, with an exact allowlist; unquoted attribute values refused; SNMP and Pi-hole number columns are numbers or nothing | `test_web_static.py`, `test_protocol.py`, `test_lan.py`, browser "Text a device sends" |
| **Message template limits** | Growth from replace and join predicted and stopped cheaply, line cap, total budget, deep brackets and overflow marked; every caller (notifications, bot, custom commands, workflow steps) falls back to a short notice; the preview needs edit rights and is rate limited | `test_tpl.py`, `test_notify.py` |
| **Device access on writes** | A user limited to some devices acknowledges, sets maintenance, links upstream and acts on Proxmox guests only for those; network-wide routes need every device; workflows checked at save and at run; a scoped user manager cannot change someone who sees more; Use stored credentials and host key approval need their own permissions | `test_scope_writes.py`, `test_users.py`, `test_workflows.py`, `test_hostactions.py` |
| **Login security** | Wrong authenticator codes count towards the lockout and survive a right password; parallel codes limited; required 2FA (admins or all) forces enrolment straight after the password and can only be turned on by an administrator who has 2FA; lockouts audited and alerted | `test_totp.py`, `test_auth.py` |
| **HTTPS failure and web server limits** | A failed certificate refuses logins from other computers while this machine still gets in; off then self-signed turns HTTPS on again; slow clients dropped, connection caps per address and in total | `test_tls.py`, `test_api.py` |
| **Audit and security alerts** | Audit rows name who and from where, a 90-day floor apart from events; each security alert fires once, also in quiet hours, with the off switch honoured | `test_backups_audit.py`, `test_storage.py`, `test_notify.py` |
| **Backups, restore and updates (0.12.0)** | Every archive with a passphrase carries a tag and a changed member fails; no clear key off the box without a passphrase; UNVERIFIED and FORGET restores; safety copies in root's folder; Undo only with the recorded copy; root helpers do not follow links; the installer's container kind, key paste, strict networks, firewall check before enabling, settings kept on upgrade and service limits | `test_deploy.py`, `test_update.py`, `test_compat.py` |
| **Reports (0.15.0)** | Every template runs and lists its columns; filters by group, tag and device; chosen columns and order; a v3 device shows its user and security level, never a password; CSV cells stay numbers and are safe for spreadsheets; the PDF writer's pages, fonts, tables and charts; saved reports run on schedule, keep the newest files and reach Telegram; network-wide templates need every device and a limited user's saved reports stay their own | `test_reports.py`, `test_pdfdoc.py`, browser "Reports" |
| **Map and inventory (0.16.0)** | The Wi-Fi button draws each access point's devices around it (weak ones marked) and hides them again; dashes flow down and up on a measured link and stop when Traffic is off; the internet globe and its rates come from the gateway's WAN interface and are left out when there is none; Inventory groups by where a device connects, sorts by name inside and folds | `test_topology.py`, browser "Map: an access point shows its Wi-Fi devices", "Inventory: groups" |
| **Live system** | Server up, vault enabled with key outside the data folder, every device online with fresh data, expected tables per template, auto-detect agrees with assigned template, database growth within budget | `live_checks.py` |

Not covered by automated tests (checked manually or not at all): the installer on a real Proxmox host (5.1, 5.2, 5.5: syntax-checked and unit-tested only), the outbound firewall, Telegram against the real API (mocked), a real first-run apply in a browser (API-tested), QNAP models other than TS-x41, behaviour on Debian (Phase 5.1), live mode rendering under real traffic, very long-running retention (days to months), Fix SNMP and workflows against a real host (unit tests mock SSH; run them by hand on a test host first), the drag-to-reorder handle in the workflow editor (the arrows are browser-tested, the drag is not).

## 3. Snapshot: last full run

**2026-11-01 end-to-end run before manual testing: all suites PASS.** Unit and API 151 / 151; browser 24 / 24 including both SSH checks (`HM_TEST_SSH_HOST=192.168.1.50`: real host key fetched and matched the approved fingerprint, dummy login refused as intended); live 21 / 21 on a database copy; installer built with every `bash -n` check ok; Python 3.12 compatibility clean. Visual pass: 23 pages screenshotted on a copy of the real database with no JavaScript errors. Fixed from the pass: empty Watched and Recent changes panels now hidden (UI rule), `mem_used_pct` labelled, sensor names capitalised, "1 errors" wording.

**2026-11-02 update (Phase 15): unit and API 252 / 252, browser 33 / 33 with HM_TEST_SSH_HOST=192.168.1.50, first visit check pass, live 21 / 21 on a database copy, Python 3.12 compatibility clean. New suites: test_totp, test_custom_oids, test_availability, test_proxmox, test_devices_extra; browser checks for 2FA, availability and Proxmox, Telegram editor and triggers. The browser harness answers step-up password prompts itself (window.__noAutoConfirm to inspect one).**

**2026-11-01 update (port checks): unit and API 197 / 197 pass (new `test_service_check.py`: TCP check open and closed, status from port and ping, service problems, API validation and shared address, probe, map placement, device table migration), browser 29 / 29 pass (new: add a port check). home_monitor.sh not rebuilt.**

**2026-11-01 update (Phase 12: layout, users, automation builder): unit and API 184 / 184 pass (new `test_users.py`: permission table, roles, device access, user API, block / log out / password reset end sessions, last admin protected, per-section settings permission, notifications unread / read, event log filters and pages; new `test_automation.py` and schedule tests from the automation work), browser 28 / 28 pass with HM_TEST_SSH_HOST=192.168.1.50 (new: shell theme / menu / bell / back to top, event log filters, settings one section at a time and the leave guard, users add / block / delete, credential key generation, workflow builder; SSH task checks replaced by workflow checks; the harness now accepts the app's own dialogs and saves a screenshot of any failure to tests/results/fail_<check>.png; `HM_ONLY=t_a,t_b` runs a subset), live 21 / 21 pass on a database copy, installer rebuilt, Python 3.12 compatibility clean. Real server restarted; events table migrated (94 events kept, `actor` column, nullable device), the existing account is Administrator.**

**2026-11-01 update (alert rules): unit and API 151 / 151 pass (new `test_alerts.py`, 17: inheritance and sources, validation, Telegram decision, thresholds / severity / off under overrides, component severity, waits and pending problems, minimum severity and per-rule never, reminders and acknowledgement, API get / put / reset / rejects, device overrides removed with the device, settings migration, error counter reset), browser 24 / 24 pass (new: template override saved, inherited on the device, reset; Telegram columns hidden while Telegram is off), live 21 / 21 pass on a database copy, installer rebuilt, Python 3.12 compatibility clean. Real server restarted; migration checked on the real database (old threshold settings removed, open problems kept as raised).**

**2026-11-01 update (device profiles): unit and API 134 / 134 pass (new `test_profiles.py`, 11), browser 23 / 23 pass, installer rebuilt with every `bash -n` check ok, Python 3.12 compatibility check clean. The new Health tab, UPS headline cards and printer supply bars were checked by screenshot on a database copy with two seeded devices. Live checks not re-run: no monitored device uses a new profile.**

**2026-10-31 (evening), all suites PASS: 167 checks.** Windows 11, Python 3.15.2, Edge headless, 15 real devices. Live checks on a copy of the real database (throwaway account in the copy only).

| Suite | Result | Detail |
| :--- | :--- | :--- |
| Unit and API | 123 / 123 pass | 13.5 s, `-W error::ResourceWarning` clean. New since the afternoon: `test_setup.py` (8), `test_notify.py` (8), `test_deploy.py` (8, including the move from a key-file install to a passphrase key), Fix SNMP install (2), LAN host rules (1) |
| Browser | 23 / 23 pass | New: setup preview walked through all ten steps (plan shown, nothing written), tick two devices and delete them. SSH checks skipped (no `HM_TEST_SSH_HOST`) |
| Live | 21 / 21 pass | 15 devices on the right template; the media server VM now reports full data (view widened); two other hosts still restricted; 90,392 rows per day; no plaintext community |

Run on the real server: login gate (401 without a session). WAN peak samples written by the real server after its restart.

### Defects found in the 2026-10-31 round (all fixed and re-tested)

| Found by | Defect | Fix |
| :--- | :--- | :--- |
| Live data check | The server "restart" earlier in the day left the 2026-10-30 process running: the port lookup returned nothing, so nothing was stopped, and the new process could not bind. New features were not live and no WAN peaks were recorded. | Stopped the processes by their `server.py` command line; The development notes now give that method and a check of the process creation time. |
| Code review | `database.py` held a second, identical copy of the snapshot table, event and history functions (105 lines). | Duplicate removed; a scan finds no other duplicated definitions in the modules. |
| Unit test | Running Fix SNMP twice added a blank line each time. | The blank line after the managed block is removed with it; reruns are byte-identical. |
| Live probe | Windows program names such as "7-Zip 24.08 (x64)" kept the version in the name, so an update would show as a removal plus an install. | A trailing "(...)" after the version stays in the name; the version is split off. |
| Live probe | Linux process lists were mostly kernel threads (pve 311 names). | Processes without an executable path are left out on Linux (68 remain). |
| Live data check | The 2026-10-30 snapshot reported 23,276 metric rows per day. The real rate since that evening is about 3,670 rows an hour, 88,000 a day. | Corrected here and in the development notes. Still within budget. |
| Code check | `server.py` used `List` in type hints without importing it. Python 3.14+ evaluates hints lazily so it ran here, but Python 3.12 (Ubuntu 24.04) evaluates them at import and would have crashed on start. | Imported; every module now passes a 3.12 grammar and annotation-name check before building the installer. |
| Browser test | The sort test assumed three devices, which only exist when `HM_TEST_SSH_HOST` is set. | Expects two. |

### Earlier round (2026-10-30, all fixed)

Plaintext community residue in a free database page (secure_delete plus one-time VACUUM), decrypted community sent to the browser for editing, leaked database connections, connection resets on early error replies, stale credential list in the task editor, dashboard resize collapsing a tile, Windows OpenSSH rejecting `-F nul`, Windows `ssh-keyscan` failing on modern key exchange.

### Known limitations (accepted)

- Oversized request bodies (over 64 KB) can surface as a connection reset rather than HTTP 413, because refusing to read them is the protection.
- Each SSH-enabled browser or live run logs one failed login on `HM_TEST_SSH_HOST` (dummy credential `admin` or `hm-test`).
- Sessions live in memory: restarting the server logs everyone out.
- The session cookie has no Secure flag because the app speaks plain HTTP on the LAN. SameSite=Strict and HttpOnly still apply.

## 4. What to re-run after a change

| Files changed | Re-run |
| :--- | :--- |
| `vault.py`, secret handling in `database.py` or `server.py` | unit (`test_vault.py`) + live |
| `poller.py`, `profiles/*.json` | unit (`test_protocol.py`, `test_storage.py`) + live |
| `database.py` (other) | unit |
| `server.py` routes, validation, scheduler | unit (`test_api.py`, `test_storage.py`) + browser |
| `ssh_runner.py` | unit (`test_ssh.py`, `test_workflows.py`, `test_snmpfix.py`) + browser with `HM_TEST_SSH_HOST` |
| `auth.py`, session gate in `server.py` | unit (`test_auth.py`) + browser (login runs first) |
| `topology.py`, `web/map.js` | unit (`test_topology.py`) + browser "Map" |
| `workflows.py`, `web/workflows.js` | unit (`test_workflows.py`) + browser "Workflow" |
| `snmpfix.py` | unit (`test_snmpfix.py`); then a real run on one host |
| `discovery.py`, `setup.py`, `web/setup.js` | unit (`test_setup.py`) + browser "Setup preview" |
| `notify.py` | unit (`test_notify.py`); a real test message from Settings |
| `reports.py`, `pdfdoc.py`, `web/reports.js` | unit (`test_reports.py`, `test_pdfdoc.py`) + browser "Reports" |
| `deploy/*` | `py -3.15 deploy/build.py` (bash -n) + unit (`test_deploy.py`); then a run on Proxmox |
| `web/*` | browser (+ unit `test_api.py` for the no-inline-handler check) |
| Anything before packaging or deployment | `--all` |

After a run, update section 3 (date, counts, notable details) and add any defects found.

## 4b. Report a problem

`test_report.py`: the report holds the version, devices by template and the update history; device names, addresses, account names and secrets in it are masked (whole words only, clock times kept); the route is for administrators. `test_deploy.py`: `--report` on a fake Proxmox host copies this build's `report.py` in, runs it with the journal, removes it and saves the output, changing nothing else.

## 5. Demo mode

Demo mode runs the app on made-up devices: for trying it without a network (the installer's "start with demo data", or `--demo`), for testing and for screenshots. While it is on, the poller answers for every device whose address is in a documentation range (192.0.2.0/24, 198.51.100.0/24 and 203.0.113.0/24) from `demo.py` instead of the network. Devices with any other address are polled as usual.

It is on from the moment `demo.py seed` fills a database until Settings, Demo data removes the demo again (a flag in the database). `MONITOR_DEMO=1` also switches it on, for development. To run it on this computer (PowerShell, from the project folder):

```
$env:MONITOR_DB_PATH = "$PWD\demo-data\monitor.db"
$env:MONITOR_KEY_FILE = "$PWD\demo-data\vault.key"
py -3.15 demo.py seed
py -3.15 server.py
```

- The seed adds 16 generic devices (router, switches, access points, NAS, hypervisor, servers, printer, UPS, a TV and two port or web checks) with groups, tags, a map layout, 7 days of history and past events. It takes about half a minute.
- It refuses a database that holds any device outside the documentation ranges (`--force` overrides) and a database that already holds the demo set. It creates no account: create the admin account in the browser as usual.
- It records what it made. Removing the demo deletes exactly those devices (only while they still have their made-up addresses) and the groups and tags it added when nothing else uses them, then turns demo mode off. With no device left the setup guide opens again.
- Readings follow a daily curve with smooth noise, seeded by device id and time. Some devices drop off for a few minutes now and then (and restart), and the backup NAS disk fills past 90% before a clean-up every ten days.
- Tests (`test_demo.py`): the seed uses documentation addresses only and creates no account; it refuses real data and a second run; demo polling gives plausible values with every network call patched to fail; the flag turns it on and off; removing it keeps real devices, a demo device moved to a real address and tags still in use.
