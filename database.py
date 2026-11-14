"""Database persistence layer for the Homelab Monitor platform.

Provides SQLite initialization with Write-Ahead Logging (WAL) enabled,
schema migrations and parameterized query execution for devices,
metrics, settings, credentials and audit records.
"""

import contextlib
import json
import os
import sqlite3
import threading
import time
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple

from vault import VAULT, VaultError

# Settings whose values are secrets: encrypted at rest, decrypted on read.
SECRET_SETTINGS = {"default_snmp_community", "telegram_token", "proxmox_token_secret", "tls_key", "pihole_secret", "unifi_secret",
                   "proxmox_action_secret"}
COMMUNITY_CONTEXT = "device:snmp_community"
# A device's SNMPv3 settings (user, level, protocols and both passwords), as JSON sealed by the vault.
SNMP_V3_CONTEXT = "device:snmp_v3"

# MONITOR_DB_PATH overrides the default location. Production deployments should
# point this at local disk (e.g. /var/lib/homelab-monitor/monitor.db) since
# file-sync clients can corrupt an open SQLite WAL database.
DB_FILE = os.environ.get(
    "MONITOR_DB_PATH",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "monitor.db"),
)


# Schema version, stored in the database file (PRAGMA user_version) once startup has migrated it.
# Every migration is additive and idempotent (CREATE IF NOT EXISTS, ADD COLUMN when missing, data
# moves that check before they act), so any older file, 0 meaning "from before versions were kept",
# is brought forward on start. A file with a higher number was written by a newer build: this code
# does not know its tables and would misread them, so it refuses to start on it rather than guess.
# Raise SCHEMA_VERSION with every schema change; tests/test_compat.py holds the fingerprint of each.
SCHEMA_VERSION = 9                 # 4: inventory.ssid and inventory.quiet; 5: action_runs; 6: workflows.saved_by;
                                   # 7: audit_log.actor and audit_log.source; 8: devices.snmp_v3;
                                   # 9: reports and report_runs
# The oldest version this build can migrate from (raise only if a migration is ever dropped).
MIN_SCHEMA_VERSION = 0


class SchemaTooNew(RuntimeError):
    pass


def schema_version(path: Optional[str] = None) -> int:
    """The version stored in a database file; 0 for a file from before versions were kept."""
    conn = sqlite3.connect(f"file:{path or DB_FILE}?mode=ro", uri=True)
    try:
        return int(conn.execute("PRAGMA user_version;").fetchone()[0])
    finally:
        conn.close()


def refuse_newer_schema() -> None:
    if os.path.exists(DB_FILE):
        found = schema_version()
        if found > SCHEMA_VERSION:
            raise SchemaTooNew(f"The database was written by a newer build (schema {found}; this build knows up to "
                               f"{SCHEMA_VERSION}). Upgrade the app (home_monitor.sh --upgrade with the newer home_monitor.sh); "
                               f"the data was not changed.")


def mark_schema() -> None:
    """Records SCHEMA_VERSION once every migration of startup has run."""
    with get_connection() as conn:
        if int(conn.execute("PRAGMA user_version;").fetchone()[0]) < SCHEMA_VERSION:
            conn.execute(f"PRAGMA user_version = {int(SCHEMA_VERSION)};")
            conn.commit()


@contextlib.contextmanager
def get_connection() -> Iterator[sqlite3.Connection]:
    """Yields a connection with WAL mode, foreign keys and secure delete, and always closes it.

    sqlite3.Connection's own context manager only commits or rolls back; it
    does not close, which leaks a connection per call until garbage collection.
    """
    conn = sqlite3.connect(DB_FILE, timeout=10.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA foreign_keys = ON;")
    # Overwrite deleted content with zeros so replaced secrets do not linger in free pages.
    conn.execute("PRAGMA secure_delete = ON;")
    try:
        yield conn
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


DEVICE_COLUMNS = ("id", "hostname", "ip_address", "profile_id", "snmp_version", "snmp_community", "snmp_port",
                  "poll_interval", "ping_interval", "status", "last_ping_ms", "last_seen", "created_at", "tags",
                  "inventory", "snmp_status")


def _migrate_device_uniqueness() -> None:
    """One address may carry an SNMP device and port checks (service_port, 0 = none): the unique key
    becomes (ip_address, service_port). The old schema had UNIQUE on ip_address alone, which SQLite
    can only drop by rebuilding the table."""
    if not os.path.exists(DB_FILE):
        return
    conn = sqlite3.connect(DB_FILE, timeout=10.0)
    try:
        conn.isolation_level = None
        row = conn.execute("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'devices';").fetchone()
        if not row or "service_port" in row[0]:
            return
        cols = {r[1] for r in conn.execute("PRAGMA table_info(devices);")}
        conn.execute("PRAGMA foreign_keys = OFF;")
        conn.execute("BEGIN IMMEDIATE;")
        conn.execute("""
            CREATE TABLE devices_new (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hostname TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                profile_id TEXT NOT NULL,
                snmp_version TEXT NOT NULL DEFAULT 'v2c',
                snmp_community TEXT DEFAULT 'public',
                snmp_port INTEGER NOT NULL DEFAULT 161,
                poll_interval INTEGER,
                ping_interval INTEGER,
                status TEXT NOT NULL DEFAULT 'unknown',
                last_ping_ms REAL,
                last_seen INTEGER,
                created_at INTEGER NOT NULL,
                tags TEXT DEFAULT '[]',
                inventory TEXT NOT NULL DEFAULT '{}',
                snmp_status TEXT NOT NULL DEFAULT 'unknown',
                service_port INTEGER NOT NULL DEFAULT 0,
                UNIQUE (ip_address, service_port)
            );""")
        copy = [c for c in DEVICE_COLUMNS if c in cols]
        conn.execute(f"INSERT INTO devices_new ({', '.join(copy)}) SELECT {', '.join(copy)} FROM devices;")
        conn.execute("DROP TABLE devices;")
        conn.execute("ALTER TABLE devices_new RENAME TO devices;")
        bad = conn.execute("PRAGMA foreign_key_check;").fetchall()
        if bad:
            conn.execute("ROLLBACK;")
            raise RuntimeError(f"Device table migration stopped: foreign key check failed ({len(bad)} rows)")
        conn.execute("COMMIT;")
    finally:
        try:
            conn.execute("PRAGMA foreign_keys = ON;")
        finally:
            conn.close()


def init_db() -> None:
    """Initializes tables and indexes using idempotent schema definitions."""
    refuse_newer_schema()
    _migrate_device_uniqueness()
    with get_connection() as conn:
        cursor = conn.cursor()

        # Global system configuration
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                description TEXT,
                updated_at INTEGER NOT NULL
            );
            """
        )

        # Monitored devices inventory
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS devices (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                hostname TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                profile_id TEXT NOT NULL,
                snmp_version TEXT NOT NULL DEFAULT 'v2c',
                snmp_community TEXT DEFAULT 'public',
                snmp_port INTEGER NOT NULL DEFAULT 161,
                poll_interval INTEGER,
                ping_interval INTEGER,
                status TEXT NOT NULL DEFAULT 'unknown',
                last_ping_ms REAL,
                last_seen INTEGER,
                created_at INTEGER NOT NULL,
                tags TEXT DEFAULT '[]',
                inventory TEXT NOT NULL DEFAULT '{}',
                snmp_status TEXT NOT NULL DEFAULT 'unknown',
                service_port INTEGER NOT NULL DEFAULT 0,
                UNIQUE (ip_address, service_port)
            );
            """
        )

        # High-performance time-series metric data
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id INTEGER NOT NULL,
                metric_key TEXT NOT NULL,
                timestamp INTEGER NOT NULL,
                value REAL NOT NULL,
                FOREIGN KEY (device_id) REFERENCES devices (id) ON DELETE CASCADE
            );
            """
        )

        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_metrics_query 
            ON metrics (device_id, metric_key, timestamp);
            """
        )

        # Encrypted credential storage
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS credentials (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                cred_type TEXT NOT NULL,
                username TEXT,
                secret_encrypted TEXT NOT NULL,
                salt TEXT NOT NULL,
                nonce TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );
            """
        )

        # Automation task definitions
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS automations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                device_id INTEGER,
                target_tag TEXT,
                trigger_type TEXT NOT NULL,
                trigger_cron TEXT,
                command TEXT NOT NULL,
                credential_id INTEGER,
                expected_exit_code INTEGER NOT NULL DEFAULT 0,
                last_run INTEGER,
                last_exit_code INTEGER,
                last_output TEXT,
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at INTEGER NOT NULL,
                FOREIGN KEY (device_id) REFERENCES devices (id) ON DELETE SET NULL,
                FOREIGN KEY (credential_id) REFERENCES credentials (id) ON DELETE SET NULL
            );
            """
        )

        # System audit log
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp INTEGER NOT NULL,
                category TEXT NOT NULL,
                message TEXT NOT NULL,
                details TEXT
            );
            """
        )

        cursor.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_audit_timestamp 
            ON audit_log (timestamp DESC);
            """
        )

        # Most recent value per metric with the value before it, so "latest data"
        # views and the device list never scan the full metrics table.
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS metric_latest (
                device_id INTEGER NOT NULL,
                metric_key TEXT NOT NULL,
                value REAL NOT NULL,
                timestamp INTEGER NOT NULL,
                prev_value REAL,
                prev_timestamp INTEGER,
                PRIMARY KEY (device_id, metric_key),
                FOREIGN KEY (device_id) REFERENCES devices (id) ON DELETE CASCADE
            );
            """
        )

        # Current-state snapshots of SNMP tables (interfaces, fdb, arp, wireless
        # radios and SSIDs, storage). Each poll replaces a device's rows for a
        # table. row_key is the table index (ifIndex, MAC, IP ...), data is JSON.
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS device_tables (
                device_id INTEGER NOT NULL,
                table_name TEXT NOT NULL,
                row_key TEXT NOT NULL,
                data TEXT NOT NULL,
                updated_at INTEGER NOT NULL,
                PRIMARY KEY (device_id, table_name, row_key),
                FOREIGN KEY (device_id) REFERENCES devices (id) ON DELETE CASCADE
            );
            """
        )

        # Device event log: reachability changes, reboots, port state changes.
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id INTEGER,
                timestamp INTEGER NOT NULL,
                severity TEXT NOT NULL,
                event_type TEXT NOT NULL,
                message TEXT NOT NULL,
                actor TEXT,
                FOREIGN KEY (device_id) REFERENCES devices (id) ON DELETE CASCADE
            );
            """
        )
        # Migration: system events (an action that could not be done) have no device, and record who acted.
        event_cols = {row[1]: row for row in cursor.execute("PRAGMA table_info(events);")}
        if "actor" not in event_cols:
            cursor.execute("""
                CREATE TABLE events_new (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_id INTEGER,
                    timestamp INTEGER NOT NULL,
                    severity TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    message TEXT NOT NULL,
                    actor TEXT,
                    FOREIGN KEY (device_id) REFERENCES devices (id) ON DELETE CASCADE
                );""")
            cursor.execute("INSERT INTO events_new (id, device_id, timestamp, severity, event_type, message) "
                           "SELECT id, device_id, timestamp, severity, event_type, message FROM events;")
            cursor.execute("DROP TABLE events;")
            cursor.execute("ALTER TABLE events_new RENAME TO events;")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_device ON events (device_id, timestamp DESC);")
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events (timestamp DESC);")

        # Hourly rollups (trends). Raw samples age out after raw_retention_days;
        # these keep min/avg/max per hour for long-range graphs at ~1/60 the rows.
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS metrics_hourly (
                device_id INTEGER NOT NULL,
                metric_key TEXT NOT NULL,
                hour INTEGER NOT NULL,
                avg REAL NOT NULL,
                min REAL NOT NULL,
                max REAL NOT NULL,
                samples INTEGER NOT NULL,
                PRIMARY KEY (device_id, metric_key, hour),
                FOREIGN KEY (device_id) REFERENCES devices (id) ON DELETE CASCADE
            );
            """
        )

        # Open problems, so start and resolve events survive a restart and a
        # condition must stay clear for a while before it counts as resolved.
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS problems_active (
                device_id INTEGER NOT NULL,
                problem_key TEXT NOT NULL,
                severity TEXT NOT NULL,
                message TEXT NOT NULL,
                since INTEGER NOT NULL,
                last_seen INTEGER NOT NULL,
                PRIMARY KEY (device_id, problem_key),
                FOREIGN KEY (device_id) REFERENCES devices (id) ON DELETE CASCADE
            );
            """
        )

        # Dashboard layouts (widget list as JSON).
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS dashboards (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL UNIQUE,
                layout TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            );
            """
        )

        # SSH task run history (one row per task, device and run).
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS task_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                task_id INTEGER NOT NULL,
                device_id INTEGER NOT NULL,
                trigger TEXT NOT NULL,
                started_at INTEGER NOT NULL,
                finished_at INTEGER,
                status TEXT NOT NULL,
                exit_code INTEGER,
                stdout TEXT,
                stderr TEXT,
                FOREIGN KEY (task_id) REFERENCES automations (id) ON DELETE CASCADE,
                FOREIGN KEY (device_id) REFERENCES devices (id) ON DELETE CASCADE
            );
            """
        )
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_task_runs ON task_runs (task_id, started_at DESC);")

        # SSH host keys approved by the administrator (connections are pinned to these).
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS ssh_host_keys (
                device_id INTEGER NOT NULL,
                key_type TEXT NOT NULL,
                key_b64 TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                approved_at INTEGER NOT NULL,
                PRIMARY KEY (device_id, key_type),
                FOREIGN KEY (device_id) REFERENCES devices (id) ON DELETE CASCADE
            );
            """
        )

        # Workflows: ordered step lists (see workflows.py) and their run logs.
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS workflows (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                description TEXT NOT NULL DEFAULT '',
                steps TEXT NOT NULL,
                trigger_type TEXT NOT NULL DEFAULT 'manual',
                trigger_cron TEXT,
                is_active INTEGER NOT NULL DEFAULT 1,
                last_scheduled INTEGER,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS workflow_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                workflow_id INTEGER NOT NULL,
                trigger TEXT NOT NULL,
                status TEXT NOT NULL,
                log TEXT NOT NULL DEFAULT '[]',
                started_at INTEGER NOT NULL,
                finished_at INTEGER,
                FOREIGN KEY (workflow_id) REFERENCES workflows (id) ON DELETE CASCADE
            );
            """
        )
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_workflow_runs ON workflow_runs (workflow_id, started_at DESC);")
        # Migration: graph editor (nodes and connections), schedule picker and one-off runs.
        wf_cols = {row[1] for row in cursor.execute("PRAGMA table_info(workflows);")}
        # saved_by: who last saved it; a scheduled or event run checks that user's rights again.
        for col, ddl in (("graph", "TEXT"), ("schedule", "TEXT"), ("run_at", "INTEGER"), ("saved_by", "TEXT")):
            if col not in wf_cols:
                cursor.execute(f"ALTER TABLE workflows ADD COLUMN {col} {ddl};")
        # Migration: SSH key passphrase (encrypted) and the key's public half (not secret).
        cred_cols = {row[1] for row in cursor.execute("PRAGMA table_info(credentials);")}
        for col in ("passphrase_encrypted", "public_key"):
            if col not in cred_cols:
                cursor.execute(f"ALTER TABLE credentials ADD COLUMN {col} TEXT;")
        # A run cannot survive a restart of the monitor: close any left open.
        cursor.execute("UPDATE workflow_runs SET status = 'interrupted', finished_at = ? WHERE status = 'running';",
                       (int(time.time()),))
        # Host actions run once (hostactions.py): what ran where, by whom, and what it printed.
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS action_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                device_id INTEGER NOT NULL,
                action_id TEXT NOT NULL,
                name TEXT NOT NULL,
                choice TEXT NOT NULL DEFAULT '',
                username TEXT NOT NULL DEFAULT '',
                problem_key TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL,
                exit_code INTEGER,
                output TEXT NOT NULL DEFAULT '',
                started_at INTEGER NOT NULL,
                finished_at INTEGER,
                FOREIGN KEY (device_id) REFERENCES devices (id) ON DELETE CASCADE
            );
            """
        )
        cursor.execute("CREATE INDEX IF NOT EXISTS idx_action_runs ON action_runs (device_id, started_at DESC);")
        cursor.execute("UPDATE action_runs SET status = 'interrupted', finished_at = ? WHERE status = 'running';",
                       (int(time.time()),))

        # Network map: objects that are not monitored, manual or hidden links, saved positions.
        # Node keys: "d:<device id>", "o:<map object id>" or "monitor".
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS map_objects (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                label TEXT NOT NULL,
                kind TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS map_links (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                node_a TEXT NOT NULL,
                node_b TEXT NOT NULL,
                hidden INTEGER NOT NULL DEFAULT 0,
                created_at INTEGER NOT NULL,
                UNIQUE (node_a, node_b)
            );
            """
        )
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS map_positions (
                node TEXT PRIMARY KEY,
                x REAL NOT NULL,
                y REAL NOT NULL
            );
            """
        )

        # Inventory (inventory.py): every hardware address seen on the network, with the
        # administrator's name and notes. Schema 3.
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS inventory (
                mac TEXT PRIMARY KEY,
                ip TEXT NOT NULL DEFAULT '',
                name TEXT NOT NULL DEFAULT '',
                seen_name TEXT NOT NULL DEFAULT '',
                vendor TEXT NOT NULL DEFAULT '',
                note TEXT NOT NULL DEFAULT '',
                location TEXT NOT NULL DEFAULT '',
                purchased TEXT NOT NULL DEFAULT '',
                where_seen TEXT NOT NULL DEFAULT '',
                via TEXT NOT NULL DEFAULT '',
                device_id INTEGER,
                first_seen INTEGER NOT NULL,
                last_seen INTEGER NOT NULL,
                known INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (device_id) REFERENCES devices (id) ON DELETE SET NULL
            );
            """
        )
        # Migration (schema 4): the Wi-Fi network a device was last on, and "quiet" (kept, but never
        # announced or counted as new; inventory.py). Added the same way on a fresh database, so both match.
        inv_cols = {row[1] for row in cursor.execute("PRAGMA table_info(inventory);")}
        for col, ddl in (("ssid", "TEXT NOT NULL DEFAULT ''"), ("quiet", "INTEGER NOT NULL DEFAULT 0")):
            if col not in inv_cols:
                cursor.execute(f"ALTER TABLE inventory ADD COLUMN {col} {ddl};")

        # Notifications held during quiet hours, sent as one summary when they end.
        cursor.execute("CREATE TABLE IF NOT EXISTS notify_held (id INTEGER PRIMARY KEY AUTOINCREMENT, created_at INTEGER NOT NULL, text TEXT NOT NULL);")

        # Saved reports (schema 9): the spec (reports.py), an optional schedule and who saved it; the
        # newest runs of each are kept with their files, so a scheduled report can be fetched later.
        cursor.executescript("""
            CREATE TABLE IF NOT EXISTS reports (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                spec TEXT NOT NULL,
                schedule TEXT NOT NULL DEFAULT '',
                formats TEXT NOT NULL DEFAULT 'pdf',
                telegram INTEGER NOT NULL DEFAULT 0,
                owner TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                last_run_at INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS report_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                report_id INTEGER NOT NULL,
                made_at INTEGER NOT NULL,
                trigger TEXT NOT NULL DEFAULT '',
                total INTEGER NOT NULL DEFAULT 0,
                csv BLOB,
                pdf BLOB,
                error TEXT NOT NULL DEFAULT '',
                FOREIGN KEY (report_id) REFERENCES reports (id) ON DELETE CASCADE
            );
            CREATE INDEX IF NOT EXISTS idx_report_runs ON report_runs (report_id, made_at);
        """)

        # Web UI login. Password hashes only (scrypt, see auth.py).
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS accounts (
                username TEXT PRIMARY KEY,
                password_hash TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );
            """
        )
        # Migration: who made each audit entry and from which address (blank on older rows).
        audit_cols = {row[1] for row in cursor.execute("PRAGMA table_info(audit_log);")}
        for col in ("actor", "source"):
            if col not in audit_cols:
                cursor.execute(f"ALTER TABLE audit_log ADD COLUMN {col} TEXT NOT NULL DEFAULT '';")

        # Migration: users and roles. The first account (created before roles existed) is the administrator.
        account_cols = {row[1] for row in cursor.execute("PRAGMA table_info(accounts);")}
        for col, ddl in (("role", "TEXT NOT NULL DEFAULT 'admin'"), ("permissions", "TEXT"),
                         ("device_scope", "TEXT"), ("disabled", "INTEGER NOT NULL DEFAULT 0"),
                         ("display_name", "TEXT"), ("last_login", "INTEGER"),
                         ("notify_read_at", "INTEGER NOT NULL DEFAULT 0"),
                         # 2FA (totp.py). The secret is vault-encrypted; recovery codes are salted hashes (JSON list).
                         ("totp_secret", "TEXT"), ("totp_enabled", "INTEGER NOT NULL DEFAULT 0"),
                         ("totp_recovery", "TEXT"), ("totp_last_step", "INTEGER")):
            if col not in account_cols:
                cursor.execute(f"ALTER TABLE accounts ADD COLUMN {col} {ddl};")

        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS watches (
                device_id INTEGER NOT NULL,
                kind TEXT NOT NULL,
                name TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                PRIMARY KEY (device_id, kind, name),
                FOREIGN KEY (device_id) REFERENCES devices (id) ON DELETE CASCADE
            );
            """
        )

        # Migration: SSH task fields on the original automations table.
        auto_cols = {row[1] for row in cursor.execute("PRAGMA table_info(automations);")}
        for col, ddl in (("device_ids", "TEXT NOT NULL DEFAULT '[]'"), ("timeout_s", "INTEGER NOT NULL DEFAULT 60"),
                         ("ssh_port", "INTEGER NOT NULL DEFAULT 22"), ("last_scheduled", "INTEGER")):
            if col not in auto_cols:
                cursor.execute(f"ALTER TABLE automations ADD COLUMN {col} {ddl};")

        # Migration: system inventory (sysDescr, model, firmware ...) as JSON.
        device_cols = {row[1] for row in cursor.execute("PRAGMA table_info(devices);")}
        if "inventory" not in device_cols:
            cursor.execute("ALTER TABLE devices ADD COLUMN inventory TEXT NOT NULL DEFAULT '{}';")
        if "snmp_status" not in device_cols:
            cursor.execute("ALTER TABLE devices ADD COLUMN snmp_status TEXT NOT NULL DEFAULT 'unknown';")
        # Migration: administrator overrides. device_group replaces the group the template suggests;
        # upstream_device_id / upstream_port are the authoritative uplink on the map; overrides
        # holds details shown in the app instead of what the device reports (location, contact...).
        # service_kind: 'tcp' (connect to service_port) or 'http' (fetch service_url; service_expect holds
        # {"status": "200-399", "keyword": "...", "insecure": false}).
        for col, ddl in (("device_group", "TEXT"), ("upstream_device_id", "INTEGER"), ("upstream_port", "TEXT"),
                         ("overrides", "TEXT NOT NULL DEFAULT '{}'"), ("service_kind", "TEXT NOT NULL DEFAULT 'tcp'"),
                         ("service_url", "TEXT"), ("service_expect", "TEXT NOT NULL DEFAULT '{}'"),
                         ("snmp_v3", "TEXT NOT NULL DEFAULT ''")):
            if col not in device_cols:
                cursor.execute(f"ALTER TABLE devices ADD COLUMN {col} {ddl};")

        # Migration: problem acknowledgement (Zabbix-style ack: stays listed, stops counting).
        problem_cols = {row[1] for row in cursor.execute("PRAGMA table_info(problems_active);")}
        if "acknowledged_at" not in problem_cols:
            cursor.execute("ALTER TABLE problems_active ADD COLUMN acknowledged_at INTEGER;")
            cursor.execute("ALTER TABLE problems_active ADD COLUMN ack_note TEXT;")

        # Migration: problems wait for their rule's duration before they count (raised_at),
        # and repeat reminders track when Telegram last mentioned them.
        if "raised_at" not in problem_cols:
            cursor.execute("ALTER TABLE problems_active ADD COLUMN raised_at INTEGER;")
            cursor.execute("ALTER TABLE problems_active ADD COLUMN last_notified INTEGER;")
            cursor.execute("UPDATE problems_active SET raised_at = since;")

        # Alert rule overrides: one field per row, so each level inherits the fields it does not set.
        # Schema 2 added the tag scope; SQLite cannot change a CHECK, so an older table is rebuilt.
        row = cursor.execute("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'alert_overrides';").fetchone()
        if row and "'tag'" not in row[0]:
            cursor.execute("ALTER TABLE alert_overrides RENAME TO alert_overrides_v1;")
        cursor.execute(
            """
            CREATE TABLE IF NOT EXISTS alert_overrides (
                scope TEXT NOT NULL CHECK (scope IN ('global', 'template', 'tag', 'device')),
                target TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                field TEXT NOT NULL,
                value TEXT NOT NULL,
                updated_at INTEGER NOT NULL,
                PRIMARY KEY (scope, target, rule_id, field)
            );
            """
        )
        if row and "'tag'" not in row[0]:
            cursor.execute("INSERT INTO alert_overrides SELECT scope, target, rule_id, field, value, updated_at FROM alert_overrides_v1;")
            cursor.execute("DROP TABLE alert_overrides_v1;")
        # The SSH task alert rule became the workflow rule when SSH tasks were folded into workflows.
        cursor.execute("UPDATE OR IGNORE alert_overrides SET rule_id = 'workflow' WHERE rule_id = 'task';")
        cursor.execute("DELETE FROM alert_overrides WHERE rule_id = 'task';")

        # Migration: when each metric last wrote a history row (for on-change storage).
        latest_cols = {row[1] for row in cursor.execute("PRAGMA table_info(metric_latest);")}
        if "stored_timestamp" not in latest_cols:
            cursor.execute("ALTER TABLE metric_latest ADD COLUMN stored_timestamp INTEGER;")
            cursor.execute("UPDATE metric_latest SET stored_timestamp = timestamp;")

        # Migration: backfill metric_latest from history once.
        if cursor.execute("SELECT COUNT(*) FROM metric_latest;").fetchone()[0] == 0:
            cursor.execute(
                """
                INSERT INTO metric_latest (device_id, metric_key, value, timestamp)
                SELECT m.device_id, m.metric_key, m.value, m.timestamp
                FROM metrics m
                INNER JOIN (
                    SELECT device_id, metric_key, MAX(id) AS max_id
                    FROM metrics GROUP BY device_id, metric_key
                ) latest ON m.id = latest.max_id;
                """
            )

        # Seed initial default settings if empty
        default_settings = [
            ("default_snmp_community", "public", "Default SNMP community string across all devices"),
            ("default_snmp_version", "v2c", "Default SNMP protocol version"),
            ("default_snmp_port", "161", "Default UDP port for SNMP queries"),
            ("default_poll_interval", "60", "Global default SNMP poll interval in seconds"),
            ("default_ping_interval", "15", "Global default ICMP ping interval in seconds"),
            ("default_timeout", "2.0", "Network query timeout in seconds"),
            ("default_retries", "2", "Number of retry attempts before marking target degraded"),
            ("metric_retention_days", "30", "Days of metric history retained"),
            ("audit_retention_days", "90", "Days of audit logs retained")
        ]

        now = int(time.time())
        for key, val, desc in default_settings:
            cursor.execute(
                """
                INSERT OR IGNORE INTO settings (key, value, description, updated_at)
                VALUES (?, ?, ?, ?);
                """,
                (key, val, desc, now)
            )

        conn.commit()


# --- Device Management Queries ---

def list_devices() -> List[Dict[str, Any]]:
    """Returns all monitored devices with full SNMP details sorted by hostname."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, hostname, ip_address, profile_id, snmp_version, snmp_community, snmp_port,
                   poll_interval, ping_interval, status, last_ping_ms, last_seen, created_at, tags,
                   inventory, snmp_status, service_port, device_group, upstream_device_id, upstream_port, overrides,
                   service_kind, service_url, service_expect, snmp_v3
            FROM devices
            ORDER BY hostname ASC;
            """
        )
        return [_decode_inventory(dict(row)) for row in cursor.fetchall()]


def _decode_inventory(device: Dict[str, Any]) -> Dict[str, Any]:
    """Decodes the inventory JSON and decrypts the SNMP community for in-process use."""
    try:
        device["inventory"] = json.loads(device.get("inventory") or "{}")
    except ValueError:
        device["inventory"] = {}
    if "overrides" in device:
        try:
            device["overrides"] = json.loads(device.get("overrides") or "{}")
        except ValueError:
            device["overrides"] = {}
    if "service_expect" in device:
        try:
            device["service_expect"] = json.loads(device.get("service_expect") or "{}")
        except ValueError:
            device["service_expect"] = {}
    if "snmp_community" in device:
        device["snmp_community"] = VAULT.decrypt(device["snmp_community"], COMMUNITY_CONTEXT)
    if "snmp_v3" in device:
        try:
            v3 = json.loads(VAULT.decrypt(device["snmp_v3"], SNMP_V3_CONTEXT) or "{}") if device["snmp_v3"] else {}
        except (ValueError, VaultError):
            v3 = {}
        device["snmp_v3"] = v3 if isinstance(v3, dict) else {}
    return device


def set_device_snmp(device_id: int, version: str, settings: Optional[Dict[str, Any]]) -> None:
    """A device's SNMP version ("v2c" or "v3") and its SNMPv3 settings sealed by the vault (None or {}
    clears them). The v2c community stays as it is, so switching back needs nothing typed again."""
    value = VAULT.encrypt(json.dumps(settings, sort_keys=True), SNMP_V3_CONTEXT) if settings else ""
    with get_connection() as conn:
        conn.execute("UPDATE devices SET snmp_version = ?, snmp_v3 = ? WHERE id = ?;", (version, value, device_id))
        conn.commit()


def ensure_settings(defaults: List[tuple]) -> None:
    """Inserts any (key, value, description) setting that does not exist yet."""
    now = int(time.time())
    with get_connection() as conn:
        conn.executemany(
            "INSERT OR IGNORE INTO settings (key, value, description, updated_at) VALUES (?, ?, ?, ?);",
            [(k, v, d, now) for k, v, d in defaults]
        )
        conn.commit()


def rollup_hourly(now: Optional[int] = None, exclude: Optional[set] = None) -> int:
    """Aggregates completed hours of raw metrics into metrics_hourly.

    Re-aggregates from the last stored hour so a partially rolled hour is
    completed. exclude is a set of (device_id, metric_key) pairs kept as raw
    short-term history only (no long-term trend). Returns rows written.
    """
    now = now if now is not None else int(time.time())
    current_hour = now - now % 3600
    exclude = exclude or set()
    with get_connection() as conn:
        last = conn.execute("SELECT MAX(hour) FROM metrics_hourly;").fetchone()[0]
        start = last if last is not None else 0
        rows = conn.execute(
            """
            SELECT device_id, metric_key, timestamp - timestamp % 3600 AS hour,
                   AVG(value), MIN(value), MAX(value), COUNT(*)
            FROM metrics
            WHERE timestamp >= ? AND timestamp < ?
            GROUP BY device_id, metric_key, hour;
            """,
            (start, current_hour)
        ).fetchall()
        keep = [tuple(r) for r in rows if (r[0], r[1]) not in exclude]
        conn.executemany(
            "INSERT OR REPLACE INTO metrics_hourly (device_id, metric_key, hour, avg, min, max, samples) "
            "VALUES (?, ?, ?, ?, ?, ?, ?);",
            keep
        )
        conn.commit()
    return len(keep)


def delete_metric_history(device_id: Optional[int], keys: List[str], drop_latest: bool = False) -> int:
    """Removes stored history (raw and hourly) for metric keys, optionally for one device only."""
    if not keys:
        return 0
    placeholders = ",".join("?" for _ in keys)
    scope, params = ("", list(keys)) if device_id is None else (" AND device_id = ?", [*keys, device_id])
    with get_connection() as conn:
        n = conn.execute(f"DELETE FROM metrics WHERE metric_key IN ({placeholders}){scope};", params).rowcount
        n += conn.execute(f"DELETE FROM metrics_hourly WHERE metric_key IN ({placeholders}){scope};", params).rowcount
        if drop_latest:
            conn.execute(f"DELETE FROM metric_latest WHERE metric_key IN ({placeholders}){scope};", params)
        conn.commit()
    return n


def purge_expired(raw_retention_days: int, audit_retention_days: int,
                  trend_retention_days: int = 365, event_retention_days: Optional[int] = None) -> Dict[str, int]:
    """Deletes raw metrics, hourly trends, audit and event rows past their retention windows. The audit
    log is always kept for at least AUDIT_RETENTION_FLOOR days, whatever the database says."""
    now = int(time.time())
    events_days = audit_retention_days if event_retention_days is None else event_retention_days
    audit_retention_days = max(int(audit_retention_days), AUDIT_RETENTION_FLOOR)
    with get_connection() as conn:
        metrics_deleted = conn.execute(
            "DELETE FROM metrics WHERE timestamp < ?;", (now - raw_retention_days * 86400,)
        ).rowcount
        metrics_deleted += conn.execute(
            "DELETE FROM metrics_hourly WHERE hour < ?;", (now - trend_retention_days * 86400,)
        ).rowcount
        audit_deleted = conn.execute(
            "DELETE FROM audit_log WHERE timestamp < ?;", (now - audit_retention_days * 86400,)
        ).rowcount
        audit_deleted += conn.execute(
            "DELETE FROM events WHERE timestamp < ?;", (now - events_days * 86400,)
        ).rowcount
        conn.commit()
    return {"metrics": metrics_deleted, "audit": audit_deleted}


def get_device(device_id: int) -> Optional[Dict[str, Any]]:
    """Retrieves a single device by primary key."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, hostname, ip_address, profile_id, snmp_version, snmp_community, snmp_port,
                   poll_interval, ping_interval, status, last_ping_ms, last_seen, created_at, tags,
                   inventory, snmp_status, service_port, device_group, upstream_device_id, upstream_port, overrides,
                   service_kind, service_url, service_expect, snmp_v3
            FROM devices
            WHERE id = ?;
            """,
            (device_id,)
        )
        row = cursor.fetchone()
        return _decode_inventory(dict(row)) if row else None


def update_inventory(device_id: int, inventory: Dict[str, Any]) -> None:
    """Stores the system inventory JSON gathered during an SNMP poll."""
    with get_connection() as conn:
        conn.execute("UPDATE devices SET inventory = ? WHERE id = ?;", (json.dumps(inventory), device_id))
        conn.commit()


def add_device(
    hostname: str,
    ip_address: str,
    profile_id: str,
    snmp_version: str = "v2c",
    snmp_community: str = "public",
    snmp_port: int = 161,
    poll_interval: Optional[int] = None,
    ping_interval: Optional[int] = None,
    tags: str = "[]",
    service_port: int = 0
) -> int:
    """Inserts a new device and records an audit log entry."""
    now = int(time.time())
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO devices (
                hostname, ip_address, profile_id, snmp_version, snmp_community,
                snmp_port, poll_interval, ping_interval, created_at, tags, service_port
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                hostname, ip_address, profile_id, snmp_version, VAULT.encrypt(snmp_community, COMMUNITY_CONTEXT),
                snmp_port, poll_interval, ping_interval, now, tags, service_port
            )
        )
        device_id = cursor.lastrowid
        _audit_row(cursor, "device", f"Added device {hostname} ({ip_address})", f"Profile: {profile_id}", now=now)
        conn.commit()
        return device_id


def set_service_check(device_id: int, service_kind: str, service_url: Optional[str], service_expect: Dict[str, Any]) -> None:
    """How a port check tests its service: a TCP connect, or an HTTP(S) request with expectations."""
    with get_connection() as conn:
        conn.execute("UPDATE devices SET service_kind = ?, service_url = ?, service_expect = ? WHERE id = ?;",
                     (service_kind, service_url, json.dumps(service_expect, sort_keys=True), device_id))
        conn.commit()


def set_device_overrides(device_id: int, device_group: Optional[str], upstream_device_id: Optional[int],
                         upstream_port: Optional[str], overrides: Dict[str, str]) -> None:
    """Administrator choices that win over what the template, the poll or the map inference say."""
    with get_connection() as conn:
        conn.execute("UPDATE devices SET device_group = ?, upstream_device_id = ?, upstream_port = ?, overrides = ? WHERE id = ?;",
                     (device_group, upstream_device_id, upstream_port, json.dumps(overrides, sort_keys=True), device_id))
        conn.commit()


def update_device(
    device_id: int,
    hostname: str,
    ip_address: str,
    profile_id: str,
    snmp_community: Optional[str],
    snmp_port: int,
    poll_interval: Optional[int] = None,
    ping_interval: Optional[int] = None,
    service_port: int = 0
) -> bool:
    """Updates all configuration fields including IP address for an existing device."""
    now = int(time.time())
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE devices
            SET hostname = ?, ip_address = ?, profile_id = ?,
                snmp_community = COALESCE(?, snmp_community),
                snmp_port = ?, poll_interval = ?, ping_interval = ?, service_port = ?
            WHERE id = ?;
            """,
            (hostname, ip_address, profile_id,
             VAULT.encrypt(snmp_community, COMMUNITY_CONTEXT) if snmp_community else None,
             snmp_port, poll_interval, ping_interval, service_port, device_id)
        )
        # rowcount must be read before the audit INSERT, which resets it.
        if cursor.rowcount == 0:
            return False
        _audit_row(cursor, "device", f"Updated configuration for {hostname} ({ip_address})", f"Device ID: {device_id}", now=now)
        conn.commit()
        return True


def delete_device(device_id: int) -> bool:
    """Removes a device and cascades deletion to associated metrics."""
    now = int(time.time())
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT hostname, ip_address FROM devices WHERE id = ?;", (device_id,))
        row = cursor.fetchone()
        if not row:
            return False

        cursor.execute("DELETE FROM devices WHERE id = ?;", (device_id,))
        # Map rows reference nodes by text key, so no foreign key cascades them.
        key = f"d:{device_id}"
        cursor.execute("DELETE FROM map_links WHERE node_a = ? OR node_b = ?;", (key, key))
        cursor.execute("DELETE FROM alert_overrides WHERE scope = 'device' AND target = ?;", (str(device_id),))
        cursor.execute("UPDATE devices SET upstream_device_id = NULL, upstream_port = NULL WHERE upstream_device_id = ?;", (device_id,))
        cursor.execute("DELETE FROM map_positions WHERE node = ?;", (key,))
        _audit_row(cursor, "device", f"Removed device {row['hostname']} ({row['ip_address']})", f"Device ID: {device_id}", now=now)
        conn.commit()
        return True


def update_device_status(device_id: int, status: str, ping_ms: Optional[float] = None) -> Optional[str]:
    """Updates the operational state and ping response time for a device.

    Returns the previous status so callers can detect transitions.
    """
    now = int(time.time())
    with get_connection() as conn:
        cursor = conn.cursor()
        row = cursor.execute("SELECT status FROM devices WHERE id = ?;", (device_id,)).fetchone()
        previous = row["status"] if row else None
        cursor.execute(
            """
            UPDATE devices
            SET status = ?, last_ping_ms = ?, last_seen = ?
            WHERE id = ?;
            """,
            (status, ping_ms, now, device_id)
        )
        conn.commit()
        return previous


# --- Settings Queries ---

def get_all_settings() -> Dict[str, str]:
    """Retrieves all global configuration settings as a key-value mapping."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT key, value FROM settings;")
        return {row["key"]: VAULT.decrypt(row["value"], f"setting:{row['key']}") if row["key"] in SECRET_SETTINGS else row["value"]
                for row in cursor.fetchall()}


def delete_settings(keys: List[str]) -> None:
    """Removes settings that are no longer in the schema."""
    with get_connection() as conn:
        conn.executemany("DELETE FROM settings WHERE key = ?;", [(k,) for k in keys])
        conn.commit()


def update_setting(key: str, value: str) -> None:
    """Updates a global configuration setting."""
    now = int(time.time())
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            UPDATE settings
            SET value = ?, updated_at = ?
            WHERE key = ?;
            """,
            (VAULT.encrypt(value, f"setting:{key}") if key in SECRET_SETTINGS else value, now, key)
        )
        conn.commit()


def encrypt_existing_secrets() -> int:
    """Encrypts any plaintext community strings left from before the vault existed. Idempotent."""
    if not VAULT.enabled:
        return 0
    changed = 0
    with get_connection() as conn:
        for row in conn.execute("SELECT id, snmp_community FROM devices;").fetchall():
            if row["snmp_community"] and not VAULT.is_token(row["snmp_community"]):
                conn.execute("UPDATE devices SET snmp_community = ? WHERE id = ?;",
                             (VAULT.encrypt(row["snmp_community"], COMMUNITY_CONTEXT), row["id"]))
                changed += 1
        for key in SECRET_SETTINGS:
            row = conn.execute("SELECT value FROM settings WHERE key = ?;", (key,)).fetchone()
            if row and row["value"] and not VAULT.is_token(row["value"]):
                conn.execute("UPDATE settings SET value = ? WHERE key = ?;",
                             (VAULT.encrypt(row["value"], f"setting:{key}"), key))
                changed += 1
        conn.commit()
    return changed


def rekey_secrets() -> int:
    """Re-encrypts every stored secret under the vault's current key in one transaction.

    Used when the key moves to a new location with a fresh key. Safe to rerun:
    tokens already under the new key are left as they are.
    """
    changed = 0
    with get_connection() as conn:
        for row in conn.execute("SELECT id, snmp_community FROM devices;").fetchall():
            new = VAULT.reencrypt(row["snmp_community"], COMMUNITY_CONTEXT)
            if new != row["snmp_community"]:
                conn.execute("UPDATE devices SET snmp_community = ? WHERE id = ?;", (new, row["id"]))
                changed += 1
        for key in SECRET_SETTINGS:
            row = conn.execute("SELECT value FROM settings WHERE key = ?;", (key,)).fetchone()
            if row:
                new = VAULT.reencrypt(row["value"], f"setting:{key}")
                if new != row["value"]:
                    conn.execute("UPDATE settings SET value = ? WHERE key = ?;", (new, key))
                    changed += 1
        for row in conn.execute("SELECT id, cred_type, secret_encrypted FROM credentials;").fetchall():
            new = VAULT.reencrypt(row["secret_encrypted"], _credential_context(row["cred_type"]))
            if new != row["secret_encrypted"]:
                conn.execute("UPDATE credentials SET secret_encrypted = ? WHERE id = ?;", (new, row["id"]))
                changed += 1
        for row in conn.execute("SELECT id, cred_type, passphrase_encrypted FROM credentials "
                                "WHERE passphrase_encrypted IS NOT NULL;").fetchall():
            new = VAULT.reencrypt(row["passphrase_encrypted"], _passphrase_context(row["cred_type"]))
            if new != row["passphrase_encrypted"]:
                conn.execute("UPDATE credentials SET passphrase_encrypted = ? WHERE id = ?;", (new, row["id"]))
        for row in conn.execute("SELECT username, totp_secret FROM accounts WHERE totp_secret IS NOT NULL;").fetchall():
            new = VAULT.reencrypt(row["totp_secret"], "account:totp")
            if new != row["totp_secret"]:
                conn.execute("UPDATE accounts SET totp_secret = ? WHERE username = ?;", (new, row["username"]))
                changed += 1
                changed += 1
        conn.commit()
    return changed


def forget_secrets(conn: sqlite3.Connection) -> int:
    """Clears every stored secret in a database whose vault key is gone for good (a restore of a
    backup made without its key). The same columns rekey_secrets walks: device communities, the
    secret settings (removed, so their defaults apply), credential secrets and passphrases, and 2FA
    (turned off, as a password reset from the shell does). Returns how many values were cleared.
    Works on any older layout: tables and columns that are missing are skipped."""
    tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type = 'table';")}

    def cols(table: str) -> set:
        return {r[1] for r in conn.execute(f'PRAGMA table_info("{table}");')}
    cleared = 0
    if "devices" in tables and "snmp_community" in cols("devices"):
        cleared += conn.execute("UPDATE devices SET snmp_community = '' WHERE COALESCE(snmp_community, '') != '';").rowcount
    if "settings" in tables:
        for key in sorted(SECRET_SETTINGS):
            cleared += conn.execute("DELETE FROM settings WHERE key = ?;", (key,)).rowcount
    if "credentials" in tables:
        c = cols("credentials")
        cleared += conn.execute("UPDATE credentials SET secret_encrypted = '' WHERE secret_encrypted != '';").rowcount
        if "passphrase_encrypted" in c:
            cleared += conn.execute("UPDATE credentials SET passphrase_encrypted = NULL "
                                    "WHERE passphrase_encrypted IS NOT NULL;").rowcount
    if "accounts" in tables:
        c = cols("accounts")
        if "totp_secret" in c:
            cleared += conn.execute("UPDATE accounts SET totp_secret = NULL WHERE totp_secret IS NOT NULL;").rowcount
            sets = [f"{col} = {val}" for col, val in (("totp_enabled", "0"), ("totp_recovery", "'[]'"),
                                                      ("totp_last_step", "NULL")) if col in c]
            if sets:
                conn.execute("UPDATE accounts SET " + ", ".join(sets) + ";")
    return cleared


# --- Credentials (vault-encrypted) ---

CREDENTIAL_TYPES = ("password", "ssh_key")


def _credential_context(cred_type: str) -> str:
    return f"credential:{cred_type}"


def list_credentials() -> List[Dict[str, Any]]:
    """Credential metadata only. Secrets are never returned by this function."""
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT id, name, cred_type, username, created_at, public_key, "
            "passphrase_encrypted IS NOT NULL AS has_passphrase FROM credentials ORDER BY name;"
        ).fetchall()
        return [dict(r, has_passphrase=bool(r["has_passphrase"])) for r in rows]


def _passphrase_context(cred_type: str) -> str:
    return f"credential:{cred_type}:passphrase"


def add_credential(name: str, cred_type: str, username: str, secret: str,
                   passphrase: str = "", public_key: Optional[str] = None) -> int:
    """passphrase (SSH keys only) is encrypted like the secret; public_key is stored as given."""
    with get_connection() as conn:
        cur = conn.execute(
            "INSERT INTO credentials (name, cred_type, username, secret_encrypted, salt, nonce, created_at, "
            "passphrase_encrypted, public_key) VALUES (?, ?, ?, ?, '', '', ?, ?, ?);",
            (name, cred_type, username, VAULT.encrypt(secret, _credential_context(cred_type)), int(time.time()),
             VAULT.encrypt(passphrase, _passphrase_context(cred_type)) if passphrase else None, public_key)
        )
        conn.commit()
        return cur.lastrowid


def update_credential(cred_id: int, name: str, username: str, secret: Optional[str],
                      passphrase: Optional[str] = None, public_key: Optional[str] = None) -> bool:
    """Renames a credential and changes its username; replaces the secret only when one is given.

    A new secret also replaces the passphrase and public key (empty passphrase: none).
    """
    with get_connection() as conn:
        row = conn.execute("SELECT cred_type FROM credentials WHERE id = ?;", (cred_id,)).fetchone()
        if not row:
            return False
        if secret:
            conn.execute("UPDATE credentials SET name = ?, username = ?, secret_encrypted = ?, passphrase_encrypted = ?, "
                         "public_key = ? WHERE id = ?;",
                         (name, username, VAULT.encrypt(secret, _credential_context(row["cred_type"])),
                          VAULT.encrypt(passphrase, _passphrase_context(row["cred_type"])) if passphrase else None,
                          public_key, cred_id))
        else:
            conn.execute("UPDATE credentials SET name = ?, username = ? WHERE id = ?;", (name, username, cred_id))
        conn.commit()
        return True


def delete_credential(cred_id: int) -> bool:
    with get_connection() as conn:
        n = conn.execute("DELETE FROM credentials WHERE id = ?;", (cred_id,)).rowcount
        conn.commit()
        return n > 0


def get_credential_public(cred_id: int) -> Optional[Dict[str, Any]]:
    """A credential's public parts (no vault access): id, name, type, username and the SSH public key."""
    with get_connection() as conn:
        row = conn.execute("SELECT id, name, cred_type, username, public_key FROM credentials WHERE id = ?;",
                           (cred_id,)).fetchone()
    return dict(row) if row else None


def get_credential_secret(cred_id: int) -> Optional[Dict[str, Any]]:
    """Decrypted credential for in-process use by the SSH runner. Never send this to a client."""
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM credentials WHERE id = ?;", (cred_id,)).fetchone()
    if not row:
        return None
    passphrase = row["passphrase_encrypted"]
    return {"id": row["id"], "name": row["name"], "cred_type": row["cred_type"], "username": row["username"],
            "secret": VAULT.decrypt(row["secret_encrypted"], _credential_context(row["cred_type"])),
            "passphrase": VAULT.decrypt(passphrase, _passphrase_context(row["cred_type"])) if passphrase else ""}


COMPACT_MARKER = "secure_compacted"


def plaintext_residue_possible() -> bool:
    """True until the database has been compacted once after secrets were first encrypted."""
    with get_connection() as conn:
        return conn.execute("SELECT 1 FROM settings WHERE key = ?;", (COMPACT_MARKER,)).fetchone() is None


def compact_secure() -> None:
    """VACUUMs the database and truncates the WAL, removing old page images (including
    secrets stored before encryption existed) from free pages and the journal."""
    with get_connection() as conn:
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
    conn = sqlite3.connect(DB_FILE, timeout=30.0)
    try:
        conn.execute("VACUUM;")
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
        conn.execute("INSERT OR REPLACE INTO settings (key, value, description, updated_at) VALUES (?, '1', ?, ?);",
                     (COMPACT_MARKER, "Internal: database compacted after secret encryption", int(time.time())))
        conn.commit()
        conn.execute("PRAGMA wal_checkpoint(TRUNCATE);")
    finally:
        conn.close()


def count_encrypted_secrets() -> int:
    with get_connection() as conn:
        n = conn.execute("SELECT COUNT(*) FROM devices WHERE snmp_community LIKE 'enc1:%';").fetchone()[0]
        n += conn.execute("SELECT COUNT(*) FROM credentials WHERE secret_encrypted LIKE 'enc1:%';").fetchone()[0]
        n += conn.execute("SELECT COUNT(*) FROM credentials WHERE passphrase_encrypted LIKE 'enc1:%';").fetchone()[0]
        n += conn.execute("SELECT COUNT(*) FROM settings WHERE value LIKE 'enc1:%';").fetchone()[0]
        n += conn.execute("SELECT COUNT(*) FROM accounts WHERE totp_secret LIKE 'enc1:%';").fetchone()[0]
        return n


# --- Metric Recording & Inspection ---

def record_metric(device_id: int, metric_key: str, value: float, timestamp: Optional[int] = None) -> None:
    """Inserts a single metric data point."""
    record_metrics(device_id, {metric_key: value}, timestamp)


HEARTBEAT_SECONDS = 3600


def record_metrics(device_id: int, values: Dict[str, float], timestamp: Optional[int] = None,
                   history: Optional[Dict[str, str]] = None) -> None:
    """Records metric samples and refreshes metric_latest.

    history maps a key to its storage mode:
      "raw"    (default) every sample is written to the metrics table.
      "change" a sample is written only when the value differs from the last
               stored one, or at least hourly as a heartbeat. For near-static
               values such as radio channel or total memory.
      "hourly" at most one sample per hour.
      "none"   no history at all: only the latest value is kept. For values
               that are only shown, never graphed or compared (uptime,
               cumulative counters, inputs to a derived metric).
    metric_latest is always updated, so current values and change detection
    are unaffected by the storage mode.
    """
    if not values:
        return
    ts = timestamp if timestamp is not None else int(time.time())
    history = history or {}
    with get_connection() as conn:
        sparse = [k for k in values if history.get(k, "raw") != "raw"]
        last: Dict[str, Any] = {}
        if sparse:
            placeholders = ",".join("?" for _ in sparse)
            for row in conn.execute(
                f"SELECT metric_key, value, stored_timestamp FROM metric_latest "
                f"WHERE device_id = ? AND metric_key IN ({placeholders});",
                [device_id, *sparse]
            ):
                last[row["metric_key"]] = row

        stored = []
        for key, value in values.items():
            mode = history.get(key, "raw")
            prev = last.get(key)
            due = prev is None or prev["stored_timestamp"] is None or ts - prev["stored_timestamp"] >= HEARTBEAT_SECONDS
            if mode == "none":
                continue
            if mode == "raw" or due or (mode == "change" and prev["value"] != value):
                stored.append(key)

        conn.executemany(
            "INSERT INTO metrics (device_id, metric_key, timestamp, value) VALUES (?, ?, ?, ?);",
            [(device_id, k, ts, values[k]) for k in stored]
        )
        conn.executemany(
            """
            INSERT INTO metric_latest (device_id, metric_key, timestamp, value, stored_timestamp)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT (device_id, metric_key) DO UPDATE SET
                prev_value = metric_latest.value,
                prev_timestamp = metric_latest.timestamp,
                value = excluded.value,
                timestamp = excluded.timestamp,
                stored_timestamp = COALESCE(excluded.stored_timestamp, metric_latest.stored_timestamp);
            """,
            [(device_id, k, ts, v, ts if k in stored else None) for k, v in values.items()]
        )
        conn.commit()


def get_latest_metrics(device_id: int) -> List[Dict[str, Any]]:
    """Returns the latest value, previous value and timestamps for each metric of a device."""
    with get_connection() as conn:
        cursor = conn.execute(
            """
            SELECT metric_key, value, timestamp, prev_value, prev_timestamp
            FROM metric_latest
            WHERE device_id = ?
            ORDER BY metric_key ASC;
            """,
            (device_id,)
        )
        return [dict(row) for row in cursor.fetchall()]


def get_latest_metrics_all(keys: List[str]) -> Dict[int, Dict[str, float]]:
    """Returns {device_id: {metric_key: value}} for the requested keys across all devices."""
    if not keys:
        return {}
    placeholders = ",".join("?" for _ in keys)
    with get_connection() as conn:
        cursor = conn.execute(
            f"SELECT device_id, metric_key, value FROM metric_latest WHERE metric_key IN ({placeholders});",
            keys
        )
        result: Dict[int, Dict[str, float]] = {}
        for row in cursor.fetchall():
            result.setdefault(row["device_id"], {})[row["metric_key"]] = row["value"]
        return result


def get_metric_history_bucketed(
    device_id: int,
    metric_key: str,
    start_time: int,
    end_time: int,
    max_points: int = 300
) -> List[Dict[str, Any]]:
    """Returns time-series points averaged into at most max_points buckets.

    Each point carries avg, min and max of its bucket so charts can show the
    spread that averaging would otherwise hide. Ranges longer than two days
    read hourly trends for the part older than the raw data and raw samples
    for the rest, so long ranges keep working after raw retention expires.
    """
    bucket = max(1, (end_time - start_time) // max_points)
    with get_connection() as conn:
        raw_start = start_time
        points: List[Dict[str, Any]] = []
        if end_time - start_time > 2 * 86400:
            oldest_raw = conn.execute(
                "SELECT MIN(timestamp) FROM metrics WHERE device_id = ? AND metric_key = ?;",
                (device_id, metric_key)
            ).fetchone()[0]
            # Hourly trends cover everything before the first complete raw hour.
            boundary = end_time if oldest_raw is None else oldest_raw - oldest_raw % 3600 + 3600
            if boundary > start_time:
                cursor = conn.execute(
                    """
                    SELECT MIN(hour) AS timestamp, SUM(avg * samples) / SUM(samples) AS value,
                           MIN(min) AS min, MAX(max) AS max
                    FROM metrics_hourly
                    WHERE device_id = ? AND metric_key = ? AND hour >= ? AND hour < ?
                    GROUP BY (hour - ?) / ?
                    ORDER BY timestamp ASC;
                    """,
                    (device_id, metric_key, start_time, boundary, start_time, max(bucket, 3600))
                )
                points = [dict(row) for row in cursor.fetchall()]
                raw_start = max(start_time, boundary)
        cursor = conn.execute(
            """
            SELECT MIN(timestamp) AS timestamp, AVG(value) AS value, MIN(value) AS min, MAX(value) AS max
            FROM metrics
            WHERE device_id = ? AND metric_key = ? AND timestamp >= ? AND timestamp <= ?
            GROUP BY (timestamp - ?) / ?
            ORDER BY timestamp ASC;
            """,
            (device_id, metric_key, raw_start, end_time, start_time, bucket)
        )
        return points + [dict(row) for row in cursor.fetchall()]


# --- SNMP Table Snapshots ---

def replace_device_table(device_id: int, table_name: str, rows: Dict[str, Dict[str, Any]],
                         timestamp: Optional[int] = None) -> None:
    """Replaces all snapshot rows of one table for a device in a single transaction."""
    ts = timestamp if timestamp is not None else int(time.time())
    with get_connection() as conn:
        conn.execute("DELETE FROM device_tables WHERE device_id = ? AND table_name = ?;", (device_id, table_name))
        conn.executemany(
            """
            INSERT INTO device_tables (device_id, table_name, row_key, data, updated_at)
            VALUES (?, ?, ?, ?, ?);
            """,
            [(device_id, table_name, key, json.dumps(data), ts) for key, data in rows.items()]
        )
        conn.commit()


def get_device_table(device_id: int, table_name: str) -> Dict[str, Dict[str, Any]]:
    """Returns {row_key: data} for one snapshot table of a device. Each data dict includes updated_at."""
    with get_connection() as conn:
        cursor = conn.execute(
            "SELECT row_key, data, updated_at FROM device_tables WHERE device_id = ? AND table_name = ?;",
            (device_id, table_name)
        )
        rows = {}
        for row in cursor.fetchall():
            data = json.loads(row["data"])
            data["updated_at"] = row["updated_at"]
            rows[row["row_key"]] = data
        return rows


def get_table_all_devices(table_name: str) -> List[Dict[str, Any]]:
    """Returns every row of a snapshot table across devices, each tagged with device_id and row_key."""
    with get_connection() as conn:
        cursor = conn.execute(
            "SELECT device_id, row_key, data, updated_at FROM device_tables WHERE table_name = ?;",
            (table_name,)
        )
        out = []
        for row in cursor.fetchall():
            data = json.loads(row["data"])
            data.update(device_id=row["device_id"], row_key=row["row_key"], updated_at=row["updated_at"])
            out.append(data)
        return out


def list_table_names(device_id: int) -> List[str]:
    """Returns the snapshot tables that hold rows for a device."""
    with get_connection() as conn:
        cursor = conn.execute(
            "SELECT DISTINCT table_name FROM device_tables WHERE device_id = ?;", (device_id,)
        )
        return [row["table_name"] for row in cursor.fetchall()]


# --- Events ---

def add_event(device_id: Optional[int], severity: str, event_type: str, message: str,
              timestamp: Optional[int] = None, actor: Optional[str] = None) -> None:
    """Records an event. device_id is None for system events; actor is the user who acted, if any."""
    ts = timestamp if timestamp is not None else int(time.time())
    with get_connection() as conn:
        conn.execute(
            "INSERT INTO events (device_id, timestamp, severity, event_type, message, actor) VALUES (?, ?, ?, ?, ?, ?);",
            (device_id, ts, severity, event_type, message, actor)
        )
        conn.commit()


def list_events(device_id: Optional[int] = None, limit: int = 100) -> List[Dict[str, Any]]:
    """Returns recent events, newest first, optionally for one device."""
    query = """
        SELECT e.id, e.device_id, d.hostname, e.timestamp, e.severity, e.event_type, e.message, e.actor
        FROM events e LEFT JOIN devices d ON d.id = e.device_id
        WHERE (? IS NULL OR e.device_id = ?)
        ORDER BY e.timestamp DESC, e.id DESC LIMIT ?;
    """
    with get_connection() as conn:
        cursor = conn.execute(query, (device_id, device_id, limit))
        return [dict(row) for row in cursor.fetchall()]


def get_metric_history(
    device_id: int,
    metric_key: str,
    start_time: int,
    end_time: int
) -> List[Dict[str, Any]]:
    """Returns metric time-series points within a specified time window."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT timestamp, value
            FROM metrics
            WHERE device_id = ? AND metric_key = ? AND timestamp >= ? AND timestamp <= ?
            ORDER BY timestamp ASC;
            """,
            (device_id, metric_key, start_time, end_time)
        )
        return [dict(row) for row in cursor.fetchall()]


def get_metric_contrast(
    device_id: int,
    metric_key: str,
    duration_seconds: int = 86400,
    offset_seconds: int = 604800
) -> Dict[str, Any]:
    """Retrieves current window metrics overlaid with a past historical baseline."""
    now = int(time.time())
    current_start = now - duration_seconds

    past_end = now - offset_seconds
    past_start = past_end - duration_seconds

    current_data = get_metric_history(device_id, metric_key, current_start, now)
    past_data = get_metric_history(device_id, metric_key, past_start, past_end)

    return {
        "current": current_data,
        "past": past_data,
        "offset_seconds": offset_seconds
    }


# --- Audit Log Queries ---

def list_audit_filtered(q: str = "", category: str = "", since: Optional[int] = None, until: Optional[int] = None,
                        search_details: bool = True, offset: int = 0, limit: int = 50) -> Tuple[List[Dict[str, Any]], int]:
    """Audit log page and total. search_details is off for users who may not see sensitive details,
    so a search cannot reveal what is hidden from them."""
    where, args = [], []
    if q:
        like = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        if search_details:
            where.append("(message LIKE ? ESCAPE '\\' OR details LIKE ? ESCAPE '\\' OR actor LIKE ? ESCAPE '\\' "
                         "OR source LIKE ? ESCAPE '\\')")
            args += [like, like, like, like]
        else:
            where.append("message LIKE ? ESCAPE '\\'")
            args.append(like)
    if category:
        where.append("category = ?")
        args.append(category)
    if since is not None:
        where.append("timestamp >= ?")
        args.append(since)
    if until is not None:
        where.append("timestamp < ?")
        args.append(until)
    clause = ("WHERE " + " AND ".join(where)) if where else ""
    with get_connection() as conn:
        total = conn.execute(f"SELECT COUNT(*) FROM audit_log {clause};", args).fetchone()[0]
        rows = conn.execute(f"SELECT id, timestamp, category, message, details, actor, source FROM audit_log {clause} "
                            "ORDER BY timestamp DESC, id DESC LIMIT ? OFFSET ?;", args + [limit, offset])
        return [dict(r) for r in rows], total


def audit_categories() -> List[str]:
    with get_connection() as conn:
        return [r[0] for r in conn.execute("SELECT DISTINCT category FROM audit_log ORDER BY category;")]


def list_audit_logs(limit: int = 50) -> List[Dict[str, Any]]:
    """Returns the most recent audit log entries."""
    with get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, timestamp, category, message, details
            FROM audit_log
            ORDER BY timestamp DESC
            LIMIT ?;
            """,
            (limit,)
        )
        return [dict(row) for row in cursor.fetchall()]


def set_snmp_status(device_id: int, status: str) -> Optional[str]:
    """Stores whether the SNMP agent answered the last poll. Returns the previous value."""
    with get_connection() as conn:
        row = conn.execute("SELECT snmp_status FROM devices WHERE id = ?;", (device_id,)).fetchone()
        conn.execute("UPDATE devices SET snmp_status = ? WHERE id = ?;", (status, device_id))
        conn.commit()
        return row["snmp_status"] if row else None


# --- Problem State ---

def list_active_problems() -> List[Dict[str, Any]]:
    """Returns open problems with device names, most severe and oldest first."""
    with get_connection() as conn:
        cursor = conn.execute(
            """
            SELECT p.device_id, d.hostname, p.problem_key, p.severity, p.message, p.since, p.last_seen,
                   p.acknowledged_at, p.ack_note, p.raised_at, p.last_notified
            FROM problems_active p JOIN devices d ON d.id = p.device_id
            WHERE p.raised_at IS NOT NULL
            ORDER BY p.acknowledged_at IS NOT NULL,
                     CASE p.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'warning' THEN 2 ELSE 3 END, p.since ASC;
            """
        )
        return [dict(row) for row in cursor.fetchall()]


def sync_problems(current: List[Dict[str, Any]], resolve_after: Callable[[str], int],
                  now: Optional[int] = None) -> Dict[str, list]:
    """Reconciles evaluated problems with the stored open set.

    New problems are inserted, present ones refresh last_seen and message,
    and problems absent for at least resolve_after(problem_key) seconds are closed.
    A problem with "for_s" stays pending (raised_at NULL, not listed) until the
    condition has held that long; a pending condition that clears is dropped
    without an event. Returns {"opened": [...], "resolved": [...]} for event logging.
    """
    now = now if now is not None else int(time.time())
    opened, resolved = [], []
    with get_connection() as conn:
        stored = {(r["device_id"], r["problem_key"]): dict(r) for r in conn.execute("SELECT * FROM problems_active;")}
        seen = set()
        for p in current:
            key = (p["device_id"], p["key"])
            seen.add(key)
            wait = p.get("for_s", 0)
            if key in stored:
                raised = stored[key]["raised_at"]
                if raised is None and now - stored[key]["since"] >= wait:
                    raised = now
                    opened.append(p)
                conn.execute(
                    "UPDATE problems_active SET last_seen = ?, message = ?, severity = ?, raised_at = ? WHERE device_id = ? AND problem_key = ?;",
                    (now, p["message"], p["severity"], raised, *key)
                )
            else:
                raised = now if wait <= 0 else None
                conn.execute(
                    "INSERT INTO problems_active (device_id, problem_key, severity, message, since, last_seen, raised_at) VALUES (?, ?, ?, ?, ?, ?, ?);",
                    (*key, p["severity"], p["message"], now, now, raised)
                )
                if raised:
                    opened.append(p)
        for key, row in stored.items():
            if key in seen:
                continue
            if row["raised_at"] is None:
                conn.execute("DELETE FROM problems_active WHERE device_id = ? AND problem_key = ?;", key)
            elif now - row["last_seen"] >= resolve_after(row["problem_key"]):
                conn.execute("DELETE FROM problems_active WHERE device_id = ? AND problem_key = ?;", key)
                resolved.append(row)
        conn.commit()
    return {"opened": opened, "resolved": resolved}


def mark_problem_notified(device_id: int, problem_key: str, when: Optional[int] = None) -> None:
    """Records a reminder sent for an open problem."""
    with get_connection() as conn:
        conn.execute("UPDATE problems_active SET last_notified = ? WHERE device_id = ? AND problem_key = ?;",
                     (when if when is not None else int(time.time()), device_id, problem_key))
        conn.commit()


# --- Alert Rule Overrides ---

def list_alert_overrides() -> List[Dict[str, Any]]:
    with get_connection() as conn:
        return [dict(r) for r in conn.execute("SELECT scope, target, rule_id, field, value FROM alert_overrides;")]


def set_alert_overrides(scope: str, target: str, changes: List[Tuple[str, str, Optional[str]]]) -> None:
    """Applies (rule_id, field, value) changes at one scope in one transaction; value None removes the override."""
    now = int(time.time())
    with get_connection() as conn:
        for rule_id, field, value in changes:
            if value is None:
                conn.execute("DELETE FROM alert_overrides WHERE scope = ? AND target = ? AND rule_id = ? AND field = ?;",
                             (scope, target, rule_id, field))
            else:
                conn.execute(
                    """
                    INSERT INTO alert_overrides (scope, target, rule_id, field, value, updated_at) VALUES (?, ?, ?, ?, ?, ?)
                    ON CONFLICT (scope, target, rule_id, field) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at;
                    """,
                    (scope, target, rule_id, field, value, now)
                )
        conn.commit()


def acknowledge_problem(device_id: int, problem_key: str, acknowledged: bool, note: str = "") -> Optional[Dict[str, Any]]:
    """Sets or clears the acknowledgement on an open problem. Returns the row, or None if not open."""
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM problems_active WHERE device_id = ? AND problem_key = ? AND raised_at IS NOT NULL;", (device_id, problem_key)
        ).fetchone()
        if not row:
            return None
        conn.execute(
            "UPDATE problems_active SET acknowledged_at = ?, ack_note = ? WHERE device_id = ? AND problem_key = ?;",
            (int(time.time()) if acknowledged else None, note if acknowledged else None, device_id, problem_key)
        )
        conn.commit()
        return dict(row)


# --- Dashboards ---

def get_dashboard(name: str = "default") -> Optional[Any]:
    with get_connection() as conn:
        row = conn.execute("SELECT layout FROM dashboards WHERE name = ?;", (name,)).fetchone()
        return json.loads(row["layout"]) if row else None


def list_dashboards() -> List[Dict[str, Any]]:
    """Every saved dashboard: name, title (from its layout) and when it was last saved, oldest first."""
    with get_connection() as conn:
        rows = conn.execute("SELECT name, layout, updated_at FROM dashboards ORDER BY id;").fetchall()
    out = []
    for r in rows:
        try:
            layout = json.loads(r["layout"])
        except ValueError:
            layout = {}
        title = layout.get("title") if isinstance(layout, dict) else None
        out.append({"name": r["name"], "title": title or ("Overview" if r["name"] == "default" else r["name"]),
                    "updated_at": r["updated_at"]})
    return out


def delete_dashboard(name: str) -> bool:
    with get_connection() as conn:
        cur = conn.execute("DELETE FROM dashboards WHERE name = ?;", (name,))
        conn.commit()
        return cur.rowcount > 0


def save_dashboard(layout: Dict[str, Any], name: str = "default") -> None:
    with get_connection() as conn:
        conn.execute(
            """
            INSERT INTO dashboards (name, layout, updated_at) VALUES (?, ?, ?)
            ON CONFLICT (name) DO UPDATE SET layout = excluded.layout, updated_at = excluded.updated_at;
            """,
            (name, json.dumps(layout), int(time.time()))
        )
        conn.commit()


# --- Storage Statistics ---

def storage_stats() -> Dict[str, Any]:
    """Database file sizes, row counts and write rate for the settings page."""
    now = int(time.time())
    files = {}
    for suffix in ("", "-wal", "-shm"):
        try:
            files[suffix or "db"] = os.path.getsize(DB_FILE + suffix)
        except OSError:
            files[suffix or "db"] = 0
    with get_connection() as conn:
        counts = {t: conn.execute(f"SELECT COUNT(*) FROM {t};").fetchone()[0]
                  for t in ("metrics", "metrics_hourly", "events", "audit_log", "device_tables")}
        last_day = conn.execute("SELECT COUNT(*) FROM metrics WHERE timestamp >= ?;", (now - 86400,)).fetchone()[0]
        oldest = conn.execute("SELECT MIN(timestamp) FROM metrics;").fetchone()[0]
        oldest_trend = conn.execute("SELECT MIN(hour) FROM metrics_hourly;").fetchone()[0]
        page_size = conn.execute("PRAGMA page_size;").fetchone()[0]
        free_pages = conn.execute("PRAGMA freelist_count;").fetchone()[0]
    observed = max(1, min(86400, now - oldest)) if oldest else 86400
    return {
        "path": DB_FILE,
        "files": files,
        "total_bytes": sum(files.values()),
        "free_bytes": page_size * free_pages,
        "rows": counts,
        "metric_rows_per_day": int(last_day * 86400 / observed),
        "oldest_raw": oldest,
        "oldest_trend": oldest_trend,
    }


# The audit log always keeps at least this many days, so a change cannot be hidden by shortening it.
AUDIT_RETENTION_FLOOR = 90

# Who is acting on this thread: the web request's user and address, Telegram, or nobody ("system").
# Per thread on purpose: a thread a request starts must not inherit the request's identity.
_AUDIT = threading.local()


def set_audit_context(actor: str, source: str = "") -> None:
    _AUDIT.actor = actor
    _AUDIT.source = source


def clear_audit_context() -> None:
    _AUDIT.__dict__.clear()


@contextlib.contextmanager
def audit_context(actor: str, source: str = "") -> Iterator[None]:
    before = dict(_AUDIT.__dict__)
    set_audit_context(actor, source)
    try:
        yield
    finally:
        _AUDIT.__dict__.clear()
        _AUDIT.__dict__.update(before)


def audit_identity() -> Tuple[str, str]:
    """(actor, source) of the current thread; ("system", "") outside any request."""
    return getattr(_AUDIT, "actor", "system"), getattr(_AUDIT, "source", "")


def _audit_row(conn, category: str, message: str, details: str = "", actor: Optional[str] = None,
               now: Optional[int] = None) -> None:
    who, source = audit_identity()
    conn.execute("INSERT INTO audit_log (timestamp, category, message, details, actor, source) VALUES (?, ?, ?, ?, ?, ?);",
                 (int(time.time()) if now is None else now, category, message, details,
                  (who if actor is None else actor)[:64], source[:64]))


def add_audit(category: str, message: str, details: str = "", actor: Optional[str] = None) -> None:
    """Records an action in the audit log, with who did it and from where (the thread's context;
    actor= names someone explicitly, for routes that run before there is a session)."""
    with get_connection() as conn:
        _audit_row(conn, category, message, details, actor)
        conn.commit()



# --- SSH tasks (retired: read once at startup to convert each into a workflow) ---

TASK_COLUMNS = "id, name, command, credential_id, device_ids, trigger_type, trigger_cron, expected_exit_code, " \
               "timeout_s, ssh_port, is_active, last_run, last_scheduled, created_at"


def _decode_task(row: sqlite3.Row) -> Dict[str, Any]:
    task = dict(row)
    task["device_ids"] = json.loads(task.get("device_ids") or "[]")
    return task


def list_tasks() -> List[Dict[str, Any]]:
    with get_connection() as conn:
        return [_decode_task(r) for r in conn.execute(f"SELECT {TASK_COLUMNS} FROM automations ORDER BY name;")]


def retire_task(task_id: int) -> None:
    """Removes a task after it became a workflow (its run history goes with it)."""
    with get_connection() as conn:
        conn.execute("DELETE FROM task_runs WHERE task_id = ?;", (task_id,))
        conn.execute("DELETE FROM automations WHERE id = ?;", (task_id,))
        conn.commit()


def latest_workflow_failures() -> List[Dict[str, Any]]:
    """Each workflow whose most recent finished run failed: [{workflow_id, name, status, failed: [{host_id, title}]}].

    A failed step is reported on the host it ran against (host_id in the run log).
    """
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT r.workflow_id, w.name, r.status, r.log FROM workflow_runs r JOIN workflows w ON w.id = r.workflow_id
            JOIN (SELECT workflow_id, MAX(id) AS max_id FROM workflow_runs
                  WHERE status NOT IN ('running', 'cancelled') GROUP BY workflow_id) latest ON latest.max_id = r.id
            WHERE r.status IN ('failed', 'partial', 'error');
            """).fetchall()
    out = []
    for r in rows:
        try:
            log = json.loads(r["log"] or "[]")
        except ValueError:
            log = []
        failed = [{"host_id": e.get("host_id"), "title": e.get("title", "")} for e in log
                  if e.get("status") in ("failed", "error")]
        out.append({"workflow_id": r["workflow_id"], "name": r["name"], "status": r["status"], "failed": failed})
    return out


def get_host_keys(device_id: int) -> List[Dict[str, Any]]:
    with get_connection() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT key_type, key_b64, fingerprint, approved_at FROM ssh_host_keys WHERE device_id = ?;", (device_id,))]


def approve_host_key(device_id: int, key_type: str, key_b64: str, fp: str) -> None:
    with get_connection() as conn:
        conn.execute(
            "INSERT OR REPLACE INTO ssh_host_keys (device_id, key_type, key_b64, fingerprint, approved_at) VALUES (?, ?, ?, ?, ?);",
            (device_id, key_type, key_b64, fp, int(time.time())))
        conn.commit()


def forget_host_keys(device_id: int) -> int:
    with get_connection() as conn:
        n = conn.execute("DELETE FROM ssh_host_keys WHERE device_id = ?;", (device_id,)).rowcount
        conn.commit()
        return n


# --- Watched services and processes ---

WATCH_KINDS = ("process", "service")


def list_watches(device_id: Optional[int] = None) -> List[Dict[str, Any]]:
    """Watched process or service names, for one device or all."""
    with get_connection() as conn:
        if device_id is None:
            rows = conn.execute("SELECT device_id, kind, name, created_at FROM watches ORDER BY device_id, kind, name;")
        else:
            rows = conn.execute("SELECT device_id, kind, name, created_at FROM watches WHERE device_id = ? ORDER BY kind, name;",
                                (device_id,))
        return [dict(r) for r in rows]


def set_watch(device_id: int, kind: str, name: str, watched: bool) -> bool:
    """Adds or removes a watch. Returns True when something changed."""
    with get_connection() as conn:
        if watched:
            n = conn.execute("INSERT OR IGNORE INTO watches (device_id, kind, name, created_at) VALUES (?, ?, ?, ?);",
                             (device_id, kind, name, int(time.time()))).rowcount
        else:
            n = conn.execute("DELETE FROM watches WHERE device_id = ? AND kind = ? AND name = ?;",
                             (device_id, kind, name)).rowcount
        conn.commit()
        return n > 0


# --- Web UI account ---

def get_account(username: Optional[str] = None) -> Optional[Dict[str, Any]]:
    """The named account, or the first one when no name is given."""
    with get_connection() as conn:
        if username is None:
            row = conn.execute("SELECT username, password_hash, created_at, updated_at FROM accounts ORDER BY created_at LIMIT 1;").fetchone()
        else:
            row = conn.execute("SELECT username, password_hash, created_at, updated_at FROM accounts WHERE username = ?;",
                               (username,)).fetchone()
        return dict(row) if row else None


def create_account(username: str, password_hash: str) -> bool:
    """Creates the account only while none exists. Returns False if one already does."""
    now = int(time.time())
    with get_connection() as conn:
        conn.execute("BEGIN IMMEDIATE;")
        if conn.execute("SELECT COUNT(*) FROM accounts;").fetchone()[0]:
            conn.rollback()
            return False
        conn.execute("INSERT INTO accounts (username, password_hash, created_at, updated_at) VALUES (?, ?, ?, ?);",
                     (username, password_hash, now, now))
        conn.commit()
        return True


def set_account_password(username: str, password_hash: str) -> None:
    with get_connection() as conn:
        conn.execute("UPDATE accounts SET password_hash = ?, updated_at = ? WHERE username = ?;",
                     (password_hash, int(time.time()), username))
        conn.commit()


ACCOUNT_FIELDS = ("role", "permissions", "device_scope", "disabled", "display_name", "last_login", "notify_read_at",
                  "totp_enabled")


def get_user(username: str) -> Optional[Dict[str, Any]]:
    """The account with its role fields (password hash included: callers must not send it out)."""
    with get_connection() as conn:
        row = conn.execute(f"SELECT username, password_hash, created_at, updated_at, {', '.join(ACCOUNT_FIELDS)} "
                           "FROM accounts WHERE username = ?;", (username,)).fetchone()
        return dict(row) if row else None


def list_users() -> List[Dict[str, Any]]:
    with get_connection() as conn:
        return [dict(r) for r in conn.execute(
            f"SELECT username, created_at, updated_at, {', '.join(ACCOUNT_FIELDS)} FROM accounts ORDER BY username COLLATE NOCASE;")]


def create_user(username: str, password_hash: str, role: str, permissions: Optional[str],
                device_scope: Optional[str], display_name: Optional[str]) -> bool:
    """Adds a user. Returns False when the name is taken."""
    now = int(time.time())
    with get_connection() as conn:
        try:
            conn.execute("INSERT INTO accounts (username, password_hash, created_at, updated_at, role, permissions, "
                         "device_scope, display_name) VALUES (?, ?, ?, ?, ?, ?, ?, ?);",
                         (username, password_hash, now, now, role, permissions, device_scope, display_name))
        except sqlite3.IntegrityError:
            return False
        conn.commit()
        return True


def update_user(username: str, fields: Dict[str, Any]) -> bool:
    """Updates the given account fields. Keys must come from ACCOUNT_FIELDS (column names are not user input)."""
    cols = [k for k in fields if k in ACCOUNT_FIELDS]
    if not cols:
        return False
    with get_connection() as conn:
        n = conn.execute(f"UPDATE accounts SET {', '.join(c + ' = ?' for c in cols)}, updated_at = ? WHERE username = ?;",
                         [fields[c] for c in cols] + [int(time.time()), username]).rowcount
        conn.commit()
        return n > 0


TOTP_CONTEXT = "account:totp"


def get_totp(username: str) -> Dict[str, Any]:
    """2FA state of one account: enabled, secret (decrypted, or None), recovery hashes, last used step."""
    with get_connection() as conn:
        row = conn.execute("SELECT totp_secret, totp_enabled, totp_recovery, totp_last_step FROM accounts WHERE username = ?;",
                           (username,)).fetchone()
    if not row:
        return {"enabled": False, "secret": None, "recovery": [], "last_step": None}
    try:
        recovery = json.loads(row["totp_recovery"] or "[]")
    except ValueError:
        recovery = []
    return {"enabled": bool(row["totp_enabled"]),
            "secret": VAULT.decrypt(row["totp_secret"], TOTP_CONTEXT) if row["totp_secret"] else None,
            "recovery": recovery, "last_step": row["totp_last_step"]}


def set_totp(username: str, secret: Optional[str], enabled: bool, recovery: Optional[List[str]] = None,
             last_step: Optional[int] = None) -> None:
    """Stores the 2FA state. secret None clears it (2FA off)."""
    with get_connection() as conn:
        conn.execute("UPDATE accounts SET totp_secret = ?, totp_enabled = ?, totp_recovery = ?, totp_last_step = ?, "
                     "updated_at = ? WHERE username = ?;",
                     (VAULT.encrypt(secret, TOTP_CONTEXT) if secret else None, 1 if enabled else 0,
                      json.dumps(recovery or []), last_step, int(time.time()), username))
        conn.commit()


def set_totp_progress(username: str, last_step: Optional[int] = None, recovery: Optional[List[str]] = None) -> None:
    """After a successful code: remember its step (no replay) or drop a used recovery code."""
    with get_connection() as conn:
        if last_step is not None:
            conn.execute("UPDATE accounts SET totp_last_step = ? WHERE username = ?;", (last_step, username))
        if recovery is not None:
            conn.execute("UPDATE accounts SET totp_recovery = ? WHERE username = ?;", (json.dumps(recovery), username))
        conn.commit()


def consume_totp_step(username: str, step: int) -> bool:
    """Marks an authenticator step used. False when it (or a later one) was used already, also by a
    parallel request: the check and the write are one statement."""
    with get_connection() as conn:
        n = conn.execute("UPDATE accounts SET totp_last_step = ? WHERE username = ? "
                         "AND (totp_last_step IS NULL OR totp_last_step < ?);", (step, username, step)).rowcount
        conn.commit()
        return n == 1


def consume_recovery_code(username: str, code_hash: str) -> Optional[int]:
    """Removes one recovery code hash. Returns how many are left, or None when it was gone already
    (spent by a parallel request): the write only applies to the list it was read from."""
    with get_connection() as conn:
        row = conn.execute("SELECT totp_recovery FROM accounts WHERE username = ?;", (username,)).fetchone()
        if not row:
            return None
        try:
            codes = json.loads(row["totp_recovery"] or "[]")
        except ValueError:
            return None
        if code_hash not in codes:
            return None
        codes.remove(code_hash)
        n = conn.execute("UPDATE accounts SET totp_recovery = ? WHERE username = ? AND totp_recovery = ?;",
                         (json.dumps(codes), username, row["totp_recovery"])).rowcount
        conn.commit()
        return len(codes) if n == 1 else None


def any_totp_user() -> bool:
    with get_connection() as conn:
        return bool(conn.execute("SELECT 1 FROM accounts WHERE totp_enabled = 1 AND disabled = 0 LIMIT 1;").fetchone())


def delete_user(username: str) -> bool:
    with get_connection() as conn:
        n = conn.execute("DELETE FROM accounts WHERE username = ?;", (username,)).rowcount
        conn.commit()
        return n > 0


def device_profiles() -> List[Dict[str, Any]]:
    """Id and template of every device: enough to resolve a user's device access cheaply."""
    with get_connection() as conn:
        return [dict(r) for r in conn.execute("SELECT id, profile_id FROM devices;")]


# Events the notification centre shows: problems and their resolution, reachability, workflow
# results, actions that could not be done, updates of the monitor. Routine info (config changes, software) stays in the log.
NOTIFY_EVENT_TYPES = ("problem", "action", "workflow", "task", "reboot", "update")


def list_events_filtered(q: str = "", device_id: Optional[int] = None, severity: str = "", event_type: str = "",
                         since: Optional[int] = None, until: Optional[int] = None, allowed_ids: Optional[set] = None,
                         actor: Optional[str] = None, offset: int = 0, limit: int = 50,
                         device_ids: Optional[set] = None) -> Tuple[List[Dict[str, Any]], int]:
    """Event log page and total match count. allowed_ids limits device events to a user's device access
    (system events then show only when actor matches); device_ids keeps only those devices' events
    (the tag filter)."""
    where, args = [], []
    if device_ids is not None:
        ids = sorted(device_ids)
        where.append(f"e.device_id IN ({','.join('?' * len(ids)) or 'NULL'})")
        args += ids
    if q:
        where.append("(e.message LIKE ? ESCAPE '\\' OR d.hostname LIKE ? ESCAPE '\\')")
        like = "%" + q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%"
        args += [like, like]
    if device_id is not None:
        where.append("e.device_id = ?")
        args.append(device_id)
    if severity:
        where.append("e.severity = ?")
        args.append(severity)
    if event_type:
        where.append("e.event_type = ?")
        args.append(event_type)
    if since is not None:
        where.append("e.timestamp >= ?")
        args.append(since)
    if until is not None:
        where.append("e.timestamp < ?")
        args.append(until)
    if allowed_ids is not None:
        ids = sorted(allowed_ids)
        marks = ",".join("?" * len(ids)) or "NULL"
        where.append(f"(e.device_id IN ({marks}) OR (e.device_id IS NULL AND e.actor = ?))")
        args += ids + [actor]
    clause = ("WHERE " + " AND ".join(where)) if where else ""
    base = f"FROM events e LEFT JOIN devices d ON d.id = e.device_id {clause}"
    with get_connection() as conn:
        total = conn.execute(f"SELECT COUNT(*) {base};", args).fetchone()[0]
        rows = conn.execute(f"SELECT e.id, e.device_id, d.hostname, e.timestamp, e.severity, e.event_type, e.message, e.actor "
                            f"{base} ORDER BY e.timestamp DESC, e.id DESC LIMIT ? OFFSET ?;", args + [limit, offset])
        return [dict(r) for r in rows], total


def event_types() -> List[str]:
    with get_connection() as conn:
        return [r[0] for r in conn.execute("SELECT DISTINCT event_type FROM events ORDER BY event_type;")]


def list_notifications(allowed_ids: Optional[set], actor: str, limit: int = 30) -> List[Dict[str, Any]]:
    """Recent notification-worthy events, newest first."""
    marks = ",".join("?" * len(NOTIFY_EVENT_TYPES))
    where = [f"(e.event_type IN ({marks}) OR e.severity IN ('warning', 'high', 'critical'))"]
    args: List[Any] = list(NOTIFY_EVENT_TYPES)
    if allowed_ids is not None:
        ids = sorted(allowed_ids)
        where.append(f"(e.device_id IN ({','.join('?' * len(ids)) or 'NULL'}) OR (e.device_id IS NULL AND e.actor = ?))")
        args += ids + [actor]
    else:
        # System events (actions that could not be done) belong to whoever tried them.
        where.append("(e.device_id IS NOT NULL OR e.actor = ? OR e.actor IS NULL)")
        args.append(actor)
    with get_connection() as conn:
        rows = conn.execute(f"SELECT e.id, e.device_id, d.hostname, e.timestamp, e.severity, e.event_type, e.message, e.actor "
                            f"FROM events e LEFT JOIN devices d ON d.id = e.device_id WHERE {' AND '.join(where)} "
                            "ORDER BY e.timestamp DESC, e.id DESC LIMIT ?;", args + [limit])
        return [dict(r) for r in rows]


# --- Network map ---

MAP_OBJECT_KINDS = ("switch", "router", "modem", "ap", "server", "other")


def list_map_objects() -> List[Dict[str, Any]]:
    with get_connection() as conn:
        return [dict(r) for r in conn.execute("SELECT id, label, kind, created_at FROM map_objects ORDER BY id;")]


def add_map_object(label: str, kind: str) -> int:
    with get_connection() as conn:
        cur = conn.execute("INSERT INTO map_objects (label, kind, created_at) VALUES (?, ?, ?);", (label, kind, int(time.time())))
        conn.commit()
        return cur.lastrowid


def delete_map_object(object_id: int) -> bool:
    key = f"o:{object_id}"
    with get_connection() as conn:
        n = conn.execute("DELETE FROM map_objects WHERE id = ?;", (object_id,)).rowcount
        conn.execute("DELETE FROM map_links WHERE node_a = ? OR node_b = ?;", (key, key))
        conn.execute("DELETE FROM map_positions WHERE node = ?;", (key,))
        conn.commit()
        return n > 0


def list_map_links() -> List[Dict[str, Any]]:
    with get_connection() as conn:
        return [dict(r) for r in conn.execute("SELECT id, node_a, node_b, hidden FROM map_links ORDER BY id;")]


def set_map_link(node_a: str, node_b: str, hidden: bool) -> None:
    """Adds a manual link, or hides an inferred one. The pair is stored in sorted order."""
    a, b = sorted((node_a, node_b))
    with get_connection() as conn:
        conn.execute("INSERT INTO map_links (node_a, node_b, hidden, created_at) VALUES (?, ?, ?, ?) "
                     "ON CONFLICT (node_a, node_b) DO UPDATE SET hidden = excluded.hidden;",
                     (a, b, 1 if hidden else 0, int(time.time())))
        conn.commit()


def delete_map_link(node_a: str, node_b: str) -> bool:
    a, b = sorted((node_a, node_b))
    with get_connection() as conn:
        n = conn.execute("DELETE FROM map_links WHERE node_a = ? AND node_b = ?;", (a, b)).rowcount
        conn.commit()
        return n > 0


def get_map_positions() -> Dict[str, List[float]]:
    with get_connection() as conn:
        return {r["node"]: [r["x"], r["y"]] for r in conn.execute("SELECT node, x, y FROM map_positions;")}


def save_map_positions(positions: Dict[str, List[float]], replace: bool = False) -> None:
    with get_connection() as conn:
        if replace:
            conn.execute("DELETE FROM map_positions;")
        conn.executemany("INSERT OR REPLACE INTO map_positions (node, x, y) VALUES (?, ?, ?);",
                         [(k, float(v[0]), float(v[1])) for k, v in positions.items()])
        conn.commit()


# --- Workflows ---

WORKFLOW_RUNS_KEPT = 50


def _workflow_row(r: sqlite3.Row) -> Dict[str, Any]:
    """graph and schedule are None for workflows saved before the graph editor; the server fills them in."""
    d = dict(r)
    d["steps"] = json.loads(d["steps"])
    d["graph"] = json.loads(d["graph"]) if d.get("graph") else None
    d["schedule"] = json.loads(d["schedule"]) if d.get("schedule") else None
    d["is_active"] = bool(d["is_active"])
    return d


def list_workflows() -> List[Dict[str, Any]]:
    with get_connection() as conn:
        rows = conn.execute(
            """
            SELECT w.*, (SELECT status FROM workflow_runs r WHERE r.workflow_id = w.id ORDER BY started_at DESC, id DESC LIMIT 1) AS last_status,
                   (SELECT started_at FROM workflow_runs r WHERE r.workflow_id = w.id ORDER BY started_at DESC, id DESC LIMIT 1) AS last_run
            FROM workflows w ORDER BY w.name COLLATE NOCASE;
            """
        ).fetchall()
        return [_workflow_row(r) for r in rows]


def get_workflow(workflow_id: int) -> Optional[Dict[str, Any]]:
    with get_connection() as conn:
        r = conn.execute("SELECT * FROM workflows WHERE id = ?;", (workflow_id,)).fetchone()
        return _workflow_row(r) if r else None


def save_workflow(workflow_id: Optional[int], fields: Dict[str, Any]) -> int:
    now = int(time.time())
    graph = fields.get("graph")
    sched = fields.get("schedule")
    values = (fields["name"], fields["description"], json.dumps(fields["steps"]), fields["trigger_type"],
              fields["trigger_cron"], 1 if fields["is_active"] else 0,
              json.dumps(graph) if graph else None, json.dumps(sched) if sched else None, fields.get("run_at"),
              fields.get("saved_by"))
    with get_connection() as conn:
        if workflow_id is None:
            cur = conn.execute(
                "INSERT INTO workflows (name, description, steps, trigger_type, trigger_cron, is_active, graph, schedule, "
                "run_at, saved_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);", values + (now, now))
            workflow_id = cur.lastrowid
        else:
            conn.execute(
                "UPDATE workflows SET name = ?, description = ?, steps = ?, trigger_type = ?, trigger_cron = ?, is_active = ?, "
                "graph = ?, schedule = ?, run_at = ?, saved_by = ?, updated_at = ? WHERE id = ?;", values + (now, workflow_id))
        conn.commit()
        return workflow_id


def finish_once_workflow(workflow_id: int, graph: Dict[str, Any], sched: Dict[str, Any]) -> None:
    """A one-off schedule has fired (or was missed): the workflow becomes manual, the schedule is kept as done."""
    with get_connection() as conn:
        conn.execute("UPDATE workflows SET trigger_type = 'manual', run_at = NULL, graph = ?, schedule = ? WHERE id = ?;",
                     (json.dumps(graph), json.dumps(sched), workflow_id))
        conn.commit()


def delete_workflow(workflow_id: int) -> bool:
    with get_connection() as conn:
        n = conn.execute("DELETE FROM workflows WHERE id = ?;", (workflow_id,)).rowcount
        conn.commit()
        return n > 0


def mark_workflow_scheduled(workflow_id: int, minute: int) -> None:
    with get_connection() as conn:
        conn.execute("UPDATE workflows SET last_scheduled = ? WHERE id = ?;", (minute, workflow_id))
        conn.commit()


def start_workflow_run(workflow_id: int, trigger: str) -> int:
    with get_connection() as conn:
        cur = conn.execute("INSERT INTO workflow_runs (workflow_id, trigger, status, started_at) VALUES (?, ?, 'running', ?);",
                           (workflow_id, trigger, int(time.time())))
        # Keep the newest runs per workflow.
        conn.execute(
            "DELETE FROM workflow_runs WHERE workflow_id = ? AND id NOT IN "
            "(SELECT id FROM workflow_runs WHERE workflow_id = ? ORDER BY started_at DESC, id DESC LIMIT ?);",
            (workflow_id, workflow_id, WORKFLOW_RUNS_KEPT))
        conn.commit()
        return cur.lastrowid


def update_workflow_run(run_id: int, status: str, log_json: str, finished_at: Optional[float]) -> None:
    with get_connection() as conn:
        conn.execute("UPDATE workflow_runs SET status = ?, log = ?, finished_at = COALESCE(?, finished_at) WHERE id = ?;",
                     (status, log_json, int(finished_at) if finished_at else None, run_id))
        conn.commit()


def list_workflow_runs(workflow_id: Optional[int] = None, limit: int = 30) -> List[Dict[str, Any]]:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT r.id, r.workflow_id, w.name, r.trigger, r.status, r.started_at, r.finished_at FROM workflow_runs r "
            "JOIN workflows w ON w.id = r.workflow_id WHERE (? IS NULL OR r.workflow_id = ?) "
            "ORDER BY r.started_at DESC, r.id DESC LIMIT ?;", (workflow_id, workflow_id, limit)).fetchall()
        return [dict(r) for r in rows]


def get_workflow_run(run_id: int) -> Optional[Dict[str, Any]]:
    with get_connection() as conn:
        r = conn.execute("SELECT r.*, w.name FROM workflow_runs r JOIN workflows w ON w.id = r.workflow_id WHERE r.id = ?;",
                         (run_id,)).fetchone()
        if not r:
            return None
        d = dict(r)
        d["log"] = json.loads(d["log"])
        return d


# --- Host action runs ---

ACTION_RUNS_KEPT = 300


def start_action_run(device_id: int, action_id: str, name: str, choice: str, username: str, problem_key: str) -> int:
    with get_connection() as conn:
        cur = conn.execute(
            "INSERT INTO action_runs (device_id, action_id, name, choice, username, problem_key, status, started_at) "
            "VALUES (?, ?, ?, ?, ?, ?, 'running', ?);",
            (device_id, action_id, name, choice or "", username or "", problem_key or "", int(time.time())))
        conn.execute("DELETE FROM action_runs WHERE id NOT IN (SELECT id FROM action_runs ORDER BY id DESC LIMIT ?);",
                     (ACTION_RUNS_KEPT,))
        conn.commit()
        return cur.lastrowid


def update_action_run(run_id: int, status: str, output: str, exit_code: Optional[int] = None, finished: bool = False) -> None:
    with get_connection() as conn:
        conn.execute("UPDATE action_runs SET status = ?, output = ?, exit_code = ?, "
                     "finished_at = CASE WHEN ? THEN ? ELSE finished_at END WHERE id = ?;",
                     (status, output, exit_code, 1 if finished else 0, int(time.time()), run_id))
        conn.commit()


def list_action_runs(device_id: Optional[int] = None, limit: int = 50) -> List[Dict[str, Any]]:
    with get_connection() as conn:
        rows = conn.execute(
            "SELECT r.id, r.device_id, d.hostname, r.action_id, r.name, r.choice, r.username, r.problem_key, r.status, "
            "r.exit_code, r.started_at, r.finished_at FROM action_runs r JOIN devices d ON d.id = r.device_id "
            "WHERE (? IS NULL OR r.device_id = ?) ORDER BY r.started_at DESC, r.id DESC LIMIT ?;",
            (device_id, device_id, limit)).fetchall()
        return [dict(r) for r in rows]


def get_action_run(run_id: int) -> Optional[Dict[str, Any]]:
    with get_connection() as conn:
        r = conn.execute("SELECT r.*, d.hostname FROM action_runs r JOIN devices d ON d.id = r.device_id WHERE r.id = ?;",
                         (run_id,)).fetchone()
        return dict(r) if r else None


# --- Notifications held during quiet hours ---

def hold_notification(text: str) -> None:
    with get_connection() as conn:
        conn.execute("INSERT INTO notify_held (created_at, text) VALUES (?, ?);", (int(time.time()), text))
        # A long outage during quiet hours must not grow this without bound.
        conn.execute("DELETE FROM notify_held WHERE id NOT IN (SELECT id FROM notify_held ORDER BY id DESC LIMIT 200);")
        conn.commit()


def take_held_notifications() -> List[str]:
    with get_connection() as conn:
        rows = conn.execute("SELECT id, created_at, text FROM notify_held ORDER BY id;").fetchall()
        conn.execute("DELETE FROM notify_held;")
        conn.commit()
    return [f"{time.strftime('%H:%M', time.localtime(r['created_at']))} {r['text']}" for r in rows]


def get_plain_setting(key: str, default: str = "") -> str:
    """One setting as stored, without decrypting anything: for values read on every request."""
    with get_connection() as conn:
        row = conn.execute("SELECT value FROM settings WHERE key = ?;", (key,)).fetchone()
    return row["value"] if row else default


def set_internal_setting(key: str, value: str) -> None:
    """Writes a setting that is not part of the Settings page (setup state, site settings)."""
    now = int(time.time())
    with get_connection() as conn:
        conn.execute("INSERT INTO settings (key, value, description, updated_at) VALUES (?, ?, '', ?) "
                     "ON CONFLICT (key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at;", (key, value, now))
        conn.commit()


# --- Reports (reports.py) ---

REPORT_RUNS_KEPT = 10


def list_reports() -> List[Dict[str, Any]]:
    with get_connection() as conn:
        return [dict(r) for r in conn.execute("SELECT * FROM reports ORDER BY name COLLATE NOCASE, id;")]


def get_report(report_id: int) -> Optional[Dict[str, Any]]:
    with get_connection() as conn:
        row = conn.execute("SELECT * FROM reports WHERE id = ?;", (report_id,)).fetchone()
        return dict(row) if row else None


def save_report(report_id: Optional[int], name: str, spec: str, schedule: str, formats: str, telegram: bool,
                owner: str) -> int:
    """Adds a report (report_id None) or changes one; the owner stays who first saved it."""
    now = int(time.time())
    with get_connection() as conn:
        if report_id is None:
            cur = conn.execute("INSERT INTO reports (name, spec, schedule, formats, telegram, owner, created_at, updated_at) "
                               "VALUES (?, ?, ?, ?, ?, ?, ?, ?);", (name, spec, schedule, formats, int(telegram), owner, now, now))
            conn.commit()
            return int(cur.lastrowid)
        conn.execute("UPDATE reports SET name = ?, spec = ?, schedule = ?, formats = ?, telegram = ?, updated_at = ? WHERE id = ?;",
                     (name, spec, schedule, formats, int(telegram), now, report_id))
        conn.commit()
        return report_id


def delete_report(report_id: int) -> bool:
    with get_connection() as conn:
        conn.execute("DELETE FROM report_runs WHERE report_id = ?;", (report_id,))
        gone = conn.execute("DELETE FROM reports WHERE id = ?;", (report_id,)).rowcount > 0
        conn.commit()
        return gone


def mark_report_run(report_id: int, at: int) -> None:
    with get_connection() as conn:
        conn.execute("UPDATE reports SET last_run_at = ? WHERE id = ?;", (at, report_id))
        conn.commit()


def add_report_run(report_id: int, made_at: int, trigger: str, total: int, csv_data: Optional[bytes],
                   pdf_data: Optional[bytes], error: str = "") -> int:
    """Keeps a run and its files; only the newest REPORT_RUNS_KEPT of each report stay."""
    with get_connection() as conn:
        cur = conn.execute("INSERT INTO report_runs (report_id, made_at, trigger, total, csv, pdf, error) VALUES (?, ?, ?, ?, ?, ?, ?);",
                           (report_id, made_at, trigger, total, csv_data, pdf_data, error))
        conn.execute("DELETE FROM report_runs WHERE report_id = ? AND id NOT IN "
                     "(SELECT id FROM report_runs WHERE report_id = ? ORDER BY made_at DESC, id DESC LIMIT ?);",
                     (report_id, report_id, REPORT_RUNS_KEPT))
        conn.commit()
        return int(cur.lastrowid)


def list_report_runs(report_id: int) -> List[Dict[str, Any]]:
    with get_connection() as conn:
        return [dict(r) for r in conn.execute(
            "SELECT id, report_id, made_at, trigger, total, error, csv IS NOT NULL AS has_csv, pdf IS NOT NULL AS has_pdf, "
            "LENGTH(csv) AS csv_size, LENGTH(pdf) AS pdf_size FROM report_runs WHERE report_id = ? ORDER BY made_at DESC, id DESC;",
            (report_id,))]


def get_report_run_file(run_id: int, kind: str) -> Optional[Tuple[int, int, bytes]]:
    """(report_id, made_at, file) of a stored run; kind is csv or pdf."""
    if kind not in ("csv", "pdf"):
        return None
    with get_connection() as conn:
        row = conn.execute(f"SELECT report_id, made_at, {kind} AS data FROM report_runs WHERE id = ?;", (run_id,)).fetchone()
        return (row["report_id"], row["made_at"], bytes(row["data"])) if row and row["data"] is not None else None
