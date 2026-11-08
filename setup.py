"""First-run setup: validates the wizard's answers, describes what applying them does, and applies them.

The wizard can run in preview mode at any time (the Setup tab): the answers
are validated and turned into the same plan the real run would carry out,
and nothing is written. The real run is allowed once, on a fresh install.

Site settings are the answers that describe your environment rather
than the monitor itself: SSH commands, Syncthing, NFS mounts and Telegram.
They are stored as one JSON document (secrets excluded) that every backup
carries, so a restore re-applies them instead of asking again
(tools/sitectl.py does that on the container).
"""

import json
import re
from typing import Any, Dict, List, Optional, Tuple

import database
import sitecheck

SITE_KEY = "site_settings"
COMPLETED_KEY = "setup_completed"

_TOKEN = re.compile(r"\d{5,12}:[A-Za-z0-9_-]{30,64}")
_CHAT = re.compile(r"-?\d{1,20}")


class SetupError(ValueError):
    pass


def _local_path(value: Any, label: str) -> str:
    try:
        return sitecheck.folder(value, label)
    except sitecheck.SiteError as exc:
        raise SetupError(str(exc))


def _nfs(value: Any, label: str) -> str:
    try:
        return sitecheck.nfs_source(value, label)
    except sitecheck.SiteError as exc:
        raise SetupError(str(exc))


def _options(value: Any, label: str) -> str:
    try:
        return sitecheck.mount_options(value, label)
    except sitecheck.SiteError as exc:
        raise SetupError(str(exc))


def parse_site(raw: Any, credential_ids: set) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """Returns (site settings to store, secrets to store separately). Disabled sections keep no values."""
    raw = raw if isinstance(raw, dict) else {}
    site: Dict[str, Any] = {}
    secrets: Dict[str, Any] = {}

    ssh = raw.get("ssh") or {}
    if ssh.get("enabled") is True:
        cred = ssh.get("credential") or {}
        name = str(cred.get("name", "")).strip()
        user = str(cred.get("username", "")).strip()
        kind = cred.get("cred_type", "password")
        secret = cred.get("secret", "")
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 _.@-]{0,63}", name) or not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", user):
            raise SetupError("SSH: give the credential a name and a username")
        if kind not in database.CREDENTIAL_TYPES or not isinstance(secret, str) or not secret or len(secret) > 16384:
            raise SetupError("SSH: enter the password or paste the private key")
        site["ssh"] = {"enabled": True, "credential_name": name, "username": user, "cred_type": kind}
        secrets["credential"] = {"name": name, "username": user, "cred_type": kind, "secret": secret}
    else:
        site["ssh"] = {"enabled": False}

    st = raw.get("syncthing") or {}
    if st.get("enabled") is True:
        site["syncthing"] = {"enabled": True, "keys_source": _nfs(st.get("keys_source"), "Syncthing identity share"),
                             "data_folder": _local_path(st.get("data_folder"), "Syncthing backup folder")}
    else:
        site["syncthing"] = {"enabled": False}

    nfs = raw.get("nfs") or {}
    if nfs.get("enabled") is True:
        mounts = nfs.get("mounts")
        if not isinstance(mounts, list) or not mounts or len(mounts) > 20:
            raise SetupError("NFS: add at least one mount, or switch NFS off")
        clean, targets = [], set()
        for i, m in enumerate(mounts, 1):
            m = m if isinstance(m, dict) else {}
            target = _local_path(m.get("target"), f"NFS mount {i} folder")
            if target in targets:
                raise SetupError(f"NFS mount {i}: {target} is used twice")
            targets.add(target)
            clean.append({"source": _nfs(m.get("source"), f"NFS mount {i} export"), "target": target,
                          "options": _options(m.get("options"), f"NFS mount {i}")})
        site["nfs"] = {"enabled": True, "mounts": clean}
    else:
        site["nfs"] = {"enabled": False}

    tg = raw.get("telegram") or {}
    if tg.get("enabled") is True:
        token, chat = str(tg.get("token", "")).strip(), str(tg.get("chat_id", "")).strip()
        if not _TOKEN.fullmatch(token):
            raise SetupError("Telegram: paste the bot token from @BotFather")
        if not _CHAT.fullmatch(chat):
            raise SetupError("Telegram: press Find my chat after messaging your bot")
        site["telegram"] = {"enabled": True}
        secrets["telegram"] = {"token": token, "chat_id": chat}
    else:
        site["telegram"] = {"enabled": False}
    return site, secrets


def plan_lines(settings: Dict[str, str], site: Dict[str, Any], devices: List[Dict[str, Any]], labels: Dict[str, str]) -> List[str]:
    """What applying does, in the order it happens. Secrets are never echoed."""
    out = [f"Save setting {labels.get(k, k)}: {'(hidden)' if k == 'default_snmp_community' else v}" for k, v in settings.items()]
    if site["ssh"]["enabled"]:
        out.append(f"Store SSH credential {site['ssh']['credential_name']} for user {site['ssh']['username']} (encrypted)")
    if site["syncthing"]["enabled"]:
        out.append(f"Container: restore the Syncthing identity from {site['syncthing']['keys_source']} and back up to {site['syncthing']['data_folder']}")
    for m in site["nfs"].get("mounts", []):
        out.append(f"Container: mount {m['source']} on {m['target']} ({m['options']}), kept in /etc/fstab")
    if site["telegram"]["enabled"]:
        out.append("Switch Telegram notifications on (token stored encrypted)")
    for d in devices:
        if d.get("service_port"):
            out.append(f"Add port check {d['hostname']} ({d['ip_address']}:{d['service_port']})")
        elif d["profile_id"] == "ping_only":
            out.append(f"Add device {d['hostname']} ({d['ip_address']}), ping only")
        else:
            out.append(f"Add device {d['hostname']} ({d['ip_address']}) with template {d['profile_id']}")
    out.append("Mark setup as complete: the Setup page stops opening on start")
    return out


def get_site() -> Dict[str, Any]:
    raw = database.get_all_settings().get(SITE_KEY)
    try:
        return json.loads(raw) if raw else {}
    except ValueError:
        return {}


def is_completed() -> bool:
    return database.get_all_settings().get(COMPLETED_KEY) == "1"


def save_site(site: Dict[str, Any]) -> None:
    database.set_internal_setting(SITE_KEY, json.dumps(site, sort_keys=True))


def mark_completed() -> None:
    database.set_internal_setting(COMPLETED_KEY, "1")
