"""Checks for the site settings (NFS mounts, Syncthing) before anything acts on them.

The web app checks what the administrator types; root on the container (sitectl.py) checks the same
settings again before it mounts, copies or changes owners, because what it reads comes from the
database or from a backup, and neither can be trusted by root. Standard library only: sitectl.py
imports this on the container with nothing else of the app loaded.

The rules:
  - Folders (mount targets, the Syncthing folder) are absolute, sit below /mnt or /srv, use
    letters, digits, dot, dash and underscore only, and contain no symbolic links on the box.
  - NFS exports are host:/path with no spaces.
  - Mount options come from a fixed list, and nosuid,nodev,noexec are always added.
  - A Syncthing identity's config.xml may only sync folders inside the chosen folder (or
    Syncthing's own home), and its web interface stays on this machine unless it has a login.
"""

import os
import posixpath
import re
import xml.etree.ElementTree as ET
from typing import Any, Dict, List

SAFE_ROOTS = ("/mnt", "/srv")
_FOLDER = re.compile(r"(?:/[A-Za-z0-9._-]+){2,20}")
_NFS = re.compile(r"[A-Za-z0-9.-]{1,253}:/[A-Za-z0-9._/-]{0,200}")
_FLAGS = {"defaults", "ro", "rw", "soft", "hard", "intr", "nointr", "noatime", "nodiratime", "relatime", "_netdev",
          "nofail", "noauto", "auto", "bg", "fg", "nolock", "lock", "ac", "noac", "sync", "async", "nosuid",
          "nodev", "noexec", "x-systemd.automount"}
_KEYS = {"vers", "nfsvers", "timeo", "retrans", "rsize", "wsize", "proto", "sec", "actimeo", "acregmin", "acregmax",
         "acdirmin", "acdirmax", "port", "mountport", "x-systemd.mount-timeout", "x-systemd.idle-timeout", "retry"}
_VALUE = re.compile(r"[A-Za-z0-9.]{1,16}")
HARDENING = ("nosuid", "nodev", "noexec")


class SiteError(ValueError):
    pass


def folder(value: Any, label: str) -> str:
    text = str(value or "").strip().rstrip("/")
    parts = text.split("/")
    if (not _FOLDER.fullmatch(text) or any(p in (".", "..") for p in parts)
            or "/" + parts[1] not in SAFE_ROOTS):
        raise SiteError(f"{label}: a folder below /mnt or /srv, such as /mnt/backups")
    return text


def nfs_source(value: Any, label: str) -> str:
    text = str(value or "").strip()
    if not _NFS.fullmatch(text) or "/../" in text + "/":
        raise SiteError(f"{label}: an NFS export such as 192.168.1.10:/share/folder")
    return text


def mount_options(value: Any, label: str) -> str:
    """The options as typed, checked against the list, with nosuid, nodev and noexec added."""
    text = str(value or "").strip() or "defaults"
    out: List[str] = []
    for opt in text.split(","):
        key, eq, val = opt.partition("=")
        if (not eq and opt in _FLAGS) or (eq and key in _KEYS and _VALUE.fullmatch(val)):
            if opt not in out:
                out.append(opt)
        else:
            raise SiteError(f"{label}: the option {opt[:40] or '(empty)'} is not allowed. Use options such as "
                            f"defaults, ro, soft, vers=4 or timeo=50")
    return ",".join(out + [h for h in HARDENING if h not in out])


def check_site(site: Any) -> Dict[str, Any]:
    """The site settings with every field checked; raises SiteError on the first problem."""
    site = site if isinstance(site, dict) else {}
    clean: Dict[str, Any] = {k: v for k, v in site.items() if k not in ("nfs", "syncthing")}
    st = site.get("syncthing") or {}
    if st.get("enabled") is True:
        keys = str(st.get("keys_source") or "").strip()
        # An NFS export, or (unprivileged container) a folder the Proxmox host copied the identity into.
        keys = folder_or_staging(keys) if keys.startswith("/") else nfs_source(keys, "Syncthing identity share")
        clean["syncthing"] = {"enabled": True, "keys_source": keys,
                              "data_folder": folder(st.get("data_folder"), "Syncthing backup folder")}
    else:
        clean["syncthing"] = {"enabled": False}
    nfs = site.get("nfs") or {}
    if nfs.get("enabled") is True:
        mounts = nfs.get("mounts")
        if not isinstance(mounts, list) or not mounts or len(mounts) > 20:
            raise SiteError("NFS: add at least one mount, or switch NFS off")
        out, targets = [], set()
        for i, m in enumerate(mounts, 1):
            m = m if isinstance(m, dict) else {}
            target = folder(m.get("target"), f"NFS mount {i} folder")
            if target in targets:
                raise SiteError(f"NFS mount {i}: {target} is used twice")
            targets.add(target)
            out.append({"source": nfs_source(m.get("source"), f"NFS mount {i} export"), "target": target,
                        "options": mount_options(m.get("options"), f"NFS mount {i}")})
        clean["nfs"] = {"enabled": True, "mounts": out}
    else:
        clean["nfs"] = {"enabled": False}
    return clean


STAGING = "/root/.hm-stkeys"


def folder_or_staging(value: str) -> str:
    if value.rstrip("/") == STAGING:
        return STAGING
    raise SiteError("Syncthing identity share: an NFS export such as 192.168.1.10:/share/folder")


def no_symlinks(path: str) -> None:
    """Refuses a path when any part of it that exists is a symbolic link (checked on the box)."""
    current = "/"
    for part in path.strip("/").split("/"):
        current = os.path.join(current, part)
        if os.path.islink(current):
            raise SiteError(f"{current} is a symbolic link; refusing to use {path}")


def _loopback(address: str) -> bool:
    host = address.rsplit(":", 1)[0].strip("[]") if ":" in address else address
    return host in ("127.0.0.1", "localhost", "::1") or host.startswith("127.")


def check_syncthing_config(data: bytes, data_folder: str, home: str) -> bytes:
    """config.xml from the identity share, checked: every synced folder inside data_folder or home.
    A web interface open to the network without a login is moved to 127.0.0.1. Returns the XML to use."""
    if b"<!DOCTYPE" in data or b"<!ENTITY" in data:
        raise SiteError("config.xml contains a DOCTYPE or ENTITY; Syncthing never writes one, refusing it")
    try:
        root = ET.fromstring(data)
    except ET.ParseError as exc:
        raise SiteError(f"config.xml cannot be read ({exc})")
    if root.tag != "configuration":
        raise SiteError("config.xml is not a Syncthing configuration")
    allowed = [posixpath.normpath(data_folder), posixpath.normpath(home)]
    for f in root.iter("folder"):
        raw = (f.get("path") or "").strip()
        path = posixpath.normpath(raw.replace("~", home, 1) if raw.startswith("~") else raw)
        if not path.startswith("/") or not any(path == a or path.startswith(a + "/") for a in allowed):
            raise SiteError(f"config.xml syncs {raw or '(no path)'}, outside {data_folder}; refusing it")
    changed = False
    gui = root.find("gui")
    if gui is not None:
        addr = gui.find("address")
        has_login = bool((gui.findtext("user") or "").strip() and (gui.findtext("password") or "").strip())
        if addr is not None and not _loopback((addr.text or "").strip()) and not has_login:
            addr.text = "127.0.0.1:8384"
            changed = True
    return ET.tostring(root, encoding="utf-8", xml_declaration=True) if changed else data
