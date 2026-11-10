"""Users, roles and permissions for the web UI.

Every signed-in user can view what their device access allows. Anything that
changes state needs a permission. A role is a named bundle of permissions;
"custom" stores the chosen permissions explicitly. Device access limits which
devices a user sees and acts on: all devices, or a set of templates (hardware
profiles) and single devices.

The server checks every API request against ROUTE_PERMISSIONS. A mutating
route that is not listed needs the administrator role, so a new route is
closed until someone decides who may use it.
"""

import json
import re
from typing import Any, Dict, Iterable, List, Optional, Set

# (key, label, help). Order is the order shown in the user editor.
PERMISSIONS = [
    ("devices.poll", "Poll devices", "Poll now, poll all and live mode on device pages."),
    ("problems.ack", "Acknowledge problems", "Acknowledge and un-acknowledge open problems."),
    ("devices.manage", "Manage devices",
     "Add, edit and delete devices and watches, forget SSH host keys, copy the Fix SNMP commands and start Pi-hole, "
     "Wi-Fi and Proxmox guest actions. The address of a device decides where commands run as a stored credential's "
     "user, often root, on every device the user can reach. Running Fix SNMP also needs Use stored credentials."),
    ("map.edit", "Edit the map", "Add objects, draw or hide links and move nodes."),
    ("dashboard.edit", "Edit the dashboard", "Add, rename and delete dashboards; move, resize, rename, add and remove their tiles."),
    ("automation.run", "Run workflows",
     "Start and cancel workflows and run host actions. Their commands run as the stored credential's user, often root, "
     "on every device the user can reach. Commands also need Use stored credentials."),
    ("automation.edit", "Edit workflows",
     "Create, change and delete workflows. Their commands run as the stored credential's user, often root, on every "
     "device the user can reach, also on a schedule when nobody is watching. Commands also need Use stored credentials."),
    ("credentials.use", "Use stored credentials",
     "Run commands on hosts as a stored credential's user, often root, on every device the user can reach: in "
     "workflows, host actions, Fix SNMP and credential tests."),
    ("credentials.manage", "Manage credentials",
     "Add, change, delete and generate stored credentials and approve SSH host keys, which decides where stored "
     "credentials are sent. Commands run as the credential's user, often root, on every device the user can reach. "
     "A stored password can only be used by someone with this permission."),
    ("settings.alerts", "Alert rules", "Change thresholds, severities and Telegram choices."),
    ("settings.notifications", "Notification settings", "Telegram bot, chat, quiet hours and message texts."),
    ("settings.system", "System settings", "SNMP defaults, polling, retention and the setup wizard."),
    ("audit.view", "View the audit log", "Read the audit log."),
    ("audit.sensitive", "Sensitive audit details", "See audit details such as SSH key fingerprints and credential names."),
    ("users.manage", "Manage users", "Add, change, block, log out and delete users."),
]
PERMISSION_KEYS = [p[0] for p in PERMISSIONS]

ROLES = {
    "admin": ("Administrator", "Everything, including users.", set(PERMISSION_KEYS)),
    "operator": ("Operator", "Day to day running: poll, acknowledge, run workflows and host actions, edit the map and "
                             "dashboard. Host actions and workflow commands run as a stored credential's user, often "
                             "root, on every device the Operator can reach.",
                 {"devices.poll", "problems.ack", "automation.run", "credentials.use", "map.edit", "dashboard.edit",
                  "audit.view"}),
    "viewer": ("Viewer", "Read only.", set()),
    "custom": ("Custom", "Exactly the permissions ticked below.", None),
}

# Settings sections and the permission that may change them.
SETTING_SECTION_PERMISSION = {"notify": "settings.notifications", "telegram": "settings.notifications"}

# Mutating routes and the permission each needs. Path patterns match the whole path.
ROUTE_PERMISSIONS = [
    ("POST", r"/api/devices", "devices.manage"),
    ("POST", r"/api/devices/probe", "devices.manage"),
    ("POST", r"/api/devices/bulk-add", "devices.manage"),
    ("POST", r"/api/devices/scan", "devices.manage"),
    ("POST", r"/api/devices/tags", "devices.manage"),
    ("PUT", r"/api/taxonomy", "devices.manage"),
    ("DELETE", r"/api/devices/scan/[0-9a-f]{32}", "devices.manage"),
    ("DELETE", r"/api/setup/scan/[0-9a-f]{32}", "settings.system"),
    ("POST", r"/api/devices/bulk-delete", "devices.manage"),
    ("PUT", r"/api/devices/\d+", "devices.manage"),
    ("PUT", r"/api/devices/\d+/overview", "devices.manage"),
    ("DELETE", r"/api/devices/\d+", "devices.manage"),
    ("POST", r"/api/devices/\d+/watches", "devices.manage"),
    ("POST", r"/api/custom-oids", "devices.manage"),
    ("DELETE", r"/api/custom-oids/\d+", "devices.manage"),
    ("POST", r"/api/devices/\d+/fix-snmp(?:/preview)?", "devices.manage"),
    # A list means every one of them (all of); a tuple inside it means any one of those.
    # Approving a host key decides where stored credentials are sent.
    ("POST", r"/api/devices/\d+/hostkey", ["devices.manage", "credentials.manage"]),
    ("POST", r"/api/devices/\d+/ssh-setup", "devices.manage"),
    ("DELETE", r"/api/devices/\d+/hostkey", "devices.manage"),
    ("POST", r"/api/devices/\d+/poll", "devices.poll"),
    ("POST", r"/api/devices/\d+/live", "devices.poll"),
    ("POST", r"/api/devices/poll-all", "devices.poll"),
    ("POST", r"/api/problems/ack", "problems.ack"),
    ("POST", r"/api/map/objects", "map.edit"),
    ("DELETE", r"/api/map/objects/\d+", "map.edit"),
    ("POST", r"/api/map/links", "map.edit"),
    ("PUT", r"/api/map/positions", "map.edit"),
    ("PUT", r"/api/dashboard", "dashboard.edit"),
    ("POST", r"/api/dashboards", "dashboard.edit"),
    ("DELETE", r"/api/dashboards/[a-z0-9-]+", "dashboard.edit"),
    ("POST", r"/api/workflows/\d+/run", "automation.run"),
    ("POST", r"/api/devices/\d+/host-actions/[a-z_]+", "automation.run"),
    ("POST", r"/api/workflow-runs/\d+/cancel", "automation.run"),
    ("POST", r"/api/workflows", "automation.edit"),
    ("PUT", r"/api/workflows/\d+", "automation.edit"),
    ("DELETE", r"/api/workflows/\d+", "automation.edit"),
    ("POST", r"/api/credentials(?:/generate)?", "credentials.manage"),
    ("POST", r"/api/credentials/\d+/test", [("automation.edit", "credentials.manage"), "credentials.use"]),
    ("PUT", r"/api/credentials/\d+", "credentials.manage"),
    ("DELETE", r"/api/credentials/\d+", "credentials.manage"),
    ("PUT", r"/api/alert-rules", "settings.alerts"),
    ("POST", r"/api/notify/[\w-]+", "settings.notifications"),
    # The message editors' preview: renders sample values sent with the request and stores nothing.
    # Only the editors use it: notification and bot texts in Settings and the workflow Telegram step.
    ("POST", r"/api/template/render", ("settings.notifications", "automation.edit")),
    # POST /api/settings is checked per key (settings_permission), so any signed-in user reaches the handler.
    ("POST", r"/api/settings", None),
    ("POST", r"/api/setup/[\w/-]+", "settings.system"),
    ("POST", r"/api/users(?:/[\w.-]+(?:/[\w-]+)?)?", "users.manage"),
    ("PUT", r"/api/users/[\w.-]+", "users.manage"),
    ("DELETE", r"/api/users/[\w.-]+", "users.manage"),
    ("POST", r"/api/notifications/read", None),
    ("POST", r"/api/changes/seen", None),
    ("PUT", r"/api/proxmox/config", "settings.system"),
    ("PUT", r"/api/tls", "settings.system"),
    ("PUT", r"/api/(?:pihole|unifi)/config", "settings.system"),
    ("POST", r"/api/(?:pihole|unifi)/(?:test|fingerprint)", "settings.system"),
    ("POST", r"/api/maintenance(?:/\d+/end)?", "problems.ack"),
    ("POST", r"/api/inventory/known", "devices.manage"),
    ("POST", r"/api/inventory", "devices.manage"),
    ("PUT", r"/api/inventory/quiet-ssids", "devices.manage"),
    ("POST", r"/api/wifi/reconnect", "devices.manage"),
    ("POST", r"/api/pihole/blocking", "devices.manage"),
    ("PUT", r"/api/unifi/never", "settings.system"),
    ("PUT", r"/api/proxmox/actions", "settings.system"),
    ("POST", r"/api/proxmox/guest", "devices.manage"),
    ("PUT", r"/api/inventory/[0-9a-fA-F:.-]{12,17}", "devices.manage"),
    ("DELETE", r"/api/inventory/[0-9a-fA-F:.-]{12,17}", "devices.manage"),
    ("POST", r"/api/tls/dismiss", "settings.system"),
    ("PUT", r"/api/backups/site", "settings.system"),
    ("POST", r"/api/backups/run", "settings.system"),
    ("POST", r"/api/backups/passphrase", "settings.system"),
    ("POST", r"/api/proxmox/(?:fingerprint|test)", "settings.system"),
]
# Read routes that need a permission (everything else is readable by every signed-in user).
READ_PERMISSIONS = [
    (r"/api/audit", "audit.view"),
    (r"/api/users(?:/[\w.-]+)?", "users.manage"),
    (r"/api/credentials", ("automation.edit", "credentials.manage")),
    (r"/api/automation", ("automation.edit", "automation.run", "devices.manage", "credentials.manage")),
    (r"/api/host-actions(?:/.*)?", ("automation.run", "automation.edit")),
    # Workflow definitions and run logs (SSH output): also limited to the user's devices in the handler.
    (r"/api/workflows(?:/runs)?", ("automation.run", "automation.edit")),
    (r"/api/workflow-runs/\d+", ("automation.run", "automation.edit")),
    (r"/api/setup/[\w/-]+", "settings.system"),
    (r"/api/proxmox/config", "settings.system"),
    (r"/api/notify/bot-[\w-]+", "settings.notifications"),
    (r"/api/tls", "settings.system"),
    (r"/api/(?:pihole|unifi)/config", "settings.system"),
    # Walking a subtree is many requests to the device: limited to those who may change devices.
    (r"/api/devices/\d+/snmp-walk", "devices.manage"),
]
# Step-up tiers (auth.TIER2_SECONDS / TIER3_SECONDS). Tier 1 (a logged-in session) is the
# default. Tier 2 asks for the password: actions that lose data or act on devices. Tier 3 asks
# for the password and the authenticator code: whatever grants access or holds secrets
# (credentials, users, SSH trust, 2FA itself). Settings that store a secret are tier 2,
# checked per key in the settings handler (SECRET_SETTING_TIER).
TIER_ROUTES = [
    ("POST", r"/api/updates/install", 3),
    ("POST", r"/api/demo/remove", 2),             # deletes the demo devices and their history
    ("POST", r"/api/updates/rollback", 3),
    ("POST", r"/api/credentials(?:/.*)?", 3),
    ("PUT", r"/api/credentials/\d+", 3),
    ("DELETE", r"/api/credentials/\d+", 3),
    ("POST", r"/api/users(?:/.*)?", 3),
    ("PUT", r"/api/users/.*", 3),
    ("DELETE", r"/api/users/.*", 3),
    ("POST", r"/api/devices/\d+/hostkey", 3),
    ("DELETE", r"/api/devices/\d+/hostkey", 3),
    ("POST", r"/api/auth/2fa/(?:start|disable|recovery)", 3),
    ("DELETE", r"/api/devices/\d+", 2),
    ("POST", r"/api/devices/bulk-delete", 2),
    ("POST", r"/api/devices/\d+/fix-snmp(?:/.*)?", 2),
    ("POST", r"/api/workflows/\d+/run", 2),
    ("POST", r"/api/devices/\d+/host-actions/[a-z_]+", 2),   # runs commands on the host over SSH
    ("DELETE", r"/api/workflows/\d+", 2),
    ("PUT", r"/api/proxmox/config", 2),           # stores the API token secret
    ("PUT", r"/api/tls", 2),                      # stores a private key; changes how everyone reaches the app
    ("PUT", r"/api/(?:pihole|unifi)/config", 2),  # stores a password
    ("PUT", r"/api/proxmox/actions", 2),          # a token that may change guests
    ("POST", r"/api/proxmox/guest", 2),           # starts, stops or restarts a guest
    ("POST", r"/api/pihole/blocking", 2),         # every device on the network loses its ad blocking
    ("POST", r"/api/wifi/reconnect", 2),          # drops a device off the Wi-Fi
    ("PUT", r"/api/backups/site", 2),             # where backups go, and the Syncthing identity source
    ("POST", r"/api/backups/passphrase", 3),      # what opens and proves every backup from now on
    ("POST", r"/api/(?:pihole|unifi|proxmox)/test", 2),   # sends the stored secret to the stored address
    ("POST", r"/api/workflows", 2),               # saved workflows run unattended on devices
    ("PUT", r"/api/workflows/\d+", 2),
]
SECRET_SETTING_TIER = 2
_TIERS = [(m, re.compile(p), t) for m, p, t in TIER_ROUTES]

# Changes that reach the whole network or objects everyone shares (the map, dashboards, groups and
# tags): a user limited to some devices is refused, after the permission check and before any
# password prompt. Path patterns match the whole path.
UNSCOPED_ROUTES = [
    ("POST", r"/api/backups/passphrase"),
    ("POST", r"/api/pihole/blocking"),
    ("POST", r"/api/wifi/reconnect"),
    ("POST", r"/api/inventory"),
    ("POST", r"/api/inventory/known"),
    ("PUT", r"/api/inventory/quiet-ssids"),
    ("PUT", r"/api/inventory/[0-9a-fA-F:.-]{12,17}"),
    ("DELETE", r"/api/inventory/[0-9a-fA-F:.-]{12,17}"),
    ("POST", r"/api/map/objects"),
    ("DELETE", r"/api/map/objects/\d+"),
    ("POST", r"/api/map/links"),
    ("PUT", r"/api/map/positions"),
    ("PUT", r"/api/dashboard"),
    ("POST", r"/api/dashboards"),
    ("DELETE", r"/api/dashboards/[a-z0-9-]+"),
    ("PUT", r"/api/taxonomy"),
]
_UNSCOPED = [(m, re.compile(p)) for m, p in UNSCOPED_ROUTES]


def needs_all_devices(method: str, path: str) -> bool:
    """Whether this request needs access to every device."""
    return any(m == method and rx.fullmatch(path) for m, rx in _UNSCOPED)


def route_tier(method: str, path: str) -> int:
    """The step-up tier a request needs: 1 (session only), 2 or 3."""
    return max([t for m, rx, t in _TIERS if m == method and rx.fullmatch(path)], default=1)


_ROUTES = [(m, re.compile(p), perm) for m, p, perm in ROUTE_PERMISSIONS]
_READS = [(re.compile(p), perm) for p, perm in READ_PERMISSIONS]
_UNLISTED = object()


def _decode(text: Optional[str], default: Any) -> Any:
    if not text:
        return default
    try:
        return json.loads(text)
    except ValueError:
        return default


def permissions_for(account: Dict[str, Any]) -> Set[str]:
    role = account.get("role") or "viewer"
    if role in ROLES and ROLES[role][2] is not None:
        return set(ROLES[role][2])
    return {p for p in _decode(account.get("permissions"), []) if p in PERMISSION_KEYS}


def scope_of(account: Dict[str, Any]) -> Optional[Dict[str, List]]:
    """None means every device; otherwise {"profiles": [...], "devices": [...]}."""
    if (account.get("role") or "") == "admin":
        return None
    raw = _decode(account.get("device_scope"), None)
    if not isinstance(raw, dict) or raw.get("all", True):
        return None
    return {"profiles": [str(p) for p in raw.get("profiles", [])],
            "devices": [int(d) for d in raw.get("devices", []) if str(d).isdigit()]}


def scope_within(inner: Optional[Dict[str, List]], outer: Optional[Dict[str, List]],
                 profile_of: Dict[int, str]) -> bool:
    """Whether everything scope inner reaches is also in scope outer. None means every device.

    A single device counts as inside when it is one of outer's devices or its template is one of
    outer's templates. A template in inner must also be a template in outer: it is not expanded to
    today's devices, because it also covers devices added later. A device id that no longer exists
    is ignored (ids are never reused). profile_of maps device id to its template."""
    if outer is None:
        return True
    if inner is None:
        return False
    if not set(inner["profiles"]) <= set(outer["profiles"]):
        return False
    return all(d in outer["devices"] or profile_of[d] in outer["profiles"]
               for d in inner["devices"] if d in profile_of)


class User:
    """The signed-in user as the request handler sees it."""

    def __init__(self, account: Dict[str, Any]) -> None:
        self.username = account["username"]
        self.role = account.get("role") or "viewer"
        self.perms = permissions_for(account)
        self.scope = scope_of(account)

    def can(self, perm: Any) -> bool:
        if perm is None:
            return True
        if isinstance(perm, list):
            return all(self.can(p) for p in perm)
        if isinstance(perm, tuple):
            return any(p in self.perms for p in perm)
        return perm in self.perms

    @property
    def is_admin(self) -> bool:
        return self.role == "admin"

    def sees(self, device: Optional[Dict[str, Any]]) -> bool:
        """Whether the device is inside this user's device access."""
        if self.scope is None:
            return True
        if not device:
            return False
        return device.get("profile_id") in self.scope["profiles"] or int(device.get("id", -1)) in self.scope["devices"]

    def bind_devices(self, all_devices: Iterable[Dict[str, Any]]) -> None:
        """Resolves the scope to device ids (templates expand to their devices). Call before visible()."""
        self.allowed_ids = {d["id"] for d in all_devices if self.sees(d)}

    def sees_id(self, device_id: Optional[int]) -> bool:
        return self.scope is None or (device_id is not None and int(device_id) in self.allowed_ids)

    def visible(self, rows: Iterable[Dict[str, Any]], key: str = "device_id") -> List[Dict[str, Any]]:
        """Rows whose device (the id under key) is in scope."""
        rows = list(rows)
        if self.scope is None:
            return rows
        return [r for r in rows if self.sees_id(r.get(key))]

    def to_json(self) -> Dict[str, Any]:
        return {"username": self.username, "role": self.role, "role_label": ROLES.get(self.role, (self.role,))[0],
                "permissions": sorted(self.perms), "scoped": self.scope is not None}


def route_permission(method: str, path: str) -> Any:
    """Permission a request needs, None when any signed-in user may, or "admin" when unlisted."""
    if method == "GET":
        for rx, perm in _READS:
            if rx.fullmatch(path):
                return perm
        return None
    for m, rx, perm in _ROUTES:
        if m == method and rx.fullmatch(path):
            return perm
    return "admin"


def allowed(user: User, method: str, path: str) -> bool:
    perm = route_permission(method, path)
    if perm == "admin":
        return user.is_admin
    return user.can(perm)


def settings_permission(section: str) -> str:
    return SETTING_SECTION_PERMISSION.get(section, "settings.system")


def parse_scope(raw: Any, known_profiles: Iterable[str], known_devices: Iterable[int]) -> Dict[str, Any]:
    """Validates a device access payload: {"all": true} or {"all": false, "profiles": [...], "devices": [...]}."""
    if not isinstance(raw, dict) or raw.get("all", True) is not False:
        return {"all": True}
    profiles, devices = set(known_profiles), set(known_devices)
    out_p = sorted({str(p) for p in raw.get("profiles", []) if str(p) in profiles})
    out_d = sorted({int(d) for d in raw.get("devices", []) if str(d).isdigit() and int(d) in devices})
    return {"all": False, "profiles": out_p, "devices": out_d}


def parse_permissions(raw: Any) -> List[str]:
    if not isinstance(raw, list):
        return []
    return [p for p in PERMISSION_KEYS if p in raw]
