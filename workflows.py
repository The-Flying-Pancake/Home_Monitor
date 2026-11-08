"""Workflows: a graph of steps (commands, waits, ping and SNMP checks) drawn in the editor.

Built for restart and update sequences where order matters: restart the
device furthest from the gateway first, wait until it stops answering ping,
wait until it answers again, then move on to the next one upstream. A run
executes on its own thread inside the monitor, so it keeps going while a
restart cuts the monitor off the network; the ping and SNMP waits are what
carry it across.

Graph:
  nodes  one "trigger" node (holds the schedule) and up to MAX_STEPS steps,
         each {id, type, x, y, label, retries, ...type fields}
  edges  {from, to, kind}; kind "ok" is followed when a step succeeds,
         "fail" when it fails. A step with no "fail" edge stops the run on failure.
A run starts at the trigger and follows one path; there are no parallel branches.
Cycles and a second edge of the same kind from one node are rejected.

Step types:
  command    run a command over SSH on one or more hosts, one host at a time
  wait       pause for a number of seconds
  wait_ping  wait until a host stops answering ("down") or answers ("up")
  wait_snmp  wait until a host's SNMP agent answers again
  telegram   send a Telegram message (placeholders: workflow, trigger, status, steps, time)

Restarts: a command that restarts its host usually loses its SSH session before
ssh can report an exit code. A command step marked expect_disconnect, or one
that looks like a restart and is followed by "wait until it stops answering",
counts a dropped session (or a session that hangs until the step timeout) as
done. Refused connections and failed logins still fail: the command never ran.

Workflows saved before the graph editor have a plain step list with an
on_failure policy per step; steps_to_graph converts them on load.
"""

import json
import logging
import re
import threading
import time
from typing import Any, Callable, Dict, List, Optional

import database
import poller
import schedule
import ssh_runner

log = logging.getLogger("workflows")

# The weak-signal line for "Reconnect weak Wi-Fi devices" (set by server.py from the alert rule).
weak_dbm: Optional[Callable[[], float]] = None
STEP_TYPES = ("command", "wait", "wait_ping", "wait_snmp", "telegram", "wifi_reconnect", "pve_snapshot", "mute", "unmute")
# What "Suppress notifications" covers: this workflow's hosts, devices picked, a group, a tag or everything.
MUTE_SCOPES = ("hosts", "devices", "group", "tag", "all")
FAILURE_POLICIES = ("stop", "continue", "retry")
EDGE_KINDS = ("ok", "fail")
MAX_STEPS = 40
# Set by the server: called with (workflow, status, failed step title or "") when a run ends.
on_finished: Optional[Callable[[Dict[str, Any], str, str], None]] = None
# Set by the server: called with (workflow, trigger) when a run starts (the "Workflow started" message).
on_started: Optional[Callable[[Dict[str, Any], str], None]] = None
# Set by the server: queues a Telegram message; returns None when Telegram is off.
send_telegram: Optional[Callable[..., Optional[int]]] = None
# ssh output that means the session was cut, as a restart does (not "refused": then nothing ran).
_DROPPED = re.compile(r"closed by remote host|connection reset|broken pipe|connection to \S+ closed|"
                      r"timeout, server not responding|software caused connection abort", re.I)
_RESTART_CMD = re.compile(r"\b(reboot|shutdown\s+-r|systemctl\s+(reboot|kexec)|init\s+6|restart)\b", re.I)
# A host must answer this many pings in a row before "wait until it answers" is done.
UP_STREAK = 2
MAX_OUTPUT = 4000
POLL_SECONDS = 3
_NODE_ID = re.compile(r"[A-Za-z0-9_-]{1,32}")


class WorkflowError(ValueError):
    pass


def _int(step: Dict[str, Any], key: str, default: Optional[int], lo: int, hi: int) -> Optional[int]:
    v = step.get(key, default)
    if v is None:
        return None
    if not isinstance(v, int) or isinstance(v, bool) or not lo <= v <= hi:
        raise WorkflowError(f"'{key}' must be a whole number from {lo} to {hi}")
    return v


def _parse_step(raw: Dict[str, Any], device_ids: set, credential_ids: set) -> Dict[str, Any]:
    """Type-specific fields of one step (no failure policy)."""
    kind = raw.get("type")
    if kind not in STEP_TYPES:
        raise WorkflowError("unknown type")
    step: Dict[str, Any] = {"type": kind}
    label = raw.get("label", "")
    if not isinstance(label, str) or len(label) > 80:
        raise WorkflowError("label must be text up to 80 characters")
    step["label"] = label.strip()
    if kind == "command":
        cmd = raw.get("command")
        if not isinstance(cmd, str) or not cmd.strip() or len(cmd) > 4000 or "\x00" in cmd:
            raise WorkflowError("command must be 1 to 4000 characters")
        ids = raw.get("device_ids")
        if not isinstance(ids, list) or not ids or len(ids) > 50 or \
                not all(isinstance(x, int) and not isinstance(x, bool) for x in ids):
            raise WorkflowError("choose at least one host")
        if not set(ids) <= device_ids:
            raise WorkflowError("unknown host")
        cred = _int(raw, "credential_id", None, 1, 2 ** 31)
        if cred not in credential_ids:
            raise WorkflowError("choose a stored credential")
        # Order is kept as entered: it is the restart order.
        step.update(command=cmd.strip(), device_ids=list(dict.fromkeys(ids)), credential_id=cred,
                    timeout_s=_int(raw, "timeout_s", 60, 5, 3600), ssh_port=_int(raw, "ssh_port", 22, 1, 65535),
                    expected_exit_code=_int(raw, "expected_exit_code", 0, 0, 255),
                    any_exit=raw.get("any_exit") is True, expect_disconnect=raw.get("expect_disconnect") is True)
    elif kind == "telegram":
        text = raw.get("text")
        if not isinstance(text, str) or not text.strip() or len(text) > 1000:
            raise WorkflowError("the message must be 1 to 1000 characters")
        step["text"] = text.strip()
        step["silent"] = raw.get("silent") is True
    elif kind == "mute":
        scope = raw.get("scope", "hosts")
        if scope not in MUTE_SCOPES:
            raise WorkflowError("choose what to keep quiet")
        step["scope"] = scope
        if scope == "devices":
            ids = raw.get("device_ids")
            if not isinstance(ids, list) or not ids or len(ids) > 100 or \
                    not all(isinstance(x, int) and not isinstance(x, bool) for x in ids) or not set(ids) <= device_ids:
                raise WorkflowError("choose the devices to keep quiet")
            step["device_ids"] = list(dict.fromkeys(ids))
        elif scope in ("group", "tag"):
            target = raw.get("target")
            if not isinstance(target, str) or not target.strip() or len(target) > 64:
                raise WorkflowError(f"choose the {scope}")
            step["target"] = target.strip()
        step["until_end"] = raw.get("until_end", True) is not False
        step["minutes"] = _int(raw, "minutes", 60, 1, 1440)
        step["grace_min"] = _int(raw, "grace_min", 5, 0, 120)
    elif kind == "unmute":
        step["grace_min"] = _int(raw, "grace_min", 0, 0, 120)
    elif kind == "wait":
        step["seconds"] = _int(raw, "seconds", 30, 1, 3600)
    elif kind == "pve_snapshot":
        node, gtype = raw.get("node"), raw.get("guest_type")
        if not isinstance(node, str) or not node or len(node) > 64 or gtype not in ("qemu", "lxc"):
            raise WorkflowError("choose a guest")
        step.update(node=node, guest_type=gtype, vmid=_int(raw, "vmid", None, 1, 999999999),
                    guest_name=str(raw.get("guest_name") or "")[:80], timeout_s=_int(raw, "timeout_s", 600, 30, 3600))
        if step["vmid"] is None:
            raise WorkflowError("choose a guest")
    elif kind == "wifi_reconnect":
        dev = _int(raw, "device_id", None, 1, 2 ** 31)
        if dev not in device_ids:
            raise WorkflowError("choose an access point")
        step["device_id"] = dev
    else:
        dev = _int(raw, "device_id", None, 1, 2 ** 31)
        if dev not in device_ids:
            raise WorkflowError("choose a host")
        step["device_id"] = dev
        step["timeout_s"] = _int(raw, "timeout_s", 300, 10, 3600)
        if kind == "wait_ping":
            state = raw.get("state", "up")
            if state not in ("up", "down"):
                raise WorkflowError("state must be up or down")
            step["state"] = state
    return step


def parse_steps(steps: Any, device_ids: set, credential_ids: set) -> List[Dict[str, Any]]:
    """Validates and normalises a plain step list (older API form). Raises WorkflowError."""
    if not isinstance(steps, list) or not steps or len(steps) > MAX_STEPS:
        raise WorkflowError(f"A workflow needs 1 to {MAX_STEPS} steps")
    out = []
    for i, raw in enumerate(steps, 1):
        if not isinstance(raw, dict):
            raise WorkflowError(f"Step {i} is not an object")
        try:
            step = _parse_step(raw, device_ids, credential_ids)
            policy = raw.get("on_failure", "stop")
            if policy not in FAILURE_POLICIES:
                raise WorkflowError("on_failure must be stop, continue or retry")
            step["on_failure"] = policy
            step["retries"] = _int(raw, "retries", 2, 1, 10) if policy == "retry" else 0
        except WorkflowError as exc:
            raise WorkflowError(f"Step {i}: {exc}")
        out.append(step)
    return out


def steps_to_graph(steps: List[Dict[str, Any]], sched: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """A linear step list as a left-to-right chain. "continue" becomes a failure edge to the next step."""
    nodes = [{"id": "trigger", "type": "trigger", "x": 40, "y": 120, "schedule": sched or {"kind": "manual"}}]
    edges = []
    prev = "trigger"
    for i, s in enumerate(steps, 1):
        nid = f"n{i}"
        node = {k: v for k, v in s.items() if k != "on_failure"}
        node.update(id=nid, x=40 + i * 250, y=120, retries=s.get("retries", 0) if s.get("on_failure") == "retry" else 0)
        nodes.append(node)
        edges.append({"from": prev, "to": nid, "kind": "ok"})
        if i > 1 and steps[i - 2].get("on_failure") == "continue":
            edges.append({"from": prev, "to": nid, "kind": "fail"})
        prev = nid
    return {"nodes": nodes, "edges": edges}


def _coord(raw: Dict[str, Any], key: str) -> int:
    v = raw.get(key, 0)
    if not isinstance(v, (int, float)) or isinstance(v, bool) or not -100000 <= v <= 100000:
        raise WorkflowError("position is out of range")
    return int(round(v))


def parse_graph(graph: Any, device_ids: set, credential_ids: set, now: Optional[float] = None,
                keep_past_once: bool = False) -> Dict[str, Any]:
    """Validates a graph from the editor. Returns {nodes, edges} with normalised nodes."""
    if not isinstance(graph, dict) or not isinstance(graph.get("nodes"), list) or not isinstance(graph.get("edges"), list):
        raise WorkflowError("The workflow is missing its steps")
    raw_nodes, raw_edges = graph["nodes"], graph["edges"]
    if len(raw_nodes) > MAX_STEPS + 1 or len(raw_edges) > 3 * (MAX_STEPS + 1):
        raise WorkflowError(f"A workflow can have up to {MAX_STEPS} steps")
    nodes: Dict[str, Dict[str, Any]] = {}
    trigger = None
    for i, raw in enumerate(raw_nodes, 1):
        if not isinstance(raw, dict):
            raise WorkflowError(f"Step {i} is not an object")
        nid = raw.get("id")
        if not isinstance(nid, str) or not _NODE_ID.fullmatch(nid) or nid in nodes:
            raise WorkflowError(f"Step {i} has a missing or repeated id")
        if raw.get("type") == "trigger":
            if trigger:
                raise WorkflowError("A workflow has one trigger")
            try:
                sched = schedule.parse(raw.get("schedule"), now, allow_past_once=keep_past_once)
            except schedule.ScheduleError as exc:
                raise WorkflowError(f"Schedule: {exc}")
            if sched["kind"] == "event" and sched["when"]["device_id"] not in device_ids:
                raise WorkflowError("The trigger watches a device that does not exist")
            node = {"id": nid, "type": "trigger", "schedule": sched}
            trigger = nid
        else:
            try:
                node = _parse_step(raw, device_ids, credential_ids)
                node["retries"] = _int(raw, "retries", 0, 0, 10)
            except WorkflowError as exc:
                name = raw.get("label") if isinstance(raw.get("label"), str) and raw.get("label") else f"Step {i}"
                raise WorkflowError(f"{name}: {exc}")
            node["id"] = nid
        node["x"], node["y"] = _coord(raw, "x"), _coord(raw, "y")
        nodes[nid] = node
    if not trigger:
        raise WorkflowError("A workflow needs a trigger")
    edges = []
    out_kinds = set()
    for e in raw_edges:
        if not isinstance(e, dict) or e.get("from") not in nodes or e.get("to") not in nodes or e.get("kind") not in EDGE_KINDS:
            raise WorkflowError("A connection points at a step that does not exist")
        a, b, kind = e["from"], e["to"], e["kind"]
        if a == b or b == trigger:
            raise WorkflowError("A step cannot connect to itself or back to the trigger")
        if a == trigger and kind == "fail":
            raise WorkflowError("The trigger has no failure output")
        if (a, kind) in out_kinds:
            raise WorkflowError(f"'{title(nodes[a])}' has two {'success' if kind == 'ok' else 'failure'} connections; a run follows one path")
        out_kinds.add((a, kind))
        edges.append({"from": a, "to": b, "kind": kind})
    # Cycle check: depth-first over the edges.
    adjacent: Dict[str, List[str]] = {}
    for e in edges:
        adjacent.setdefault(e["from"], []).append(e["to"])
    state: Dict[str, int] = {}

    def visit(n: str) -> None:
        state[n] = 1
        for m in adjacent.get(n, []):
            if state.get(m) == 1:
                raise WorkflowError(f"The connections loop back to '{title(nodes[m])}'; a workflow cannot repeat steps")
            if m not in state:
                visit(m)
        state[n] = 2

    for n in nodes:
        if n not in state:
            visit(n)
    reach = {trigger}
    stack = [trigger]
    while stack:
        for m in adjacent.get(stack.pop(), []):
            if m not in reach:
                reach.add(m)
                stack.append(m)
    steps = [n for n in nodes.values() if n["type"] != "trigger"]
    if not steps:
        raise WorkflowError("Add at least one step and connect it to the trigger")
    loose = [title(n) for n in steps if n["id"] not in reach]
    if loose:
        raise WorkflowError(f"Not connected to the trigger: {', '.join(loose[:3])}")
    return {"nodes": list(nodes.values()), "edges": edges}


def graph_trigger(graph: Dict[str, Any]) -> Dict[str, Any]:
    return next(n for n in graph["nodes"] if n["type"] == "trigger")


def step_order(graph: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Steps in a stable reading order: breadth first from the trigger, success before failure."""
    by_id = {n["id"]: n for n in graph["nodes"]}
    nxt: Dict[str, List[str]] = {}
    for kind in EDGE_KINDS:
        for e in graph["edges"]:
            if e["kind"] == kind:
                nxt.setdefault(e["from"], []).append(e["to"])
    seen, out, queue = set(), [], [graph_trigger(graph)["id"]]
    while queue:
        n = queue.pop(0)
        for m in nxt.get(n, []):
            if m not in seen:
                seen.add(m)
                out.append(by_id[m])
                queue.append(m)
    return out


def title(step: Dict[str, Any], names: Optional[Dict[int, str]] = None) -> str:
    return describe(step, names or {}) if step.get("type") != "trigger" else "Trigger"


def describe(step: Dict[str, Any], names: Dict[int, str]) -> str:
    if step.get("label"):
        return step["label"]
    if step["type"] == "command":
        hosts = ", ".join(names.get(i, f"#{i}") for i in step["device_ids"])
        return f"Run '{step['command'][:40]}' on {hosts}"
    if step["type"] == "wait":
        return f"Wait {step['seconds']} s"
    if step["type"] == "telegram":
        return f"Send Telegram{' quietly' if step.get('silent') else ''}: {step['text'][:40]}"
    if step["type"] == "mute":
        what = {"hosts": "this workflow's hosts", "all": "everything", "group": f"group {step.get('target')}",
                "tag": f"tag {step.get('target')}",
                "devices": ", ".join(names.get(i, f"#{i}") for i in step.get("device_ids") or [])}[step["scope"]]
        return f"Suppress notifications for {what}"
    if step["type"] == "unmute":
        return "Notifications back on"
    if step["type"] == "pve_snapshot":
        return f"Snapshot {step.get('guest_name') or 'guest'} ({step['vmid']}) on {step['node']}"
    host = names.get(step["device_id"], f"#{step['device_id']}")
    if step["type"] == "wifi_reconnect":
        return f"Reconnect weak Wi-Fi devices on {host}"
    if step["type"] == "wait_ping":
        return f"Wait until {host} {'stops answering' if step['state'] == 'down' else 'answers'} ping"
    return f"Wait until {host} answers SNMP"


def hosts_of(workflow: Dict[str, Any]) -> List[int]:
    return sorted({i for s in workflow["steps"] for i in (s.get("device_ids") or [s.get("device_id")]) if i})


def next_ok(graph: Dict[str, Any], node_id: str) -> Optional[Dict[str, Any]]:
    by_id = {n["id"]: n for n in graph["nodes"]}
    to = next((e["to"] for e in graph["edges"] if e["from"] == node_id and e["kind"] == "ok"), None)
    return by_id.get(to)


def expects_drop(step: Dict[str, Any], graph: Optional[Dict[str, Any]] = None) -> bool:
    """Whether a lost SSH session means this command did its job (a restart)."""
    if step.get("type") != "command":
        return False
    if step.get("expect_disconnect"):
        return True
    if not graph or not _RESTART_CMD.search(step.get("command", "")):
        return False
    after = next_ok(graph, step.get("id", ""))
    return bool(after and after["type"] == "wait_ping" and after.get("state") == "down")


def dropped(result: Dict[str, Any]) -> bool:
    """ssh ended because the session was cut or hung: not refused, not a failed login, not a clean exit."""
    if result["status"] == "timeout":
        return True
    text = f"{result.get('stderr') or ''}\n{result.get('stdout') or ''}"
    if result["status"] == "error" or result.get("exit_code") in (255, None, -1, 129, 143):
        return bool(_DROPPED.search(text)) or result["status"] == "error" and not re.search(
            r"refused|permission denied|no route|could not resolve|host key|not found|connection timed out", text, re.I)
    return False


EVENT_TEXT = {
    "snmp_down": "answers ping but not SNMP",
    "offline": "goes offline",
    "online": "comes back online",
}


def event_text(sched: Dict[str, Any], names: Dict[int, str], labels: Optional[Dict[str, str]] = None) -> str:
    """Plain words for an event trigger, for example "When nas-01 CPU usage is above 90 for 10 min"."""
    w = sched["when"]
    dev = names.get(w["device_id"], f"device #{w['device_id']}")
    lasting = f" for {w['for_minutes']} min" if w.get("for_minutes") else ""
    if w["type"] == "metric":
        v = w["value"]
        metric = (labels or {}).get(w["metric"], w["metric"])
        return f"When {dev} {metric} is {w['op']} {int(v) if v == int(v) else v}{lasting}"
    if w["type"] == "watch":
        return f"When {dev} {('watched ' + w['name']) if w.get('name') else 'a watched service or process'} stops"
    if w["type"] == "problem":
        what = f"a '{w['rule']}' problem" if w.get("rule") else "a problem"
        return f"When {dev} has {what} ({w['min_severity']} or worse)"
    return f"When {dev} {EVENT_TEXT[w['type']]}{lasting}"


class TriggerWatcher:
    """Starts "When something happens" workflows. Called after each problem pass (see the server).

    A condition must hold continuously for its for_minutes; the workflow then runs once, and not
    again until the condition has cleared and come back, and at least cooldown_minutes have passed.
    "online" fires only on a seen offline to online change, so a restart of the monitor does not fire it.
    State is in memory: after a restart, a condition that is already true starts its timer again.
    """

    SEVERITY_RANK = {"info": 0, "warning": 1, "high": 2, "critical": 3}

    def __init__(self) -> None:
        self.state: Dict[int, Dict[str, Any]] = {}

    def check(self, when: Dict[str, Any], device: Dict[str, Any], latest: Dict[str, float],
              problems: List[Dict[str, Any]]) -> Optional[str]:
        """What makes the condition true right now (a short text), or None."""
        t = when["type"]
        if t == "metric":
            v = latest.get(when["metric"])
            if not isinstance(v, (int, float)):
                return None
            hit = v > when["value"] if when["op"] == "above" else v < when["value"]
            return f"{when['metric']} {v:g} {when['op']} {when['value']:g}" if hit else None
        if t == "snmp_down":
            return "ping answers, SNMP does not" if device["status"] != "offline" and device.get("snmp_status") == "no_response" else None
        if t == "offline":
            return "device offline" if device["status"] == "offline" else None
        if t == "online":
            return "device back online" if device["status"] != "offline" else None
        mine = [p for p in problems if p["device_id"] == device["id"]]
        if t == "watch":
            for p in mine:
                key = p.get("problem_key") or ""
                if key.startswith("watch:") and (not when.get("name") or key.split(":", 2)[-1].lower() == when["name"].lower()):
                    return p["message"]
            return None
        for p in mine:
            if self.SEVERITY_RANK.get(p["severity"], 0) < self.SEVERITY_RANK[when["min_severity"]]:
                continue
            if when.get("rule"):
                import alerts
                if alerts.rule_id_for_key(p["problem_key"], device["profile_id"]) != when["rule"]:
                    continue
            return p["message"]
        return None

    def evaluate(self, now: float, start: Callable[[Dict[str, Any], str], None],
                 workflows_list: Optional[List[Dict[str, Any]]] = None) -> List[int]:
        """Checks every active event workflow; calls start(workflow, trigger text) for those due. Returns their ids."""
        wfs = [w for w in (workflows_list if workflows_list is not None else database.list_workflows())
               if w.get("is_active") and w.get("trigger_type") == "event" and (w.get("schedule") or {}).get("kind") == "event"]
        live = {w["id"] for w in wfs}
        for gone in set(self.state) - live:
            del self.state[gone]
        if not wfs:
            return []
        devices = {d["id"]: d for d in database.list_devices()}
        problems = database.list_active_problems()
        latest_cache: Dict[int, Dict[str, float]] = {}
        fired = []
        for wf in wfs:
            sched = wf["schedule"]
            when = sched["when"]
            device = devices.get(when["device_id"])
            st = self.state.setdefault(wf["id"], {"since": None, "done": False, "last": None, "seen_false": False})
            if not device:
                continue
            if device["id"] not in latest_cache:
                latest_cache[device["id"]] = {m["metric_key"]: m["value"] for m in database.get_latest_metrics(device["id"])}
            why = self.check(when, device, latest_cache[device["id"]], problems)
            if why is None:
                st.update(since=None, done=False, seen_false=True)
                continue
            if when["type"] == "online" and not st["seen_false"]:
                st["done"] = True           # already online when first seen: not a change
                continue
            if st["since"] is None:
                st["since"] = now
            held = now - st["since"] >= (when.get("for_minutes") or 0) * 60
            cooled = st["last"] is None or now - st["last"] >= sched.get("cooldown_minutes", 30) * 60
            if held and not st["done"] and cooled:
                st.update(done=True, last=now)
                fired.append(wf["id"])
                start(wf, f"event: {why} on {device['hostname']}"[:200])
        return fired


TRIGGERS = TriggerWatcher()


class WorkflowRun:
    """One execution of a workflow. Writes its log to the database after every step."""

    def __init__(self, workflow: Dict[str, Any], run_id: int, trigger: str,
                 sleep: Callable[[float], None] = time.sleep) -> None:
        self.workflow = workflow
        self.graph = workflow.get("graph") or steps_to_graph(workflow["steps"])
        self.run_id = run_id
        self.trigger = trigger
        self.cancelled = threading.Event()
        self.sleep = sleep
        self.log: List[Dict[str, Any]] = []
        devices = database.list_devices()
        self.devices = {d["id"]: d for d in devices}
        self.names = {d["id"]: d["hostname"] for d in devices}
        # Maintenance windows a Suppress notifications step opened "until the run ends": (id, grace min).
        self.mutes: List[tuple] = []

    def _entry(self, index: int, step: Dict[str, Any], host: Optional[int] = None) -> Dict[str, Any]:
        e = {"step": index, "node": step.get("id"), "type": step["type"], "title": describe(step, self.names),
             "host": self.names.get(host) if host else None, "host_id": host,
             "status": "running", "started": time.time(), "finished": None, "detail": ""}
        self.log.append(e)
        self._save("running")
        return e

    def _save(self, status: str, finished: bool = False) -> None:
        database.update_workflow_run(self.run_id, status, json.dumps(self.log), time.time() if finished else None)

    def _wait(self, seconds: float) -> bool:
        """Sleeps in short slices so a cancel takes effect quickly. False when cancelled."""
        end = time.time() + seconds
        while time.time() < end:
            if self.cancelled.is_set():
                return False
            self.sleep(min(1.0, max(0.0, end - time.time())))
        return not self.cancelled.is_set()

    def run(self) -> str:
        status = "success"
        by_id = {n["id"]: n for n in self.graph["nodes"]}
        if on_started:
            try:
                on_started(self.workflow, self.trigger)
            except Exception:
                log.exception("Workflow start hook failed")
        nxt = {(e["from"], e["kind"]): e["to"] for e in self.graph["edges"]}
        try:
            current = nxt.get((graph_trigger(self.graph)["id"], "ok"))
            index = 0
            # parse_graph rejects cycles; the bound is a second guard for a hand-edited row.
            while current and index <= MAX_STEPS:
                if self.cancelled.is_set():
                    status = "cancelled"
                    break
                index += 1
                step = by_id[current]
                ok = self._run_step(index, step)
                if self.cancelled.is_set():
                    status = "cancelled"
                    break
                if ok:
                    current = nxt.get((step["id"], "ok"))
                elif (step["id"], "fail") in nxt:
                    status = "partial"
                    current = nxt[(step["id"], "fail")]
                else:
                    status = "failed"
                    break
        except Exception as exc:
            log.exception("Workflow %s run %s crashed", self.workflow["id"], self.run_id)
            self.log.append({"step": None, "type": "error", "title": "Internal error", "status": "error",
                             "started": time.time(), "finished": time.time(), "detail": str(exc)[:500]})
            status = "error"
        if self.mutes:
            self._release_mutes()
        self._save(status, finished=True)
        if on_finished:
            failed = next((e["title"] for e in reversed(self.log) if e["status"] in ("failed", "error")), "")
            try:
                on_finished(self.workflow, status, failed)
            except Exception:
                log.exception("Workflow finish hook failed")
        sev = "info" if status == "success" else "warning"
        text = {"success": "completed", "partial": "completed after a failed step", "failed": "stopped at a failed step",
                "cancelled": "was cancelled", "error": "stopped on an internal error"}[status]
        for device_id in hosts_of(self.workflow):
            if device_id in self.devices:
                database.add_event(device_id, sev, "workflow", f"Workflow '{self.workflow['name']}' {text} ({self.trigger})")
        return status

    def _run_step(self, index: int, step: Dict[str, Any]) -> bool:
        attempts = 1 + (step.get("retries") or 0)
        hosts = step["device_ids"] if step["type"] == "command" else [step.get("device_id")]
        drop_ok = expects_drop(step, self.graph)
        for host in hosts:
            for attempt in range(1, attempts + 1):
                entry = self._entry(index, step, host)
                ok, detail = self._execute(step, host)
                if not ok and drop_ok and attempt == 1 and "refused" in detail.lower():
                    # A restart already under way refuses new sessions: say so instead of retrying into it.
                    detail += "\n(The host refused SSH. If an earlier run already restarted it, this is expected.)"
                entry.update(status="ok" if ok else ("cancelled" if self.cancelled.is_set() else "failed"),
                             finished=time.time(), detail=(detail if attempt == 1 else f"Attempt {attempt}: {detail}")[:MAX_OUTPUT])
                self._save("running")
                if ok or self.cancelled.is_set():
                    break
            if not ok:
                return False
        return True

    def _telegram(self, step: Dict[str, Any]):
        import notify
        if not send_telegram:
            return False, "Telegram is not available"
        text = notify.render(step["text"], _telegram_values(self))
        if (send_telegram(text, silent=True) if step.get("silent") else send_telegram(text)) is None:
            return False, "Telegram is off (Settings, Notifications)"
        return True, f"Queued for Telegram{' (quietly, no sound)' if step.get('silent') else ''}: {text}"

    def _mute(self, step: Dict[str, Any]):
        """Maintenance windows for what the step names: problems still show and are logged, nothing
        goes to Telegram, downtime counts as planned. With until_end they close grace_min minutes after
        the run ends (whatever way it ends); otherwise after minutes."""
        import maintenance
        scope = step["scope"]
        if scope == "hosts":
            targets = [("device", str(i)) for i in hosts_of(self.workflow)]
        elif scope == "devices":
            targets = [("device", str(i)) for i in step["device_ids"]]
        elif scope == "all":
            targets = [("all", "")]
        else:
            targets = [(scope, step["target"])]
        if not targets:
            return True, "Nothing to keep quiet: this workflow has no hosts"
        now = time.time()
        made = []
        for sc, target in targets:
            try:
                w = maintenance.add(sc, target, now, now + step["minutes"] * 60, f"Workflow '{self.workflow['name']}'",
                                    f"workflow:{self.workflow['id']}", now=now)
            except maintenance.MaintenanceError as exc:
                return False, str(exc)
            made.append(w["id"])
            if step["until_end"]:
                self.mutes.append((w["id"], step["grace_min"]))
        what = describe(step, self.names)[len("Suppress notifications for "):]
        how = (f"until the run ends, plus {step['grace_min']} min" if step["until_end"] else f"for {step['minutes']} min")
        return True, f"Notifications suppressed for {what} {how} (maintenance windows {', '.join(map(str, made))})"

    def _unmute(self, step: Dict[str, Any]):
        n = self._release_mutes(step["grace_min"])
        return True, ("Notifications back on" + (f" in {step['grace_min']} min" if step["grace_min"] else "")
                      if n else "Nothing was suppressed by this run")

    def _release_mutes(self, grace_min: Optional[int] = None) -> int:
        """Ends this run's windows: now plus each window's grace (or the grace given)."""
        import maintenance
        n = 0
        for wid, grace in self.mutes:
            try:
                maintenance.end_at(wid, time.time() + 60 * (grace if grace_min is None else grace_min))
                n += 1
            except Exception:
                log.exception("Could not end maintenance window %s", wid)
        self.mutes = []
        return n

    def _wifi_reconnect(self, device: Dict[str, Any]):
        """Reconnects the devices on an access point below the weak-signal line (unifi.reconnect_weak).
        Nothing to do counts as done; a device held back by the guard rails is listed, not a failure."""
        import unifi
        if not unifi.is_enabled() or not unifi.is_configured():
            return False, "UniFi is not connected (Settings, UniFi)"
        line = weak_dbm() if weak_dbm else -75
        done, skipped = unifi.reconnect_weak(device["id"], line)
        lines = [f"Reconnected: {', '.join(done)}" if done else f"No device on {device['hostname']} below {line:g} dBm needed it"]
        if skipped:
            lines.append("Left alone: " + "; ".join(skipped))
        if done:
            database.add_event(device["id"], "info", "action", f"Workflow '{self.workflow['name']}' reconnected {', '.join(done)}")
        failed = [s for s in skipped if "refused" in s or "not connected" in s]
        return not failed, "\n".join(lines)

    def _execute(self, step: Dict[str, Any], host: Optional[int]):
        kind = step["type"]
        if kind == "wait":
            return self._wait(step["seconds"]), f"Waited {step['seconds']} s"
        if kind == "telegram":
            return self._telegram(step)
        if kind == "mute":
            return self._mute(step)
        if kind == "unmute":
            return self._unmute(step)
        if kind == "pve_snapshot":
            import proxmox
            try:
                name = proxmox.snapshot(step["node"], step["guest_type"], step["vmid"],
                                        f"Before workflow '{self.workflow['name']}'", step["timeout_s"], self.cancelled.is_set)
            except proxmox.ProxmoxError as exc:
                return False, str(exc)
            return True, f"Snapshot {name} of {step.get('guest_name') or step['vmid']} taken (Proxmox, the guest's Snapshots)"
        device = self.devices.get(host)
        if not device:
            return False, "Host no longer exists"
        if kind == "wifi_reconnect":
            return self._wifi_reconnect(device)
        if kind == "command":
            keys = database.get_host_keys(device["id"])
            if not keys:
                return False, "SSH host key not approved. Use Host keys on the Automation page to review and approve it."
            cred = database.get_credential_secret(step["credential_id"])
            if not cred:
                return False, "The step's credential no longer exists."
            r = ssh_runner.run_command(device["ip_address"], step["ssh_port"], cred, step["command"], keys, step["timeout_s"])
            out = (r.get("stdout") or "") + (("\n" + r["stderr"]) if r.get("stderr") else "")
            if r["status"] == "completed" and (step["any_exit"] or r["exit_code"] == step["expected_exit_code"]):
                return True, f"Exit {r['exit_code']} in {r['duration']:.1f} s\n{out}".strip()
            if expects_drop(step, self.graph) and dropped(r):
                return True, f"The connection dropped, as a restart does (expected)\n{out}".strip()
            if r["status"] == "completed":
                return False, f"Exit {r['exit_code']} (expected {step['expected_exit_code']})\n{out}".strip()
            return False, f"{r['status']}: {out}".strip()
        started = time.time()
        deadline = started + step["timeout_s"]
        streak = checks = 0
        while True:
            if kind == "wait_ping":
                alive, _ = poller.ping_host(device["ip_address"], 2.0)
                checks += 1
                if step["state"] == "down" and not alive:
                    # Already down counts: a fast restart may have dropped before this step began.
                    return True, f"{device['hostname']} stopped answering after {time.time() - started:.0f} s"
                if step["state"] == "up":
                    streak = streak + 1 if alive else 0
                    # Two replies in a row, so a host that answers once mid-boot is not taken as up.
                    if streak >= UP_STREAK:
                        return True, f"{device['hostname']} answered again after {time.time() - started:.0f} s"
            else:
                value = poller.snmp_get(device["ip_address"], "1.3.6.1.2.1.1.3.0", device.get("snmp_community") or "public",
                                        device.get("snmp_port") or 161, 2.0, 0)
                if value is not None and poller.has_value(value):
                    return True, f"SNMP answered after {time.time() - (deadline - step['timeout_s']):.0f} s"
            if time.time() >= deadline:
                if kind == "wait_ping":
                    state = "still answering" if step["state"] == "down" else "not answering"
                    return False, (f"Gave up after {step['timeout_s']} s: {device['hostname']} was {state} "
                                   f"({checks} checks). Raise the step's timeout if this host takes longer.")
                return False, f"Gave up after {step['timeout_s']} s: SNMP did not answer"
            if not self._wait(POLL_SECONDS):
                return False, "Cancelled"


def _telegram_values(run: "WorkflowRun") -> Dict[str, Any]:
    done = [e for e in run.log if e.get("status") in ("ok", "failed", "cancelled")]
    steps = "\n".join(f"{'✅' if e['status'] == 'ok' else '❌'} {e['title']}{(' on ' + e['host']) if e.get('host') else ''}"
                      for e in done)
    failed = any(e["status"] == "failed" for e in done)
    return {"workflow": run.workflow["name"], "trigger": run.trigger, "time": time.strftime("%Y-%m-%d %H:%M"),
            "status": "a step failed" if failed else "all steps so far succeeded", "steps": steps or "(no steps yet)"}


def preflight(workflow: Dict[str, Any]) -> List[Dict[str, Any]]:
    """What stops a run before it starts: missing hosts, unapproved host keys, missing credentials.

    Returns [{"message", "device_id"}]; empty when the run can start.
    """
    devices = {d["id"]: d for d in database.list_devices()}
    creds = {c["id"] for c in database.list_credentials()}
    out, seen = [], set()
    for s in workflow["steps"]:
        for host in (s.get("device_ids") or [s.get("device_id")]):
            if host and host not in devices and ("gone", host) not in seen:
                seen.add(("gone", host))
                out.append({"message": f"Workflow '{workflow['name']}': a host it uses no longer exists", "device_id": None})
        if s["type"] != "command":
            continue
        if s["credential_id"] not in creds and ("cred", s["credential_id"]) not in seen:
            seen.add(("cred", s["credential_id"]))
            out.append({"message": f"Workflow '{workflow['name']}': '{describe(s, {})}' has no stored SSH credential",
                        "device_id": None})
        for host in s["device_ids"]:
            if host in devices and ("key", host) not in seen and not database.get_host_keys(host):
                seen.add(("key", host))
                out.append({"message": f"Workflow '{workflow['name']}' cannot run on {devices[host]['hostname']}: "
                                       "its SSH host key is not approved (Host keys on the Automation page)",
                            "device_id": host})
    return out


class WorkflowManager:
    """Starts runs on their own threads, one at a time per workflow, and cancels them."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.active: Dict[int, WorkflowRun] = {}

    def start(self, workflow: Dict[str, Any], trigger: str) -> int:
        with self.lock:
            if workflow["id"] in self.active:
                raise WorkflowError("This workflow is already running")
            run_id = database.start_workflow_run(workflow["id"], trigger)
            run = WorkflowRun(workflow, run_id, trigger)
            self.active[workflow["id"]] = run

        def body() -> None:
            try:
                run.run()
            finally:
                with self.lock:
                    self.active.pop(workflow["id"], None)

        threading.Thread(target=body, name=f"workflow-{workflow['id']}", daemon=True).start()
        return run_id

    def cancel(self, run_id: int) -> bool:
        with self.lock:
            for run in self.active.values():
                if run.run_id == run_id:
                    run.cancelled.set()
                    return True
        return False

    def running(self) -> Dict[int, int]:
        with self.lock:
            return {wid: r.run_id for wid, r in self.active.items()}


MANAGER = WorkflowManager()
