"""Browser tests: drives the real UI in headless Edge/Chrome against an isolated server.

Run:  py -3.15 tests/browser_checks.py
Optional: HM_TEST_SSH_HOST=<ip of a host running sshd> enables the host key
approval and task run checks (no login succeeds: a dummy credential is used).

The script starts its own server process on a free port with a temporary
database and vault key (see tests/_env.py), so the live server and data are
not touched. Results are printed and written to tests/results/browser.json.
"""

import json
import os
import subprocess
import sys
import time
import traceback
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tests import _env  # noqa: E402
from tests.cdp import Browser  # noqa: E402

BASE = f"http://127.0.0.1:{_env.PORT}"
SSH_HOST = os.environ.get("HM_TEST_SSH_HOST")
RESULTS = []
UI_USER, UI_PASSWORD = "ui-admin", "browser test passphrase"
COOKIE = {"value": ""}


def api(path, body=None, method=None):
    headers = {"Content-Type": "application/json"}
    if COOKIE["value"]:
        headers["Cookie"] = COOKIE["value"]
    req = urllib.request.Request(BASE + path, data=None if body is None else json.dumps(body).encode(),
                                 headers=headers, method=method or ("POST" if body is not None else "GET"))
    with urllib.request.urlopen(req, timeout=30) as r:
        cookie = r.headers.get("Set-Cookie")
        if cookie:
            COOKIE["value"] = cookie.split(";", 1)[0]
        return json.load(r)


def check(name):
    def wrap(fn):
        def run(b):
            t = time.time()
            try:
                detail = fn(b) or ""
                RESULTS.append({"test": name, "ok": True, "detail": detail, "seconds": round(time.time() - t, 1)})
                print(f"  PASS  {name}  {detail}")
            except Exception as exc:
                RESULTS.append({"test": name, "ok": False, "detail": f"{type(exc).__name__}: {exc}", "seconds": round(time.time() - t, 1)})
                print(f"  FAIL  {name}  {type(exc).__name__}: {exc}")
                traceback.print_exc(limit=1)
                # A screenshot of the moment it failed, for whoever reads the result.
                try:
                    import base64
                    shot = b.send("Page.captureScreenshot", {"format": "png"})
                    os.makedirs(os.path.join(_env.ROOT, "tests", "results"), exist_ok=True)
                    with open(os.path.join(_env.ROOT, "tests", "results", f"fail_{fn.__name__}.png"), "wb") as f:
                        f.write(base64.b64decode(shot["data"]))
                except Exception:
                    pass
        run.__name__ = fn.__name__
        return run
    return wrap


def run(b, code):
    """Runs statements in their own block, so const/let names do not collide across calls."""
    return b.eval("{" + code + "}")


def shot(b, name, selector):
    """HM_SHOTS=1: a picture of one element in tests/results (for reviewing a screen by eye)."""
    if not os.environ.get("HM_SHOTS"):
        return
    import base64
    b.eval(f"document.querySelector({json.dumps(selector)}).scrollIntoView(); true")
    time.sleep(0.8)
    r = rect(b, selector)
    data = b.send("Page.captureScreenshot", {"format": "png", "clip": {"x": r["x"], "y": r["y"], "width": r["w"], "height": r["h"], "scale": 1}})
    os.makedirs(os.path.join(_env.ROOT, "tests", "results"), exist_ok=True)
    with open(os.path.join(_env.ROOT, "tests", "results", f"shot_{name}.png"), "wb") as f:
        f.write(base64.b64decode(data["data"]))


def goto(b, hash_):
    b.eval(f"window.location.hash = {json.dumps(hash_)}; true")
    time.sleep(0.6)


def rect(b, selector):
    r = b.eval(f"(() => {{ const e = document.querySelector({json.dumps(selector)}); if (!e) return null; "
               f"const r = e.getBoundingClientRect(); return {{x: r.left, y: r.top, w: r.width, h: r.height}}; }})()")
    if not r:
        raise AssertionError(f"element not found: {selector}")
    return r


# --- Login -------------------------------------------------------------------

@check("Login screen blocks the app, rejects a wrong password, then logs in")
def t_login(b):
    b.wait_for("!document.getElementById('auth-screen').classList.contains('hidden')")
    mode = b.eval("document.getElementById('auth-title').textContent")
    assert mode == "Log in", mode
    login = ("document.getElementById('auth-username').value = {u}; document.getElementById('auth-password').value = {p};"
             "document.getElementById('auth-submit').click(); true")
    b.eval(login.format(u=json.dumps(UI_USER), p=json.dumps("not the password")))
    b.wait_for("!document.getElementById('auth-error').classList.contains('hidden')")
    err = b.eval("document.getElementById('auth-error').textContent")
    assert "Wrong username or password" in err, err
    b.eval(login.format(u=json.dumps(UI_USER), p=json.dumps(UI_PASSWORD)))
    b.wait_for("document.getElementById('auth-screen').classList.contains('hidden')")
    b.wait_for("document.querySelectorAll('#dash-grid [data-wid]').length > 0")
    user = b.eval("document.getElementById('header-username').textContent")
    assert user == UI_USER, user
    return "wrong password refused, then signed in"


@check("Required 2FA: the setup screen covers the app, shows the QR code and Log out leaves")
def t_forced_2fa_enrolment(b):
    import database
    database.set_internal_setting("require_2fa", "all")
    try:
        b.eval("api('/api/devices').catch(() => {}); true")
        b.wait_for("!document.getElementById('enrol-screen').classList.contains('hidden')")
        b.wait_for("!!document.querySelector('#enrol-body img')")
        assert b.eval("!document.getElementById('btn-2fa-cancel')"), "Cancel shown on the required screen"
    finally:
        database.set_internal_setting("require_2fa", "off")
    b.eval("document.getElementById('enrol-logout').click(); true")
    b.wait_for("document.readyState === 'complete' && typeof loadDashboard === 'function'")
    b.wait_for("!document.getElementById('auth-screen').classList.contains('hidden')")
    b.eval("document.getElementById('auth-username').value = %s; document.getElementById('auth-password').value = %s;"
           "document.getElementById('auth-submit').click(); true" % (json.dumps(UI_USER), json.dumps(UI_PASSWORD)))
    b.wait_for("document.getElementById('auth-screen').classList.contains('hidden')")
    return "screen over the app, QR drawn, logged out and back in"


@check("Log out returns to the login screen")
def t_logout(b):
    b.eval("document.getElementById('btn-logout').click(); true")
    b.wait_for("!document.getElementById('auth-screen').classList.contains('hidden')")
    b.eval("document.getElementById('auth-username').value = %s; document.getElementById('auth-password').value = %s;"
           "document.getElementById('auth-submit').click(); true" % (json.dumps(UI_USER), json.dumps(UI_PASSWORD)))
    b.wait_for("document.getElementById('auth-screen').classList.contains('hidden')")
    return "logged out and back in"


@check("Signed out: the login screen is the whole page, nothing of the app behind it")
def t_login_page(b):
    assert b.eval("document.documentElement.dataset.auth") == "in"
    # A fresh page starts as pending: the app stays invisible until the session is known.
    assert b.eval("(() => { const h = document.createElement('html'); h.dataset.auth = 'pending'; return h.dataset.auth; })()") == "pending"
    b.eval("document.documentElement.dataset.auth = 'out'; true")
    hidden = b.eval("['sidebar', 'topbar'].map(id => getComputedStyle(document.getElementById(id)).visibility)")
    view = b.eval("getComputedStyle(document.getElementById('view-dashboard')).visibility")
    b.eval("document.documentElement.dataset.auth = 'in'; true")
    assert hidden == ["hidden", "hidden"] and view == "hidden", (hidden, view)
    return "sidebar, top bar and pages hidden while signed out"


@check("HTTPS lost: the login page has no form, only the notice")
def t_https_lost_login(b):
    # The status as another computer would get it while HTTPS has failed.
    b.eval("window.__realFetch = window.fetch; window.fetch = (u, o) => String(u) === '/api/auth/status'"
           " ? Promise.resolve(new Response(JSON.stringify({configured: true, authenticated: false, https_lost: true})))"
           " : window.__realFetch(u, o); ensureSession(); true")
    try:
        b.wait_for("!document.getElementById('auth-screen').classList.contains('hidden')")
        shown = b.eval("['auth-fields', 'auth-submit', 'auth-forgot', 'auth-https-lost']"
                       ".map(id => !document.getElementById(id).classList.contains('hidden'))")
        assert shown == [False, False, False, True], shown
        title = b.eval("document.getElementById('auth-title').textContent")
        assert title == "HTTPS is not working", title
        assert "/root/update.sh" in b.eval("document.getElementById('auth-https-lost').textContent")
    finally:
        b.eval("window.fetch = window.__realFetch; httpsLost = false; const s = document.getElementById('auth-screen');"
               " s.classList.add('hidden'); hide(document.getElementById('auth-https-lost')); show(document.getElementById('auth-submit'));"
               " document.documentElement.dataset.auth = 'in'; if (s._resolve) s._resolve(); true")
    return "form, button and forgot link hidden; the notice says how to get back in"


@check("Audit log: Who and From columns")
def t_audit_columns(b):
    goto(b, "#/audit")
    b.wait_for("document.querySelectorAll('#audit-table-body tr td').length > 1")
    heads = b.eval("[...document.querySelectorAll('#tbl-audit thead th')].map(th => th.textContent)")
    assert heads == ["Time", "Category", "Message", "Who", "From", "Details"], heads
    cells = b.eval("document.querySelector('#audit-table-body tr').children.length")
    assert cells == 6, cells
    who = b.eval("[...document.querySelectorAll('#audit-table-body tr')].map(r => r.children[3].textContent)")
    assert UI_USER in who, who
    return "six columns, rows name who did it"


@check("Dashboards: add one from a template, switch, rename a tile, delete it")
def t_dashboards(b):
    goto(b, "#/dashboard")
    b.wait_for("!!document.querySelector('#dash-grid [data-wid]')")
    b.eval("window.__noAutoDialog = true; document.getElementById('dash-new').click(); true")
    b.wait_for("document.querySelectorAll('.dash-tpl').length === 21")
    run(b, "const f = document.querySelector('.dash-tpl input[value=\"proxmox\"]'); f.checked = true; f.dispatchEvent(new Event('change', {bubbles: true}));")
    assert b.eval("document.getElementById('dash-new-title').value") == "Proxmox"
    run(b, "document.getElementById('dash-new-title').value = 'Rack room'; document.querySelector('.dash-tpl').closest('form').requestSubmit(); window.__noAutoDialog = false;")
    b.wait_for("dashTitle === 'Rack room' && !!document.querySelector('#dash-grid [data-wid]')")
    name = b.eval("dashName")
    assert name != "default"
    assert not b.eval("document.getElementById('dash-pick').classList.contains('hidden')"), "switcher hidden with two dashboards"
    b.wait_for("[...document.querySelectorAll('#dash-grid .widget-body')].every(x => !x.textContent.includes('Loading'))", timeout=15)
    # Switch back to the Overview and again to the new one.
    run(b, "const p = document.getElementById('dash-pick'); p.value = 'default'; p.dispatchEvent(new Event('change'));")
    b.wait_for("dashName === 'default'")
    run(b, f"const p = document.getElementById('dash-pick'); p.value = '{name}'; p.dispatchEvent(new Event('change'));")
    b.wait_for(f"dashName === '{name}'")
    # Rename the first tile from edit mode.
    b.eval("document.getElementById('dash-edit').click(); true")
    b.eval("window.__noAutoDialog = true; document.querySelector('#dash-grid [data-act=rename]').click(); true")
    b.wait_for("!!document.querySelector('form.dialog .dialog-input')")
    run(b, "const d = document.querySelector('form.dialog'); d.querySelector('.dialog-input').value = 'Guests upstairs'; d.requestSubmit(); window.__noAutoDialog = false;")
    b.wait_for("document.querySelector('#dash-grid [data-title]').textContent === 'Guests upstairs'")
    time.sleep(0.6)
    assert api(f"/api/dashboard?name={name}")["layout"][0]["name"] == "Guests upstairs"
    assert not b.eval("document.getElementById('dash-delete').classList.contains('hidden')"), "delete hidden"
    b.eval("document.getElementById('dash-delete').click(); true")
    b.wait_for("dashName !== " + json.dumps(name), timeout=10)
    b.eval("if (dashEditing) document.getElementById('dash-edit').click(); true")
    assert name not in [d["name"] for d in api("/api/dashboards")["dashboards"]]
    return "template picked, switched both ways, tile renamed, dashboard deleted"


# --- Dashboard ---------------------------------------------------------------

@check("Dashboard renders the default tiles")
def t_dashboard(b):
    goto(b, "#/dashboard")
    n = b.wait_for("document.querySelectorAll('#dash-grid [data-wid]').length")
    assert n == len(api("/api/dashboard")["layout"]), n
    return f"{n} tiles"


@check("Resize a tile by dragging its corner (width and height)")
def t_resize(b):
    b.eval("document.getElementById('dash-edit').click(); true")
    b.wait_for("document.getElementById('dash-grid').classList.contains('editing')")
    before = next(w for w in api("/api/dashboard")["layout"] if w["id"] == "w-problems")
    h = rect(b, '[data-wid="w-problems"] .resize-handle')
    colw = b.eval("(document.getElementById('dash-grid').clientWidth - 14 * 3) / 4")
    b.mouse_drag(h["x"] + 8, h["y"] + 8, h["x"] + 8 + colw + 14, h["y"] + 8 + 104)
    time.sleep(0.8)
    after = next(w for w in api("/api/dashboard")["layout"] if w["id"] == "w-problems")
    assert after["span"] == before["span"] + 1 and after["rows"] == before["rows"] + 1, (before, after)
    return f"span {before['span']}->{after['span']}, rows {before['rows']}->{after['rows']}"


@check("Move a tile by dragging its header")
def t_move(b):
    order = [w["id"] for w in api("/api/dashboard")["layout"]]
    src = rect(b, '[data-wid="w-events"] .widget-head')
    dst = rect(b, '[data-wid="w-summary"]')
    b.mouse_drag(src["x"] + 40, src["y"] + 12, dst["x"] + 20, dst["y"] + dst["h"] / 2)
    time.sleep(0.8)
    new = [w["id"] for w in api("/api/dashboard")["layout"]]
    assert new.index("w-events") < new.index("w-summary"), new
    assert new != order
    return "events tile moved before summary"


@check("Change grid width to 8 columns (tile widths scale)")
def t_columns(b):
    span = next(w for w in api("/api/dashboard")["layout"] if w["id"] == "w-wan")["span"]
    run(b, "const s = document.getElementById('dash-columns'); s.value = '8'; s.dispatchEvent(new Event('change')); true")
    time.sleep(0.8)
    d = api("/api/dashboard")
    new = next(w for w in d["layout"] if w["id"] == "w-wan")["span"]
    assert d["columns"] == 8 and new == span * 2, (d["columns"], span, new)
    css = b.eval("getComputedStyle(document.getElementById('dash-grid')).gridTemplateColumns.split(' ').length")
    assert css == 8, css
    return f"wan tile span {span}->{new}"


@check("Graph tile: add, configure in dialog, chart draws")
def t_graph_tile(b):
    run(b, "const s = document.getElementById('dash-add'); s.value = 'graph'; s.dispatchEvent(new Event('change')); true")
    b.wait_for("!document.getElementById('modal-widget').classList.contains('hidden')")
    run(b, f"const s = document.getElementById('widget-device'); s.value = '{DEV_GRAPH}'; s.dispatchEvent(new Event('change')); true")
    b.wait_for("Array.from(document.querySelectorAll('#widget-graph option')).some(o => o.textContent === 'Ping latency')")
    run(b, "const g = document.getElementById('widget-graph'); g.value = Array.from(g.options).find(o => o.textContent === 'Ping latency').value; "
           "document.getElementById('widget-hours').value = '24'; document.getElementById('btn-save-widget').click(); true")
    time.sleep(1.0)
    tile = next(w for w in api("/api/dashboard")["layout"] if w["type"] == "graph")
    assert tile["config"]["title"] == "Ping latency" and tile["config"]["device_id"] == DEV_GRAPH, tile
    b.wait_for(f"!!document.querySelector('[data-wid=\"{tile['id']}\"] svg')", timeout=10)
    return tile["id"]


@check("Tile content redraws to the new size after resizing")
def t_content_follows(b):
    tile = next(w for w in api("/api/dashboard")["layout"] if w["type"] == "graph")
    sel = f'[data-wid="{tile["id"]}"]'
    b.eval(f"document.querySelector('{sel}').scrollIntoView({{block: 'start'}}); true")
    time.sleep(0.3)
    h0 = b.eval(f"document.querySelector('{sel} svg').getAttribute('height')")
    w0 = b.eval(f"document.querySelector('{sel} svg').getAttribute('width')")
    hd = rect(b, f"{sel} .resize-handle")
    colw = b.eval("(document.getElementById('dash-grid').clientWidth - 14 * 7) / 8")
    b.mouse_drag(hd["x"] + 8, hd["y"] + 8, hd["x"] + 8 + 2 * (colw + 14), hd["y"] + 8 + 2 * 104)
    time.sleep(1.2)
    h1 = b.eval(f"document.querySelector('{sel} svg').getAttribute('height')")
    w1 = b.eval(f"document.querySelector('{sel} svg').getAttribute('width')")
    layout = b.eval(f"(() => {{ const w = document.querySelector('{sel}'); const body = w.querySelector('[data-body]'); "
                    f"const host = w.querySelector('.chart-host'); return {{widget: w.clientHeight, body: body.clientHeight, "
                    f"bodyClass: body.className, host: host.clientHeight, hostClass: host.className, "
                    f"display: getComputedStyle(body).display, hostFlex: getComputedStyle(host).flexGrow}}; }})()")
    assert float(h1) > float(h0) and float(w1) > float(w0), (w0, h0, w1, h1, layout)
    b.eval("document.getElementById('dash-edit').click(); true")
    return f"svg {w0}x{h0} -> {w1}x{h1}"


# --- Workflows ---------------------------------------------------------------

def _pointer(b, selector, kind, x=None, y=None):
    """Dispatches a pointer event at the centre of selector (or at x, y)."""
    return b.eval(f"""(() => {{ const el = document.querySelector({json.dumps(selector)}); const r = el.getBoundingClientRect();
        const x = {x if x is not None else 'r.left + r.width / 2'}, y = {y if y is not None else 'r.top + r.height / 2'};
        el.dispatchEvent(new PointerEvent({json.dumps(kind)}, {{bubbles: true, clientX: x, clientY: y, pointerId: 1, button: 0}}));
        return [x, y]; }})()""")


@check("Workflow builder: drag and click steps in, connect, delete, schedule picker, save, run, graph shows the result")
def t_workflow(b):
    # This check answers the in-app confirmation itself (it also checks that one appears).
    b.eval("window.__noAutoDialog = true; true")
    goto(b, "#/automation")
    b.wait_for("typeof openWorkflowModal === 'function' && wfList !== null")
    b.eval("document.getElementById('btn-add-workflow').click(); true")
    b.wait_for("!document.getElementById('modal-workflow').classList.contains('hidden')")
    b.eval("document.getElementById('wf-name').value = 'UI wait flow'; true")
    # A new workflow opens on the Templates tab of the left column; the list is there, its options on the right.
    b.wait_for("!document.querySelector('[data-pal-tpls]').classList.contains('hidden')")
    assert b.eval("!!document.querySelector('[data-pal-tpls] [data-tpl=\"ha_weekly_tidy\"]')"), "host action templates missing"
    b.eval("document.querySelector('[data-pal-tpls] [data-tpl=\"ha_weekly_tidy\"]').click(); true")
    b.wait_for("document.querySelector('#wfb-panel .wfb-panel-title').textContent === 'Weekly tidy-up on Linux hosts'")
    b.eval("document.querySelector('[data-pal-tab=\"steps\"]').click(); true")
    b.wait_for("!document.querySelector('[data-pal-steps]').classList.contains('hidden')")
    assert b.eval("document.querySelectorAll('.wfb-pal-group').length") == 3
    # Click Wait in the palette: added after the trigger and connected to it.
    _pointer(b, "[data-pal='1']", "pointerdown")
    _pointer(b, "[data-pal='1']", "pointerup")
    b.wait_for("document.querySelectorAll('#wfb-canvas .wfb-node').length === 2")
    # Drag "Wait until down" from the palette onto the canvas: dropped at the end of the path.
    _pointer(b, "[data-pal='2']", "pointerdown")
    cx, cy = b.eval("(() => { const r = document.getElementById('wfb-canvas').getBoundingClientRect(); return [r.left + r.width * 0.7, r.top + r.height * 0.6]; })()")
    _pointer(b, "[data-pal='2']", "pointermove", cx, cy)
    _pointer(b, "[data-pal='2']", "pointerup", cx, cy)
    b.wait_for("document.querySelectorAll('#wfb-canvas .wfb-node').length === 3")
    edges = b.eval("wfb.draft.graph.edges.length")
    assert edges == 2, f"{edges} connections after two adds"
    # The dropped step is selected; Delete removes it and its connection.
    b.eval("document.dispatchEvent(new KeyboardEvent('keydown', {key: 'Delete', bubbles: true})); true")
    b.wait_for("document.querySelectorAll('#wfb-canvas .wfb-node').length === 2 && wfb.draft.graph.edges.length === 1")
    # Edit the wait in the side panel.
    b.eval("wfb.sel = {kind: 'node', id: wfb.draft.graph.nodes[1].id}; wfRenderPanel(); true")
    run(b, "const i = document.querySelector('#wfb-panel [data-f=\"seconds\"]'); i.value = '1'; i.dispatchEvent(new Event('input', {bubbles: true})); true")
    # Schedule: every week on Sunday at 04:00, picked without cron.
    run(b, "wfb.sel = {kind: 'node', id: 'trigger'}; wfRenderPanel(); "
           "const k = document.querySelector('#wfb-panel [data-s=\"kind\"]'); k.value = 'weekly'; k.dispatchEvent(new Event('change', {bubbles: true})); true")
    b.wait_for("document.querySelector('#wfb-panel .wfb-summary').textContent === 'Every Sunday at 04:00'")
    b.eval("document.getElementById('btn-save-workflow').click(); true")
    b.wait_for("document.getElementById('modal-workflow').classList.contains('hidden')")
    wf = next(w for w in api("/api/workflows")["workflows"] if w["name"] == "UI wait flow")
    assert [(s["type"], s["seconds"]) for s in wf["steps"]] == [("wait", 1)], wf["steps"]
    assert (wf["trigger_cron"], wf["schedule_text"]) == ("0 4 * * 0", "Every Sunday at 04:00"), wf
    b.wait_for(f"document.querySelector('[data-wf-start=\"{wf['id']}\"]') !== null")
    b.eval(f"document.querySelector('[data-wf-start=\"{wf['id']}\"]').click(); true")
    # In-app confirmation, not the browser's.
    b.wait_for("!!document.querySelector('.dialog-backdrop')")
    b.eval("document.querySelector('.dialog-backdrop [type=submit]').click(); true")
    # The run needs a password confirmation once the login confirmation has expired.
    time.sleep(0.8)
    if b.eval("!document.getElementById('modal-confirm-password').classList.contains('hidden')"):
        b.eval(f"document.getElementById('confirm-password').value = {json.dumps(UI_PASSWORD)};"
               "document.getElementById('confirm-password-form').requestSubmit(); true")
    b.wait_for("!document.getElementById('modal-wf-run').classList.contains('hidden')")
    b.wait_for("document.querySelector('#wf-run-status .status-pill') && document.querySelector('#wf-run-status .status-pill').textContent === 'success'", timeout=20)
    entries = b.eval("document.querySelectorAll('#wf-run-log .wf-log-entry').length")
    b.wait_for("document.querySelectorAll('#wf-run-graph .wfb-node.st-ok').length === 1")
    b.eval("document.getElementById('btn-close-wf-run').click(); true")
    b.eval("window.__noAutoDialog = false; true")
    return f"built by palette click and drag, saved weekly, ran, {entries} log entr{'y' if entries == 1 else 'ies'}, graph marked"


# --- Setup wizard and bulk delete -----------------------------------------

@check("Setup is gone from the menu once applied; an old link to it opens the dashboard")
def t_setup_preview(b):
    # The sandbox started empty, so it counts as a fresh install; mark it set up.
    import setup
    setup.mark_completed()
    b.eval("setupCompleted = true; true")
    assert b.eval("!document.getElementById('nav-setup')"), "Setup still in the menu"
    goto(b, "#/dashboard")
    goto(b, "#/setup")
    b.wait_for("!document.getElementById('view-dashboard').classList.contains('hidden')")
    assert b.eval("document.getElementById('view-setup').classList.contains('hidden')"), "setup opened after it was applied"
    return "no menu entry, #/setup shows the dashboard"


@check("Password confirmation opens on top of the Fix SNMP window")
def t_confirm_on_top(b):
    goto(b, f"#/device/{DEV_GRAPH}")
    b.wait_for("!!document.getElementById('detail-header-name').textContent")
    b.eval("window.__noAutoConfirm = true; document.getElementById('modal-fixsnmp').classList.remove('hidden'); window.__c = promptConfirm(); true")
    b.wait_for("!document.getElementById('modal-confirm-password').classList.contains('hidden')")
    top = b.eval("(() => { const r = document.querySelector('#modal-confirm-password .modal').getBoundingClientRect();"
                 " const el = document.elementFromPoint(r.left + r.width / 2, r.top + 20);"
                 " return el && el.closest('#modal-confirm-password') ? 'confirm' : (el && el.closest('.modal-backdrop') || {}).id; })()")
    b.eval("document.getElementById('btn-cancel-confirm').click(); document.getElementById('modal-fixsnmp').classList.add('hidden'); window.__noAutoConfirm = false; true")
    assert top == "confirm", f"top element belongs to {top}"
    return "password window is on top"


@check("Availability page, device card, chart zoom and enlarge, Proxmox form")
def t_availability(b):
    import availability
    now = int(time.time())
    for i in range(30):
        availability.record(DEV_GRAPH, i != 10, 2.0 + i % 3, ts=now - 1800 + i * 60)
    goto(b, "#/availability")
    b.wait_for("!!document.querySelector('#avail-body .avail-row')")
    rows = b.eval("document.querySelectorAll('#avail-body .avail-row').length")
    assert rows == len(api("/api/availability")["devices"]), rows
    # The scheduler keeps adding failed checks for this (offline) device, so a second API read can
    # already differ from the one the page drew. Compare the chip with the API answer the page drew
    # it from, read in the same JavaScript turn (the page's 30 s refresh cannot come in between).
    chip, page = b.eval(f"[document.querySelector('.avail-row[href=\"#/device/{DEV_GRAPH}\"] .avail-chip').textContent,"
                        f" availData.devices.find(d => d.id === {DEV_GRAPH})]")
    want = page["uptime"]["24h"]
    assert want is not None and want < 100 and chip.startswith(f"{want:.1f}") and chip.endswith("24 h"), (chip, want)
    # And that answer is the server's: no newer than a read made now, which can only have more failed checks.
    later = next(d for d in api("/api/availability")["devices"] if d["id"] == DEV_GRAPH)["uptime"]["24h"]
    assert later <= want, (later, want)
    goto(b, f"#/device/{DEV_GRAPH}")
    b.wait_for("!document.getElementById('detail-availability').classList.contains('hidden')")
    assert "incident" in b.eval("document.getElementById('detail-availability').textContent")
    goto(b, f"#/device/{DEV_GRAPH}/graphs")
    b.wait_for("!!document.querySelector('#graph-grid .chart-host svg')")
    run(b, "const s = document.querySelector('#graph-grid .chart-host svg'); const r = s.getBoundingClientRect();"
           "const ev = (t, x) => new MouseEvent(t, {clientX: x, clientY: r.top + 40, bubbles: true, button: 0});"
           "s.dispatchEvent(ev('mousedown', r.left + r.width * 0.6)); window.dispatchEvent(ev('mousemove', r.left + r.width * 0.9));"
           "window.dispatchEvent(ev('mouseup', r.left + r.width * 0.9)); true")
    b.wait_for("!!document.querySelector('#graph-grid [data-chart-reset]')")
    b.eval("document.querySelector('#graph-grid [data-chart-reset]').click(); true")
    b.wait_for("!document.querySelector('#graph-grid [data-chart-reset]')")
    b.eval("document.querySelector('#graph-grid [data-chart-enlarge]').click(); true")
    b.wait_for("!!document.querySelector('.chart-modal .chart-modal-host svg')")
    tall = b.eval("document.querySelector('.chart-modal .chart-modal-host svg').getBoundingClientRect().height")
    assert tall > 250, tall
    # The readout bubble shows above the enlarged window, not behind it.
    run(b, "const s = document.querySelector('.chart-modal .chart-modal-host svg'); const r = s.getBoundingClientRect();"
           "s.dispatchEvent(new MouseEvent('mousemove', {clientX: r.left + r.width * 0.8, clientY: r.top + r.height / 2, bubbles: true})); true")
    b.wait_for("!document.getElementById('chart-tooltip').classList.contains('hidden')")
    zt, zm = b.eval("[getComputedStyle(document.getElementById('chart-tooltip')).zIndex, getComputedStyle(document.querySelector('.chart-modal').closest('.modal-backdrop')).zIndex].map(Number)")
    assert zt > zm, (zt, zm)
    b.eval("document.querySelector('.chart-modal [data-hours=\"1\"]').click(); true")
    b.wait_for("!!document.querySelector('.chart-modal .chart-modal-host svg')")
    b.eval("document.querySelector('.chart-modal [data-close]').click(); true")
    # Proxmox: off, it is out of the menu and its form is hidden; switching it on shows the form.
    assert b.eval("document.getElementById('nav-proxmox').classList.contains('hidden')"), "Proxmox in the menu while off"
    goto(b, "#/settings/proxmox")
    b.wait_for("document.getElementById('pve-enabled').value === 'off'")
    assert b.eval("document.getElementById('pve-config').classList.contains('hidden')"), "form shown while off"
    run(b, "const s = document.getElementById('pve-enabled'); s.value = 'on'; s.dispatchEvent(new Event('change')); true")
    b.wait_for("!document.getElementById('pve-config').classList.contains('hidden')")
    assert b.eval("document.getElementById('nav-proxmox').classList.contains('hidden')"), "in the menu before a connection is saved"
    run(b, "const s = document.getElementById('pve-enabled'); s.value = 'off'; s.dispatchEvent(new Event('change')); true")
    b.wait_for("document.getElementById('pve-config').classList.contains('hidden')")
    return f"{rows} rows, {chip} with incidents listed, zoom and reset, enlarged {tall:.0f} px, Proxmox switch shows and hides its form"


@check("Settings: its menu replaces the main menu, Back returns to the page you came from")
def t_settings_sidebar(b):
    goto(b, "#/events")
    goto(b, "#/settings/polling")
    visible = "(id => { const e = document.getElementById(id); return !!e && e.offsetParent !== null; })"
    assert b.eval(f"{visible}('settings-nav')"), "settings menu not shown in the sidebar"
    assert not b.eval(f"{visible}('nav-dashboard')"), "main menu still shown in Settings"
    assert b.eval("!!document.querySelector('#sidebar #settings-nav a[data-section=polling].active')")
    assert b.eval("document.getElementById('settings-back').getAttribute('href')") == "#/events"
    b.eval("document.getElementById('settings-back').click(); true")
    b.wait_for("window.location.hash === '#/events'")
    b.wait_for(f"{visible}('nav-dashboard')")
    assert not b.eval(f"{visible}('settings-nav')"), "settings menu left behind"
    return "menu swapped in Settings and back on leaving"


@check("Settings, Backups: no backup passphrase shows the warning and the command; a passphrase hides it")
def t_backup_passphrase_bar(b):
    goto(b, "#/settings/backups")
    b.wait_for("!!document.getElementById('backups-panel')")
    # The card as an installed monitor shows it (this test server is a development copy without one).
    base = ("{installed: true, folder: '/var/lib/homelab-monitor/backups', syncthing: true, count: 0, latest: null, "
            "total_bytes: 0, schedule: 'Daily', results: {}, pending: {}, syncthing_settings: {}, key_state: 'withheld', ")
    got = run(b, "const d = document.createElement('div'); "
                 f"d.innerHTML = backupsSection({base} passphrase_set: false}}); "
                 "const bar = d.querySelector('#bk-no-passphrase'); "
                 f"const e = document.createElement('div'); e.innerHTML = backupsSection({base} passphrase_set: true, key_state: 'sealed'}}); "
                 "const dev = document.createElement('div'); dev.innerHTML = backupsSection(Object.assign({base} passphrase_set: false}}, {{installed: false}})); "
                 "[!!bar && bar.textContent.includes('/root/backup-passphrase.sh'), d.textContent.includes('Left out of backups that leave this box'), "
                 "!!e.querySelector('#bk-no-passphrase'), e.textContent.includes('Sealed with your passphrase'), "
                 "!!dev.querySelector('#bk-no-passphrase')]")
    assert got == [True, True, False, True, False], got
    return "warning and command shown without a passphrase, hidden with one and on a development copy"


@check("Updates: red number on Settings while a version waits, skip hides it; new version card, live progress and result")
def t_updates(b):
    result = os.path.join(_env.TMP, "data", "update-check.result.json")
    with open(result, "w", encoding="utf-8") as f:
        json.dump({"ok": True, "newer": True, "latest": "98.0.0", "current": "0.0.1", "time": int(time.time()),
                   "published": "2026-12-01T00:00:00Z", "changes": [
                       {"version": "98.0.0", "notes": "### Better\n- **One** thing\n- `two` <script>x</script>"},
                       {"version": "97.0.0", "notes": "- Older"}]}, f)
    try:
        goto(b, "#/dashboard")
        run(b, "refreshUpdateBadge(); true")
        b.wait_for("!document.getElementById('nav-settings-badge').classList.contains('hidden')")
        goto(b, "#/settings/updates")
        b.wait_for("!!document.querySelector('#settings-nav a[data-section=updates] .nav-badge')")
        # The card as an installed monitor shows it (this test server is a development copy).
        base = ("{installed: true, current: '0.0.1', repository: 'https://example.com/r', rollback: {}, skipped: '', "
                "waiting: 1, pending: {check: false, work: false}, check: {ok: true, newer: true, latest: '98.0.0', "
                "published: '2026-12-01', time: Math.floor(Date.now() / 1000), changes: [{version: '98.0.0', "
                "notes: '### Better\\n- **One** thing\\n- <script>x</script>'}, {version: '97.0.0', notes: '- Older'}]}}")
        hero = run(b, f"const d = document.createElement('div'); d.id = 'upd-test'; d.className = 'settings-card'; "
                      f"d.innerHTML = updatesSection({base}); document.getElementById('settings-sections').appendChild(d); "
                      "[!!d.querySelector('[data-update-action=install]'), !!d.querySelector('[data-update-action=skip]'), "
                      "d.querySelectorAll('.update-change').length, d.querySelectorAll('.update-notes-body li').length, "
                      "!!d.querySelector('.update-notes-body strong'), !!d.querySelector('.update-notes-body script')]")
        assert hero == [True, True, 2, 3, True, False], hero
        shot(b, "update_available", "#upd-test")
        prog = run(b, f"const s = Object.assign({base}, {{pending: {{check: false, work: true}}, progress: {{state: 'running', "
                      "to: '98.0.0', current: 'backup', steps: {download: 'ok', verify: 'ok', ready: 'ok', copy: 'ok', check: 'ok', "
                      "repair: 'skip', backup: 'run'}}}); const d = document.getElementById('upd-test'); d.innerHTML = updatesSection(s); "
                      "[d.querySelectorAll('.ustep-ok').length, d.querySelectorAll('.ustep-run').length, "
                      "d.querySelector('.update-pct').textContent, d.querySelector('.update-bar span').getBoundingClientRect().width > 50, "
                      "!!d.querySelector('[data-update-action=install]')]")
        assert prog == [5, 1, "72%", True, False], prog
        shot(b, "update_progress", "#upd-test")
        res = run(b, f"const s = Object.assign({base}, {{progress: {{state: 'failed', to: '98.0.0', finished: 5, error: 'It did not start', "
                     "steps: {health: 'fail'}}}); const d = document.getElementById('upd-test'); d.innerHTML = updatesSection(s); "
                     "[!!d.querySelector('.update-result.failed'), d.querySelector('.update-error').textContent, "
                     "!!d.querySelector('[data-update-action=dismiss]')]")
        assert res == [True, "It did not start", True], res
        shot(b, "update_failed", "#upd-test")
        shot(b, "update_nav", "#settings-nav")
        run(b, "document.getElementById('upd-test').remove(); true")
        # Skipping that version takes the number away until a newer one is out.
        api("/api/updates/skip", {"version": "98.0.0"})
        run(b, "refreshUpdateBadge(); true")
        b.wait_for("document.getElementById('nav-settings-badge').classList.contains('hidden')")
        api("/api/updates/unskip", {})
    finally:
        os.remove(result)
    run(b, "refreshUpdateBadge(); true")
    b.wait_for("document.getElementById('nav-settings-badge').classList.contains('hidden')")
    goto(b, "#/dashboard")          # leave Settings, so the next check loads it fresh
    return "number shown and skipped; card, progress at 72% and failure drawn"


@check("Settings, Demo data: only while there is demo data; Remove turns it off and the entry goes")
def t_demo_card(b):
    import sqlite3

    def setting(key, value=None):
        with sqlite3.connect(os.environ["MONITOR_DB_PATH"]) as conn:
            if value is not None:
                conn.execute("INSERT INTO settings (key, value, description, updated_at) VALUES (?, ?, '', 0) "
                             "ON CONFLICT (key) DO UPDATE SET value = excluded.value;", (key, value))
            row = conn.execute("SELECT value FROM settings WHERE key = ?;", (key,)).fetchone()
        return row[0] if row else None
    goto(b, "#/settings/alerts")
    assert not b.eval("!!document.querySelector('#settings-nav a[data-section=demo]')"), "Demo data shown without demo data"
    setting("demo_mode", "on")
    setting("demo_seed", "{}")       # nothing recorded: removing deletes no device here
    before = len(api("/api/devices")["devices"])
    goto(b, "#/dashboard")
    goto(b, "#/settings/demo")
    b.wait_for("!!document.querySelector('#settings-nav a[data-section=demo]') && !!document.getElementById('btn-demo-remove')")
    run(b, "document.getElementById('btn-demo-remove').click(); true")
    b.wait_for("!document.querySelector('#settings-nav a[data-section=demo]')", timeout=20)
    assert setting("demo_mode") == "off"
    assert len(api("/api/devices")["devices"]) == before, "a device was removed"
    goto(b, "#/dashboard")
    return "shown while on, removed with a password, entry gone"


@check("Notifications, Messages: each message box is the card's full width")
def t_message_rows(b):
    api("/api/settings", {"telegram_enabled": "on"})
    goto(b, "#/settings/notify")
    b.wait_for("!!document.querySelector('[data-ntab-go=messages]')")
    b.eval("document.querySelector('[data-ntab-go=messages]').click(); true")
    b.wait_for("!!document.querySelector('.setting-row.tpl-row:not(.hidden):not(.ntab-off) textarea')")
    card = b.eval("document.querySelector('[data-card=notify]').getBoundingClientRect().width")
    box = b.eval("document.querySelector('.setting-row.tpl-row:not(.hidden):not(.ntab-off) textarea').getBoundingClientRect().width")
    api("/api/settings", {"telegram_enabled": "off"})
    assert box > card * 0.85, (box, card)
    return f"message box {box:.0f} px of a {card:.0f} px card"


@check("Notifications, Commands: the builder edits /status and adds, previews and deletes a command of your own")
def t_command_replies(b):
    api("/api/settings", {"telegram_enabled": "on"})
    try:
        goto(b, "#/settings/notify")
        b.wait_for("!!document.querySelector('[data-ntab-go=commands]')")
        b.eval("document.querySelector('[data-ntab-go=commands]').click(); true")
        b.wait_for("!!document.querySelector('[data-bot-edit=status]')")
        rows = b.eval("[...document.querySelectorAll('.setting-row:not(.ntab-off) textarea')].length")
        assert rows == 0, rows                                            # replies live in the builder, not as rows
        # A built-in reply: edit, live preview from the server, save.
        b.eval("window.__noAutoDialog = true; document.querySelector('[data-bot-edit=status]').click(); true")
        b.wait_for("!!document.querySelector('.bot-editor textarea.bot-tpl')")
        b.eval("const ta = document.querySelector('.bot-editor textarea.bot-tpl'); ta.value = 'Up {up} of {total}\\n{down_list}';"
               "ta.dispatchEvent(new Event('input', {bubbles: true})); true")
        b.wait_for("document.querySelector('.bot-preview').textContent.startsWith('Up ')", timeout=10)
        preview = b.eval("document.querySelector('.bot-preview').textContent")
        assert "{" not in preview, preview
        b.eval("document.querySelector('.bot-editor [type=submit]').click(); true")
        b.wait_for("!document.querySelector('.bot-editor')", timeout=10)
        assert api("/api/settings")["bot_tpl_status"].startswith("Up {up}")
        # A command of your own: devices, one picked, a figure placeholder, preview, save, then delete.
        b.eval("document.querySelector('[data-bot-add]').click(); true")
        b.wait_for("!!document.querySelector('.bot-editor .bot-pick-item')", timeout=10)
        run(b, "const f = document.querySelector('.bot-editor'); f.querySelector('.bot-f-name').value = 'rack';"
               "f.querySelector('.bot-f-desc').value = 'The rack';"
               "const box = f.querySelector('.bot-pick-item input'); box.checked = true; box.dispatchEvent(new Event('change', {bubbles: true}));"
               "const line = f.querySelector('textarea[data-part=line]'); line.value = '>> {device} {state}';"
               "line.dispatchEvent(new Event('input', {bubbles: true})); true")
        b.wait_for("document.querySelector('.bot-preview').textContent.includes('>> ')", timeout=10)
        run(b, "const f = document.querySelector('.bot-editor'); const s = f.querySelector('.bot-f-sort'); s.value = 'device';"
               "s.dispatchEvent(new Event('change', {bubbles: true})); f.querySelector('.bot-f-limit').value = '1';"
               "f.querySelector('.bot-f-limit').dispatchEvent(new Event('input', {bubbles: true})); true")
        vars_ =b.eval("[...document.querySelectorAll('.bot-vars-item code')].map(c => c.textContent).join(' ')")
        assert "{uptime_7d}" in vars_, vars_
        b.eval("document.querySelector('.bot-editor [type=submit]').click(); true")
        b.wait_for("!!document.querySelector('[data-bot-edit=rack]')", timeout=10)
        saved = api("/api/notify/bot-commands")["custom"]
        assert [c["name"] for c in saved] == ["rack"] and len(saved[0]["pick"]) == 1 and (saved[0]["sort"], saved[0]["limit"]) == ("device", 1), saved
        b.eval("window.__noAutoDialog = false; document.querySelector('[data-bot-del=rack]').click(); true")
        b.wait_for("!document.querySelector('[data-bot-edit=rack]')", timeout=10)
    finally:
        b.eval("window.__noAutoDialog = false; document.querySelectorAll('.bot-editor').forEach(f => f.closest('.modal-backdrop').remove()); true")
        api("/api/notify/bot-commands", {"custom": [], "off": [], "texts": {"status": ""}})
        api("/api/settings", {"telegram_enabled": "off"})
    return f"preview {preview!r}; /rack added and deleted"


@check("Add a port check: SNMP fields hide, Test connection, save")
def t_service_check(b):
    goto(b, "#/devices")
    b.eval("document.getElementById('btn-open-add').click(); true")
    b.wait_for("!document.getElementById('modal-add-device').classList.contains('hidden')")
    b.eval("document.querySelector('#add-kind [data-kind=service]').click(); true")
    assert b.eval("document.getElementById('input-community').closest('.form-row').classList.contains('hidden')"), "SNMP fields still shown"
    assert not b.eval("document.getElementById('input-service-port').closest('.form-group').classList.contains('hidden')")
    # The test server's own port is open, so the check finds it answering.
    run(b, f"document.getElementById('input-ip').value = '127.0.0.1'; document.getElementById('input-service-port').value = '{_env.PORT}';"
           "document.getElementById('input-hostname').value = 'ui-web'; true")
    b.eval("document.getElementById('btn-probe').click(); true")
    b.wait_for("document.getElementById('probe-results-box').classList.contains('probe-success')")
    b.eval("document.getElementById('btn-submit-device').click(); true")
    b.wait_for("document.getElementById('modal-add-device').classList.contains('hidden')")
    dev = next(d for d in api("/api/devices")["devices"] if d["hostname"] == "ui-web")
    assert (dev["profile_id"], dev["service_port"]) == ("service_check", _env.PORT), dev
    b.wait_for("document.getElementById('device-table-body').textContent.includes('TCP port')")
    api(f"/api/devices/{dev['id']}", method="DELETE")
    return f"port {_env.PORT} answered, saved as a port check"


@check("Add: a ping-only device (no SNMP fields), and the full port range warns first")
def t_add_ping(b):
    goto(b, "#/devices")
    b.eval("document.getElementById('btn-open-add').click(); true")
    b.wait_for("!document.getElementById('modal-add-device').classList.contains('hidden')")
    b.eval("document.querySelector('#add-kind [data-kind=ping]').click(); true")
    visible = "(id => { const e = document.getElementById(id); return !!e && e.offsetParent !== null; })"
    assert not b.eval(f"{visible}('input-community')"), "SNMP community shown for a ping device"
    assert not b.eval(f"{visible}('select-profile')"), "template shown for a ping device"
    assert b.eval("document.getElementById('btn-probe').textContent") == "Test ping"
    run(b, "document.getElementById('input-ip').value = '127.0.0.1'; document.getElementById('input-hostname').value = 'ui-ping'; true")
    b.eval("document.getElementById('btn-probe').click(); true")
    b.wait_for("document.getElementById('probe-results-box').className.includes('probe-')", timeout=20)
    b.eval("document.getElementById('check-allow-unverified').checked = true; document.getElementById('btn-submit-device').click(); true")
    b.wait_for("document.getElementById('modal-add-device').classList.contains('hidden')")
    dev = next(d for d in api("/api/devices")["devices"] if d["hostname"] == "ui-ping")
    assert (dev["profile_id"], dev["snmp"]) == ("ping_only", False), dev
    b.wait_for("document.getElementById('device-table-body').textContent.includes('Ping only')")
    # Service scan: the full range is offered, with a warning.
    b.eval("document.getElementById('btn-open-add').click(); true")
    b.eval("document.querySelector('#add-kind [data-kind=service]').click(); document.querySelector('#add-how [data-how=scan]').click(); true")
    assert not b.eval(f"{visible}('scan-port-warn')"), "warning shown before choosing all ports"
    b.eval("document.querySelector('#scan-port-mode [data-port-mode=all]').click(); true")
    assert b.eval(f"{visible}('scan-port-warn')"), "no warning for the full range"
    b.eval("document.getElementById('btn-close-modal').click(); true")
    api(f"/api/devices/{dev['id']}", method="DELETE")
    return "ping device added without SNMP, full range warns"


@check("Setup, Services step: open ports on the ticked devices become port checks")
def t_setup_services(b):
    import database
    import setup as site_setup
    database.set_internal_setting(site_setup.COMPLETED_KEY, "0")
    try:
        b.eval("setupCompleted = false; applySetupLock(); true")
        goto(b, "#/setup")
        b.wait_for("!!setupState")
        run(b, """
            const s = setupState;
            s.step = SETUP_STEPS.findIndex(x => x[0] === 'services');
            s.picked = {'192.168.77.10': {hostname: 'nas', profile_id: 'ping_only'}};
            s.services.wanted = true;
            s.services.job = {id: 'x', finished: true, done: 1, total: 1, seconds: 2, results: []};
            s.services.results = [{ip: '192.168.77.10', open_ports: [22, 5001], monitored_ports: []}];
            renderSetup(); true""")
        b.wait_for("!!document.querySelector('[data-svc=\"192.168.77.10:5001\"]')")
        b.eval("const c = document.querySelector('[data-svc=\"192.168.77.10:5001\"]'); c.checked = true; c.dispatchEvent(new Event('change', {bubbles: true})); true")
        devices = b.eval("JSON.stringify(setupPayload().devices)")
        devices = json.loads(devices)
        assert {"ip_address": "192.168.77.10", "hostname": "nas", "profile_id": "ping_only"} in devices, devices
        svc = [d for d in devices if d.get("service_port")]
        assert svc == [{"ip_address": "192.168.77.10", "service_port": 5001, "hostname": "nas web 5001", "profile_id": "service_check"}], svc
        body = b.eval("document.getElementById('setup-body').textContent")
        assert "Look for services on these devices?" in body and "All 65,535 ports" in body, body[:300]
    finally:
        site_setup.mark_completed()
        b.eval("setupCompleted = true; applySetupLock(); true")
    return "ticked port becomes a service_check in the setup payload"


@check("Groups and tags: add in Settings, tag in Edit and in bulk, filter the list, alert rules by tag")
def t_groups_tags(b):
    ids = [api("/api/devices", {"hostname": f"tg-{i}", "ip_address": f"192.0.2.{110 + i}", "profile_id": "ping_only"})["device_id"] for i in (1, 2)]
    goto(b, "#/settings/groups")
    b.wait_for("!!document.querySelector('[data-taxo-add=group] input')")
    run(b, "const f = document.querySelector('[data-taxo-add=group]'); f.querySelector('input').value = 'Garage'; f.requestSubmit(); true")
    b.wait_for("document.getElementById('taxonomy-settings').textContent.includes('Garage')")
    run(b, "const f = document.querySelector('[data-taxo-add=tag]'); f.querySelector('input').value = 'critical'; f.requestSubmit(); true")
    b.wait_for("!!document.querySelector('#taxonomy-settings .tag-chip')")
    gid = next(g["id"] for g in api("/api/taxonomy")["groups"] if g["name"] == "Garage")
    # Edit: tags and the new group.
    goto(b, "#/devices")
    b.wait_for(f"!!document.querySelector('[data-action=edit][data-id=\"{ids[0]}\"]')")
    b.eval(f"document.querySelector('[data-action=edit][data-id=\"{ids[0]}\"]').click(); true")
    b.wait_for("!document.getElementById('modal-edit-device').classList.contains('hidden')")
    b.wait_for(f"[...document.getElementById('edit-group').options].some(o => o.value === '{gid}')")
    run(b, f"document.getElementById('edit-tags').value = 'critical, garage-door'; document.getElementById('edit-group').value = '{gid}';"
           "document.getElementById('btn-save-edit-device').click(); true")
    b.wait_for("document.getElementById('modal-edit-device').classList.contains('hidden')")
    dev = next(d for d in api("/api/devices")["devices"] if d["id"] == ids[0])
    assert (dev["tags"], dev["group"]) == (["critical", "garage-door"], gid), dev
    # Bulk: tick both, add a tag.
    goto(b, "#/dashboard")
    goto(b, "#/devices")
    b.wait_for(f"!!document.querySelector('[data-select=\"{ids[1]}\"]')")
    for i in ids:
        run(b, f"const c = document.querySelector('[data-select=\"{i}\"]'); c.checked = true; c.dispatchEvent(new Event('change', {{bubbles: true}})); true")
    b.eval("window.__noAutoDialog = true; document.getElementById('btn-tag-selected').click(); true")
    # The tag manager: type a new tag, Add, then the confirm button.
    b.wait_for("!!document.querySelector('form.tag-picker .tag-picker-new input')")
    run(b, "const d = document.querySelector('form.tag-picker'); d.querySelector('.tag-picker-new input').value = 'lab';"
           "d.querySelector('[data-new]').click(); d.requestSubmit(); true")
    b.eval("window.__noAutoDialog = false; true")
    b.wait_for("document.getElementById('device-table-body').textContent.includes('lab')", timeout=15)
    tags = {d["id"]: d["tags"] for d in api("/api/devices")["devices"]}
    assert "lab" in tags[ids[0]] and "lab" in tags[ids[1]], tags
    # Filter the list by tag: only the device tagged critical stays.
    b.wait_for("[...document.getElementById('devices-filter-tag').options].some(o => o.value === 'critical')")
    run(b, "const t = document.getElementById('devices-filter-tag'); t.value = 'critical'; t.dispatchEvent(new Event('change')); true")
    shown = b.eval("[...document.querySelectorAll('#device-table-body [data-select]')].map(c => Number(c.dataset.select))")
    assert shown == [ids[0]], shown
    run(b, "const t = document.getElementById('devices-filter-tag'); t.value = ''; t.dispatchEvent(new Event('change')); true")
    # Alert rules for the tag open from its row in Settings.
    goto(b, "#/settings/alerts/tag/critical")
    b.wait_for("document.getElementById('ar-scope').value === 'tag' && document.getElementById('ar-target').value === 'critical'")
    # A dashboard tile can show one tag.
    goto(b, "#/dashboard")
    b.eval("document.getElementById('dash-edit').click(); true")
    b.wait_for("!!document.querySelector('#dash-grid [data-act-filter]')")
    opts = b.eval("[...document.querySelector('#dash-grid [data-act-filter]').options].map(o => o.value)")
    assert "tag:critical" in opts and f"group:{gid}" in opts, opts
    b.eval("document.getElementById('dash-edit').click(); true")
    for i in ids:
        api(f"/api/devices/{i}", method="DELETE")
    api("/api/taxonomy", {"kind": "group", "action": "delete", "id": gid}, method="PUT")
    return "group and tag added, Edit and bulk tagging, tag filter, alert rules by tag, tile filter"


@check("HTTPS: asked once after an upgrade, Keep HTTP ends it; Settings, HTTPS shows the chosen mode's form")
def t_https(b):
    import database
    database.set_internal_setting("tls_prompt", "pending")
    # The question comes with the features check that runs when the user is applied (as on page load).
    b.eval("tlsAsked = false; refreshFeatures(); true")
    b.wait_for("!!document.querySelector('.tls-ask')")
    b.eval("document.querySelector('[data-tls-ask=\"keep\"]').click(); true")
    b.wait_for("!document.querySelector('.tls-ask')")
    assert api("/api/features")["tls_prompt"] is False, "still asking"
    goto(b, "#/settings/https")
    b.wait_for("document.getElementById('tls-mode').value === 'off'")
    shown = "[...document.querySelectorAll('#settings-https [data-tls]')].filter(f => !f.classList.contains('hidden')).map(f => f.dataset.tls)"
    assert b.eval(shown) == [], b.eval(shown)
    for mode in ("self-signed", "own"):
        run(b, f"const s = document.getElementById('tls-mode'); s.value = '{mode}'; s.dispatchEvent(new Event('change')); true")
        assert b.eval(shown) == [mode], (mode, b.eval(shown))
    assert "localhost" in b.eval("document.getElementById('tls-names-help').textContent")
    # A wrong pair is refused with the reason, and nothing changes.
    run(b, "document.getElementById('tls-cert').value = 'not a certificate'; document.getElementById('tls-key').value = 'nor a key';"
           "document.getElementById('tls-own').requestSubmit(); true")
    b.wait_for("document.getElementById('tls-msg').classList.contains('text-err')")
    assert api("/api/tls")["mode"] == "off"
    return "question shown and answered, forms follow the choice, a bad certificate is refused"


@check("Tags from the Devices list (+ tag), and a dashboard tile filtered by tag when it is added")
def t_tag_quick(b):
    goto(b, "#/devices")
    b.wait_for(f"!!document.querySelector('[data-action=\"tags\"][data-id=\"{DEV_GRAPH}\"]')")
    assert not b.eval("document.getElementById('devices-filter-tag').classList.contains('hidden')"), "tag filter hidden"
    # The suite answers dialogs by itself; this one is filled in by the check.
    b.eval("window.__noAutoDialog = true; true")
    b.eval(f"document.querySelector('[data-action=\"tags\"][data-id=\"{DEV_GRAPH}\"]').click(); true")
    b.wait_for("!!document.querySelector('form.tag-picker')")
    # Applied tags are listed as chips with a remove button; the count bubble is on the row.
    run(b, "const d = document.querySelector('form.tag-picker'); d.querySelector('.tag-picker-new input').value = 'rack';"
           "d.querySelector('[data-new]').click(); "
           "if (!d.querySelector('[data-applied] [data-remove=\"rack\"]')) throw new Error('rack not applied in the picker');"
           "d.requestSubmit(); window.__noAutoDialog = false; true")
    b.wait_for(f"(lastFleet && lastFleet[0].find(d => d.id === {DEV_GRAPH}) || {{tags: []}}).tags.includes('rack')")
    b.wait_for(f"!!document.querySelector('[data-action=\"tags\"][data-id=\"{DEV_GRAPH}\"] .tag-count')")
    goto(b, "#/dashboard")
    b.wait_for("!!document.querySelector('#dash-grid [data-wid]')")
    b.eval("document.getElementById('dash-edit').click(); true")
    run(b, "window.__noAutoDialog = true; const s = document.getElementById('dash-add'); s.value = 'problems'; s.dispatchEvent(new Event('change')); true")
    b.wait_for("!!document.getElementById('wf-filter')")
    opts = b.eval("[...document.getElementById('wf-filter').options].map(o => o.value)")
    assert "tag:rack" in opts, opts
    run(b, "document.getElementById('wf-filter').value = 'tag:rack'; document.getElementById('wf-filter').closest('form').requestSubmit(); window.__noAutoDialog = false; true")
    b.wait_for("dashLayout.some(w => w.type === 'problems' && w.config.filter === 'tag:rack')")
    b.eval("document.getElementById('dash-edit').click(); true")
    time.sleep(0.8)
    assert any(w["type"] == "problems" and w["config"].get("filter") == "tag:rack" for w in api("/api/dashboard")["layout"])
    return "tag added from the list, filter always shown, new Problems tile shows tag rack"


@check("Custom SNMP tab: custom value with its graph, Add to overview, browse built in; Overview: Choose graphs")
def t_custom_snmp(b):
    import database
    r = api("/api/custom-oids", {"scope": "device", "target": str(DEV_GRAPH), "oid": "1.3.6.1.4.1.9999.1.1.0",
                                 "label": "Box temperature", "unit": "C", "kind": "gauge", "scale": 1})
    cid = r.get("id") or next(c["id"] for c in api(f"/api/custom-oids?device={DEV_GRAPH}")["definitions"] if c["label"] == "Box temperature")
    now = int(time.time())
    for i in range(20):
        database.record_metric(DEV_GRAPH, f"custom.{cid}", 30 + i % 4, timestamp=now - 1200 + i * 60)
    goto(b, f"#/device/{DEV_GRAPH}/snmp")
    b.wait_for(f"!!document.querySelector('[data-coid-chart=\"{cid}\"] svg')", timeout=15)
    assert not b.eval("document.querySelector('#detail-tabs [data-tab=\"snmp\"]').classList.contains('hidden')")
    assert "33" in b.eval(f"document.querySelector('[data-coid-now=\"{cid}\"]').textContent")
    assert not b.eval("!!document.querySelector('[data-panel=\"latest\"] #custom-oids-panel')"), "still on Latest Data"
    b.eval(f"document.querySelector('[data-overview-pin=\"custom.{cid}\"]').click(); true")
    b.wait_for(f"Array.isArray(lastDetail.overview_graphs) && lastDetail.overview_graphs.includes('custom.{cid}')")
    assert f"custom.{cid}" in api(f"/api/devices/{DEV_GRAPH}")["overview_graphs"]
    # Browse opens the walk inside the tab (the test device does not answer; only the panel is checked).
    b.eval("document.getElementById('btn-snmp-walk').click(); true")
    assert not b.eval("document.getElementById('snmp-walk-inline').classList.contains('hidden')")
    b.eval("document.getElementById('btn-snmp-walk').click(); true")
    # Overview: the custom graph is there; Choose graphs takes everything off, Use the default brings the set back.
    goto(b, f"#/device/{DEV_GRAPH}")
    b.wait_for("[...document.querySelectorAll('#overview-charts .chart-card')].some(c => c.dataset.title === 'Box temperature (C)')", timeout=15)
    b.eval("window.__noAutoDialog = true; document.getElementById('btn-overview-graphs').click(); true")
    b.wait_for("!!document.querySelector('.overview-chooser')")
    run(b, "document.querySelectorAll('.overview-chooser input:checked').forEach(i => { i.checked = false; });"
           "document.querySelector('.overview-chooser').requestSubmit(); true")
    b.wait_for("!!document.querySelector('#overview-charts [data-choose-graphs]')", timeout=15)
    assert api(f"/api/devices/{DEV_GRAPH}")["overview_graphs"] == []
    b.eval("document.querySelector('#overview-charts [data-choose-graphs]').click(); true")
    b.wait_for("!!document.querySelector('.overview-chooser [data-default]:not([disabled])')")
    b.eval("document.querySelector('.overview-chooser [data-default]').click(); window.__noAutoDialog = false; true")
    b.wait_for("lastDetail.overview_graphs === null")
    assert api(f"/api/devices/{DEV_GRAPH}")["overview_graphs"] is None
    api(f"/api/custom-oids/{cid}", method="DELETE")
    return "value and graph shown, put on the Overview, chooser clears and resets"


@check("What's changed: shown once after an upgrade, newest first; Got it ends it")
def t_changes(b):
    import changelog
    import database
    database.set_internal_setting(changelog.SEEN_KEY, "{}")
    b.eval("showChanges(); true")
    b.wait_for("!!document.querySelector('.changes-window')")
    n = b.eval("document.querySelectorAll('.changes-window .changes-release').length")
    assert n == len(changelog.RELEASES), n
    first = b.eval("document.querySelector('.changes-window .changes-release h3').textContent")
    assert first.startswith(changelog.RELEASES[-1]["title"]), first
    b.eval("document.querySelector('.changes-window [data-ok]').click(); true")
    b.wait_for("!document.querySelector('.changes-window')")
    time.sleep(0.5)
    assert api("/api/changes")["unseen"] == []
    b.eval("showChanges(); true")
    time.sleep(0.8)
    assert not b.eval("!!document.querySelector('.changes-window')"), "shown again"
    return f"{n} notes, newest first, not shown again"


@check("Inventory: Wi-Fi network column, quiet networks, Known per row, add by hand, weak Wi-Fi per device")
def t_inventory_quiet(b):
    import database
    import inventory
    now = int(time.time())
    with database.get_connection() as c:
        for mac, name, ssid in (("aa:aa:aa:00:01:01", "tenant-tv", "Tenant"), ("aa:aa:aa:00:01:02", "my-tablet", "Home")):
            c.execute("INSERT OR REPLACE INTO inventory (mac, ip, seen_name, vendor, where_seen, via, first_seen, last_seen, known, ssid) "
                      "VALUES (?, '', ?, 'Acme', 'ap-kitchen (Wi-Fi, -70 dBm)', 'wifi', ?, ?, 0, ?);", (mac, name, now, now, ssid))
        c.commit()
    database.delete_settings([inventory.QUIET_SSIDS_KEY])
    try:
        goto(b, "#/inventory")
        b.eval("window.__noAutoDialog = true; true")       # these windows are filled in by the check itself
        b.wait_for("document.getElementById('inventory-body').textContent.includes('tenant-tv')")
        assert "Wi-Fi network" in b.eval("document.querySelector('#tbl-inventory thead').textContent")
        assert "Home" in b.eval("document.querySelector('[data-inv-edit=\"aa:aa:aa:00:01:02\"]').closest('tr').textContent")
        # Quiet networks: tick Tenant, save; its device leaves the list (and is not known).
        run(b, "document.getElementById('btn-inv-quiet-nets').click(); true")
        b.wait_for("!!document.querySelector('[data-net=\"Tenant\"]')")
        run(b, "document.querySelector('[data-net=\"Tenant\"]').checked = true; document.querySelector('[data-net=\"Tenant\"]').closest('form').requestSubmit(); true")
        b.wait_for("!document.getElementById('inventory-body').textContent.includes('tenant-tv')")
        assert "1 quiet not shown" in b.eval("document.getElementById('inv-count').textContent")
        assert "No quiet networks" not in b.eval("document.getElementById('toast-stack').textContent"), "saved twice"
        run(b, "const s = document.getElementById('inv-show'); s.value = 'quiet'; s.dispatchEvent(new Event('change')); true")
        b.wait_for("document.getElementById('inventory-body').textContent.includes('tenant-tv')")
        assert "quiet" in b.eval("document.querySelector('#inventory-body tr').textContent").lower()
        run(b, "const s = document.getElementById('inv-show'); s.value = ''; s.dispatchEvent(new Event('change')); true")
        # Known on one row, without the Edit window.
        run(b, "document.querySelector('[data-inv-known=\"aa:aa:aa:00:01:02\"]').click(); true")
        b.wait_for("!document.querySelector('[data-inv-known=\"aa:aa:aa:00:01:02\"]') && !!document.querySelector('[data-inv-edit=\"aa:aa:aa:00:01:02\"]')")
        # Edit: weak Wi-Fi with its own line (the input only then), and the Quiet box.
        run(b, "document.querySelector('[data-inv-edit=\"aa:aa:aa:00:01:02\"]').click(); true")
        b.wait_for("!!document.getElementById('inv-wifi-alert')")
        assert b.eval("document.querySelector('.inv-wifi-line').classList.contains('hidden')")
        run(b, "const s = document.getElementById('inv-wifi-alert'); s.value = 'line'; s.dispatchEvent(new Event('change')); "
               "document.getElementById('inv-wifi-line').value = '-86'; true")
        assert not b.eval("document.querySelector('.inv-wifi-line').classList.contains('hidden')")
        assert b.eval("!!document.getElementById('inv-quiet')")
        run(b, "document.getElementById('inv-wifi-alert').closest('form').requestSubmit(); true")
        b.wait_for("document.getElementById('inventory-body').textContent.includes('weak Wi-Fi below -86 dBm')")
        # Add a device by hand: it is in, as known.
        run(b, "document.getElementById('btn-inv-add').click(); true")
        b.wait_for("!!document.getElementById('inv-add-mac')")
        run(b, "document.getElementById('inv-add-mac').value = 'aa:aa:aa:00:01:09'; document.getElementById('inv-add-name').value = 'Shed camera'; "
               "document.getElementById('inv-add-mac').closest('form').requestSubmit(); true")
        b.wait_for("document.getElementById('inventory-body').textContent.includes('Shed camera')")
        assert not b.eval("document.querySelector('[data-inv-edit=\"aa:aa:aa:00:01:09\"]').closest('tr').classList.contains('inv-new')")
    finally:
        b.eval("window.__noAutoDialog = false; document.querySelectorAll('.inv-editor').forEach(f => f.closest('.modal-backdrop').remove()); true")
        database.delete_settings([inventory.QUIET_SSIDS_KEY, inventory.WIFI_ALERT_KEY])
        with database.get_connection() as c:
            c.execute("DELETE FROM inventory WHERE mac LIKE 'aa:aa:aa:00:01:%';")
            c.commit()
    return "column, quiet network, Known, own weak line and add by hand work"


@check("Host actions: Fix... on a problem, suggested first, preview before run, typed name for a restart, runs on Automation")
def t_host_actions(b):
    import database
    dev = api("/api/devices", {"hostname": "ha-ui-host", "ip_address": "192.0.2.171", "profile_id": "linux_host"})["device_id"]
    now = int(time.time())
    with database.get_connection() as c:
        c.execute("INSERT INTO problems_active (device_id, problem_key, severity, message, since, last_seen, raised_at) "
                  "VALUES (?, 'forecast_full:1', 'warning', 'Storage / is 54% full and growing', ?, ?, ?);", (dev, now, now, now))
        c.commit()
    try:
        goto(b, f"#/device/{dev}")
        b.wait_for("!document.getElementById('btn-detail-hostact').classList.contains('hidden')")
        b.wait_for(f"!!document.querySelector('#detail-problems [data-ha-device=\"{dev}\"]')", timeout=20)
        run(b, f"document.querySelector('#detail-problems [data-ha-device=\"{dev}\"]').click(); true")
        b.wait_for("!document.getElementById('modal-hostact').classList.contains('hidden') && !!document.querySelector('[data-ha-open]')")
        prob = b.eval("document.getElementById('ha-problem').textContent")
        assert "54% full" in prob, prob
        # Suggested for the problem: the disk check first; the rest only on request.
        first = b.eval("document.querySelector('[data-ha-open]').dataset.haOpen")
        assert first == "disk_usage", first
        assert "Restart the machine" not in b.eval("document.getElementById('ha-list').textContent"), "all actions shown"
        run(b, "document.getElementById('btn-ha-all').click(); true")
        b.wait_for("document.getElementById('ha-list').textContent.includes('Restart the machine')")
        # No credential yet, or no host key yet: the window says which.
        assert b.eval("!document.getElementById('ha-nocred').classList.contains('hidden') || "
                      "!document.getElementById('ha-hostkey').classList.contains('hidden')"), "no note about the missing credential or key"
        # A clean-up: Preview shows, Run waits for it.
        run(b, "document.querySelector('[data-ha-open=\"journal_vacuum\"]').click(); true")
        b.wait_for("!document.getElementById('ha-detail').classList.contains('hidden')")
        assert not b.eval("document.getElementById('btn-ha-preview').classList.contains('hidden')"), "no Preview"
        assert b.eval("document.getElementById('btn-ha-run').disabled"), "Run before a preview"
        size = b.eval("document.getElementById('ha-choice').value")
        assert size == "200M", size
        # A restart asks for the name.
        run(b, "document.getElementById('btn-ha-back').click(); true")
        b.wait_for("!!document.querySelector('[data-ha-open=\"reboot\"]')")
        run(b, "document.querySelector('[data-ha-open=\"reboot\"]').click(); true")
        b.wait_for("!!document.getElementById('ha-confirm')")
        label = b.eval("document.getElementById('btn-ha-run').textContent")
        assert label == "Restart", label
        run(b, "document.getElementById('btn-close-hostact').click(); true")
        # Copy console commands without a key: a plain warning first; Cancel copies nothing.
        b.eval(f"window.__noAutoDialog = true; window.__ss = 'waiting'; copySshSetup({dev}, null).then(r => {{ window.__ss = r; }}); true")
        b.wait_for("!!document.querySelector('form.dialog') && "
                   "document.querySelector('form.dialog .modal-header').textContent.includes('turns on password login for root')", timeout=10)
        msg = b.eval("document.querySelector('form.dialog .dialog-message').textContent")
        assert "including as root" in msg, msg
        run(b, "document.querySelector('form.dialog [data-dialog=cancel]').click(); window.__noAutoDialog = false; true")
        b.wait_for("window.__ss === null")
        # Automation page: the section with its host picker.
        goto(b, "#/automation")
        b.wait_for("[...document.getElementById('ha-host-pick').options].some(o => o.textContent === 'ha-ui-host')")
        # The catalogue is in the workflow command templates too.
        b.wait_for("typeof WF_COMMAND_TEMPLATES !== 'undefined' && WF_COMMAND_TEMPLATES.some(t => t.id === 'ha_disk_usage')")
    finally:
        b.eval("window.__noAutoDialog = false; const m = document.getElementById('modal-hostact'); if (m) m.classList.add('hidden'); true")
        api(f"/api/devices/{dev}", method="DELETE")
    return "suggested actions, preview gate, typed confirmation and the Automation section work"


@check("Inventory lists new devices; Maintenance on a device page; Pi-hole and UniFi settings show their steps when on")
def t_lan_ui(b):
    import database
    now = int(time.time())
    with database.get_connection() as c:
        c.execute("INSERT OR REPLACE INTO inventory (mac, ip, seen_name, vendor, where_seen, via, first_seen, last_seen, known) "
                  "VALUES ('aa:aa:aa:00:00:01', '192.0.2.150', 'mystery', 'Acme', 'ui-graph port 3', 'cable', ?, ?, 0);", (now, now))
        c.commit()
    goto(b, "#/inventory")
    assert not b.eval("document.getElementById('nav-inventory').classList.contains('hidden')"), "Inventory not in the menu"
    b.wait_for("document.querySelectorAll('#inventory-body tr.inv-new').length === 1")
    assert "mystery" in b.eval("document.getElementById('inventory-body').textContent")
    b.eval("document.getElementById('btn-inv-known').click(); true")
    b.wait_for("document.querySelectorAll('#inventory-body tr.inv-new').length === 0")
    # Monitor: the Add window opens with its address and name, on Ping, saying where it came from.
    b.eval("document.querySelector('[data-inv-monitor=\"aa:aa:aa:00:00:01\"]').click(); true")
    b.wait_for("!document.getElementById('modal-add-device').classList.contains('hidden')")
    assert b.eval("document.getElementById('input-ip').value") == "192.0.2.150"
    assert b.eval("document.getElementById('input-hostname').value") == "mystery"
    assert b.eval("document.querySelector('#add-kind [data-kind=\"ping\"]').classList.contains('active')")
    assert "From the Inventory" in b.eval("document.getElementById('add-from-inv').textContent")
    b.eval("document.getElementById('btn-cancel-modal').click(); true")
    # Maintenance from the device page: the notice shows, the button ends it.
    goto(b, f"#/device/{DEV_GRAPH}")
    b.wait_for("!!lastDetail && lastDetail.device.id === %d" % DEV_GRAPH)
    run(b, "window.__noAutoDialog = true; document.getElementById('btn-detail-maint').click(); true")
    b.wait_for("!!document.getElementById('dm-minutes')")
    run(b, "document.getElementById('dm-note').value = 'ui test'; document.getElementById('dm-minutes').closest('form').requestSubmit(); window.__noAutoDialog = false; true")
    b.wait_for("!document.getElementById('detail-maint').classList.contains('hidden')", timeout=10)
    assert "ui test" in b.eval("document.getElementById('detail-maint').textContent")
    assert b.eval("document.getElementById('btn-detail-maint').textContent") == "End maintenance"
    wid = next(w["id"] for w in api("/api/maintenance")["windows"] if w["state"] == "active")
    api(f"/api/maintenance/{wid}/end", {})
    # Settings: switching Pi-hole and UniFi on shows the steps and the form.
    for kind, p_ in (("pihole", "ph"), ("unifi", "uf")):
        goto(b, f"#/settings/{kind}")
        b.wait_for(f"document.getElementById('{p_}-enabled').value === 'off'")
        assert b.eval(f"document.getElementById('{p_}-config').classList.contains('hidden')"), f"{kind} form shown while off"
        run(b, f"const s = document.getElementById('{p_}-enabled'); s.value = 'on'; s.dispatchEvent(new Event('change')); true")
        b.wait_for(f"!document.getElementById('{p_}-config').classList.contains('hidden')")
        assert b.eval(f"document.querySelectorAll('#{p_}-config .pve-steps li').length") >= 3
        run(b, f"const s = document.getElementById('{p_}-enabled'); s.value = 'off'; s.dispatchEvent(new Event('change')); true")
        b.wait_for(f"document.getElementById('{p_}-config').classList.contains('hidden')")
    goto(b, "#/settings/maintenance")
    b.wait_for("document.querySelectorAll('#maint-body tr').length >= 1")
    run(b, "const s = document.getElementById('maint-scope'); s.value = 'tag'; s.dispatchEvent(new Event('change')); true")
    assert not b.eval("document.getElementById('maint-target-wrap').classList.contains('hidden')")
    return "new device shown and marked known, maintenance on and off from the device page, setup steps behind the switches"


@check("Pi-hole settings: an http:// address shows a reminder that the password travels unencrypted")
def t_pihole_http_warning(b):
    goto(b, "#/settings/pihole")
    b.wait_for("document.getElementById('ph-enabled').value === 'off'")
    run(b, "const s = document.getElementById('ph-enabled'); s.value = 'on'; s.dispatchEvent(new Event('change')); true")
    b.wait_for("!document.getElementById('ph-config').classList.contains('hidden')")
    try:
        typed = "{ const u = document.getElementById('ph-url'); u.value = %r; u.dispatchEvent(new Event('input')); } true"
        hidden = "document.getElementById('ph-url-http').classList.contains('hidden')"
        b.eval(typed % "HTTP://192.0.2.53")
        b.wait_for("!" + hidden)
        assert "unencrypted" in b.eval("document.getElementById('ph-url-http').textContent")
        b.eval(typed % "https://192.0.2.53")
        b.wait_for(hidden)
        b.eval(typed % "")
        b.wait_for(hidden)
    finally:
        run(b, "const s = document.getElementById('ph-enabled'); s.value = 'off'; s.dispatchEvent(new Event('change')); true")
        b.wait_for("document.getElementById('ph-config').classList.contains('hidden')")
    return "shown for http://, hidden for https:// and when empty"


@check("Wi-Fi and Pi-hole pages appear once connected; Wi-Fi lists devices weakest first; the workflow step is offered")
def t_wifi_pihole(b):
    import database
    assert b.eval("document.getElementById('nav-wifi').classList.contains('hidden')"), "Wi-Fi in the menu before UniFi is set up"
    api("/api/unifi/config", {"url": "https://192.0.2.1", "username": "monitor", "secret": "pw", "site": "default"}, method="PUT")
    api("/api/pihole/config", {"url": "http://192.0.2.5", "secret": "s"}, method="PUT")
    now = int(time.time())
    database.replace_device_table(DEV_GRAPH, "wifi_clients", {
        "aa:bb:cc:dd:ee:01": {"mac": "aa:bb:cc:dd:ee:01", "name": "good phone", "signal": -52, "band": "5 GHz", "experience": 97},
        "aa:bb:cc:dd:ee:02": {"mac": "aa:bb:cc:dd:ee:02", "name": "far laptop", "signal": -84, "band": "2.4 GHz", "experience": 31}}, now)
    b.eval("refreshFeatures(); true")
    b.wait_for("!document.getElementById('nav-wifi').classList.contains('hidden') && !document.getElementById('nav-pihole').classList.contains('hidden')")
    goto(b, "#/wifi")
    b.wait_for("document.querySelectorAll('#wifi-body tr').length === 2")
    first = b.eval("document.querySelector('#wifi-body tr td strong').textContent")
    assert first == "far laptop", first
    assert b.eval("document.querySelectorAll('#wifi-aps .wifi-ap').length") == 1
    run(b, "document.getElementById('wifi-weak-only').click(); true")
    assert b.eval("document.querySelectorAll('#wifi-body tr').length") == 1
    goto(b, "#/pihole")
    b.wait_for("document.getElementById('ph-kpis').textContent.includes('No monitored device')")
    goto(b, "#/automation")
    assert b.eval("WF_PALETTE.some(p => p.type === 'wifi_reconnect')")
    api("/api/unifi/config", {"disconnect": True}, method="PUT")
    api("/api/pihole/config", {"disconnect": True}, method="PUT")
    api("/api/unifi/config", {"enabled": False}, method="PUT")
    api("/api/pihole/config", {"enabled": False}, method="PUT")
    database.replace_device_table(DEV_GRAPH, "wifi_clients", {}, now)
    b.eval("refreshFeatures(); true")
    b.wait_for("document.getElementById('nav-wifi').classList.contains('hidden')")
    return "menu entries follow the connections, weakest device first, weak filter, Pi-hole page explains a missing device, step in the palette"


@check("Guide: contents, search and links between sections")
def t_guide(b):
    goto(b, "#/guide")
    b.wait_for("document.querySelectorAll('#guide-toc a').length >= 10")
    n = b.eval("document.querySelectorAll('#guide-body section').length")
    run(b, "const s = document.getElementById('guide-search'); s.value = 'PVEAuditor'; s.dispatchEvent(new Event('input')); true")
    shown = b.eval("[...document.querySelectorAll('#guide-body section:not(.hidden)')].map(s => s.id)")
    assert "proxmox" in shown and len(shown) < n, shown
    run(b, "const s = document.getElementById('guide-search'); s.value = ''; s.dispatchEvent(new Event('input')); true")
    goto(b, "#/guide/alerts")
    b.wait_for("document.querySelector('#guide-toc a.active') && document.querySelector('#guide-toc a.active').dataset.guideLink === 'alerts'")
    assert b.eval("document.getElementById('topbar-title').textContent") == "Guide"
    return f"{n} sections, search narrows to {len(shown)}"


@check("Devices: tick boxes reveal Delete selected, which deletes both")
def t_bulk_delete(b):
    ids = [api("/api/devices", {"hostname": f"bulk-{i}", "ip_address": f"192.0.2.{70 + i}", "profile_id": "generic_device"})["device_id"] for i in (1, 2)]
    goto(b, "#/devices")
    b.wait_for(f"document.querySelector('[data-select=\"{ids[1]}\"]') !== null")
    assert b.eval("document.getElementById('device-selection').classList.contains('hidden')"), "bar shown before any selection"
    for i in ids:
        run(b, f"const c = document.querySelector('[data-select=\"{i}\"]'); c.checked = true; c.dispatchEvent(new Event('change', {{bubbles: true}})); true")
    label = b.eval("document.getElementById('btn-delete-selected').textContent")
    assert label == "Delete selected (2)", label
    b.eval("document.getElementById('btn-delete-selected').click(); true")
    b.wait_for(f"document.querySelector('[data-select=\"{ids[0]}\"]') === null")
    left = {d["id"] for d in api("/api/devices")["devices"]}
    assert not set(ids) & left, left
    return "2 deleted"


# --- Network map -------------------------------------------------------------

@check("Map: nodes drawn, add an object, link it, downstream shown on click")
def t_map(b):
    goto(b, "#/map")
    n = b.wait_for("document.querySelectorAll('#map-svg [data-node]').length")
    assert n == len(api("/api/devices")["devices"]), n
    b.eval("document.getElementById('map-edit').click(); document.getElementById('map-add-label').value = 'ISP modem';"
           "document.getElementById('map-add-form').requestSubmit(); true")
    b.wait_for("document.querySelectorAll('#map-svg [data-node]').length === %d" % (n + 1))
    obj = next(x["key"] for x in api("/api/map")["nodes"] if x["label"] == "ISP modem")
    dev = f"d:{DEV_GRAPH}"
    # Link the modem to a device with the Link tool, then select the modem.
    b.eval(f"document.getElementById('map-link').click(); onNodeClick({json.dumps(obj)}); true")
    b.eval(f"onNodeClick({json.dumps(dev)}); true")
    b.wait_for("document.querySelectorAll('#map-svg .map-link.manual').length === 1")
    b.eval("document.getElementById('map-edit').click(); true")
    b.eval(f"onNodeClick({json.dumps(obj)}); true")
    b.wait_for("document.querySelector('#map-info .map-info-title') !== null")
    title = b.eval("document.querySelector('#map-info .map-info-title').textContent")
    assert title == "ISP modem", title
    # Arrange as tree, then no two boxes may overlap.
    b.eval("document.getElementById('map-edit').click(); document.getElementById('map-layout').click(); true")
    time.sleep(0.5)
    overlaps = b.eval("(() => { const ks = mapData.nodes.map(n => n.key); let bad = 0;"
                      " for (let i = 0; i < ks.length; i++) for (let j = i + 1; j < ks.length; j++) {"
                      " const a = mapData.positions[ks[i]], c = mapData.positions[ks[j]];"
                      " if (Math.abs(a[0] - c[0]) < MAP_NODE_W && Math.abs(a[1] - c[1]) < MAP_NODE_H) bad++; } return bad; })()")
    b.eval("document.getElementById('map-edit').click(); true")
    assert overlaps == 0, overlaps
    # The monitor itself is not drawn; the side panel explains where it sits instead.
    assert not b.eval("!!document.querySelector('#map-svg [data-node=\"monitor\"]')"), "monitor drawn on the map"
    b.eval("onNodeClick(null); true")
    # Zoom buttons change the scale; Fit brings it back and keeps the legend off the boxes.
    s0 = b.eval("mapView.scale")
    b.eval("document.getElementById('map-zoom-in').click(); true")
    assert b.eval("mapView.scale") > s0, "zoom in did nothing"
    b.eval("document.getElementById('map-zoom-out').click(); document.getElementById('map-zoom-out').click(); true")
    assert b.eval("mapView.scale") < s0 * 1.01, "zoom out did nothing"
    b.eval("document.getElementById('map-fit').click(); true")
    covered = b.eval("(() => { const l = document.querySelector('.map-legend').getBoundingClientRect();"
                     " return [...document.querySelectorAll('#map-svg [data-node] rect.map-card')].filter(r => {"
                     " const c = r.getBoundingClientRect(); return c.bottom > l.top && c.top < l.bottom && c.right > l.left && c.left < l.right; }).length; })()")
    assert covered == 0, f"{covered} boxes under the legend"
    return f"{n} device nodes, object linked, no overlaps, monitor not drawn, zoom and fit"


@check("Graph legend switches a series off: line, scale and hover readout follow, the enlarged view keeps it")
def t_series_toggle(b):
    goto(b, f"#/device/{DEV_GRAPH}/graphs")
    b.wait_for("!!document.querySelector('#graph-grid .chart-host')")
    # A two series graph (download and upload) drawn into a card of its own.
    run(b, "const card = document.createElement('div'); card.id = 'toggle-card'; card.dataset.title = 'Toggle test';"
           "card.innerHTML = '<div class=\"chart-host\" style=\"height:200px\"></div>'; document.getElementById('graph-grid').prepend(card);"
           "const now = Math.floor(Date.now() / 1000); const pts = f => Array.from({length: 60}, (_, i) => ({timestamp: now - 3600 + i * 60, value: f(i)}));"
           "lineChart(card.querySelector('.chart-host'), [{label: 'Download', key: 'dl', points: pts(i => 1000)}, {label: 'Upload', key: 'ul', points: pts(i => 10)}],"
           " {hours: 1, fmt: v => String(v)}); true")
    host = "document.querySelector('#toggle-card .chart-host')"
    hover = (f"(() => {{ const s = {host}.querySelector('svg'); const r = s.getBoundingClientRect();"
             " s.dispatchEvent(new MouseEvent('mousemove', {clientX: r.left + r.width * 0.7, clientY: r.top + 40, bubbles: true}));"
             " return document.getElementById('chart-tooltip').textContent; })()")
    lines = f"{host}.querySelectorAll('svg path.series').length"
    both = b.eval(lines)
    tip = b.eval(hover)
    assert "Download" in tip and "Upload" in tip, tip
    b.eval(f"{host}.querySelector('[data-series-toggle=\"Download\"]').click(); true")
    assert b.eval(lines) == both - 1, (both, b.eval(lines))
    tip = b.eval(hover)
    assert "Upload" in tip and "Download" not in tip, tip
    assert b.eval(f"{host}.querySelector('[data-series-toggle=\"Download\"]').classList.contains('off')")
    # The last shown series cannot be switched off.
    b.eval(f"{host}.querySelector('[data-series-toggle=\"Upload\"]').click(); true")
    assert not b.eval(f"{host}.querySelector('[data-series-toggle=\"Upload\"]').classList.contains('off')"), "all series off"
    # The enlarged view starts with the same choice.
    b.eval(f"openChartModal({host}); true")
    b.wait_for("!!document.querySelector('.chart-modal .chart-modal-host svg')")
    off = b.eval("document.querySelector('.chart-modal [data-series-toggle=\"Download\"]').classList.contains('off')")
    b.eval("document.querySelector('.chart-modal [data-close]').click(); document.getElementById('toggle-card').remove(); true")
    assert off, "enlarged view shows the hidden series"
    return f"{both} lines, Download hidden from line and readout, last series stays on, enlarged view keeps it"


# --- Devices page ------------------------------------------------------------

@check("Sort a table by clicking a column header")
def t_sort(b):
    b.eval("document.getElementById('devices-group').checked = false; document.getElementById('devices-group').dispatchEvent(new Event('change')); true")
    goto(b, "#/devices")
    b.wait_for("document.querySelectorAll('#device-table-body tr').length >= 2")
    names = "Array.from(document.querySelectorAll('#device-table-body tr td:nth-child(2)')).map(td => td.textContent.trim())"
    b.eval("document.querySelectorAll('#tbl-devices thead th')[1].click(); true")
    asc = b.eval(names)
    b.eval("document.querySelectorAll('#tbl-devices thead th')[1].click(); true")
    desc = b.eval(names)
    assert asc == sorted(asc, key=str.lower) and desc == list(reversed(asc)), (asc, desc)
    return " < ".join(asc)


@check("Collapse and expand a device group")
def t_groups(b):
    b.eval("document.getElementById('devices-group').checked = true; document.getElementById('devices-group').dispatchEvent(new Event('change')); true")
    b.wait_for("!!document.querySelector('#device-table-body tr.group-row')")
    rows = "document.querySelectorAll('#device-table-body tr:not(.group-row)').length"
    n0 = b.eval(rows)
    b.eval("document.querySelector('#device-table-body tr.group-row').click(); true")
    time.sleep(0.3)
    n1 = b.eval(rows)
    b.eval("document.querySelector('#device-table-body tr.group-row').click(); true")
    time.sleep(0.3)
    assert n1 < n0 and b.eval(rows) == n0, (n0, n1)
    return f"{n0} rows -> {n1} collapsed -> {n0}"


@check("Acknowledge a problem from the devices page")
def t_ack(b):
    b.wait_for("!!document.querySelector('#problems-body [data-ack=\"1\"]')", timeout=60)
    b.eval("document.querySelector('#problems-body [data-ack=\"1\"]').click(); true")
    time.sleep(1.0)
    acked = [p for p in api("/api/problems")["problems"] if p["acknowledged_at"]]
    assert acked and acked[0]["ack_note"] == "ui-test", acked
    # Seen to, still true: it moves to Acknowledged problems, out of Current problems and off the dashboard.
    key = json.dumps(acked[0]["problem_key"])
    dev = int(acked[0]["device_id"])
    sel = f"'[data-ack-device=\"{dev}\"][data-ack-key=' + JSON.stringify({key}) + ']'"
    b.wait_for(f"!!document.querySelector('#acked-body ' + {sel})")
    assert b.eval(f"!document.querySelector('#problems-body ' + {sel})"), "still in Current problems"
    assert not b.eval("document.getElementById('acked-panel').classList.contains('hidden')")
    goto(b, "#/dashboard")
    b.wait_for("!!document.querySelector('#dash-grid [data-wid]')")
    time.sleep(1.0)
    assert b.eval(f"!document.querySelector('#dash-grid ' + {sel})"), "acknowledged problem still on the dashboard"
    goto(b, "#/devices")
    return acked[0]["message"] + "; moved to Acknowledged problems, off the dashboard"


@check("Device page shows the LIVE badge")
def t_live(b):
    goto(b, f"#/device/{DEV_GRAPH}")
    text = b.wait_for("(() => { const t = document.getElementById('btn-live').textContent; return t.startsWith('LIVE') ? t : ''; })()")
    return text


# --- Settings ----------------------------------------------------------------

@check("Settings: edit, see unsaved count, save")
def t_settings(b):
    goto(b, "#/settings")
    b.wait_for("!!document.getElementById('setting-problem_resolve_minutes')")
    run(b, "const i = document.getElementById('setting-problem_resolve_minutes'); i.value = '17'; i.dispatchEvent(new Event('input', {bubbles: true})); true")
    dirty = b.eval("document.getElementById('settings-dirty').textContent")
    assert "1 unsaved" in dirty and not b.eval("document.getElementById('btn-save-settings').disabled"), dirty
    b.eval("document.getElementById('btn-save-settings').click(); true")
    time.sleep(1.0)
    assert api("/api/settings")["problem_resolve_minutes"] == "17"
    return dirty


@check("Settings: invalid value blocks save; secret field is empty")
def t_settings_invalid(b):
    b.wait_for("document.getElementById('setting-problem_resolve_minutes').value === '17'")
    run(b, "const i = document.getElementById('setting-problem_resolve_minutes'); i.value = '500'; i.dispatchEvent(new Event('input', {bubbles: true})); true")
    assert b.eval("document.getElementById('btn-save-settings').disabled")
    assert b.eval("document.getElementById('setting-default_snmp_community').value") == ""
    b.eval("document.getElementById('btn-discard-settings').click(); true")
    return "save disabled for 500 min, community not sent to browser"


@check("Alert rules: template override saved, inherited on the device, then reset")
def t_alert_rules(b):
    goto(b, "#/settings/alerts/template/generic_device")
    b.wait_for("!!document.querySelector('[data-ar-rule=cpu][data-ar-field=threshold]') && document.getElementById('ar-scope').value === 'template'")
    assert b.eval("document.querySelector('#alert-rules th.ar-tg').classList.contains('hidden')"), "Telegram columns shown while Telegram is off"
    assert b.eval("document.getElementById('ar-save').classList.contains('hidden')"), "Save shown before any change"
    run(b, "const i = document.querySelector('[data-ar-rule=cpu][data-ar-field=threshold]'); i.value = '93'; i.dispatchEvent(new Event('change', {bubbles: true})); true")
    b.wait_for("!document.getElementById('ar-save').classList.contains('hidden')")
    b.eval("document.getElementById('ar-save').click(); true")
    b.wait_for("document.getElementById('ar-save').classList.contains('hidden') && !!document.querySelector('[data-ar-reset=cpu]')")
    rules = api("/api/alert-rules?scope=template&target=generic_device")["rules"]
    here = next(r for r in rules if r["id"] == "cpu")["here"]
    assert here == {"threshold": 93.0}, here
    dev = api(f"/api/alert-rules?scope=device&target={DEV_GRAPH}")["rules"]
    cpu = next(r for r in dev if r["id"] == "cpu")
    b.eval("document.querySelector('[data-ar-reset=cpu]').click(); true")
    b.eval("document.getElementById('ar-save').click(); true")
    b.wait_for("document.getElementById('ar-save').classList.contains('hidden') && !document.querySelector('[data-ar-reset=cpu]')")
    rules = api("/api/alert-rules?scope=template&target=generic_device")["rules"]
    here = next(r for r in rules if r["id"] == "cpu")["here"]
    assert here == {}, here
    return f"saved 93 on the template (device sees {cpu['effective']['threshold']:g} from {cpu['source']['threshold']}), reset"


@check("Shell: theme switch, menu collapse, bell, back to top")
def t_shell(b):
    goto(b, "#/devices")
    before = b.eval("getComputedStyle(document.body).backgroundColor")
    b.eval("document.getElementById('btn-theme').click(); true")
    after = b.eval("getComputedStyle(document.body).backgroundColor")
    assert before != after, "theme did not change the background"
    stored, shown = b.eval("localStorage.getItem('monitor.theme.v1')"), b.eval("document.documentElement.dataset.theme")
    assert stored == shown, (stored, shown)
    b.eval("document.getElementById('btn-theme').click(); true")
    b.eval("document.getElementById('btn-sidebar-collapse').click(); true")
    assert b.eval("document.getElementById('app-shell').classList.contains('collapsed')"), "menu did not collapse"
    b.wait_for("document.getElementById('sidebar').getBoundingClientRect().width < 80")
    b.eval("document.getElementById('btn-sidebar-collapse').click(); true")
    assert b.eval("!!document.getElementById('nav-events')"), "Events missing from the menu"
    database_event = api("/api/notifications")
    b.eval("document.getElementById('btn-bell').click(); true")
    b.wait_for("!document.getElementById('bell-panel').classList.contains('hidden')")
    items = b.eval("document.querySelectorAll('#bell-list .bell-item').length")
    assert items == len(database_event["items"]), (items, len(database_event["items"]))
    b.eval("document.body.click(); true")
    assert b.eval("document.getElementById('bell-panel').classList.contains('hidden')"), "bell did not close"
    b.eval("window.scrollTo(0, 2000); window.dispatchEvent(new Event('scroll')); true")
    if b.eval("window.scrollY") > 400:
        assert not b.eval("document.getElementById('btn-to-top').classList.contains('hidden')"), "no back to top button"
    title = b.eval("document.getElementById('topbar-title').textContent")
    assert title == "Devices", title
    return f"theme toggled and stored, menu collapsed, bell listed {items}, title {title!r}"


@check("Event log: filters, page numbers")
def t_event_log(b):
    goto(b, "#/events")
    b.wait_for("document.querySelectorAll('#events-body tr').length > 0")
    total = api("/api/events?per_page=50")["total"]
    pager = b.eval("document.getElementById('events-pager').textContent")
    assert f"of {total:,}" in pager.replace(" ", ","), pager
    run(b, "const s = document.getElementById('ev-severity'); s.value = 'critical'; s.dispatchEvent(new Event('change', {bubbles: true})); true")
    expected = api("/api/events?severity=critical")["total"]
    b.wait_for("!document.getElementById('ev-clear').classList.contains('hidden')")
    time.sleep(0.5)
    rows = b.eval("[...document.querySelectorAll('#events-body tr')].filter(r => !r.querySelector('.empty-cell')).length")
    assert rows == min(expected, 50), (rows, expected)
    b.eval("document.getElementById('ev-clear').click(); true")
    b.wait_for("document.getElementById('ev-clear').classList.contains('hidden')")
    return f"{total} events, {expected} critical"


@check("Settings: one section at a time, leaving with unsaved changes asks")
def t_settings_guard(b):
    goto(b, "#/settings/polling")
    b.wait_for("!!document.getElementById('setting-default_poll_interval') && !document.querySelector('[data-card=polling]').classList.contains('hidden')")
    visible = b.eval("[...document.querySelectorAll('#view-settings [data-card]')].filter(c => !c.classList.contains('hidden')).length")
    assert visible == 1, visible
    run(b, "const i = document.getElementById('setting-default_poll_interval'); i.value = '77'; i.dispatchEvent(new Event('input', {bubbles: true})); true")
    # Another section keeps the edit; leaving Settings asks (answered Stay).
    b.eval("window.location.hash = '#/settings/snmp'; true")
    b.wait_for("!document.querySelector('[data-card=snmp]').classList.contains('hidden')")
    assert b.eval("document.getElementById('setting-default_poll_interval').value") == "77"
    pending = b.eval("JSON.stringify(unsavedSummary('#/devices'))")
    assert pending != "[]", f"no unsaved changes detected: {pending}"
    b.eval("window.__noAutoDialog = true; window.location.hash = '#/devices'; true")
    b.wait_for("!!document.querySelector('form.dialog')")
    assert b.eval("window.location.hash").startswith("#/settings"), "left without asking"
    b.eval("document.querySelector('form.dialog [data-dialog=cancel]').click(); true")
    b.wait_for("!document.querySelector('form.dialog')")
    assert b.eval("document.getElementById('setting-default_poll_interval').value") == "77"
    b.eval("window.__noAutoDialog = false; document.getElementById('btn-discard-settings').click(); true")
    b.wait_for("document.getElementById('btn-save-settings').classList.contains('hidden')")
    return "edit kept across sections; leaving asked first; discarded"


@check("Two-factor authentication: turn on with a QR code, recovery codes shown, turn off")
def t_two_factor(b):
    import totp
    goto(b, "#/settings/account")
    b.wait_for("!!document.getElementById('btn-2fa-on')")
    b.eval("document.getElementById('btn-2fa-on').click(); true")
    b.wait_for("!!document.querySelector('#twofa-qr img') && document.querySelector('#twofa-qr img').complete && document.querySelector('#twofa-qr img').naturalWidth > 0")
    secret = b.eval("document.querySelector('.twofa-secret code').textContent").replace(" ", "")
    run(b, f"document.getElementById('twofa-code').value = '{totp.code_at(secret)}';"
           "document.getElementById('twofa-confirm').requestSubmit(); true")
    # The recovery codes dialog is accepted by the harness; then the card says On.
    b.wait_for("document.querySelector('#account-2fa .status-pill').textContent === 'On'")
    # Turning 2FA on or off logs out the account's other sessions (0.7.0). This harness's own API
    # session is one of them: it must have been logged out, then it logs in again.
    try:
        api("/api/auth/2fa")
        raise AssertionError("another session stayed logged in after 2FA was turned on")
    except urllib.error.HTTPError as exc:
        assert exc.code == 401, exc.code
    # The account now has 2FA: the harness logs in with a code (MFA step) to look.
    step = api("/api/auth/login", {"username": UI_USER, "password": UI_PASSWORD})
    assert step.get("mfa_required"), step
    time.sleep(31 - time.time() % 30)                          # a fresh code: the browser just used this one
    api("/api/auth/login/mfa", {"challenge": step["challenge"], "code": totp.code_at(secret)})
    assert api("/api/auth/2fa")["enabled"]
    b.eval("document.getElementById('btn-2fa-off').click(); true")
    b.wait_for("document.querySelector('#account-2fa .status-pill').textContent === 'Off'")
    COOKIE["value"] = ""
    api("/api/auth/login", {"username": UI_USER, "password": UI_PASSWORD})
    assert not api("/api/auth/2fa")["enabled"]
    return "turned on with a code from the secret shown, then off; other sessions logged out each time"


@check("Users: add an operator, edit role, block, delete")
def t_users(b):
    goto(b, "#/settings/users")
    b.wait_for("!!document.querySelector('[data-user-edit]')")
    b.eval("document.getElementById('btn-add-user').click(); true")
    b.wait_for("!!document.getElementById('ue-username')")
    run(b, "document.getElementById('ue-username').value = 'ui-op'; document.getElementById('ue-password').value = 'ui operator password';"
           "const r = document.getElementById('ue-role'); r.value = 'operator'; r.dispatchEvent(new Event('change', {bubbles: true})); true")
    assert b.eval("document.querySelector('#ue-perms input[value=\"problems.ack\"]').checked"), "operator permissions not shown"
    b.eval("document.querySelector('.user-editor [type=submit]').click(); true")
    b.wait_for("!!document.querySelector('[data-user-edit=\"ui-op\"]')")
    u = next(x for x in api("/api/users")["users"] if x["username"] == "ui-op")
    assert u["role"] == "operator", u
    b.eval("document.querySelector('[data-user-menu=\"ui-op\"]').click(); true")
    b.wait_for("!!document.querySelector('[data-user-action=block]')")
    b.eval("document.querySelector('[data-user-action=block]').click(); true")
    b.wait_for("document.querySelector('[data-user-edit=\"ui-op\"]').closest('tr').textContent.includes('Blocked')")
    b.eval("document.querySelector('[data-user-menu=\"ui-op\"]').click(); true")
    b.wait_for("!!document.querySelector('[data-user-action=delete]')")
    b.eval("document.querySelector('[data-user-action=delete]').click(); true")
    b.wait_for("!document.querySelector('[data-user-edit=\"ui-op\"]')")
    return "added operator, blocked, deleted"


# --- Automation --------------------------------------------------------------

@check("Credential dialog: add, edit, delete")
def t_credentials(b):
    b.eval("window.__noAutoDialog = true; true")    # answers the delete and key dialogs itself
    goto(b, "#/automation")
    b.wait_for("!!document.getElementById('btn-add-credential')")
    b.eval("document.getElementById('btn-add-credential').click(); "
           "document.getElementById('cred-name').value = 'ui-cred'; document.getElementById('cred-username').value = 'root'; "
           "document.getElementById('cred-password').value = 'ui-secret-123'; document.getElementById('btn-save-credential').click(); true")
    b.wait_for("!!document.querySelector('#credentials-body [data-cred-edit]')")
    cred = next(c for c in api("/api/credentials")["credentials"] if c["name"] == "ui-cred")
    b.eval(f"document.querySelector('[data-cred-edit=\"{cred['id']}\"]').click(); "
           "document.getElementById('cred-username').value = 'admin'; document.getElementById('btn-save-credential').click(); true")
    time.sleep(1.0)
    assert next(c for c in api("/api/credentials")["credentials"] if c["id"] == cred["id"])["username"] == "admin"
    assert b.eval("document.getElementById('cred-password').value") == ""   # secret cleared from the DOM
    b.eval("document.getElementById('btn-add-credential').click(); document.getElementById('cred-name').value = 'ui-temp'; "
           "document.getElementById('cred-password').value = 'x'; document.getElementById('btn-save-credential').click(); true")
    b.wait_for("document.querySelectorAll('#credentials-body [data-cred-delete]').length === 2")
    tmp = next(c for c in api("/api/credentials")["credentials"] if c["name"] == "ui-temp")
    b.eval(f"document.querySelector('[data-cred-delete=\"{tmp['id']}\"]').click(); true")
    b.wait_for("!!document.querySelector('.dialog-backdrop')")
    # A dangerous confirm button arms after a short delay (it cannot be clicked by accident).
    b.wait_for("!document.querySelector('.dialog-backdrop [type=submit]').disabled")
    b.eval("document.querySelector('.dialog-backdrop [type=submit]').click(); true")
    time.sleep(1.0)
    assert all(c["name"] != "ui-temp" for c in api("/api/credentials")["credentials"])
    # Generate a key pair here: the public key is shown, the private key never leaves the server.
    if b.eval("keygenAvailable"):
        b.eval("document.getElementById('btn-add-credential').click(); document.getElementById('cred-name').value = 'ui-key'; "
               "document.getElementById('cred-type').value = 'ssh_key'; document.getElementById('cred-type').dispatchEvent(new Event('change')); "
               "document.querySelector('input[name=cred-key-mode][value=generate]').checked = true; "
               "document.getElementById('cred-key-source').dispatchEvent(new Event('change', {bubbles: true})); "
               "document.getElementById('btn-save-credential').click(); true")
        b.wait_for("!!document.querySelector('.dialog-backdrop .dialog-detail')", timeout=20)
        pub = b.eval("document.querySelector('.dialog-backdrop .dialog-detail').textContent")
        assert pub.startswith("ssh-ed25519 "), pub
        b.eval("document.querySelector('.dialog-backdrop [type=submit]').click(); true")
        key = next(c for c in api("/api/credentials")["credentials"] if c["name"] == "ui-key")
        assert key["public_key"] == pub and "PRIVATE" not in json.dumps(api("/api/credentials")), key
        b.eval("window.__noAutoDialog = false; true")
        return "added, renamed user, deleted second, generated a key pair"
    b.eval("window.__noAutoDialog = false; true")
    return "added, renamed user, deleted second"


@check("Run command step: host, template command, save")
def t_task(b):
    b.wait_for("autoData && autoData.credentials.length")
    target = DEV_SSH or DEV_GRAPH
    b.eval("document.getElementById('btn-add-workflow').click(); true")
    b.wait_for("!document.getElementById('modal-workflow').classList.contains('hidden')")
    b.eval("document.getElementById('wf-name').value = 'ui-task'; true")
    _pointer(b, "[data-pal='0']", "pointerdown")
    _pointer(b, "[data-pal='0']", "pointerup")
    b.wait_for("!!document.querySelector('#wfb-panel [data-host-add]')")
    run(b, f"const s = document.querySelector('#wfb-panel [data-host-add]'); s.value = '{target}'; s.dispatchEvent(new Event('change', {{bubbles: true}})); true")
    b.wait_for("!!document.querySelector('#wfb-panel [data-template]')")
    run(b, "const t = document.querySelector('#wfb-panel [data-template]'); t.value = 'apt_update'; t.dispatchEvent(new Event('change', {bubbles: true})); true")
    b.wait_for("document.querySelector('#wfb-panel [data-f=\"command\"]').value.includes('DEBIAN_FRONTEND=noninteractive')")
    # Plain command for the run check: replace the template text.
    run(b, "const c = document.querySelector('#wfb-panel [data-f=\"command\"]'); c.value = 'uptime'; c.dispatchEvent(new Event('input', {bubbles: true}));"
           "document.getElementById('btn-save-workflow').click(); true")
    b.wait_for("document.getElementById('modal-workflow').classList.contains('hidden')")
    wf = next(w for w in api("/api/workflows")["workflows"] if w["name"] == "ui-task")
    assert wf["steps"][0]["device_ids"] == [target] and wf["steps"][0]["command"] == "uptime", wf["steps"]
    return f"workflow {wf['id']} on device {target}"


@check("Workflows: Suppress notifications step, Send quietly and quiet templates")
def t_quiet_steps(b):
    goto(b, "#/automation")
    b.wait_for("typeof newStep === 'function' && wfList !== null")
    b.eval("document.getElementById('btn-add-workflow').click(); true")
    b.wait_for("!document.getElementById('modal-workflow').classList.contains('hidden')")
    try:
        run(b, "const n = newStep('mute'); wfb.draft.graph.nodes.push(n); wfb.sel = { kind: 'node', id: n.id }; wfb.panel = 'node'; wfRenderPanel(); true")
        b.wait_for("!!document.querySelector('#wfb-panel [data-f=scope]')")
        assert b.eval("document.querySelector('#wfb-panel [data-f=until_end]').checked")
        run(b, "const s = document.querySelector('#wfb-panel [data-f=scope]'); s.value = 'group'; s.dispatchEvent(new Event('change', {bubbles: true})); true")
        b.wait_for("!!document.querySelector('#wfb-panel select[data-f=target]')")
        run(b, "const n = newStep('telegram'); wfb.draft.graph.nodes.push(n); wfb.sel = { kind: 'node', id: n.id }; wfRenderPanel(); true")
        b.wait_for("!!document.querySelector('#wfb-panel [data-f=silent]')")
        run(b, "wfb.panel = 'templates'; wfb.template = 'unifi_restart_order'; wfRenderPanel(); true")
        b.wait_for("!!document.getElementById('wfb-tpl-quiet')")
        assert b.eval("document.getElementById('wfb-tpl-quiet').checked"), "restarts should be quiet by default"
        names = b.eval("WF_FLOW_TEMPLATES.map(t => t.id).join(',')")
        for want in ("pve_snapshot_update", "restart_service", "free_space", "health_check", "pihole_refresh", "wifi_tidy"):
            assert want in names, names
        palette = b.eval("WF_PALETTE.map(p => p.type).join(',')")
        assert "mute" in palette and "unmute" in palette, palette
    finally:
        b.eval("window.__noAutoDialog = false; hide(document.getElementById('modal-workflow')); wfb = null; true")
    return f"steps and options shown; {len(names.split(','))} workflow templates"


@check("Telegram editor (emoji, preview), event trigger fields, two-panel run viewer")
def t_telegram_editor(b):
    goto(b, "#/automation")
    b.wait_for("typeof openTemplateEditor === 'function' && wfList !== null")
    b.eval("window.__tgSaved = null; openTemplateEditor({ title: 'T', value: 'Hi {device}', placeholders: { device: 'Device name' },"
           " sample: { device: 'nas-01' }, presets: ['✅ {device}'], onSave: t => { window.__tgSaved = t; } }); true")
    b.wait_for("!!document.querySelector('.tg-editor')")
    b.wait_for("document.querySelector('.tg-preview').textContent === 'Hi nas-01'", timeout=10)
    # The preview is the server's engine: a condition and a filter work in it.
    b.eval("{ const ta = document.querySelector('.tg-text'); ta.value = '{if device == \"nas-01\"}{device|lower}{end}';"
           "ta.dispatchEvent(new Event('input')); } true")
    b.wait_for("document.querySelector('.tg-preview').textContent === 'nas-01'", timeout=10)
    # A text that grows too long: the preview shows the server's message, not a local fill.
    grow = "|replace:n:" + "n" * 20
    b.eval("{ const ta = document.querySelector('.tg-text'); ta.value = '{device" + grow * 5 + "}';"
           "ta.dispatchEvent(new Event('input')); } true")
    b.wait_for("document.querySelector('.tg-preview').textContent.startsWith('This template makes the text too long')", timeout=10)
    assert b.eval("!!document.querySelector('.tg-tricks .tg-var')"), "tricks missing"
    b.eval("{ const ta = document.querySelector('.tg-text'); ta.value = 'Hi {device}'; ta.dispatchEvent(new Event('input')); } true")
    run(b, "const ta = document.querySelector('.tg-text'); ta.selectionStart = ta.selectionEnd = 0;"
           "document.querySelector('.tg-emoji').click(); document.querySelector('.tg-editor [type=submit]').click(); true")
    b.wait_for("window.__tgSaved !== null")
    saved = b.eval("window.__tgSaved")
    assert saved.endswith("Hi {device}") and saved != "Hi {device}", saved
    # Event trigger: pick the kind, then a device; the fields for the condition appear.
    b.eval("document.getElementById('btn-add-workflow').click(); true")
    b.wait_for("!document.getElementById('modal-workflow').classList.contains('hidden')")
    run(b, "wfb.sel = { kind: 'node', id: 'trigger' }; wfb.panel = 'node'; wfRenderPanel();"
           "const k = document.querySelector('#wfb-panel [data-s=kind]'); k.value = 'event'; k.dispatchEvent(new Event('change', {bubbles: true})); true")
    b.wait_for("!!document.querySelector('#wfb-panel [data-ev=type]')")
    run(b, f"const d = document.querySelector('#wfb-panel [data-ev=device_id]'); d.value = '{DEV_GRAPH}'; d.dispatchEvent(new Event('change', {{bubbles: true}}));"
           "const t = document.querySelector('#wfb-panel [data-ev=type]'); t.value = 'metric'; t.dispatchEvent(new Event('change', {bubbles: true})); true")
    b.wait_for("!!document.querySelector('#wfb-panel select[data-ev=metric]')", timeout=10)
    summary = b.eval("document.querySelector('#wfb-panel .wfb-summary').textContent")
    assert summary.startswith("When ui-graph"), summary
    b.eval("window.__noAutoDialog = false; hide(document.getElementById('modal-workflow')); wfb = null; true")
    split = b.eval("getComputedStyle(document.getElementById('wf-run-split')).display")
    assert split == "grid", split
    return f"saved {saved!r}; {summary}"


@check("Host key dialog: fetch fingerprint and approve")
def t_hostkey(b):
    if not DEV_SSH:
        return "skipped (set HM_TEST_SSH_HOST)"
    goto(b, "#/automation")
    b.wait_for("!!document.querySelector('[data-wf-keys]')")
    b.eval("document.querySelector('[data-wf-keys]').click(); true")
    b.wait_for("!!document.querySelector('#hostkeys-body [data-hk-approve]')", timeout=30)
    fp = b.eval("document.querySelector('#hostkeys-body [data-hk-approve]').dataset.fp")
    b.eval("document.querySelector('#hostkeys-body [data-hk-approve]').click(); true")
    time.sleep(2.0)
    approved = api(f"/api/devices/{DEV_SSH}/hostkey")["approved"]
    assert approved and approved[0]["fingerprint"] == fp, approved
    b.eval("document.getElementById('btn-done-hostkeys').click(); true")
    return fp


@check("Run the command workflow and see its step output")
def t_run(b):
    if not DEV_SSH:
        return "skipped (set HM_TEST_SSH_HOST)"
    b.eval("window.__noAutoDialog = true; true")
    goto(b, "#/automation")
    b.eval("loadAutomation(); true")
    b.wait_for("!!(autoData && autoData.devices.find(d => d.host_key))", timeout=10)
    wf = next(w for w in api("/api/workflows")["workflows"] if w["name"] == "ui-task")
    b.wait_for(f"document.querySelector('[data-wf-start=\"{wf['id']}\"]') !== null")
    b.eval(f"document.querySelector('[data-wf-start=\"{wf['id']}\"]').click(); true")
    b.wait_for("!!document.querySelector('.dialog-backdrop')")
    b.eval("document.querySelector('.dialog-backdrop [type=submit]').click(); true")
    time.sleep(0.8)
    if b.eval("!document.getElementById('modal-confirm-password').classList.contains('hidden')"):
        b.eval(f"document.getElementById('confirm-password').value = {json.dumps(UI_PASSWORD)};"
               "document.getElementById('confirm-password-form').requestSubmit(); true")
    b.wait_for("!document.getElementById('modal-wf-run').classList.contains('hidden')")
    b.wait_for("(() => { const p = document.querySelector('#wf-run-status .status-pill'); return p && p.textContent !== 'running'; })()", timeout=60)
    status = b.eval("document.querySelector('#wf-run-status .status-pill').textContent")
    detail = b.eval("(document.querySelector('#wf-run-log .wf-log-detail') || {}).textContent || ''")
    b.eval("document.getElementById('btn-close-wf-run').click(); window.__noAutoDialog = false; true")
    assert status in ("failed", "success"), status
    return f"status {status}: {detail.strip()[:60]}"


@check("Without Use stored credentials: Host actions, Run command and host key approval are hidden; the run-as line shows")
def t_credentials_use_hiding(b):
    import database
    dev = api("/api/devices", {"hostname": "cu-ui-host", "ip_address": "192.0.2.172", "profile_id": "linux_host"})["device_id"]
    # Through the API: the vault key lives in the server process.
    cred = api("/api/credentials", {"name": "cu-ui-key", "cred_type": "password", "username": "hm-ui", "secret": "cu-ui-secret"})["id"]
    display = "getComputedStyle(document.querySelector(%r)).display"
    try:
        goto(b, "#/automation")
        b.eval("loadAutomation(); true")
        b.wait_for(f"!!(autoData && autoData.credentials.some(c => c.id === {cred}) && autoData.devices.some(d => d.id === {dev}))", timeout=10)
        # With every permission: the run-as line names the credential's user.
        b.eval(f"openHostActions({dev}); true")
        b.wait_for("!document.getElementById('modal-hostact').classList.contains('hidden')")
        run(b, f"const s = document.getElementById('ha-cred'); s.value = '{cred}'; s.dispatchEvent(new Event('change')); true")
        line = b.eval("document.getElementById('ha-runas').textContent")
        assert line == "Runs as hm-ui using the credential cu-ui-key.", line
        assert b.eval(display % "#btn-ha-hostkey") != "none", "Review host key hidden from an administrator"
        run(b, "document.getElementById('btn-close-hostact').click(); true")
        # Without Use stored credentials and Manage credentials.
        b.eval("window.__savedUser = currentUser; applyCurrentUser(Object.assign({}, currentUser, {permissions: "
               "currentUser.permissions.filter(p => p !== 'credentials.use' && p !== 'credentials.manage')})); true")
        assert b.eval("haCanRun() === false && document.getElementById('btn-detail-hostact').dataset.perm.includes('credentials.use')"), "Host actions still offered"
        assert b.eval(display % "#wfb-palette .wfb-t-command") == "none", "Run command still in the palette"
        assert b.eval(display % "#wfb-palette .wfb-t-wait") != "none", "other steps hidden too"
        assert b.eval(display % "#btn-ha-hostkey") == "none", "Review host key shown"
        assert b.eval(display % "#ha-hostkey .hk-ask") != "none", "no word on who can approve"
        # The host key window offers no Approve button, only who can approve.
        b.eval("window.__realApi = api; api = async () => ({approved: [], presented: {key_type: 'ssh-ed25519', fingerprint: 'SHA256:cu'}}); true")
        b.eval(f"openHostKeys({{device_ids: [{dev}], ssh_port: 22}}); true")
        b.wait_for("document.getElementById('hostkeys-body').textContent.includes('SHA256:cu')")
        assert not b.eval("!!document.querySelector('#hostkeys-body [data-hk-approve]')"), "Approve offered"
        assert "Manage credentials" in b.eval("document.getElementById('hostkeys-body').textContent")
    finally:
        b.eval("if (window.__realApi) { api = window.__realApi; window.__realApi = null; }"
               "if (window.__savedUser) { applyCurrentUser(window.__savedUser); window.__savedUser = null; }"
               "document.getElementById('modal-hostkeys').classList.add('hidden');"
               "document.getElementById('modal-hostact').classList.add('hidden'); true")
        database.delete_credential(cred)
        database.delete_device(dev)
    return "hidden without the permissions, run-as line names the user"


@check("Limited to some devices: no map or dashboard editing, no group and tag changes, no Proxmox snapshot step or keeping everything quiet")
def t_scoped_user_hiding(b):
    display = "getComputedStyle(document.querySelector(%r)).display"
    goto(b, "#/dashboard")
    for sel in ("#dash-new", "#dash-edit", "#map-edit", "#wfb-palette .wfb-t-pve_snapshot"):
        assert b.eval(display % sel) != "none", f"{sel} hidden from an administrator"
    mute = ("(() => { const keep = wfb; wfb = wfb || {draft: {graph: {nodes: [], edges: []}}};"
            " try { return wfPanelStep({id: 'm', type: 'mute', scope: 'hosts', device_ids: [], until_end: true, minutes: 60, grace_min: 5}); }"
            " finally { wfb = keep; } })().includes('Everything')")
    assert b.eval(mute), "Everything missing for an administrator"
    try:
        b.eval("window.__savedUser = currentUser; applyCurrentUser(Object.assign({}, currentUser, {scoped: true})); true")
        for sel in ("#dash-new", "#dash-edit", "#map-edit", "#wfb-palette .wfb-t-pve_snapshot"):
            assert b.eval(display % sel) == "none", f"{sel} shown to a limited user"
        assert b.eval(display % "#wfb-palette .wfb-t-mute") != "none", "other steps hidden too"
        assert not b.eval(mute), "Everything offered to a limited user"
        goto(b, "#/settings/groups")
        b.wait_for("!!document.querySelector('#taxonomy-settings .taxo-table')")
        b.eval("renderTaxonomySettings(); true")
        assert not b.eval("!!document.querySelector('#taxonomy-settings [data-taxo-rename-group]')"), "group rename offered"
    finally:
        b.eval("if (window.__savedUser) { applyCurrentUser(window.__savedUser); window.__savedUser = null; } true")
        goto(b, "#/dashboard")
    return "hidden for a limited user, shown for an administrator"


@check("Text a device sends in a number column stays plain text on the page")
def t_device_text_stays_text(b):
    import database
    keep = database.get_device_table(DEV_GRAPH, "interfaces")
    now = int(time.time())
    probe = '<img id="probe" src="x">'
    try:
        database.replace_device_table(DEV_GRAPH, "interfaces", {"1": {
            "if_index": 1, "label": "eth1", "descr": "eth1", "kind": "port", "oper": 1, "oper_text": "up", "admin": 1,
            "mtu": probe, "speed_mbps": 1000}}, now)
        goto(b, f"#/device/{DEV_GRAPH}/ports")
        b.wait_for("document.querySelectorAll('#ports-body tr').length >= 1 && document.getElementById('ports-body').textContent.includes('eth1')")
        assert b.eval("document.getElementById('probe') === null"), "the device's text became an element"
        assert probe in b.eval("document.getElementById('ports-body').textContent"), "the text is not shown"
    finally:
        database.replace_device_table(DEV_GRAPH, "interfaces", {k: {x: y for x, y in v.items() if x != "updated_at"} for k, v in keep.items()}, now)
    return "shown as text, no element made"


@check("Phone: every page fits the screen; the menu is a drawer that closes on a choice")
def t_phone(b):
    b.send("Emulation.setDeviceMetricsOverride", {"width": 390, "height": 844, "deviceScaleFactor": 2, "mobile": True})
    try:
        fits = ("(() => { const w = innerWidth; return {w, scroll: document.documentElement.scrollWidth,"
                " shell: Math.round(document.getElementById('app-shell').getBoundingClientRect().width)}; })()")
        routes = ["#/dashboard", "#/devices", f"#/device/{DEV_GRAPH}", "#/events", "#/availability", "#/map", "#/automation",
                  "#/inventory", "#/guide", "#/audit", "#/settings/alerts", "#/settings/notify", "#/settings/groups", "#/settings/account"]
        for route in routes:
            b.eval(f"location.hash = {json.dumps(route)}; true")
            time.sleep(0.8)
            r = b.eval(fits)
            # A phone widens the page to fit whatever is wider than the screen: it must stay 390.
            assert r["w"] == 390 and r["scroll"] <= 391 and r["shell"] <= 391, (route, r)
        # The menu: hidden until the menu button opens it; choosing a page closes it.
        b.eval("location.hash = '#/dashboard'; true")
        time.sleep(0.5)
        hidden = "document.getElementById('sidebar').getBoundingClientRect().right <= 1"
        b.wait_for(hidden, timeout=3)
        assert b.eval("getComputedStyle(document.getElementById('btn-menu')).display") != "none"
        b.eval("document.getElementById('btn-menu').click(); true")
        b.wait_for("document.getElementById('sidebar').getBoundingClientRect().left >= 0"
                   " && getComputedStyle(document.getElementById('sidebar-scrim')).display === 'block'", timeout=3)
        b.eval("document.getElementById('nav-devices').click(); true")
        b.wait_for("location.hash === '#/devices' && !document.getElementById('app-shell').classList.contains('menu-open')", timeout=3)
        b.wait_for(hidden, timeout=3)
        # A window fills the screen.
        b.eval(f"openEditModal({DEV_GRAPH}); true")
        b.wait_for("!document.getElementById('modal-edit-device').classList.contains('hidden')")
        box = b.eval("(() => { const r = document.querySelector('#modal-edit-device .modal').getBoundingClientRect(); return [r.left, r.width]; })()")
        assert box[0] <= 1 and box[1] >= 389, box
        b.eval("document.getElementById('modal-edit-device').classList.add('hidden'); true")
        # Fields are 16 px, so the phone does not zoom in on a tap.
        size = b.eval("getComputedStyle(document.getElementById('edit-ip')).fontSize")
        assert size == "16px", size
    finally:
        b.send("Emulation.clearDeviceMetricsOverride")
        b.eval("location.hash = '#/dashboard'; true")
        time.sleep(0.5)
    return f"{len(routes)} pages at 390 px, menu drawer, full-screen window"


@check("No JavaScript errors were raised")
def t_no_js_errors(b):
    errors = [e for e in b.events if e.get("method") == "Runtime.exceptionThrown"]
    assert not errors, errors[:2]
    return "none"


def main() -> int:
    global DEV_GRAPH, DEV_SSH
    env = dict(os.environ)
    server = subprocess.Popen([sys.executable, os.path.join(_env.ROOT, "server.py")], env=env,
                              stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, cwd=_env.ROOT)
    browser = None
    try:
        for _ in range(60):
            try:
                api("/api/auth/status")
                break
            except OSError:
                time.sleep(0.5)
        api("/api/auth/setup", {"username": UI_USER, "password": UI_PASSWORD})
        # Seed: an offline device (raises a problem) and one with ping history (for graphs).
        DEV_GRAPH = api("/api/devices", {"hostname": "ui-graph", "ip_address": "192.0.2.61", "profile_id": "generic_device"})["device_id"]
        api("/api/devices", {"hostname": "ui-offline", "ip_address": "192.0.2.62", "profile_id": "generic_device"})
        DEV_SSH = api("/api/devices", {"hostname": "ui-ssh", "ip_address": SSH_HOST, "profile_id": "generic_device"})["device_id"] if SSH_HOST else None
        import database
        import setup as site_setup
        # These checks stand for an install already set up; until then the app opens the setup guide.
        site_setup.mark_completed()
        now = int(time.time())
        database.record_metrics(DEV_GRAPH, {"icmp_ping_ms": 1.0}, timestamp=now - 7200)
        for i in range(60):
            database.record_metrics(DEV_GRAPH, {"icmp_ping_ms": 1.0 + (i % 7)}, timestamp=now - 3600 + i * 60)

        browser = Browser(_env.free_port(), height=2400)
        browser.send("Runtime.enable")
        browser.send("Page.enable")
        # Dialog prompts would block a headless page: answer them.
        # The app draws its own confirmation windows (.dialog); accept each one as it appears,
        # filling any text field with "ui-test". The browser's own dialogs are stubbed as a backstop.
        browser.send("Page.addScriptToEvaluateOnNewDocument", {"source": (
            "window.confirm = () => true; window.prompt = () => 'ui-test';"
            "new MutationObserver(() => { const d = document.querySelector('form.dialog:not([data-auto])');"
            " if (!d || window.__noAutoDialog) return; d.dataset.auto = '1'; const i = d.querySelector('.dialog-input');"
            " if (i) i.value = 'ui-test'; setTimeout(() => d.requestSubmit(), 0); })"
            ".observe(document, { childList: true, subtree: true });"
            # Step-up password prompts (tier 2 / 3 after the window lapses) are answered with the test
            # password; checks that inspect the prompt set window.__noAutoConfirm.
            "setInterval(() => { const m = document.getElementById('modal-confirm-password');"
            " if (!m || m.classList.contains('hidden') || window.__noAutoConfirm || m.dataset.auto === '1') return;"
            " m.dataset.auto = '1'; document.getElementById('confirm-password').value = " + json.dumps(UI_PASSWORD) + ";"
            " document.getElementById('confirm-password-form').requestSubmit();"
            " setTimeout(() => { m.dataset.auto = ''; }, 1500); }, 300);")})
        browser.send("Page.navigate", {"url": BASE + "/#/dashboard"})
        browser.wait_for("document.readyState === 'complete' && typeof loadDashboard === 'function'")

        print(f"Browser checks against {BASE} (isolated database {_env.TMP})")
        for test in (t_login, t_dashboard, t_resize, t_move, t_columns, t_graph_tile, t_content_follows, t_map, t_sort, t_groups,
                     t_ack, t_live, t_settings, t_settings_invalid, t_alert_rules, t_shell, t_event_log, t_settings_guard, t_two_factor, t_users, t_confirm_on_top, t_availability, t_series_toggle, t_settings_sidebar, t_updates, t_demo_card, t_message_rows, t_command_replies, t_service_check, t_add_ping, t_setup_services, t_groups_tags, t_https, t_tag_quick, t_custom_snmp, t_changes, t_lan_ui, t_pihole_http_warning, t_inventory_quiet, t_host_actions, t_credentials_use_hiding, t_scoped_user_hiding, t_wifi_pihole, t_guide, t_credentials, t_task, t_workflow, t_quiet_steps, t_telegram_editor, t_setup_preview, t_bulk_delete, t_hostkey, t_run, t_dashboards, t_login_page, t_https_lost_login, t_forced_2fa_enrolment, t_logout, t_device_text_stays_text, t_audit_columns, t_phone, t_no_js_errors):
            # HM_ONLY=t_users,t_shell runs a subset (login always runs first) while debugging.
            only = os.environ.get("HM_ONLY")
            if only and test is not t_login and test.__name__ not in only.split(","):
                continue
            test(browser)
    finally:
        if browser:
            browser.close()
        server.terminate()
        try:
            server.wait(timeout=10)
        except subprocess.TimeoutExpired:
            server.kill()
    out = os.path.join(_env.ROOT, "tests", "results")
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, "browser.json"), "w", encoding="utf-8") as f:
        json.dump({"run_at": time.strftime("%Y-%m-%d %H:%M:%S"), "ssh_host": bool(SSH_HOST), "results": RESULTS}, f, indent=2)
    failed = [r for r in RESULTS if not r["ok"]]
    print(f"\n{len(RESULTS) - len(failed)} passed, {len(failed)} failed")
    return 1 if failed else 0


DEV_GRAPH = DEV_SSH = None

if __name__ == "__main__":
    sys.exit(main())
