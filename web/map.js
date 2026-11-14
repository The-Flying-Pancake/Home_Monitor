/* Network map: inferred topology plus hand-drawn objects and links, drawn as SVG.
 *
 * Nodes are dragged to arrange the map (positions are saved server-side).
 * Dragging a node also moves everything that hangs off it (its downstream
 * branch), which follows on a damped spring and settles at its old offset;
 * Alt-drag moves one node only. After a drag, and when the map loads, a short
 * collision pass nudges overlapping boxes apart.
 * Clicking a node highlights everything downstream of it: the nodes whose
 * path to the gateway passes through it, i.e. what loses connectivity when
 * it restarts. In edit mode you add objects that are not monitored,
 * draws links between any two nodes, and hides inferred links that are wrong.
 * Links are smooth curves between the sides of two boxes that face each other;
 * of the possible side pairs the one that passes through no other box (and is
 * shortest) is drawn, so a link always visibly meets both boxes wherever they
 * are dragged. Port names sit in small tags at the ends. Hovering a box lights
 * up its links. Dropped boxes snap to the background grid.
 * This monitor is not drawn (it confused people who did not know what it was);
 * the side panel says where it is connected and warns when a restart would cut
 * it off.
 * Relies on helpers from app.js (api, escapeHtml, showToast, confirmDialog).
 */

const MAP_NODE_W = 196;
const MAP_NODE_H = 64;
const MAP_GAP_X = 44;        // between sibling subtrees
const MAP_GAP_Y = 72;        // between a parent's bottom and its children's top
const MAP_SNAP = 20;         // the background grid; dropped boxes snap to it
const MAP_COMB_AT = 2;       // this many leaf children or more are stacked in columns (keeps the tree narrow and readable)
const MAP_COMB_ROWS = 4;     // leaves per column
const MAP_TRUNK = 18;        // trunk offset left of a stacked column
const MAP_COMB_ROW = MAP_NODE_H + 16;
const MAP_COMB_COL = MAP_NODE_W + MAP_TRUNK + 24;
const MAP_MARGIN = 14;       // minimum clearance kept between boxes by the collision pass
const MAP_KIND_LABEL = { gateway: "Gateway", switch: "Switch", ap: "Access point", nas: "NAS", host: "Host",
  monitor: "This monitor", router: "Router", modem: "Modem", server: "Server", other: "Object", service: "Service" };
const MAP_HINT = "Drag to arrange; a device's branch moves with it (hold Alt to move one box). Click a device to see what depends on it.";

let mapData = null;
let mapSelected = null;
let mapEditing = false;
let mapLinkFrom = null;
let mapView = { x: -40, y: -40, scale: 1 };
let mapFitted = false;
let mapAnim = null;          // spring state while a branch follows a drag
const MAP_HIDDEN_KEYS = new Set(["monitor"]);   // in the data (dependencies), not drawn
const mapShown = n => !MAP_HIDDEN_KEYS.has(n.key) && n.kind !== "monitor" && !mapFoldHidden.has(n.key);

/* Folding: a box with devices below it can hide them (its fold button, or the side panel). Tidy
 * arranges what is shown as a tree while you look, without saving it, so the rest closes up around a
 * folded branch. Both are remembered in this browser. */
const MAP_FOLD_STORE = "monitor.map.folded";
const MAP_TIDY_STORE = "monitor.map.tidy";
let mapFolded = new Set();
let mapFoldHidden = new Set();
let mapTidy = false;
let mapDrawnPos = {};

function mapComputeFolded() {
  const children = mapChildren(mapData);
  const out = new Set();
  const walk = k => (children[k] || []).forEach(c => { if (!out.has(c)) { out.add(c); walk(c); } });
  mapFolded.forEach(k => walk(k));
  mapFoldHidden = out;
}

function mapBelowCount(key) {
  const children = mapChildren(mapData);
  let n = 0;
  const walk = k => (children[k] || []).forEach(c => { n += 1; walk(c); });
  walk(key);
  return n;
}

function mapToggleFold(key) {
  if (mapFolded.has(key)) mapFolded.delete(key); else mapFolded.add(key);
  storeSet(MAP_FOLD_STORE, JSON.stringify([...mapFolded]));
  drawMap();
  if (mapTidy) fitMap();
}

function initMap() {
  document.getElementById("map-edit").addEventListener("click", () => {
    mapEditing = !mapEditing;
    mapLinkFrom = null;
    document.getElementById("map-edit").textContent = mapEditing ? "Done" : "Edit";
    document.getElementById("map-edit").classList.toggle("btn-primary", mapEditing);
    document.querySelectorAll(".map-edit-only").forEach(el => el.classList.toggle("hidden", !mapEditing));
    document.querySelectorAll(".map-view-only").forEach(el => el.classList.toggle("hidden", mapEditing));
    updateMapHint();
    drawMap();
  });
  document.getElementById("map-layout").addEventListener("click", async () => {
    const positions = autoLayout(mapData, true);
    mapData.positions = positions;
    drawMap();
    fitMap();
    try {
      await api("/api/map/positions", { method: "PUT", body: { positions, replace: true } });
      showToast("Map arranged as a tree from the gateway", "success");
    } catch (err) {
      showToast(`Could not save layout: ${err.message}`, "error");
    }
  });
  document.getElementById("map-add-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const label = document.getElementById("map-add-label").value.trim();
    const kind = document.getElementById("map-add-kind").value;
    if (!label) return;
    try {
      await api("/api/map/objects", { method: "POST", body: { label, kind } });
      document.getElementById("map-add-label").value = "";
      showToast(`Added ${label}. Draw its links with Link.`, "success");
      await loadMap();
    } catch (err) {
      showToast(`Could not add object: ${err.message}`, "error");
    }
  });
  document.getElementById("map-fit").addEventListener("click", () => fitMap());
  for (const [id, f] of [["map-zoom-in", 1.25], ["map-zoom-out", 1 / 1.25]]) {
    document.getElementById(id).addEventListener("click", () => {
      const svg = document.getElementById("map-svg");
      const w = mapViewBoxWidth(), h = (svg.clientHeight || 600) / mapView.scale;
      const cx = mapView.x + w / 2, cy = mapView.y + h / 2;
      mapView.scale = Math.min(4, Math.max(0.25, mapView.scale * f));
      mapView.x = cx - mapViewBoxWidth() / 2;
      mapView.y = cy - (svg.clientHeight || 600) / mapView.scale / 2;
      setViewBox();
    });
  }
  mapTraffic = storeGet(MAP_TRAFFIC_STORE) === "1";
  try { mapFolded = new Set(JSON.parse(storeGet(MAP_FOLD_STORE) || "[]")); } catch (e) { mapFolded = new Set(); }
  mapTidy = storeGet(MAP_TIDY_STORE) === "1";
  const tidyBtn = document.getElementById("map-tidy");
  const syncTidy = () => { tidyBtn.classList.toggle("btn-primary", mapTidy); tidyBtn.setAttribute("aria-pressed", String(mapTidy)); };
  syncTidy();
  tidyBtn.addEventListener("click", () => {
    mapTidy = !mapTidy;
    storeSet(MAP_TIDY_STORE, mapTidy ? "1" : "0");
    syncTidy();
    drawMap();
    fitMap();
  });
  mapWifi = storeGet(MAP_WIFI_STORE) === "1";
  const wifiBtn = document.getElementById("map-wifi");
  const syncWifi = () => { wifiBtn.classList.toggle("btn-primary", mapWifi); wifiBtn.setAttribute("aria-pressed", String(mapWifi)); };
  syncWifi();
  wifiBtn.addEventListener("click", () => {
    mapWifi = !mapWifi;
    storeSet(MAP_WIFI_STORE, mapWifi ? "1" : "0");
    syncWifi();
    drawMap();
  });
  const traffic = document.getElementById("map-traffic");
  const syncTraffic = () => { traffic.classList.toggle("btn-primary", mapTraffic); traffic.setAttribute("aria-pressed", String(mapTraffic)); };
  syncTraffic();
  traffic.addEventListener("click", () => {
    mapTraffic = !mapTraffic;
    storeSet(MAP_TRAFFIC_STORE, mapTraffic ? "1" : "0");
    syncTraffic();
    drawMap();
  });
  document.getElementById("map-link").addEventListener("click", () => {
    mapLinkFrom = mapLinkFrom === null ? "" : null;
    updateMapHint();
  });

  const svg = document.getElementById("map-svg");
  let drag = null;
  svg.addEventListener("pointerdown", (ev) => {
    const fold = ev.target.closest("[data-fold]");
    if (fold) {
      ev.stopPropagation();
      mapToggleFold(fold.dataset.fold);
      return;
    }
    const g = ev.target.closest("[data-node]");
    const pt = mapPoint(ev);
    if (g) {
      const key = g.dataset.node;
      const pos = mapData.positions[key];
      const branch = ev.altKey ? [] : mapDownstream(key).filter(k => mapData.positions[k]);
      const offsets = Object.fromEntries(branch.map(k => [k, [mapData.positions[k][0] - pos[0], mapData.positions[k][1] - pos[1]]]));
      drag = { kind: "node", key, dx: pt.x - pos[0], dy: pt.y - pos[1], moved: false, offsets, start: [...pos] };
    } else if (!ev.target.closest("[data-link]")) {
      drag = { kind: "pan", sx: ev.clientX, sy: ev.clientY, vx: mapView.x, vy: mapView.y, moved: false };
    }
    if (drag) svg.setPointerCapture(ev.pointerId);
  });
  svg.addEventListener("pointermove", (ev) => {
    if (!drag) return;
    if (drag.kind === "node") {
      if (mapTidy && !mapEditing) return;
      const pt = mapPoint(ev);
      const x = Math.round(pt.x - drag.dx), y = Math.round(pt.y - drag.dy);
      if (Math.abs(drag.start[0] - x) + Math.abs(drag.start[1] - y) > 2) drag.moved = true;
      mapData.positions[drag.key] = [x, y];
      if (drag.moved) {
        springTargets(drag.key, drag.offsets);
        drawMap();
      }
    } else {
      const rect = svg.getBoundingClientRect();
      const k = (rect.width ? mapViewBoxWidth() / rect.width : 1);
      mapView.x = drag.vx - (ev.clientX - drag.sx) * k;
      mapView.y = drag.vy - (ev.clientY - drag.sy) * k;
      drag.moved = true;
      setViewBox();
    }
  });
  svg.addEventListener("pointerup", async (ev) => {
    const d = drag;
    drag = null;
    if (!d) return;
    if (d.kind === "node" && d.moved) {
      const group = [d.key, ...Object.keys(d.offsets)];
      await springSettled();
      // Snap the dropped box to the grid; its branch moves by the same amount.
      const p0 = mapData.positions[d.key];
      const sx = Math.round(p0[0] / MAP_SNAP) * MAP_SNAP - p0[0], sy = Math.round(p0[1] / MAP_SNAP) * MAP_SNAP - p0[1];
      for (const k of group) if (mapData.positions[k]) mapData.positions[k] = [mapData.positions[k][0] + sx, mapData.positions[k][1] + sy];
      const before = Object.fromEntries(Object.entries(mapData.positions).map(([k, v]) => [k, [...v]]));
      resolveOverlaps(mapData.positions, new Set(group));
      drawMap();
      const changed = { };
      for (const [k, v] of Object.entries(mapData.positions)) {
        if (group.includes(k) || !before[k] || before[k][0] !== v[0] || before[k][1] !== v[1]) changed[k] = v;
      }
      try {
        await api("/api/map/positions", { method: "PUT", body: { positions: changed } });
      } catch (err) {
        showToast(`Could not save position: ${err.message}`, "error");
      }
    } else if (d.kind === "node") {
      onNodeClick(d.key);
    } else if (!d.moved) {
      mapSelected = null;
      drawMap();
    }
  });
  svg.addEventListener("click", async (ev) => {
    const line = ev.target.closest("[data-link]");
    if (!line || !mapEditing) return;
    const link = mapData.links[parseInt(line.dataset.link, 10)];
    // Removing the stored row deletes a manual link, or un-hides an inferred one.
    const action = link.source === "manual" || link.hidden ? "remove" : "hide";
    const message = link.source === "manual" ? "Remove this link from the map?"
      : link.hidden ? "Show this inferred link again?" : "Hide this inferred link? Use this when the map guessed wrong.";
    const ok = await confirmDialog({
      title: link.source === "manual" ? "Remove link" : link.hidden ? "Show link" : "Hide link",
      message, confirmLabel: action === "remove" && link.source === "manual" ? "Remove" : link.hidden ? "Show" : "Hide",
      danger: link.source === "manual",
    });
    if (!ok) return;
    try {
      await api("/api/map/links", { method: "POST", body: { a: link.a, b: link.b, action } });
      await loadMap();
    } catch (err) {
      showToast(`Could not change link: ${err.message}`, "error");
    }
  });
  svg.addEventListener("wheel", (ev) => {
    ev.preventDefault();
    const pt = mapPoint(ev);
    // Wheel up (away from you) zooms in, wheel down zooms out.
    const factor = ev.deltaY > 0 ? 1 / 1.15 : 1.15;
    mapView.scale = Math.min(4, Math.max(0.25, mapView.scale * factor));
    const rect = svg.getBoundingClientRect();
    mapView.x = pt.x - (ev.clientX - rect.left) * mapViewBoxWidth() / rect.width;
    mapView.y = pt.y - (ev.clientY - rect.top) * mapViewBoxWidth() / rect.width;
    setViewBox();
  }, { passive: false });
  svg.addEventListener("pointerover", (ev) => {
    const g = ev.target.closest("[data-node]");
    const key = g ? g.dataset.node : null;
    svg.querySelectorAll("[data-link]").forEach(el => el.classList.toggle("hover", !!key && (el.dataset.a === key || el.dataset.b === key)));
  });
  svg.addEventListener("pointerleave", () => svg.querySelectorAll("[data-link].hover").forEach(el => el.classList.remove("hover")));
  new ResizeObserver(() => { if (mapData) setViewBox(); }).observe(svg);
}

async function loadMap() {
  try {
    mapData = await api("/api/map");
  } catch (err) {
    showToast(`Could not load map: ${err.message}`, "error");
    return;
  }
  const kinds = document.getElementById("map-add-kind");
  if (!kinds.options.length) {
    kinds.innerHTML = mapData.object_kinds.map(k => `<option value="${escapeHtml(k)}">${escapeHtml(MAP_KIND_LABEL[k] || k)}</option>`).join("");
  }
  const missing = mapData.nodes.filter(n => mapShown(n) && !mapData.positions[n.key]).map(n => n.key);
  if (missing.length) {
    const auto = autoLayout(mapData, false);
    for (const [k, v] of Object.entries(auto)) if (!mapData.positions[k]) mapData.positions[k] = v;
  }
  // Saved positions are your own arrangement: only boxes that overlap are moved, and only as far as needed.
  const before = JSON.stringify(mapData.positions);
  const moved = resolveOverlaps(mapData.positions, new Set());
  if (mapSelected && !mapData.nodes.some(n => n.key === mapSelected)) mapSelected = null;
  updateMapHint();
  drawMap();
  if (!mapFitted) fitMap();
  else setViewBox();
  if (moved.size && JSON.stringify(mapData.positions) !== before) {
    const positions = Object.fromEntries([...moved].map(k => [k, mapData.positions[k]]));
    api("/api/map/positions", { method: "PUT", body: { positions } }).catch(() => {});
  }
}

/** Zooms and pans so every node is visible with a margin, never enlarging past 100 %. */
function fitMap() {
  const svg = document.getElementById("map-svg");
  const pts = mapData.nodes.filter(mapShown).map(n => (mapDrawnPos[n.key] || mapData.positions[n.key])).filter(Boolean);
  if (!pts.length || !svg.clientWidth) return setViewBox();
  const pad = 40;
  const minX = Math.min(...pts.map(p => p[0])) - pad, maxX = Math.max(...pts.map(p => p[0])) + MAP_NODE_W + pad;
  const minY = Math.min(...pts.map(p => p[1])) - pad, maxY = Math.max(...pts.map(p => p[1])) + MAP_NODE_H + pad;
  // Never smaller than about 60 %: below that the text is too small to read; a bigger map pans instead.
  // The legend strip along the bottom is kept clear so it never covers the last row.
  const legend = document.querySelector(".map-legend"), h = svg.clientHeight - (legend ? legend.offsetHeight + 16 : 0);
  mapView.scale = Math.max(0.6, Math.min(1.1, svg.clientWidth / (maxX - minX), h / (maxY - minY)));
  mapView.x = minX - (svg.clientWidth / mapView.scale - (maxX - minX)) / 2;
  mapView.y = minY - Math.max(0, (h / mapView.scale - (maxY - minY)) / 4);
  mapFitted = true;
  setViewBox();
}

function mapChildren(data) {
  const children = {};
  for (const [n, p] of Object.entries(data.parent)) if (p && !MAP_HIDDEN_KEYS.has(n)) (children[p] = children[p] || []).push(n);
  const label = k => (data.nodes.find(n => n.key === k) || {}).label || k;
  Object.values(children).forEach(list => list.sort((a, b) => label(a).localeCompare(label(b))));
  return children;
}

/**
 * Layered tree layout from the root. Each subtree is measured first and siblings
 * are placed side by side by subtree width, so boxes cannot overlap. A parent
 * with MAP_COMB_AT or more leaf children stacks those leaves in columns (fed by
 * a trunk on their left) instead of one wide row. Nodes with no path to the
 * root are put in a grid under the tree. With all false, only nodes without a
 * saved position are returned.
 */
function autoLayout(data, all) {
  const children = mapChildren(data);
  const positions = {};
  const kidsOf = k => mapFolded.has(k) ? [] : children[k] || [];

  // Blocks: a laid-out piece with a width and a place(left, top) function.
  const block = (node) => {
    const kids = kidsOf(node);
    const leaves = kids.filter(k => !kidsOf(k).length);
    const comb = leaves.length >= MAP_COMB_AT;
    const parts = [];
    for (const k of kids) if (!comb || kidsOf(k).length) parts.push(block(k));
    if (comb) {
      const cols = Math.ceil(leaves.length / MAP_COMB_ROWS);
      const rows = Math.ceil(leaves.length / cols);
      parts.push({
        w: MAP_TRUNK + cols * MAP_NODE_W + (cols - 1) * (MAP_COMB_COL - MAP_NODE_W),
        place: (left, top) => leaves.forEach((k, i) => {
          positions[k] = [left + MAP_TRUNK + Math.floor(i / rows) * MAP_COMB_COL, top + (i % rows) * MAP_COMB_ROW];
        }),
      });
    }
    const span = parts.reduce((s, p) => s + p.w, 0) + Math.max(0, parts.length - 1) * MAP_GAP_X;
    const w = Math.max(MAP_NODE_W, span);
    return {
      w,
      place: (left, top) => {
        positions[node] = [Math.round(left + (w - MAP_NODE_W) / 2), top];
        let x = left + (w - span) / 2;
        for (const p of parts) {
          p.place(x, top + MAP_NODE_H + MAP_GAP_Y);
          x += p.w + MAP_GAP_X;
        }
      },
    };
  };
  let width = 6 * (MAP_NODE_W + MAP_GAP_X);
  if (data.root) {
    const b = block(data.root);
    b.place(0, 0);
    width = Math.max(width, b.w);
  }
  // Nodes with no path to the gateway: a grid under the tree.
  const bottom = Math.max(-MAP_NODE_H, ...Object.values(positions).map(p => p[1])) + MAP_NODE_H + MAP_GAP_Y + 30;
  const perRow = Math.max(1, Math.floor((width + MAP_GAP_X) / (MAP_NODE_W + MAP_GAP_X)));
  let loose = 0;
  for (const n of data.nodes) {
    if (positions[n.key] || !mapShown(n)) continue;
    positions[n.key] = [(loose % perRow) * (MAP_NODE_W + MAP_GAP_X), bottom + Math.floor(loose / perRow) * (MAP_NODE_H + 30)];
    loose += 1;
  }
  for (const k of Object.keys(positions)) positions[k] = positions[k].map(Math.round);
  if (!all) for (const k of Object.keys(positions)) if (data.positions[k]) delete positions[k];
  return positions;
}

/**
 * Pushes overlapping boxes apart (keeping MAP_MARGIN between them) along the axis
 * of least overlap. Pinned keys (the branch just dropped) do not move. Returns
 * the keys that moved. Bounded iterations: a dense cluster settles in a few.
 */
function resolveOverlaps(positions, pinned) {
  const keys = Object.keys(positions).filter(k => mapData.nodes.some(n => n.key === k && mapShown(n)));
  const moved = new Set();
  const w = MAP_NODE_W + MAP_MARGIN, h = MAP_NODE_H + MAP_MARGIN;
  for (let iter = 0; iter < 40; iter++) {
    let any = false;
    for (let i = 0; i < keys.length; i++) {
      for (let j = i + 1; j < keys.length; j++) {
        const a = keys[i], b = keys[j];
        const pa = positions[a], pb = positions[b];
        const ox = w - Math.abs(pa[0] - pb[0]), oy = h - Math.abs(pa[1] - pb[1]);
        if (ox <= 0 || oy <= 0) continue;
        const fa = pinned.has(a), fb = pinned.has(b);
        if (fa && fb) continue;
        any = true;
        // Share the push, or give it all to the free box.
        const sa = fa ? 0 : fb ? 1 : 0.5, sb = 1 - sa;
        if (ox < oy) {
          const dir = pa[0] < pb[0] || (pa[0] === pb[0] && a < b) ? -1 : 1;
          pa[0] += Math.ceil(dir * ox * sa); pb[0] -= Math.ceil(dir * ox * sb);
        } else {
          const dir = pa[1] < pb[1] || (pa[1] === pb[1] && a < b) ? -1 : 1;
          pa[1] += Math.ceil(dir * oy * sa); pb[1] -= Math.ceil(dir * oy * sb);
        }
        if (sa) moved.add(a);
        if (sb) moved.add(b);
      }
    }
    if (!any) break;
  }
  for (const k of moved) positions[k] = positions[k].map(Math.round);
  return moved;
}

// --- Branch spring ---

const mapReducedMotion = () => window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;

/** Sets where each branch node should end up; the animation loop pulls them there. */
function springTargets(key, offsets) {
  const keys = Object.keys(offsets);
  if (!keys.length) return;
  const base = mapData.positions[key];
  if (!mapAnim) mapAnim = { nodes: {}, frame: null, waiters: [] };
  const depth = depthsBelow(key);
  for (const k of keys) {
    const target = [base[0] + offsets[k][0], base[1] + offsets[k][1]];
    const st = mapAnim.nodes[k] || (mapAnim.nodes[k] = { v: [0, 0], depth: depth[k] || 1 });
    st.target = target;
  }
  if (mapReducedMotion()) {
    for (const [k, st] of Object.entries(mapAnim.nodes)) mapData.positions[k] = [...st.target];
    finishSpring();
    return;
  }
  if (!mapAnim.frame) mapAnim.frame = requestAnimationFrame(springStep);
}

/** Damped spring per node; deeper nodes are a little softer, so the branch trails like a chain. */
function springStep() {
  const anim = mapAnim;
  if (!anim) return;
  let busy = false;
  for (const [k, st] of Object.entries(anim.nodes)) {
    const p = mapData.positions[k];
    if (!p) continue;
    const stiff = 0.28 / (1 + 0.35 * (st.depth - 1)), damp = 0.62;
    for (const i of [0, 1]) {
      st.v[i] = st.v[i] * damp + (st.target[i] - p[i]) * stiff;
      p[i] += st.v[i];
    }
    if (Math.abs(st.target[0] - p[0]) + Math.abs(st.target[1] - p[1]) > 0.5 || Math.abs(st.v[0]) + Math.abs(st.v[1]) > 0.5) busy = true;
    else { p[0] = st.target[0]; p[1] = st.target[1]; st.v = [0, 0]; }
  }
  drawMap();
  if (busy) anim.frame = requestAnimationFrame(springStep);
  else { anim.frame = null; if (anim.waiters.length) finishSpring(); }
}

function finishSpring() {
  const anim = mapAnim;
  if (!anim) return;
  if (anim.frame) cancelAnimationFrame(anim.frame);
  for (const [k, st] of Object.entries(anim.nodes)) if (mapData.positions[k]) mapData.positions[k] = st.target.map(Math.round);
  mapAnim = null;
  anim.waiters.forEach(fn => fn());
}

/** Resolves once the branch has come to rest (immediately when nothing is moving). */
function springSettled() {
  if (!mapAnim) return Promise.resolve();
  return new Promise(resolve => {
    mapAnim.waiters.push(resolve);
    if (!mapAnim.frame) finishSpring();
  });
}

function depthsBelow(key) {
  const children = mapChildren(mapData);
  const out = {};
  const walk = (k, d) => (children[k] || []).forEach(c => { out[c] = d; walk(c, d + 1); });
  walk(key, 1);
  return out;
}

function mapDownstream(key) {
  const children = {};
  for (const [n, p] of Object.entries(mapData.parent)) if (p) (children[p] = children[p] || []).push(n);
  const out = [];
  const stack = [...(children[key] || [])];
  while (stack.length) {
    const n = stack.pop();
    out.push(n);
    stack.push(...(children[n] || []));
  }
  return out;
}

async function onNodeClick(key) {
  if (mapEditing && mapLinkFrom !== null) {
    if (mapLinkFrom === "") {
      mapLinkFrom = key;
      updateMapHint();
      drawMap();
      return;
    }
    if (mapLinkFrom !== key) {
      try {
        await api("/api/map/links", { method: "POST", body: { a: mapLinkFrom, b: key, action: "add" } });
      } catch (err) {
        showToast(`Could not add link: ${err.message}`, "error");
      }
    }
    mapLinkFrom = null;
    updateMapHint();
    await loadMap();
    return;
  }
  mapSelected = mapSelected === key ? null : key;
  drawMap();
}

function updateMapHint() {
  const hint = document.getElementById("map-hint");
  hint.textContent = mapLinkFrom === null ? MAP_HINT
    : mapLinkFrom === "" ? "Link: click the first node." : "Link: click the second node.";
  document.getElementById("map-link").classList.toggle("btn-primary", mapLinkFrom !== null);
}

function mapViewBoxWidth() {
  const svg = document.getElementById("map-svg");
  return (svg.clientWidth || 1000) / mapView.scale;
}

function setViewBox() {
  const svg = document.getElementById("map-svg");
  const w = mapViewBoxWidth();
  const h = (svg.clientHeight || 600) / mapView.scale;
  svg.setAttribute("viewBox", `${mapView.x} ${mapView.y} ${w} ${h}`);
}

function mapPoint(ev) {
  const svg = document.getElementById("map-svg");
  const rect = svg.getBoundingClientRect();
  const w = mapViewBoxWidth();
  return { x: mapView.x + (ev.clientX - rect.left) * w / rect.width, y: mapView.y + (ev.clientY - rect.top) * w / rect.width };
}

function nodeState(n) {
  if (n.kind === "monitor") return "monitor";
  if (!n.device_id) return "object";
  if (n.status === "offline") return "down";
  if (n.problems) return "warn";
  return "up";
}

// --- Link routing ---

const MAP_SIDES = { top: [0, -1], bottom: [0, 1], left: [-1, 0], right: [1, 0] };

function mapAnchor(p, side) {
  return { top: [p[0] + MAP_NODE_W / 2, p[1]], bottom: [p[0] + MAP_NODE_W / 2, p[1] + MAP_NODE_H],
           left: [p[0], p[1] + MAP_NODE_H / 2], right: [p[0] + MAP_NODE_W, p[1] + MAP_NODE_H / 2] }[side];
}

/** Cubic curve leaving a along side sa and arriving at b along side sb. */
function mapCurve(a, sa, b, sb) {
  const k = Math.max(28, Math.min(150, Math.hypot(b[0] - a[0], b[1] - a[1]) * 0.45));
  const na = MAP_SIDES[sa], nb = MAP_SIDES[sb];
  return [a, [a[0] + na[0] * k, a[1] + na[1] * k], [b[0] + nb[0] * k, b[1] + nb[1] * k], b];
}

function curvePoint(c, t) {
  const u = 1 - t;
  return [0, 1].map(i => u * u * u * c[0][i] + 3 * u * u * t * c[1][i] + 3 * u * t * t * c[2][i] + t * t * t * c[3][i]);
}

/** How many other boxes the curve passes through (sampled; boxes shrunk a little so grazing is allowed). */
function curveHits(c, boxes) {
  let hits = 0;
  for (const b of boxes) {
    const l = b[0] + 6, t = b[1] + 6, r = b[0] + MAP_NODE_W - 6, btm = b[1] + MAP_NODE_H - 6;
    for (let i = 1; i < 24; i++) {
      const [x, y] = curvePoint(c, i / 24);
      if (x > l && x < r && y > t && y < btm) { hits++; break; }
    }
  }
  return hits;
}

/**
 * Picks the sides a link leaves u and enters c by: every side pair is scored by the
 * boxes it would cross, whether each end faces the other box, and its length; the
 * best one wins. So the link always meets the sides that face each other, and goes
 * around other boxes when it can.
 */
function routeLink(u, c, boxes) {
  const uc = [u[0] + MAP_NODE_W / 2, u[1] + MAP_NODE_H / 2], cc = [c[0] + MAP_NODE_W / 2, c[1] + MAP_NODE_H / 2];
  let best = null;
  for (const sa of Object.keys(MAP_SIDES)) {
    for (const sb of Object.keys(MAP_SIDES)) {
      const a = mapAnchor(u, sa), b = mapAnchor(c, sb);
      const na = MAP_SIDES[sa], nb = MAP_SIDES[sb];
      // An end facing away from the other box would loop round it.
      const away = (na[0] * (cc[0] - uc[0]) + na[1] * (cc[1] - uc[1]) < 0 ? 1 : 0)
        + (nb[0] * (uc[0] - cc[0]) + nb[1] * (uc[1] - cc[1]) < 0 ? 1 : 0);
      const curve = mapCurve(a, sa, b, sb);
      const score = curveHits(curve, boxes) * 10000 + away * 2000 + Math.hypot(b[0] - a[0], b[1] - a[1]);
      if (!best || score < best.score) best = { score, curve, sa, sb };
    }
  }
  return best;
}

// Small line icons per kind of box (24 x 24, drawn with the box's text colour).
const MAP_ICONS = {
  gateway: '<circle cx="12" cy="12" r="8"/><path d="M4 12h16M12 4c2.5 2.4 2.5 13.6 0 16M12 4c-2.5 2.4-2.5 13.6 0 16"/>',
  router: '<circle cx="12" cy="12" r="8"/><path d="M4 12h16M12 4c2.5 2.4 2.5 13.6 0 16M12 4c-2.5 2.4-2.5 13.6 0 16"/>',
  switch: '<rect x="3" y="7" width="18" height="10" rx="2"/><path d="M7 12h.01M10 12h.01M13 12h.01M16 12h.01"/>',
  ap: '<path d="M5 10a10 10 0 0 1 14 0M8 13a6 6 0 0 1 8 0M11 16a2 2 0 0 1 2 0"/><circle cx="12" cy="19" r="0.6"/>',
  nas: '<rect x="5" y="4" width="14" height="6" rx="1.5"/><rect x="5" y="14" width="14" height="6" rx="1.5"/><path d="M8 7h.01M8 17h.01"/>',
  host: '<rect x="4" y="4" width="16" height="7" rx="1.5"/><rect x="4" y="13" width="16" height="7" rx="1.5"/><path d="M8 7.5h.01M8 16.5h.01"/>',
  server: '<rect x="4" y="4" width="16" height="7" rx="1.5"/><rect x="4" y="13" width="16" height="7" rx="1.5"/><path d="M8 7.5h.01M8 16.5h.01"/>',
  service: '<path d="M9 3v5M15 3v5M7 8h10v3a5 5 0 0 1-10 0zM12 16v5"/>',
  modem: '<rect x="4" y="11" width="16" height="8" rx="2"/><path d="M8 11 6 5M16 11l2-6M8 15h.01M12 15h.01"/>',
  other: '<circle cx="12" cy="12" r="7"/>',
};

/** Path through points with rounded corners (radius r), for the trunk links of a stacked column. */
function roundedPath(pts, r = 9) {
  let d = `M${pts[0][0]},${pts[0][1]}`;
  for (let i = 1; i < pts.length - 1; i++) {
    const [p0, p1, p2] = [pts[i - 1], pts[i], pts[i + 1]];
    const l1 = Math.hypot(p1[0] - p0[0], p1[1] - p0[1]), l2 = Math.hypot(p2[0] - p1[0], p2[1] - p1[1]);
    const k = Math.min(r, l1 / 2, l2 / 2);
    if (!k) { d += ` L${p1[0]},${p1[1]}`; continue; }
    const a = [p1[0] - (p1[0] - p0[0]) / l1 * k, p1[1] - (p1[1] - p0[1]) / l1 * k];
    const b = [p1[0] + (p2[0] - p1[0]) / l2 * k, p1[1] + (p2[1] - p1[1]) / l2 * k];
    d += ` L${Math.round(a[0])},${Math.round(a[1])} Q${p1[0]},${p1[1]} ${Math.round(b[0])},${Math.round(b[1])}`;
  }
  const e = pts[pts.length - 1];
  return d + ` L${e[0]},${e[1]}`;
}

/**
 * Children stacked in a column under their parent share one trunk: down from the parent,
 * along the column's left side, a short branch into each child. childKey -> trunk geometry.
 */
function mapTrunks(pos, shownKeys) {
  const out = {};
  const byParent = {};
  for (const [child, parent] of Object.entries(mapData.parent)) {
    if (!parent || !pos[child] || !pos[parent] || !shownKeys.has(child) || !shownKeys.has(parent)) continue;
    if (pos[child][1] < pos[parent][1] + MAP_NODE_H + 8) continue;           // only children below their parent
    (byParent[parent] = byParent[parent] || []).push(child);
  }
  for (const [parent, kids] of Object.entries(byParent)) {
    const columns = {};
    for (const k of kids) (columns[Math.round(pos[k][0] / 8)] = columns[Math.round(pos[k][0] / 8)] || []).push(k);
    for (const col of Object.values(columns)) {
      if (col.length < 2) continue;
      const left = Math.min(...col.map(k => pos[k][0])), top = Math.min(...col.map(k => pos[k][1]));
      const p = pos[parent];
      const start = [Math.round(p[0] + MAP_NODE_W / 2), p[1] + MAP_NODE_H];
      const ymid = Math.round(start[1] + Math.max(14, Math.min(34, (top - start[1]) / 2)));
      for (const k of col) out[k] = { start, ymid, trunkX: Math.round(left - 22) };
    }
  }
  return out;
}

// Traffic on links (the Traffic button, remembered in this browser).
const MAP_TRAFFIC_STORE = "monitor.map.traffic";
let mapTraffic = false;            // read from storage in initMap (storeGet is in shell.js, loaded later)
const MAP_WIFI_STORE = "monitor.map.wifi";
let mapWifi = false;               // the Wi-Fi button: each access point's devices drawn around it

/* Traffic flowing along a link: blue dashes towards the child (down), green towards the parent (up).
 * More traffic flows faster; the dashes are faint, so the map stays calm. */
function mapFlow(l, up, d) {
  const r = l.rate;
  if (!r) return "";
  const fromUp = r.at === up;
  const down = fromUp ? r.out : r.in, upward = fromUp ? r.in : r.out;
  const speed = bps => typeof bps === "number" && bps > 1000 ? Math.max(0.8, 6 - Math.log10(bps) * 0.6) : 0;
  const line = (cls, bps) => speed(bps) ? `<path class="map-flow ${escapeHtml(cls)}" d="${escapeHtml(d)}" style="animation-duration:${speed(bps).toFixed(1)}s"></path>` : "";
  return line("down", down) + line("up", upward);
}

/* The internet above the gateway: a globe, linked to it, with the gateway's WAN traffic when Traffic is on. */
function mapInternet(pos) {
  const root = mapData.root;
  if (!root || !pos[root] || !mapShown(mapData.nodes.find(n => n.key === root) || {})) return "";
  const gx = Math.round(pos[root][0] + MAP_NODE_W / 2), gy = Math.round(pos[root][1]);
  const cx = gx, cy = gy - 70;
  const net = mapData.internet;
  let html = `<path class="map-link internet" d="M${cx},${cy + 18} L${gx},${gy}"></path>`;
  if (mapTraffic && net) {
    const speed = bps => typeof bps === "number" && bps > 1000 ? Math.max(0.8, 6 - Math.log10(bps) * 0.6) : 0;
    // Down comes from the internet to the gateway: the path runs globe to gateway.
    if (speed(net.down)) html += `<path class="map-flow down" d="M${cx},${cy + 18} L${gx},${gy}" style="animation-duration:${speed(net.down).toFixed(1)}s"></path>`;
    if (speed(net.up)) html += `<path class="map-flow up" d="M${cx},${cy + 18} L${gx},${gy}" style="animation-duration:${speed(net.up).toFixed(1)}s"></path>`;
  }
  html += `<g class="map-internet" transform="translate(${cx},${cy})"><circle r="18"></circle>
    <g transform="translate(-12,-12)"><svg width="24" height="24" viewBox="0 0 24 24">${MAP_ICONS.gateway}</svg></g>
    <text y="-24">Internet</text><title>The internet${net ? `, through ${escapeHtml(net.links.join(", "))}` : ""}</title></g>`;
  if (mapTraffic && net) {
    const text = `\u2193${mapRate(net.down)} \u2191${mapRate(net.up)}`;
    const w = text.length * 6.3 + 12;
    html += `<g class="map-rate-tag" transform="translate(${Math.round(cx + 26)},${Math.round(cy - 8)})"><title>${escapeHtml(`Internet: down ${mapRate(net.down)}bit/s, up ${mapRate(net.up)}bit/s`)}</title>` +
      `<rect width="${Math.round(w)}" height="16" rx="8"></rect><text x="${Math.round(w / 2)}" y="11.5">${escapeHtml(text)}</text></g>`;
  }
  return html;
}

/* The Wi-Fi button: an access point's devices in a fan below it, coloured by signal (weak in orange). */
function mapWifiFan(n, p) {
  if (!n.wifi || !n.wifi.clients.length) return "";
  const shown = n.wifi.clients.slice(0, 24);
  const cx = p[0] + MAP_NODE_W / 2, cy = p[1] + MAP_NODE_H;
  const count = shown.length;
  const radius = 70 + Math.min(60, count * 3);
  let html = "";
  shown.forEach((c, i) => {
    const a = Math.PI * (0.15 + 0.7 * (count === 1 ? 0.5 : i / (count - 1)));
    const x = Math.round(cx + Math.cos(a) * radius * 1.4), y = Math.round(cy + Math.sin(a) * radius);
    const weak = typeof c.signal === "number" && c.signal < n.wifi.weak_dbm;
    const label = String(c.name || "").length > 14 ? String(c.name).slice(0, 13) + "…" : String(c.name || "");
    html += `<path class="map-link wifi map-wifi-link" d="M${Math.round(cx)},${Math.round(cy)} L${x},${y}"></path>
      <g class="map-wifi-dot${weak ? " weak" : ""}" transform="translate(${x},${y})"><circle r="7"></circle>
        <text y="19">${escapeHtml(label)}</text><title>${escapeHtml(`${c.name}${c.ssid ? `, ${c.ssid}` : ""}${typeof c.signal === "number" ? `, ${Math.round(c.signal)} dBm` : ""}`)}</title></g>`;
  });
  if (n.wifi.count > count) {
    html += `<text class="map-wifi-more" x="${Math.round(cx)}" y="${Math.round(cy + radius + 34)}">+${escapeHtml(n.wifi.count - count)} more</text>`;
  }
  return html;
}

function mapRate(bps) {
  if (typeof bps !== "number") return "-";
  return bps >= 1e9 ? `${(bps / 1e9).toFixed(1)}G` : bps >= 1e6 ? `${(bps / 1e6).toFixed(bps >= 1e7 ? 0 : 1)}M` : bps >= 1e3 ? `${Math.round(bps / 1e3)}k` : `${Math.round(bps)}`;
}

/* A link's traffic as "down / up" from the parent's side of the tree: down flows towards the child. */
function mapRateTag(l, up, mid) {
  const r = l.rate;
  if (!r) return "";
  const fromUp = r.at === up;
  const down = fromUp ? r.out : r.in, upward = fromUp ? r.in : r.out;
  const busy = r.speed ? Math.max(down || 0, upward || 0) / (r.speed * 1e6) : 0;
  const text = `\u2193${mapRate(down)} \u2191${mapRate(upward)}`;
  const w = text.length * 6.3 + 12;
  return `<g class="map-rate-tag${busy >= 0.7 ? " busy" : ""}" transform="translate(${Math.round(mid[0] - w / 2)},${Math.round(mid[1] - 8)})">` +
    `<title>${escapeHtml(`Down ${mapRate(down)}bit/s, up ${mapRate(upward)}bit/s${r.speed ? ` on a ${r.speed} Mbit/s port (${Math.round(busy * 100)}% busy)` : ""}`)}</title>` +
    `<rect width="${Math.round(w)}" height="16" rx="8"></rect><text x="${Math.round(w / 2)}" y="11.5">${escapeHtml(text)}</text></g>`;
}

function mapPortTag(text, at) {
  const w = Math.max(22, text.length * 6.3 + 10);
  return `<g class="map-port-tag" transform="translate(${Math.round(at[0] - w / 2)},${Math.round(at[1] - 8)})">` +
    `<rect width="${Math.round(w)}" height="16" rx="8"></rect><text x="${Math.round(w / 2)}" y="11.5">${escapeHtml(text)}</text></g>`;
}

function drawMap() {
  if (!mapData) return;
  const svg = document.getElementById("map-svg");
  mapComputeFolded();
  const pos = mapTidy && !mapEditing ? autoLayout(mapData, true) : mapData.positions;
  mapDrawnPos = pos;
  const affected = new Set(mapSelected ? mapDownstream(mapSelected) : []);
  const shownKeys = new Set(mapData.nodes.filter(mapShown).map(n => n.key));
  // The background grid (one dot per snap step) and the links under the boxes.
  let html = `<defs><pattern id="map-grid" width="${MAP_SNAP}" height="${MAP_SNAP}" patternUnits="userSpaceOnUse">` +
    `<circle cx="1" cy="1" r="1" class="map-grid-dot"></circle></pattern></defs>` +
    `<rect class="map-grid" x="-20000" y="-20000" width="40000" height="40000" fill="url(#map-grid)"></rect>`;
  const tags = [];
  const trunks = mapTrunks(pos, shownKeys);

  mapData.links.forEach((l, i) => {
    if (!pos[l.a] || !pos[l.b] || !shownKeys.has(l.a) || !shownKeys.has(l.b) || (l.hidden && !mapEditing)) return;
    // From the tree parent to the child when known, so port tags land at the right ends.
    let up = l.a, down = l.b, upPort = l.a_port, downPort = l.b_port;
    if (mapData.parent[l.a] === l.b) [up, down, upPort, downPort] = [l.b, l.a, l.b_port, l.a_port];
    const trunk = mapData.parent[down] === up ? trunks[down] : null;
    let d, c, route;
    if (trunk) {
      // A stacked column: the shared trunk, then a branch into the child's left side.
      const cp = pos[down], midY = Math.round(cp[1] + MAP_NODE_H / 2);
      const pts = [trunk.start, [trunk.start[0], trunk.ymid], [trunk.trunkX, trunk.ymid], [trunk.trunkX, midY], [cp[0], midY]];
      d = roundedPath(pts);
      c = [pts[0], pts[0], [cp[0], midY], [cp[0], midY]];
      route = { sa: "bottom", sb: "left", trunk: [trunk.trunkX, midY] };
    } else {
      const others = Object.entries(pos).filter(([k]) => k !== up && k !== down && shownKeys.has(k)).map(([, p]) => p);
      route = routeLink(pos[up], pos[down], others);
      c = route.curve.map(p => p.map(v => Math.round(v)));
      d = `M${c[0][0]},${c[0][1]} C${c[1][0]},${c[1][1]} ${c[2][0]},${c[2][1]} ${c[3][0]},${c[3][1]}`;
    }
    const hot = mapSelected && (affected.has(l.a) || affected.has(l.b) || l.a === mapSelected || l.b === mapSelected);
    const cls = ["map-link", l.source === "manual" || l.source === "owner" ? "manual" : "", l.kind === "virtual" || l.kind === "service" ? "virtual" : "",
      l.kind === "wifi" ? "wifi" : "",
      l.hidden ? "hidden-link" : "", hot ? "hot" : "", mapSelected && !hot ? "dim" : ""].filter(Boolean).join(" ");
    html += `<g data-link="${i}" data-a="${escapeHtml(l.a)}" data-b="${escapeHtml(l.b)}" class="map-link-g${mapSelected && !hot ? " dim" : ""}">` +
      `<path class="map-link-hit" d="${escapeHtml(d)}"></path><path class="${cls}" d="${escapeHtml(d)}"></path>` +
      `<circle class="map-link-end" cx="${escapeHtml(c[0][0])}" cy="${escapeHtml(c[0][1])}" r="3"></circle><circle class="map-link-end" cx="${escapeHtml(c[3][0])}" cy="${escapeHtml(c[3][1])}" r="3"></circle></g>`;
    // Port tags just off each end, along the side the link leaves by; drawn above everything.
    const off = (side, p) => [p[0] + MAP_SIDES[side][0] * (MAP_SIDES[side][0] ? 26 : 0), p[1] + MAP_SIDES[side][1] * 16];
    if (route.trunk) {
      // On a shared trunk the parent's port labels each branch where it leaves the trunk.
      if (upPort) tags.push(mapPortTag(upPort, route.trunk));
    } else {
      if (upPort) tags.push(mapPortTag(upPort, off(route.sa, c[0])));
      if (downPort) tags.push(mapPortTag(downPort, off(route.sb, c[3])));
    }
    if (mapTraffic && l.rate && !mapEditing) html += mapFlow(l, up, d);
    if (mapTraffic && l.rate && !mapEditing) {
      // The middle of the line: of the curve's two control points, or of the trunk branch.
      const mid = route.trunk ? [(route.trunk[0] + c[3][0]) / 2, route.trunk[1]]
        : [(c[0][0] + 3 * c[1][0] + 3 * c[2][0] + c[3][0]) / 8, (c[0][1] + 3 * c[1][1] + 3 * c[2][1] + c[3][1]) / 8];
      tags.push(mapRateTag(l, up, mid));
    }
  });

  const below = {};
  for (const n of mapData.nodes) if (pos[n.key] && mapShown(n)) below[n.key] = mapBelowCount(n.key);
  for (const n of mapData.nodes) {
    if (!pos[n.key] || !mapShown(n)) continue;
    const [x, y] = pos[n.key].map(Math.round);
    const state = nodeState(n);
    const cls = ["map-node", `state-${state}`, n.key === mapSelected ? "selected" : "", affected.has(n.key) ? "affected" : "",
      mapSelected && n.key !== mapSelected && !affected.has(n.key) ? "dim" : "", n.key === mapLinkFrom ? "linking" : ""].filter(Boolean).join(" ");
    const label = n.label.length > 22 ? n.label.slice(0, 21) + "…" : n.label;
    const sub = n.port ? `${n.ip}:${n.port}` : n.ip || "";
    const wifi = n.wifi ? `${n.wifi.count} on Wi-Fi${n.wifi.weak ? `, ${n.wifi.weak} weak` : ""}` : "";
    const kind = [MAP_KIND_LABEL[n.kind] || n.kind, wifi || (n.clients ? `+${n.clients} other host${n.clients === 1 ? "" : "s"}` : "")].filter(Boolean).join("  ·  ");
    html += `<g class="${cls}" data-node="${escapeHtml(n.key)}" transform="translate(${escapeHtml(x)},${escapeHtml(y)})">` +
      `<rect class="map-card" width="${MAP_NODE_W}" height="${MAP_NODE_H}" rx="8"></rect>` +
      `<rect class="map-stripe" x="0" y="0" width="5" height="${MAP_NODE_H}" rx="2"></rect>` +
      `<g class="map-icon" transform="translate(14,${Math.round(MAP_NODE_H / 2 - 12)})"><svg width="24" height="24" viewBox="0 0 24 24">${MAP_ICONS[n.kind] || MAP_ICONS.other}</svg></g>` +
      `<text class="map-label" x="48" y="22">${escapeHtml(label)}</text>` +
      `<text class="map-sub" x="48" y="39">${escapeHtml(sub)}</text>` +
      `<text class="map-kind" x="48" y="54">${escapeHtml(kind)}</text>` +
      (n.problems ? `<g class="map-badge" transform="translate(${MAP_NODE_W - 14},12)"><circle r="8"></circle><text y="3.5">${Number(n.problems)}</text></g>` : "") +
      (below[n.key] ? `<g class="map-fold${mapFolded.has(n.key) ? " folded" : ""}" data-fold="${escapeHtml(n.key)}" transform="translate(${MAP_NODE_W / 2},${MAP_NODE_H})">` +
        `<rect x="${mapFolded.has(n.key) ? -22 : -11}" y="-8" width="${mapFolded.has(n.key) ? 44 : 22}" height="16" rx="8"></rect>` +
        `<text y="4">${mapFolded.has(n.key) ? `+${Number(below[n.key])}` : "\u2013"}</text>` +
        `<title>${escapeHtml(mapFolded.has(n.key) ? `Show the ${below[n.key]} device${below[n.key] === 1 ? "" : "s"} below it` : "Hide what is below it")}</title></g>` : "") +
      `<title>${escapeHtml(n.label)}${n.problems ? ` (${escapeHtml(n.problems)} problem${n.problems > 1 ? "s" : ""})` : ""}</title></g>`;
  }
  let under = mapEditing ? "" : mapInternet(pos);
  if (mapWifi && !mapEditing) {
    for (const n of mapData.nodes) if (pos[n.key] && mapShown(n)) under += mapWifiFan(n, pos[n.key]);
  }
  svg.innerHTML = under + html + tags.join("");
  renderMapInfo(affected);
}

/** Where this monitor sits: the box it hangs off and the port, from the links. */
function mapMonitorInfo() {
  const mon = mapData.nodes.find(n => n.key === "monitor" || n.kind === "monitor");
  if (!mon) return "";
  const parentKey = mapData.parent[mon.key];
  const parent = mapData.nodes.find(n => n.key === parentKey);
  const link = mapData.links.find(l => (l.a === mon.key && l.b === parentKey) || (l.b === mon.key && l.a === parentKey));
  const port = link ? (link.a === parentKey ? link.a_port : link.b_port) : "";
  return `<div class="map-monitor"><div class="map-info-head">This monitor</div>
    <div class="dim">${escapeHtml(mon.ip || "")}${parent ? `, connected through <strong>${escapeHtml(parent.label)}</strong>${port ? ` port ${escapeHtml(port)}` : ""}` : ", not placed on the network yet"}.</div>
    <div class="dim">It is not drawn on the map. Restarting anything between it and the gateway cuts it off, and the map warns about that when you click such a device.</div></div>`;
}

/** An access point's Wi-Fi devices, weakest first, with a bar for the signal. */
function mapWifiInfo(n) {
  if (!n.wifi) return "";
  const pct = s => Math.max(4, Math.min(100, ((s + 95) / 55) * 100));
  return `<div class="map-info-head">On Wi-Fi: ${escapeHtml(n.wifi.count)} device${n.wifi.count === 1 ? "" : "s"}${n.wifi.weak ? `, ${escapeHtml(n.wifi.weak)} below ${escapeHtml(n.wifi.weak_dbm)} dBm` : ""}</div>
    <ul class="map-wifi">${n.wifi.clients.map(c => {
      const weak = typeof c.signal === "number" && c.signal < n.wifi.weak_dbm;
      return `<li class="${weak ? "weak" : ""}"><span class="map-wifi-name" title="${escapeHtml([c.ssid, c.band].filter(Boolean).join(", "))}">${escapeHtml(c.name)}</span>
        <span class="map-wifi-bar"><span style="width:${typeof c.signal === "number" ? pct(c.signal).toFixed(0) : 0}%"></span></span>
        <span class="map-wifi-dbm">${typeof c.signal === "number" ? `${escapeHtml(Math.round(c.signal))} dBm` : "-"}</span></li>`;
    }).join("")}</ul>
    ${n.wifi.count > n.wifi.clients.length ? `<div class="dim">and ${escapeHtml(n.wifi.count - n.wifi.clients.length)} more on the <a href="#/wifi">Wi-Fi page</a></div>` : ""}`;
}

function renderMapInfo(affected) {
  const box = document.getElementById("map-info");
  if (!mapSelected) {
    box.innerHTML = `<div class="dim">Click a device to see what depends on it: everything highlighted loses its connection while the device restarts.</div>${mapMonitorInfo()}`;
    return;
  }
  const byKey = Object.fromEntries(mapData.nodes.map(n => [n.key, n]));
  const n = byKey[mapSelected];
  const list = [...affected].map(k => byKey[k]).filter(n => n && mapShown(n)).sort((a, b) => a.label.localeCompare(b.label));
  const hosts = [mapSelected, ...affected].reduce((sum, k) => sum + ((byKey[k] || {}).clients || 0), 0);
  const cutsMonitor = affected.has("monitor") || mapSelected === "monitor";
  const reachable = mapSelected in mapData.parent;
  const unmanaged = n.object_id ? `<button class="btn map-edit-only${mapEditing ? "" : " hidden"}" data-delete-object="${Number(n.object_id)}">Delete object</button>` : "";
  box.innerHTML = `
    <div class="map-info-title">${escapeHtml(n.label)}</div>
    <div class="dim">${escapeHtml([MAP_KIND_LABEL[n.kind] || n.kind, n.ip].filter(Boolean).join(" • "))}</div>
    ${n.device_id ? `<div><a class="device-link" href="#/device/${Number(n.device_id)}">Open device page</a></div>` : ""}
    ${!reachable ? `<div class="text-warn">Not connected to the gateway on this map. Draw its link in Edit mode.</div>` : ""}
    ${cutsMonitor ? `<div class="text-err">Restarting this cuts off this monitor: it cannot watch the restart and will see everything downstream as down until it comes back.</div>` : ""}
    <div class="map-info-head">Affected by a restart: ${list.length} device${list.length === 1 ? "" : "s"}${hosts ? `, about ${escapeHtml(hosts)} other host${hosts === 1 ? "" : "s"}` : ""}</div>
    <ul class="map-affected">${list.map(x => `<li>${escapeHtml(x.label)} <span class="dim">${escapeHtml(MAP_KIND_LABEL[x.kind] || x.kind)}</span></li>`).join("") || "<li class=\"dim\">Nothing downstream</li>"}</ul>
    ${mapWifiInfo(n)}
    ${mapBelowCount(n.key) ? `<div><button type="button" class="btn btn-small" data-fold-side="${escapeHtml(n.key)}">${mapFolded.has(n.key)
      ? `Show the ${escapeHtml(mapBelowCount(n.key))} device${mapBelowCount(n.key) === 1 ? "" : "s"} below it` : "Hide what is below it"}</button></div>` : ""}
    ${unmanaged}`;
  const sideFold = box.querySelector("[data-fold-side]");
  if (sideFold) sideFold.addEventListener("click", () => mapToggleFold(sideFold.dataset.foldSide));
  const del = box.querySelector("[data-delete-object]");
  if (del) {
    del.addEventListener("click", async () => {
      const ok = await confirmDialog({ title: "Delete object", message: `Delete ${n.label} from the map? Its links go with it.`,
        confirmLabel: "Delete", danger: true });
      if (!ok) return;
      try {
        await api(`/api/map/objects/${Number(del.dataset.deleteObject)}`, { method: "DELETE" });
        mapSelected = null;
        await loadMap();
      } catch (err) {
        showToast(`Could not delete: ${err.message}`, "error");
      }
    });
  }
}
