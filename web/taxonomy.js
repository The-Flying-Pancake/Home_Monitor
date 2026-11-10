/* Groups and tags in the browser (taxonomy.py on the server).
 *
 * loadTaxonomy() fetches both once after sign-in and after every change, rebuilds DEVICE_GROUPS
 * (app.js) so every grouped list uses the administrator's names and order, and refills the group and
 * tag filters found on the pages ([data-filter-group], [data-filter-tag]). Settings, Groups and
 * tags manages both: add, rename, order, colour and description; deleting a custom group sends
 * its devices back to their template's group, deleting a tag removes it from every device and
 * its alert rules. Tags are set per device in Edit, or for several devices at once from the
 * Devices page selection bar.
 */

let taxo = { groups: [], tags: [], colours: [] };

async function loadTaxonomy() {
  try {
    taxo = await api("/api/taxonomy");
  } catch (err) {
    return taxo;
  }
  for (const k of Object.keys(DEVICE_GROUPS)) delete DEVICE_GROUPS[k];
  for (const g of taxo.groups) DEVICE_GROUPS[g.id] = [g.name, g.rank];
  fillTaxonomyFilters();
  return taxo;
}

const tagInfo = name => taxo.tags.find(t => t.name.toLowerCase() === String(name).toLowerCase());

function tagChips(tags) {
  return (tags || []).map(t => {
    const info = tagInfo(t);
    return `<span class="tag-chip tag-${escapeHtml(info ? info.colour : "grey")}"${info && info.description ? ` title="${escapeHtml(info.description)}"` : ""}>${escapeHtml(t)}</span>`;
  }).join("");
}

/** A device's tags in little room: "+ tag" with a count bubble; hovering (or focusing) lists them.
 * data-action="tags" opens the tag manager (Devices page click handler). */
function tagBadge(id, tags, name) {
  const list = tags || [];
  const pop = list.length ? `<span class="tag-pop" role="tooltip"><span class="tag-pop-title">Tags on ${escapeHtml(name || "this device")}</span>${tagChips(list)}</span>` : "";
  const editable = can("devices.manage");
  if (!list.length && !editable) return "";
  return `<span class="tag-wrap"><button type="button" class="tag-add${list.length ? " has-tags" : ""}" ${editable ? `data-action="tags" data-id="${Number(id)}"` : "disabled"}
    title="${list.length ? escapeHtml(list.join(", ")) : "Add tags"}" aria-label="${list.length ? `${list.length} tag${list.length === 1 ? "" : "s"}: ${escapeHtml(list.join(", "))}` : "Add tags"}">${editable ? "+ tag" : "tags"}${list.length ? `<span class="tag-count">${list.length}</span>` : ""}</button>${pop}</span>`;
}

/** The tag manager: applied tags (click x to remove), the other tags in use (click to add) and a box
 * for a new one. Resolves with the final list, or null when cancelled. */
function tagPicker({ title, applied = [], confirmLabel = "Save tags", help = "", available = null }) {
  return new Promise(resolve => {
    let chosen = [...applied];
    const low = t => String(t).toLowerCase();
    const has = t => chosen.some(x => low(x) === low(t));
    const back = document.createElement("div");
    back.className = "modal-backdrop dialog-backdrop";
    back.innerHTML = `<form class="modal dialog tag-picker" role="dialog" aria-modal="true">
      <div class="modal-header"><span>${escapeHtml(title)}</span></div>
      <div class="modal-body">
        ${help ? `<div class="form-help">${escapeHtml(help)}</div>` : ""}
        <div class="tag-picker-cols">
          <div><div class="tag-picker-label">Applied</div><div class="tag-picker-box" data-applied></div></div>
          <div><div class="tag-picker-label">Available <span class="dim">(click to add)</span></div><div class="tag-picker-box" data-available></div></div>
        </div>
        <div class="tag-picker-new"><input type="text" maxlength="32" placeholder="New tag, e.g. office" aria-label="New tag"><button type="button" class="btn" data-new>Add</button></div>
        <div class="form-help">New tags join the list in Settings, Groups and tags, where they get a colour and a description.</div>
      </div>
      <div class="modal-footer"><a href="#/settings/groups" class="dim tag-picker-manage" data-x>Manage tags</a><button type="button" class="btn" data-x>Cancel</button><button type="submit" class="btn btn-primary">${escapeHtml(confirmLabel)}</button></div>
    </form>`;
    document.body.appendChild(back);
    const form = back.querySelector("form");
    const input = form.querySelector(".tag-picker-new input");
    const pool = () => (available || taxo.tags.map(t => t.name)).filter(t => !has(t));
    const chip = (t, act) => {
      const info = tagInfo(t);
      return `<button type="button" class="tag-chip tag-pick tag-${escapeHtml(info ? info.colour : "grey")}" data-${escapeHtml(act)}="${escapeHtml(t)}"
        title="${act === "remove" ? "Remove" : "Add"} ${escapeHtml(t)}${info && info.description ? ": " + escapeHtml(info.description) : ""}">${escapeHtml(t)}<span aria-hidden="true">${act === "remove" ? " \u00d7" : " +"}</span></button>`;
    };
    const draw = () => {
      form.querySelector("[data-applied]").innerHTML = chosen.map(t => chip(t, "remove")).join("") || `<span class="dim">No tags</span>`;
      form.querySelector("[data-available]").innerHTML = pool().map(t => chip(t, "add")).join("") || `<span class="dim">${taxo.tags.length ? "All of them are applied" : "No tags yet: type one below"}</span>`;
    };
    const addNew = () => {
      const t = input.value.trim().slice(0, 32);
      if (t && !has(t)) chosen.push((tagInfo(t) || { name: t }).name);
      input.value = "";
      draw();
      input.focus();
    };
    const done = v => { back.remove(); resolve(v); };
    form.addEventListener("click", ev => {
      const b = ev.target.closest("button, a");
      if (!b) return;
      if (b.dataset.remove !== undefined) { chosen = chosen.filter(x => low(x) !== low(b.dataset.remove)); draw(); }
      else if (b.dataset.add !== undefined) { chosen.push(b.dataset.add); draw(); }
      else if (b.dataset.new !== undefined) addNew();
      else if (b.dataset.x !== undefined) { if (b.tagName === "BUTTON") ev.preventDefault(); done(null); }
    });
    input.addEventListener("keydown", ev => { if (ev.key === "Enter") { ev.preventDefault(); addNew(); } });
    form.addEventListener("submit", ev => { ev.preventDefault(); if (input.value.trim()) addNew(); done(chosen); });
    back.addEventListener("keydown", ev => { if (ev.key === "Escape") done(null); });
    draw();
    input.focus();
  });
}

/** Group and tag filter: true when the device is in the group (if any) and has the tag (if any). */
function deviceMatches(d, group, tag) {
  return (!group || d.group === group) && (!tag || (d.tags || []).some(t => t.toLowerCase() === tag.toLowerCase()));
}

/** Fills every group and tag filter on the pages, keeping what each had chosen. */
function fillTaxonomyFilters() {
  document.querySelectorAll("[data-filter-group]").forEach(sel => {
    const v = sel.value;
    sel.innerHTML = `<option value="">All groups</option>` + taxo.groups.filter(g => g.devices)
      .map(g => `<option value="${escapeHtml(g.id)}">${escapeHtml(g.name)}</option>`).join("");
    sel.value = [...sel.options].some(o => o.value === v) ? v : "";
  });
  document.querySelectorAll("[data-filter-tag]").forEach(sel => {
    const v = sel.value;
    sel.innerHTML = `<option value="">All tags</option>` + taxo.tags
      .map(t => `<option value="${escapeHtml(t.name)}">${escapeHtml(t.name)}</option>`).join("");
    if (!taxo.tags.length) sel.innerHTML += `<option value="" disabled>No tags yet: use + tag beside a device</option>`;
    sel.value = [...sel.options].some(o => o.value === v) ? v : "";
    sel.classList.remove("hidden");
  });
}

async function taxoChange(body, done) {
  try {
    const r = await api("/api/taxonomy", { method: "PUT", body });
    taxo = Object.assign(taxo, r);
    await loadTaxonomy();
    renderTaxonomySettings();
    if (done) showToast(done, "success");
    return true;
  } catch (err) {
    showToast(err.message, "error");
    return false;
  }
}

// --- Settings, Groups and tags ---

function renderTaxonomySettings() {
  const box = document.getElementById("taxonomy-settings");
  if (!box) return;
  // Groups and tags are shared by every device: changing them needs access to every device.
  const edit = can("devices.manage") && !(currentUser && currentUser.scoped);
  const move = (kind, i, n) => edit ? `<span class="taxo-move">
      <button type="button" class="btn btn-small" data-taxo-move="${escapeHtml(kind)}" data-i="${escapeHtml(i)}" data-d="-1"${i === 0 ? " disabled" : ""} aria-label="Move up">&uarr;</button>
      <button type="button" class="btn btn-small" data-taxo-move="${escapeHtml(kind)}" data-i="${escapeHtml(i)}" data-d="1"${i === n - 1 ? " disabled" : ""} aria-label="Move down">&darr;</button></span>` : "";
  const groups = taxo.groups.map((g, i) => `<tr>
      <td class="taxo-order">${move("group", i, taxo.groups.length)}</td>
      <td class="text-cell"><strong>${escapeHtml(g.name)}</strong></td>
      <td class="dim">${g.builtin ? "Built in: devices land here by template" : "Your own"}</td>
      <td>${g.devices ? `<a href="#/devices" data-taxo-show-group="${escapeHtml(g.id)}">${escapeHtml(g.devices)} device${g.devices === 1 ? "" : "s"}</a>` : `<span class="dim">none</span>`}</td>
      <td class="actions-cell">${edit ? `<button type="button" class="btn btn-small" data-taxo-rename-group="${escapeHtml(g.id)}">Rename</button>
        ${g.builtin ? "" : `<button type="button" class="btn btn-small btn-danger" data-taxo-delete-group="${escapeHtml(g.id)}">Delete</button>`}` : ""}</td></tr>`).join("");
  const colours = (selected, name) => `<select data-taxo-colour="${escapeHtml(name)}"${edit ? "" : " disabled"}>${taxo.colours.map(c =>
    `<option value="${escapeHtml(c)}"${c === selected ? " selected" : ""}>${escapeHtml(c)}</option>`).join("")}</select>`;
  const tags = taxo.tags.length ? taxo.tags.map((t, i) => `<tr>
      <td class="taxo-order">${move("tag", i, taxo.tags.length)}</td>
      <td class="text-cell">${tagChips([t.name])}</td>
      <td>${colours(t.colour, t.name)}</td>
      <td><input type="text" class="taxo-desc" data-taxo-desc="${escapeHtml(t.name)}" value="${escapeHtml(t.description)}" maxlength="200" placeholder="What it is for"${edit ? "" : " disabled"}></td>
      <td>${t.devices ? `<a href="#/devices" data-taxo-show-tag="${escapeHtml(t.name)}">${escapeHtml(t.devices)} device${t.devices === 1 ? "" : "s"}</a>` : `<span class="dim">none</span>`}</td>
      <td><a href="#/settings/alerts/tag/${encodeURIComponent(t.name)}">${t.rules ? `${escapeHtml(t.rules)} alert setting${t.rules === 1 ? "" : "s"}` : "Alert rules"}</a></td>
      <td class="actions-cell">${edit ? `<button type="button" class="btn btn-small" data-taxo-rename-tag="${escapeHtml(t.name)}">Rename</button>
        <button type="button" class="btn btn-small btn-danger" data-taxo-delete-tag="${escapeHtml(t.name)}">Delete</button>` : ""}</td></tr>`).join("")
    : `<tr><td colspan="7" class="empty-cell">No tags yet. Add one here, or type it on a device in Edit.</td></tr>`;
  box.innerHTML = `
    <div class="taxo-part">
      <h4>Groups</h4>
      <p class="form-help">Every device is in one group: the one its template suggests, or the one chosen in Edit device. The Devices and Availability pages list devices by group in this order.</p>
      <table class="taxo-table"><thead><tr><th></th><th>Group</th><th>Kind</th><th>Devices</th><th></th></tr></thead><tbody>${groups}</tbody></table>
      ${edit ? `<form class="taxo-add" data-taxo-add="group"><input type="text" maxlength="48" placeholder="New group, e.g. Garage" required><button type="submit" class="btn">Add group</button></form>` : ""}
    </div>
    <div class="taxo-part">
      <h4>Tags</h4>
      <p class="form-help">Any number per device, for what cuts across groups: a room, an owner, how critical it is. Filter by them on the Devices, Availability and Events pages and on dashboard tiles. Each tag can have its own <strong>alert rules</strong> (they sit between the template and the device; when two tags of a device set the same thing, the one lower in this list wins).</p>
      <table class="taxo-table"><thead><tr><th></th><th>Tag</th><th>Colour</th><th>Description</th><th>Devices</th><th>Alerts</th><th></th></tr></thead><tbody>${tags}</tbody></table>
      ${edit ? `<form class="taxo-add" data-taxo-add="tag"><input type="text" maxlength="32" placeholder="New tag, e.g. critical" required><button type="submit" class="btn">Add tag</button></form>` : ""}
    </div>`;
}

function initTaxonomy() {
  const root = document.getElementById("settings-groups");
  if (!root) return;
  root.addEventListener("submit", async ev => {
    const form = ev.target.closest("[data-taxo-add]");
    if (!form) return;
    ev.preventDefault();
    const input = form.querySelector("input");
    const kind = form.dataset.taxoAdd;
    if (await taxoChange({ kind, action: "add", name: input.value.trim() }, `${kind === "group" ? "Group" : "Tag"} ${input.value.trim()} added`)) input.value = "";
  });
  root.addEventListener("change", ev => {
    const c = ev.target.closest("[data-taxo-colour]");
    if (c) taxoChange({ kind: "tag", action: "edit", name: c.dataset.taxoColour, colour: c.value });
    const d = ev.target.closest("[data-taxo-desc]");
    if (d) taxoChange({ kind: "tag", action: "edit", name: d.dataset.taxoDesc, description: d.value });
  });
  root.addEventListener("click", async ev => {
    const b = ev.target.closest("button, a");
    if (!b) return;
    if (b.dataset.taxoMove) {
      const kind = b.dataset.taxoMove, i = Number(b.dataset.i), j = i + Number(b.dataset.d);
      const list = kind === "group" ? taxo.groups.map(g => g.id) : taxo.tags.map(t => t.name);
      [list[i], list[j]] = [list[j], list[i]];
      taxoChange(kind === "group" ? { kind, action: "order", ids: list } : { kind, action: "order", names: list });
    } else if (b.dataset.taxoRenameGroup) {
      const g = taxo.groups.find(x => x.id === b.dataset.taxoRenameGroup);
      const name = await promptDialog({ title: `Rename ${g.name}`, input: { label: "New name", value: g.name }, confirmLabel: "Rename" });
      if (name && name.trim() !== g.name) taxoChange({ kind: "group", action: "rename", id: g.id, name: name.trim() }, "Group renamed");
    } else if (b.dataset.taxoDeleteGroup) {
      const g = taxo.groups.find(x => x.id === b.dataset.taxoDeleteGroup);
      if (await confirmDialog({ title: `Delete the group ${g.name}?`, danger: true, confirmLabel: "Delete group",
        message: g.devices ? `Its ${g.devices} device${g.devices === 1 ? "" : "s"} go back to the group their template suggests. Nothing else changes.` : "No devices are in it." })) {
        taxoChange({ kind: "group", action: "delete", id: g.id }, "Group deleted");
      }
    } else if (b.dataset.taxoRenameTag) {
      const t = tagInfo(b.dataset.taxoRenameTag);
      const name = await promptDialog({ title: `Rename the tag ${t.name}`, message: "Every device and alert rule with this tag follows.",
        input: { label: "New name", value: t.name }, confirmLabel: "Rename" });
      if (name && name.trim() !== t.name) taxoChange({ kind: "tag", action: "rename", name: t.name, new_name: name.trim() }, "Tag renamed");
    } else if (b.dataset.taxoDeleteTag) {
      const t = tagInfo(b.dataset.taxoDeleteTag);
      if (await confirmDialog({ title: `Delete the tag ${t.name}?`, danger: true, confirmLabel: "Delete tag",
        message: `It is removed from ${t.devices} device${t.devices === 1 ? "" : "s"}${t.rules ? ` and its ${t.rules} alert setting${t.rules === 1 ? " is" : "s are"} deleted` : ""}. The devices themselves stay.` })) {
        taxoChange({ kind: "tag", action: "delete", name: t.name }, "Tag deleted");
      }
    } else if (b.dataset.taxoShowGroup !== undefined || b.dataset.taxoShowTag !== undefined) {
      // Devices page, filtered to this group or tag.
      devicesFilter = { group: b.dataset.taxoShowGroup || "", tag: b.dataset.taxoShowTag || "" };
    }
  });
}

// --- Devices page: several devices at once ---

/** "+ tag" on a device row: the tag manager for that device. */
async function editDeviceTags(id) {
  const d = (lastFleet ? lastFleet[0] : []).find(x => x.id === id);
  if (!d) return;
  const old = d.tags || [];
  const picked = await tagPicker({ title: `Tags for ${d.hostname}`, applied: old,
    help: "Tags label devices so lists, dashboard tiles, maintenance windows and alert rules can pick them out." });
  if (picked === null) return;
  const now = [...new Set(picked)];
  const low = a => a.map(t => t.toLowerCase());
  const add = now.filter(t => !low(old).includes(t.toLowerCase()));
  const remove = old.filter(t => !low(now).includes(t.toLowerCase()));
  if (!add.length && !remove.length) return;
  try {
    await api("/api/devices/tags", { method: "POST", body: { device_ids: [id], add, remove } });
    await loadTaxonomy();
    loadDevices();
  } catch (err) {
    showToast(err.message, "error");
  }
}

async function bulkTag(add) {
  const ids = [...selectedDevices];
  if (!ids.length) return;
  const n = `${ids.length} device${ids.length === 1 ? "" : "s"}`;
  // Removing offers the tags those devices actually have.
  const onThem = [...new Set((lastFleet ? lastFleet[0] : []).filter(d => ids.includes(d.id)).flatMap(d => d.tags || []))];
  const tags = await tagPicker({ title: add ? `Add tags to ${n}` : `Remove tags from ${n}`, confirmLabel: add ? "Add tags" : "Remove tags",
    available: add ? null : onThem,
    help: add ? "Put the tags to add under Applied." : "Put the tags to remove under Applied. Only tags on the selected devices are offered." });
  if (!tags || !tags.length) return;
  try {
    const r = await api("/api/devices/tags", { method: "POST", body: { device_ids: ids, [add ? "add" : "remove"]: tags } });
    showToast(`${add ? "Tagged" : "Untagged"} ${r.changed} device${r.changed === 1 ? "" : "s"}`, "success");
    await loadTaxonomy();
    loadDevices();
  } catch (err) {
    showToast(err.message, "error");
  }
}

document.addEventListener("DOMContentLoaded", initTaxonomy);

// Hover (or keyboard focus) on a tag badge shows its list in a floating box beside it.
(function tagFloat() {
  let box = null;
  const hideFloat = () => { if (box) { box.remove(); box = null; } };
  const show = wrap => {
    const pop = wrap.querySelector(".tag-pop");
    if (!pop) return;
    hideFloat();
    box = document.createElement("div");
    box.id = "tag-float";
    box.setAttribute("role", "tooltip");
    box.innerHTML = pop.innerHTML;
    document.body.appendChild(box);
    const r = wrap.getBoundingClientRect(), h = box.offsetHeight, w = box.offsetWidth;
    const below = r.bottom + 4 + h <= window.innerHeight;
    box.style.top = `${below ? r.bottom + 4 : Math.max(4, r.top - 4 - h)}px`;
    box.style.left = `${Math.max(4, Math.min(r.left, window.innerWidth - w - 4))}px`;
  };
  document.addEventListener("mouseover", ev => { const w = ev.target.closest && ev.target.closest(".tag-wrap"); if (w) show(w); });
  document.addEventListener("mouseout", ev => {
    const w = ev.target.closest && ev.target.closest(".tag-wrap");
    if (w && !(ev.relatedTarget && w.contains(ev.relatedTarget))) hideFloat();
  });
  document.addEventListener("focusin", ev => { const w = ev.target.closest && ev.target.closest(".tag-wrap"); if (w) show(w); else hideFloat(); });
  document.addEventListener("click", hideFloat, true);
  window.addEventListener("scroll", hideFloat, true);
})();
