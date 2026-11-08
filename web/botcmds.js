/* Settings, Notifications, Commands: the Telegram command builder.
 *
 * Lists the built-in commands (their reply texts can be edited, each can be switched off) and the
 * ones you add (add, edit, switch off, delete). A command of your own says what it shows (devices,
 * Wi-Fi networks, Proxmox guests, ...), which items, an optional filter, and its reply: a header,
 * a line repeated for each item and a footer, with placeholders. The preview is the real reply,
 * built by the server from current data (POST /api/notify/bot-preview); nothing is saved until Save.
 * Relies on app.js helpers (api, escapeHtml, showToast, confirmDialog) and TG_EMOJIS (telegram.js).
 */

let botData = null;      // GET /api/notify/bot-commands

async function renderBotBuilder(force) {
  const box = document.getElementById("bot-builder");
  if (!box) return;
  if (botData && !force && box.dataset.ready) return;
  box.dataset.ready = "1";
  try {
    botData = await api("/api/notify/bot-commands");
  } catch (err) {
    box.innerHTML = `<div class="text-err">${escapeHtml(err.message)}</div>`;
    return;
  }
  const src = botData.sources;
  const row = (c, builtin) => `<tr>
      <td><code>/${escapeHtml(c.name)}</code>${builtin ? ' <span class="dim">built in</span>' : ""}</td>
      <td>${escapeHtml(builtin ? c.description : `${(src[c.source] || {}).label || c.source}: ${c.description}`)}</td>
      <td><label class="bot-on"><input type="checkbox" data-bot-on="${escapeHtml(c.name)}"${c.on ? " checked" : ""}> on</label></td>
      <td class="bot-actions"><button type="button" class="btn btn-small" data-bot-edit="${escapeHtml(c.name)}" data-bot-builtin="${builtin ? 1 : 0}">Edit</button>
        ${builtin ? "" : `<button type="button" class="btn btn-small btn-danger" data-bot-del="${escapeHtml(c.name)}">Delete</button>`}</td>
    </tr>`;
  box.innerHTML = `
    <div class="form-help">Send these to your bot in Telegram. Built-in commands can be reworded; your own commands show what you choose.
      All of them only read. Telegram's command menu (type /) follows this list.</div>
    ${botData.answering ? "" : `<div class="form-help text-warn">The bot is not answering now: switch on Telegram and <em>Answer commands</em> under Delivery.</div>`}
    <table class="storage-table bot-table"><thead><tr><th>Command</th><th>What it answers</th><th></th><th></th></tr></thead>
      <tbody>${botData.builtin.map(c => row(c, true)).join("")}${botData.custom.map(c => row(c, false)).join("")}</tbody></table>
    <div class="notify-actions"><button type="button" class="btn btn-primary" data-bot-add${botData.custom.length >= botData.max ? " disabled" : ""}>Add command</button>
      <span class="dim">${botData.custom.length} of ${botData.max} of your own</span></div>`;
}

function botOff() {
  return [...botData.builtin, ...botData.custom].filter(c => !c.on).map(c => c.name);
}

async function botSave(custom, off, texts) {
  const view = await api("/api/notify/bot-commands", { method: "POST", body: { custom, off, texts: texts || {} } });
  botData = view;
  await renderBotBuilder(true);
  return view;
}

const botStrip = c => ({ name: c.name, description: c.description, source: c.source, only: c.only || "", pick: c.pick || [],
  sort: c.sort || "", desc: !!c.desc, limit: c.limit || 0, header: c.header || "", line: c.line || "", footer: c.footer || "" });

document.addEventListener("change", async (ev) => {
  const t = ev.target.closest && ev.target.closest("[data-bot-on]");
  if (!t || !botData) return;
  const c = [...botData.builtin, ...botData.custom].find(x => x.name === t.dataset.botOn);
  if (!c) return;
  c.on = t.checked;
  try {
    await botSave(botData.custom.map(botStrip), botOff());
    showToast(`/${c.name} ${c.on ? "on" : "off"}`, "success");
  } catch (err) {
    showToast(err.message, "error");
    renderBotBuilder(true);
  }
});

document.addEventListener("click", async (ev) => {
  if (!botData) return;
  const add = ev.target.closest("[data-bot-add]");
  if (add) { openBotEditor(null); return; }
  const edit = ev.target.closest("[data-bot-edit]");
  if (edit) {
    if (edit.dataset.botBuiltin === "1") openBuiltinEditor(botData.builtin.find(c => c.name === edit.dataset.botEdit));
    else openBotEditor(botData.custom.find(c => c.name === edit.dataset.botEdit));
    return;
  }
  const del = ev.target.closest("[data-bot-del]");
  if (del) {
    const name = del.dataset.botDel;
    if (!(await confirmDialog({ title: `Delete /${name}?`, message: "The bot stops answering it. This cannot be undone.", confirmLabel: "Delete", danger: true }))) return;
    try {
      await botSave(botData.custom.filter(c => c.name !== name).map(botStrip), botOff().filter(n => n !== name));
      showToast(`/${name} deleted`, "success");
    } catch (err) { showToast(err.message, "error"); }
  }
});

// --- Shared editor pieces ---

function botVarButtons(vars) {
  return Object.entries(vars || {}).map(([k, help]) =>
    `<button type="button" class="tg-var" data-ins="{${escapeHtml(k)}}"><code>{${escapeHtml(k)}}</code><span class="dim">${escapeHtml(help)}</span></button>`).join("");
}

function botModal(title, body) {
  const back = document.createElement("div");
  back.className = "modal-backdrop dialog-backdrop";
  back.innerHTML = `<form class="modal modal-wide tg-editor bot-editor" role="dialog" aria-modal="true">
    <div class="modal-header"><span>${escapeHtml(title)}</span>
      <button type="button" class="btn" data-bot-close aria-label="Close">&times;</button></div>
    <div class="modal-body">${body}</div>
    <div class="modal-footer"><span class="bot-err text-err"></span>
      <button type="button" class="btn" data-bot-close>Cancel</button>
      <button type="submit" class="btn btn-primary">Save</button></div>
  </form>`;
  document.body.appendChild(back);
  const form = back.querySelector("form");
  let focused = null;
  form.addEventListener("focusin", (e) => { if (e.target.matches("textarea.bot-tpl")) focused = e.target; });
  form.addEventListener("click", (e) => {
    const ins = e.target.closest("[data-ins]");
    if (!ins) return;
    const ta = focused || form.querySelector("textarea.bot-tpl[data-part=line]") || form.querySelector("textarea.bot-tpl");
    if (!ta) return;
    const a = ta.selectionStart ?? ta.value.length, b = ta.selectionEnd ?? a;
    ta.value = ta.value.slice(0, a) + ins.dataset.ins + ta.value.slice(b);
    ta.focus();
    ta.selectionStart = ta.selectionEnd = a + ins.dataset.ins.length;
    ta.dispatchEvent(new Event("input", { bubbles: true }));
  });
  const close = async () => {
    if (form.dataset.dirty && !(await confirmDialog({ title: "Discard your changes?", confirmLabel: "Discard", danger: true }))) return;
    back.remove();
  };
  form.addEventListener("input", () => { form.dataset.dirty = "1"; });
  form.addEventListener("click", (e) => { if (e.target.closest("[data-bot-close]")) close(); });
  back.addEventListener("keydown", (e) => { if (e.key === "Escape" && !document.querySelector(".dialog:not(.bot-editor)")) { e.stopPropagation(); close(); } });
  return { back, form };
}

function botPreviewer(form, payload) {
  let timer = null, seq = 0;
  const out = form.querySelector(".bot-preview");
  const run = async () => {
    const mine = ++seq;
    try {
      const r = await api("/api/notify/bot-preview", { method: "POST", body: payload() });
      if (mine === seq) { out.textContent = r.text || " "; out.classList.remove("text-err"); }
    } catch (err) {
      if (mine === seq) { out.textContent = err.message; out.classList.add("text-err"); }
    }
  };
  const later = () => { clearTimeout(timer); timer = setTimeout(run, 400); };
  form.addEventListener("input", later);
  form.addEventListener("change", later);
  run();
  return run;
}

const botEmojiRow = () => `<div class="tg-label">Emoji <span class="dim">(click to insert)</span></div>
  <div class="tg-emojis">${(typeof TG_EMOJIS !== "undefined" ? TG_EMOJIS : []).map(e => `<button type="button" class="tg-emoji" data-ins="${escapeHtml(e)}">${escapeHtml(e)}</button>`).join("")}</div>`;

// --- A built-in command: its reply texts ---

function openBuiltinEditor(c) {
  if (!c) return;
  const body = `<div class="tg-body">
    <div class="tg-main">
      <div class="form-help">${escapeHtml(c.description)}. Clear a box to get the original text back.</div>
      ${c.templates.map(t => `
        <div class="tg-label">${escapeHtml(t.label)} <span class="dim">${escapeHtml(t.help)}</span></div>
        <textarea class="tg-text bot-tpl" rows="5" maxlength="500" spellcheck="false" data-key="${escapeHtml(t.key)}">${escapeHtml(t.text)}</textarea>
        <div class="bot-presets">${[t.default, ...t.presets].map((p, i) =>
          `<button type="button" class="btn btn-small" data-bot-preset="${escapeHtml(t.key)}" data-i="${i}">${i ? `Ready-made ${i}` : "Original"}</button>`).join("")}</div>`).join("")}
      ${botEmojiRow()}
      <div class="tg-label">Preview <span class="dim">(the real reply, now)</span></div>
      ${c.name === "device" ? `<input type="text" class="bot-arg" placeholder="Device name (empty: one with problems)">` : ""}
      <div class="tg-preview bot-preview"></div>
    </div>
    <div class="tg-side">
      <div class="tg-label">Placeholders <span class="dim">(click to insert where the cursor is)</span></div>
      ${c.templates.map(t => `<div class="dim">${escapeHtml(t.label)}</div><div class="tg-vars">${botVarButtons(t.placeholders)}</div>`).join("")}
      ${tgTricksHtml(botData.tricks)}
    </div></div>`;
  const { back, form } = botModal(`/${c.name} reply`, body);
  const texts = () => Object.fromEntries([...form.querySelectorAll("textarea.bot-tpl")].map(ta => [ta.dataset.key, ta.value]));
  botPreviewer(form, () => ({ builtin: c.name, texts: texts(), arg: (form.querySelector(".bot-arg") || {}).value || "" }));
  form.addEventListener("click", (e) => {
    const b = e.target.closest("[data-bot-preset]");
    if (!b) return;
    const t = c.templates.find(x => x.key === b.dataset.botPreset);
    const ta = form.querySelector(`textarea[data-key="${CSS.escape(t.key)}"]`);
    ta.value = [t.default, ...t.presets][Number(b.dataset.i)];
    ta.dispatchEvent(new Event("input", { bubbles: true }));
  });
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    try {
      await botSave(botData.custom.map(botStrip), botOff(), texts());
      back.remove();
      showToast(`/${c.name} reply saved`, "success");
    } catch (err) { form.querySelector(".bot-err").textContent = err.message; }
  });
}

// --- A command of your own ---

function openBotEditor(existing) {
  const src = botData.sources;
  const first = Object.keys(src)[0];
  const c = existing ? { ...existing, pick: [...(existing.pick || [])] }
    : { name: "", description: "", source: first, only: "", pick: [], ...src[first].default };
  const body = `<div class="tg-body">
    <div class="tg-main">
      <div class="form-row">
        <div class="form-group"><label>Command</label><div class="bot-name"><span>/</span><input type="text" class="bot-f-name" maxlength="32"
          placeholder="wifi" value="${escapeHtml(c.name)}" spellcheck="false" autocomplete="off"></div></div>
        <div class="form-group"><label>Description <span class="dim">(in /help and the menu)</span></label>
          <input type="text" class="bot-f-desc" maxlength="100" value="${escapeHtml(c.description)}"></div>
      </div>
      <div class="form-row">
        <div class="form-group"><label>Shows</label><select class="bot-f-source">${Object.entries(src).map(([k, s]) =>
          `<option value="${escapeHtml(k)}"${k === c.source ? " selected" : ""}>${escapeHtml(s.label)}</option>`).join("")}</select></div>
        <div class="form-group bot-only-group"><label>Only</label><select class="bot-f-only"></select></div>
      </div>
      <div class="bot-sort">
        <div class="form-group"><label>Sort by</label><select class="bot-f-sort"></select></div>
        <label class="bot-on"><input type="checkbox" class="bot-f-desc"${c.desc ? " checked" : ""}> highest first</label>
        <div class="form-group"><label>At most <span class="dim">(lines, 0 is all)</span></label>
          <input type="number" class="bot-f-limit" min="0" max="${botData.max_limit || 200}" value="${Number(c.limit || 0)}"></div>
      </div>
      <div class="form-help bot-src-help"></div>
      <div class="bot-pick-group"><div class="tg-label">Covers <span class="dim bot-pick-count"></span></div>
        <input type="text" class="bot-pick-search" placeholder="Search">
        <div class="bot-pick"></div></div>
      <div class="tg-label">Header <span class="dim">(once, at the top)</span></div>
      <textarea class="tg-text bot-tpl" data-part="header" rows="2" maxlength="800" spellcheck="false">${escapeHtml(c.header)}</textarea>
      <div class="tg-label">Line <span class="dim">(once for each item)</span></div>
      <textarea class="tg-text bot-tpl" data-part="line" rows="2" maxlength="800" spellcheck="false">${escapeHtml(c.line)}</textarea>
      <div class="tg-label">Footer <span class="dim">(once, at the end)</span></div>
      <textarea class="tg-text bot-tpl" data-part="footer" rows="2" maxlength="800" spellcheck="false">${escapeHtml(c.footer)}</textarea>
      <div class="bot-presets"><button type="button" class="btn btn-small" data-bot-reset>Start from the example text</button></div>
      ${botEmojiRow()}
      <div class="tg-label">Preview <span class="dim">(the real reply, now)</span></div>
      <input type="text" class="bot-arg" placeholder="Try a word after the command, like /wifi guest (optional)">
      <div class="tg-preview bot-preview"></div>
    </div>
    <div class="tg-side">
      <div class="tg-label">For the header and footer</div><div class="tg-vars bot-vars-summary"></div>
      <div class="tg-label">For each line</div><div class="tg-vars bot-vars-item"></div>
      <div class="bot-metrics-group hidden"><div class="tg-label">Any figure a device records</div>
        <input type="text" class="bot-metric-search" placeholder="Search figures"><div class="tg-vars bot-vars-metric"></div></div>
      ${tgTricksHtml(botData.tricks)}
    </div></div>`;
  const { back, form } = botModal(existing ? `Edit /${existing.name}` : "Add a command", body);
  const $ = sel => form.querySelector(sel);
  let choices = [], metrics = [];
  let shownSource = c.source;
  const picked = new Set(c.pick);

  const drawPick = () => {
    const q = $(".bot-pick-search").value.trim().toLowerCase();
    $(".bot-pick").innerHTML = choices.filter(x => !q || x.label.toLowerCase().includes(q)).slice(0, 300).map(x =>
      `<label class="bot-pick-item"><input type="checkbox" value="${escapeHtml(x.id)}"${picked.has(x.id) ? " checked" : ""}> ${escapeHtml(x.label)}</label>`).join("")
      || `<div class="dim">${choices.length ? "Nothing matches." : "Nothing to pick yet: is it connected?"}</div>`;
    $(".bot-pick-count").textContent = picked.size ? `(${picked.size} picked)` : "(all: tick some to limit it)";
  };
  const drawMetrics = () => {
    const q = $(".bot-metric-search").value.trim().toLowerCase();
    const list = metrics.filter(m => !q || m.key.toLowerCase().includes(q) || (m.label || "").toLowerCase().includes(q)).slice(0, 80);
    $(".bot-vars-metric").innerHTML = botVarButtons(Object.fromEntries(list.map(m => [m.key, m.label || "Latest value"])));
  };
  const drawSource = async (resetText) => {
    const s = src[$(".bot-f-source").value];
    $(".bot-src-help").textContent = s.help;
    $(".bot-f-only").innerHTML = s.only.map(([v, l]) => `<option value="${escapeHtml(v)}"${v === c.only ? " selected" : ""}>${escapeHtml(l)}</option>`).join("");
    $(".bot-only-group").classList.toggle("hidden", !s.only.length);
    $(".bot-vars-summary").innerHTML = botVarButtons(s.summary);
    $(".bot-vars-item").innerHTML = botVarButtons(s.item);
    const sortNow = c.sort && (c.sort in s.item || c.sort.startsWith("metric:")) ? c.sort : "";
    $(".bot-f-sort").innerHTML = `<option value="">As listed</option>` + Object.entries(s.item).map(([k, help]) =>
      `<option value="${escapeHtml(k)}"${k === sortNow ? " selected" : ""}>{${escapeHtml(k)}} ${escapeHtml(help)}</option>`).join("")
      + (sortNow.startsWith("metric:") ? `<option value="${escapeHtml(sortNow)}" selected>{${escapeHtml(sortNow)}}</option>` : "");
    if (resetText) {
      for (const part of ["header", "line", "footer"]) $(`textarea[data-part=${part}]`).value = s.default[part] || "";
    }
    $(".bot-pick-group").classList.toggle("hidden", !s.pickable);
    choices = []; metrics = [];
    drawPick();
    if (s.pickable) {
      try {
        const r = await api(`/api/notify/bot-choices?source=${encodeURIComponent($(".bot-f-source").value)}`);
        choices = r.choices || [];
        metrics = r.metrics || [];
      } catch (err) { choices = []; }
      drawPick();
    }
    $(".bot-metrics-group").classList.toggle("hidden", !metrics.length);
    drawMetrics();
  };
  const command = () => ({
    name: $(".bot-f-name").value.trim().replace(/^\//, "").toLowerCase(), description: $(".bot-f-desc").value.trim(),
    source: $(".bot-f-source").value, only: $(".bot-f-only").value || "", pick: [...picked],
    sort: $(".bot-f-sort").value || "", desc: $(".bot-f-desc").checked, limit: Number($(".bot-f-limit").value) || 0,
    header: $("textarea[data-part=header]").value, line: $("textarea[data-part=line]").value, footer: $("textarea[data-part=footer]").value,
  });
  form.addEventListener("change", async (e) => {
    if (e.target.matches(".bot-f-source")) {
      picked.clear();
      c.only = "";
      c.sort = "";
      // Still the previous source's example (or empty): replaced without asking.
      const was = src[shownSource].default;
      const touched = ["header", "line", "footer"].some(p => $(`textarea[data-part=${p}]`).value.trim() && $(`textarea[data-part=${p}]`).value !== (was[p] || ""));
      shownSource = $(".bot-f-source").value;
      const reset = !touched || await confirmDialog({ title: "Use the example text for this?", message: "The placeholders differ between sources. Replace the header, line and footer with the example?", confirmLabel: "Replace" });
      await drawSource(reset);
      form.dispatchEvent(new Event("input"));
    }
    if (e.target.closest(".bot-pick")) {
      if (e.target.checked) picked.add(e.target.value); else picked.delete(e.target.value);
      $(".bot-pick-count").textContent = picked.size ? `(${picked.size} picked)` : "(all: tick some to limit it)";
    }
  });
  form.addEventListener("input", (e) => {
    if (e.target.matches(".bot-pick-search")) drawPick();
    if (e.target.matches(".bot-metric-search")) drawMetrics();
  });
  form.addEventListener("click", (e) => {
    if (!e.target.closest("[data-bot-reset]")) return;
    const s = src[$(".bot-f-source").value];
    for (const part of ["header", "line", "footer"]) $(`textarea[data-part=${part}]`).value = s.default[part] || "";
    form.dispatchEvent(new Event("input"));
  });
  // The preview needs a name that passes the checks; a new command previews as /preview.
  botPreviewer(form, () => ({ command: { ...command(), name: command().name || "preview" }, arg: $(".bot-arg").value }));
  form.addEventListener("submit", async (e) => {
    e.preventDefault();
    const mine = command();
    // An edited command keeps its place in the list; a new one goes last.
    const list = existing ? botData.custom.map(x => (x.name === existing.name ? mine : botStrip(x)))
      : [...botData.custom.map(botStrip), mine];
    const off = botOff().filter(n => !existing || n !== existing.name);
    if (existing && !existing.on) off.push(mine.name);
    try {
      await botSave(list, off);
      back.remove();
      showToast(`/${mine.name} saved`, "success");
    } catch (err) { $(".bot-err").textContent = err.message; }
  });
  drawSource(false);
  $(".bot-f-name").focus();
}
