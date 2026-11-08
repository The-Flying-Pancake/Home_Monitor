/* Telegram message editing and the credential test.
 *
 * openTemplateEditor: a window for one message text with the placeholders that event offers
 * (click to insert at the cursor), an emoji palette, ready-made texts and a live preview with
 * sample values. Used by Settings, Notifications (each message template gets an Edit button)
 * and by the workflow editor's Send Telegram step. Saving writes the text back to the caller;
 * Settings then saves it with the rest of the page as usual.
 *
 * testCredential: logs in to one host with a stored credential and runs `true`.
 * Relies on app.js helpers (api, escapeHtml, showToast, confirmDialog, updateSettingsDirty, openHostKeys).
 */

const TG_EMOJIS = ["✅", "❌", "⚠️", "ℹ️", "🔴", "🟢", "🟡", "🔵", "🔥", "🚨", "⏱️", "🔁", "▶️", "⏹️", "🖥️", "📶",
  "💾", "🌡️", "🔌", "🛠️", "🔒", "🔑", "📦", "🌐", "📡", "⚡", "🔋", "🧰", "📣", "👀"];
let tgInfo = null;   // /api/notify/info: placeholders, presets, emojis, sample

function tgRender(text, values) {
  return text.replace(/\{(\w+)\}/g, (m, k) => (k in values ? String(values[k]) : m));
}

/** Command replies as the bot writes them: a line left empty by its placeholders is dropped. */
function tgRenderReply(text, values) {
  return text.split("\n").flatMap(line => {
    const names = [...line.matchAll(/\{(\w+)\}/g)].map(m => m[1]);
    let done = tgRender(line, values).replace(/\s+$/, "");
    if (line.startsWith("{")) done = done.replace(/^ +/, "");
    return names.length && names.every(n => n in values) && !done.trim() ? [] : done.split("\n");
  }).join("\n").replace(/^\n+|\n+$/g, "");
}

/** The "Tricks" list (tpl.TRICKS from the server): click one to insert its example. */
async function tgTricks() {
  if (!tgInfo || !tgInfo.tricks) {
    try { tgInfo = Object.assign(tgInfo || {}, await api("/api/notify/info")); } catch (err) { /* the list stays empty */ }
  }
  return (tgInfo && tgInfo.tricks) || [];
}

function tgTricksHtml(tricks) {
  return `<details class="tg-tricks"><summary>Tricks: conditions, arithmetic, sorting and more</summary>
    <div class="tg-vars">${(tricks || []).map(([what, ex]) =>
      `<button type="button" class="tg-var" data-ins="${escapeHtml(ex)}"><span>${escapeHtml(what)}</span><code>${escapeHtml(ex)}</code></button>`).join("")}</div>
    <div class="dim tg-tricks-more">Filters: upper, lower, title, trim, default, before, after, round, fixed, int, abs, add, sub, mul, div,
      plural, bar, truncate, pad, lpad, replace, first, last, sort, rsort, unique, count, join. The Guide (Notifications) explains each.</div>
  </details>`;
}

/** Renders with the server's engine (the real result); the simple fill when that is not reachable. */
function tgServerPreview(el, textOf, values, fallback) {
  let timer = null, seq = 0;
  const run = async () => {
    const mine = ++seq;
    try {
      const r = await api("/api/template/render", { method: "POST", body: { text: textOf(), values } });
      if (mine === seq) el.textContent = r.text || " ";
    } catch (err) {
      if (mine === seq) el.textContent = (fallback || tgRender)(textOf(), values) || " ";
    }
  };
  return () => { clearTimeout(timer); timer = setTimeout(run, 250); };
}

/** opts: title, value, placeholders {name: help}, presets [text], sample {name: value}, max, onSave(text). */
function openTemplateEditor(opts) {
  const back = document.createElement("div");
  back.className = "modal-backdrop dialog-backdrop";
  const emojis = (tgInfo && tgInfo.emojis) || TG_EMOJIS;
  const max = opts.max || 500;
  back.innerHTML = `<form class="modal modal-wide tg-editor" role="dialog" aria-modal="true">
    <div class="modal-header"><span>${escapeHtml(opts.title || "Message")}</span>
      <button type="button" class="btn" data-tg-close aria-label="Close">&times;</button></div>
    <div class="modal-body tg-body">
      <div class="tg-main">
        <textarea class="tg-text" rows="7" maxlength="${max}" spellcheck="true"></textarea>
        <div class="tg-count dim"></div>
        <div class="tg-label">Emoji <span class="dim">(click to insert)</span></div>
        <div class="tg-emojis">${emojis.map(e => `<button type="button" class="tg-emoji" data-ins="${escapeHtml(e)}">${escapeHtml(e)}</button>`).join("")}</div>
        <div class="tg-label">Preview <span class="dim">(${escapeHtml(opts.sampleNote || "sample values")})</span></div>
        <div class="tg-preview"></div>
      </div>
      <div class="tg-side">
        <div class="tg-label">Placeholders <span class="dim">(click to insert)</span></div>
        <div class="tg-vars">${Object.entries(opts.placeholders || {}).map(([k, help]) =>
          `<button type="button" class="tg-var" data-ins="{${escapeHtml(k)}}"><code>{${escapeHtml(k)}}</code><span class="dim">${escapeHtml(help)}</span></button>`).join("")}</div>
        <div class="tg-tricks-slot"></div>
        ${(opts.presets || []).length ? `<div class="tg-label">Ready-made</div>
          <div class="tg-presets">${opts.presets.map((p, i) => `<button type="button" class="tg-preset" data-preset="${i}">${escapeHtml(p)}</button>`).join("")}</div>` : ""}
      </div>
    </div>
    <div class="modal-footer"><button type="button" class="btn" data-tg-close>Cancel</button>
      <button type="submit" class="btn btn-primary">Use this text</button></div>
  </form>`;
  document.body.appendChild(back);
  const box = back.querySelector("form");
  const ta = box.querySelector(".tg-text");
  ta.value = opts.value || "";
  const start = ta.value;
  const preview = tgServerPreview(box.querySelector(".tg-preview"), () => ta.value, opts.sample || {}, opts.render);
  const refresh = () => {
    preview();
    box.querySelector(".tg-count").textContent = `${ta.value.length} / ${max}`;
  };
  tgTricks().then(t => { const slot = box.querySelector(".tg-tricks-slot"); if (slot) slot.innerHTML = tgTricksHtml(t); });
  const insert = (text) => {
    const a = ta.selectionStart ?? ta.value.length, b = ta.selectionEnd ?? a;
    ta.value = (ta.value.slice(0, a) + text + ta.value.slice(b)).slice(0, max);
    ta.focus();
    ta.selectionStart = ta.selectionEnd = Math.min(a + text.length, ta.value.length);
    refresh();
  };
  const close = async () => {
    if (ta.value !== start && !(await confirmDialog({ title: "Discard this text?", confirmLabel: "Discard", danger: true }))) return;
    back.remove();
  };
  box.addEventListener("click", async (ev) => {
    const ins = ev.target.closest("[data-ins]");
    if (ins) { insert(ins.dataset.ins); return; }
    const pre = ev.target.closest("[data-preset]");
    if (pre) {
      const text = opts.presets[Number(pre.dataset.preset)];
      if (ta.value.trim() && ta.value !== text && !(await confirmDialog({ title: "Replace the text?", message: "Use this ready-made text instead of the current one?", confirmLabel: "Replace" }))) return;
      ta.value = text;
      refresh();
      return;
    }
    if (ev.target.closest("[data-tg-close]")) close();
  });
  ta.addEventListener("input", refresh);
  box.addEventListener("submit", (ev) => {
    ev.preventDefault();
    back.remove();
    opts.onSave(ta.value);
  });
  back.addEventListener("keydown", (ev) => { if (ev.key === "Escape" && !document.querySelector(".dialog:not(.tg-editor)")) { ev.stopPropagation(); close(); } });
  refresh();
  ta.focus();
}

/** Settings, Notifications: an Edit button beside each message template, opening the editor. */
function decorateTemplateRows(info) {
  tgInfo = info || tgInfo;
  document.querySelectorAll('#settings-sections textarea[data-setting^="notify_tpl_"], #settings-sections textarea[data-setting^="bot_tpl_"]').forEach(ta => {
    if (ta.parentElement.querySelector("[data-tpl-edit]")) return;
    const b = document.createElement("button");
    b.type = "button";
    b.className = "btn btn-small";
    b.dataset.tplEdit = ta.dataset.setting;
    b.textContent = "Edit";
    b.title = "Open the editor: placeholders, emoji, ready-made texts and a preview";
    ta.insertAdjacentElement("afterend", b);
  });
}

document.addEventListener("click", (ev) => {
  const b = ev.target.closest("[data-tpl-edit]");
  if (!b) return;
  const key = b.dataset.tplEdit;
  const ta = document.querySelector(`#settings-sections textarea[data-setting="${CSS.escape(key)}"]`);
  if (!ta || ta.disabled) return;
  const info = tgInfo || {};
  const label = ta.closest(".setting-row") ? ta.closest(".setting-row").querySelector("label").textContent : "Message";
  const save = (text) => {
    ta.value = text;
    ta.dispatchEvent(new Event("input", { bubbles: true }));
  };
  if (key.startsWith("bot_tpl_")) {
    const cmd = key.slice("bot_tpl_".length);
    const c = (info.commands || {})[cmd] || {};
    openTemplateEditor({
      title: label, value: ta.value, max: 500, placeholders: c.placeholders || {},
      presets: c.presets || [], sample: (info.command_samples || {})[cmd] || {},
      sampleNote: "your figures as of opening Settings; the first ready-made text is the original",
      render: tgRenderReply, onSave: save,
    });
    return;
  }
  const kind = key.slice("notify_tpl_".length);
  const names = (info.event_placeholders || {})[kind] || Object.keys(info.placeholders || {});
  openTemplateEditor({
    title: label, value: ta.value, max: 500,
    placeholders: Object.fromEntries(names.map(n => [n, (info.placeholders || {})[n] || ""])),
    presets: (info.presets || {})[kind] || [], sample: info.sample || {},
    onSave: save,
  });
});

// --- Credential test ---

/** Logs in to deviceId with credential credId and runs `true`; writes the result into out (an element) and a toast. */
async function testCredential(credId, deviceId, port, out) {
  if (out) { out.textContent = "Testing..."; out.className = "dim"; }
  try {
    const r = await api(`/api/credentials/${Number(credId)}/test`, { method: "POST", body: { device_id: Number(deviceId), ssh_port: Number(port) || 22 } });
    if (r.need_hostkey) {
      if (out) out.textContent = "Host key not approved yet.";
      if (await confirmDialog({ title: "Approve the host key first", message: r.message, confirmLabel: "Review host key" })) {
        openHostKeys({ device_ids: [r.device_id], ssh_port: Number(port) || 22 });
      }
      return;
    }
    if (out) { out.textContent = r.message; out.className = r.ok ? "text-ok" : "text-err"; }
    showToast(r.message, r.ok ? "success" : "error");
  } catch (err) {
    if (out) { out.textContent = err.message; out.className = "text-err"; }
    showToast(`Test failed: ${err.message}`, "error");
  }
}

/** Credential list: Test asks which host, then tries the login. */
document.addEventListener("click", async (ev) => {
  const b = ev.target.closest("[data-cred-test]");
  if (!b) return;
  const hosts = (typeof autoData !== "undefined" && autoData && autoData.devices) || [];
  if (!hosts.length) { showToast("Add a device first, then test the credential against it.", "error"); return; }
  const back = document.createElement("div");
  back.className = "modal-backdrop dialog-backdrop";
  back.innerHTML = `<form class="modal dialog" role="dialog" aria-modal="true">
    <div class="modal-header"><span>Test credential</span></div>
    <div class="modal-body">
      <div class="dialog-message">Logs in over SSH and runs <code>true</code>, which changes nothing.</div>
      <div class="form-row"><div class="form-group"><label>Host</label><select class="ct-host">${hosts.map(d =>
        `<option value="${Number(d.id)}">${escapeHtml(d.hostname)} (${escapeHtml(d.ip_address)})</option>`).join("")}</select></div>
        <div class="form-group"><label>SSH port</label><input type="number" class="ct-port" value="22" min="1" max="65535"></div></div>
      <div class="ct-result dim"></div>
    </div>
    <div class="modal-footer"><button type="button" class="btn" data-ct-close>Close</button>
      <button type="submit" class="btn btn-primary">Test</button></div>
  </form>`;
  document.body.appendChild(back);
  const box = back.querySelector("form");
  box.addEventListener("submit", (e) => {
    e.preventDefault();
    testCredential(b.dataset.credTest, box.querySelector(".ct-host").value, box.querySelector(".ct-port").value, box.querySelector(".ct-result"));
  });
  box.querySelector("[data-ct-close]").addEventListener("click", () => back.remove());
  back.addEventListener("keydown", (e) => { if (e.key === "Escape") back.remove(); });
  box.querySelector(".ct-host").focus();
});
