// HTTPS: Settings, System, HTTPS, and the one-time question after an upgrade from before HTTPS (tls.py).

let tlsState = null;

async function loadTlsSettings() {
  try {
    tlsState = await api("/api/tls");
  } catch (err) {
    tlsSay(err.message, "text-err");
    return;
  }
  renderTlsSettings(true);
}

function tlsSay(text, kind = "") {
  const msg = document.getElementById("tls-msg");
  msg.textContent = text;
  msg.className = `form-help ${kind}`;
}

const TLS_HELP = {
  "off": "Now: plain HTTP. Nothing is encrypted.",
  "self-signed": "Now: HTTPS with a certificate the monitor made and renews itself.",
  "own": "Now: HTTPS with your own certificate.",
};

/** The selected mode's form only; the current certificate's details while HTTPS is on. */
function renderTlsSettings(fill) {
  const t = tlsState || {};
  const sel = document.getElementById("tls-mode");
  if (fill) sel.value = t.mode || "off";
  sel.disabled = !can("settings.system");
  const pick = sel.value;
  document.getElementById("tls-mode-help").textContent = TLS_HELP[t.mode] || "";
  const failed = document.getElementById("tls-failure");
  failed.textContent = t.failure ? `HTTPS could not start: ${t.failure}. Logins from other computers are refused until this is fixed. Choose a certificate below or switch HTTPS off.` : "";
  failed.classList.toggle("hidden", !t.failure);
  document.querySelectorAll("#settings-https [data-tls]").forEach(f =>
    f.classList.toggle("hidden", f.dataset.tls !== pick || !can("settings.system") || (pick === "off" && t.mode === "off")));
  document.getElementById("btn-tls-self").textContent = t.mode === "self-signed" ? "Save names" : "Use this";
  document.getElementById("btn-tls-own").textContent = t.mode === "own" ? "Check and replace" : "Check and use";
  if (fill) {
    document.getElementById("tls-names").value = (t.extra_names || []).join(", ");
    document.getElementById("tls-cert").value = "";
    document.getElementById("tls-key").value = "";
  }
  document.getElementById("tls-names-help").textContent =
    `Always covered: ${(t.machine_names || []).join(", ")}. Add any other name or address you open the monitor by.`;
  const box = document.getElementById("tls-current");
  const c = t.certificate;
  box.classList.toggle("hidden", !c);
  if (!c) return;
  const day = ts => new Date(ts * 1000).toLocaleDateString();
  const left = Math.floor((c.not_after - Date.now() / 1000) / 86400);
  const leftText = left < 0 ? `<span class="text-err">expired</span>` : left <= 21 ? `<span class="text-warn">${left} days left</span>` : `${left} days left`;
  box.innerHTML = `<table class="kv-table"><tbody>
      <tr><td>Issued to</td><td>${escapeHtml(c.subject)}</td></tr>
      <tr><td>Names</td><td>${escapeHtml(c.names.join(", ") || "none listed")}</td></tr>
      <tr><td>Issued by</td><td>${escapeHtml(c.self_signed ? "itself (self-signed)" : c.issuer)}</td></tr>
      <tr><td>Valid</td><td>${escapeHtml(day(c.not_before))} to ${escapeHtml(day(c.not_after))}, ${leftText}${t.mode === "self-signed" ? ", renewed automatically" : ""}</td></tr>
      <tr><td>Fingerprint (SHA-256)</td><td><code class="tls-fp">${escapeHtml(c.fingerprint)}</code></td></tr>
    </tbody></table>
    <a class="btn" href="/api/tls/certificate" download="homelab-monitor.crt" data-tls-download>Download certificate</a>`;
}

/** After a change, move this page to the address the monitor now answers on. */
function tlsFollow(state, note) {
  tlsState = state;
  const want = state.active ? "https:" : "http:";
  if (location.protocol !== want) {
    tlsSay(`${note} Opening ${want}//${location.host} ...`, "text-ok");
    setTimeout(() => { location.href = `${want}//${location.host}${location.pathname}#/settings/https`; }, 1200);
    return;
  }
  renderTlsSettings(true);
  tlsSay(note, "text-ok");
}

async function tlsApply(body, button, note) {
  button.disabled = true;
  tlsSay("Working...");
  try {
    const r = await api("/api/tls", { method: "PUT", body });
    tlsFollow(r.tls, note);
  } catch (err) {
    tlsSay(err.message, "text-err");
  } finally {
    button.disabled = false;
  }
}

let tlsAsked = false;

/** Asked once per page load, of someone who may change it, until they choose. */
function askHttps() {
  if (tlsAsked || document.querySelector(".tls-ask")) return;
  tlsAsked = true;
  const back = document.createElement("div");
  back.className = "modal-backdrop dialog-backdrop";
  back.innerHTML = `<div class="modal dialog tls-ask" role="dialog" aria-modal="true" aria-labelledby="tls-ask-title">
    <div class="modal-header"><span id="tls-ask-title">Encrypt the connection to the monitor?</span></div>
    <div class="modal-body">
      <div class="dialog-message">This version can serve the monitor over HTTPS, so passwords and settings cannot be read off the network. It still answers on the same address: http:// links are sent on to https://.</div>
      <ul class="tls-ask-list">
        <li><strong>Use HTTPS</strong>: the monitor makes its own certificate and renews it. Your browser warns once; continue, or trust the certificate (Settings, HTTPS).</li>
        <li><strong>Use my own certificate</strong>: opens Settings, HTTPS to upload it.</li>
        <li><strong>Keep HTTP</strong>: no change. You can switch any time in Settings, HTTPS.</li>
      </ul>
      <div class="form-help" id="tls-ask-msg"></div>
    </div>
    <div class="modal-footer">
      <button type="button" class="btn" data-tls-ask="keep">Keep HTTP</button>
      <button type="button" class="btn" data-tls-ask="own">Use my own certificate</button>
      <button type="button" class="btn btn-primary" data-tls-ask="self">Use HTTPS</button>
    </div></div>`;
  document.body.appendChild(back);
  const close = () => { document.removeEventListener("keydown", onKey, true); back.remove(); };
  // Escape or a click outside asks again next time; only a choice ends the question.
  const onKey = ev => { if (ev.key === "Escape") { ev.preventDefault(); ev.stopPropagation(); close(); } };
  document.addEventListener("keydown", onKey, true);
  back.addEventListener("mousedown", ev => { if (ev.target === back) close(); });
  const say = (t, k = "") => { const m = back.querySelector("#tls-ask-msg"); m.textContent = t; m.className = `form-help ${k}`; };
  back.addEventListener("click", async ev => {
    const b = ev.target.closest("[data-tls-ask]");
    if (!b) return;
    const choice = b.dataset.tlsAsk;
    try {
      if (choice === "keep") {
        await api("/api/tls/dismiss", { method: "POST" });
        close();
      } else if (choice === "own") {
        await api("/api/tls/dismiss", { method: "POST" });
        close();
        location.hash = "#/settings/https";
        const sel = document.getElementById("tls-mode");
        setTimeout(() => { sel.value = "own"; renderTlsSettings(false); }, 400);
      } else {
        back.querySelectorAll("button").forEach(x => { x.disabled = true; });
        say("Making the certificate...");
        const r = await api("/api/tls", { method: "PUT", body: { mode: "self-signed", extra_names: "" } });
        if (r.tls.active) {
          say(`Done. Opening https://${location.host} ... Your browser will warn once about the certificate.`, "text-ok");
          setTimeout(() => { location.href = `https://${location.host}${location.pathname}${location.hash}`; }, 1800);
        } else {
          close();
        }
      }
    } catch (err) {
      back.querySelectorAll("button").forEach(x => { x.disabled = false; });
      say(err.message, "text-err");
    }
  });
  back.querySelector("[data-tls-ask=self]").focus();
}

function initTls() {
  document.getElementById("tls-mode").addEventListener("change", () => { tlsSay(""); renderTlsSettings(false); });
  document.getElementById("tls-self").addEventListener("submit", ev => {
    ev.preventDefault();
    tlsApply({ mode: "self-signed", extra_names: document.getElementById("tls-names").value },
      document.getElementById("btn-tls-self"), tlsState && tlsState.mode === "self-signed" ? "Saved." : "HTTPS is on.");
  });
  document.getElementById("tls-own").addEventListener("submit", ev => {
    ev.preventDefault();
    tlsApply({ mode: "own", certificate: document.getElementById("tls-cert").value, key: document.getElementById("tls-key").value },
      document.getElementById("btn-tls-own"), "Certificate checked and in use.");
  });
  document.getElementById("tls-off").addEventListener("submit", async ev => {
    ev.preventDefault();
    const ok = await confirmDialog({ title: "Switch to plain HTTP?", danger: true, confirmLabel: "Switch to HTTP",
      message: "Passwords and settings travel unencrypted on the network from now on. The certificate is kept, so switching back to HTTPS uses the same one." });
    if (ok) tlsApply({ mode: "off" }, document.getElementById("btn-tls-off"), "Switched to HTTP.");
  });
  // Download certificate: fetched by the page and saved from memory. A plain link is a separate
  // download request, and Chrome fails those ("Network error") while the certificate is not yet
  // trusted, which is exactly when it is needed.
  document.getElementById("tls-current").addEventListener("click", async ev => {
    const link = ev.target.closest("[data-tls-download]");
    if (!link) return;
    ev.preventDefault();
    try {
      const res = await fetch("/api/tls/certificate", { credentials: "same-origin" });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      const url = URL.createObjectURL(new Blob([await res.text()], { type: "application/x-x509-ca-cert" }));
      const a = Object.assign(document.createElement("a"), { href: url, download: "homelab-monitor.crt" });
      document.body.appendChild(a);
      a.click();
      a.remove();
      setTimeout(() => URL.revokeObjectURL(url), 10000);
    } catch (err) {
      tlsSay(`Could not download the certificate: ${err.message}`, "text-err");
    }
  });
  // Choose file: read the PEM text into the box next to it (nothing is uploaded until Check).
  document.querySelectorAll("#settings-https input[type=file][data-into]").forEach(input => input.addEventListener("change", async () => {
    const file = input.files[0];
    if (!file) return;
    if (file.size > 48 * 1024) { tlsSay("That file is far larger than a certificate or key.", "text-err"); return; }
    document.getElementById(input.dataset.into).value = await file.text();
    input.value = "";
  }));
}

document.addEventListener("DOMContentLoaded", initTls);
