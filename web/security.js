/* Two-factor authentication (Settings, Account) and the forgotten-password flow on the login screen.
 *
 * 2FA: start shows a QR code (drawn by the server as SVG, no external service) and the secret
 * for typing in; a first code turns it on and shows 8 recovery codes once. Turning it off and
 * new recovery codes are tier 3 steps (the shared step-up dialog in app.js asks).
 * Recovery: username and authenticator code, then a one-time code sent to the Telegram chat,
 * then a new password.
 */

let twoFaState = null;

async function renderTwoFactor() {
  const box = document.getElementById("account-2fa");
  if (!box) return;
  try {
    twoFaState = await api("/api/auth/2fa");
  } catch (err) {
    box.innerHTML = "";
    return;
  }
  const on = twoFaState.enabled;
  box.innerHTML = `<h4>Two-factor authentication</h4>
    <div class="twofa-row">
      <span class="status-pill ${on ? "status-ok" : "status-warn"}">${on ? "On" : "Off"}</span>
      <span class="dim">${on
        ? `Logging in and the most sensitive changes also ask for a code from your phone. ${twoFaState.recovery_left} recovery code${twoFaState.recovery_left === 1 ? "" : "s"} left.`
        : "Recommended: logging in and the most sensitive changes (credentials, users, SSH trust) then also ask for a code from an authenticator app."}</span>
    </div>
    <div class="twofa-actions">
      ${on ? `<button type="button" class="btn" id="btn-2fa-recovery">New recovery codes</button>
              <button type="button" class="btn btn-danger" id="btn-2fa-off">Turn off</button>`
           : `<button type="button" class="btn btn-primary" id="btn-2fa-on">Set up two-factor authentication</button>`}
    </div>
    <div id="twofa-enrol"></div>`;
}

function showRecoveryCodes(codes) {
  return alertDialog({
    title: "Save your recovery codes",
    message: "Each code logs you in once if your phone is lost. Store them in your password manager or on paper. They are not shown again.",
    detail: codes.join("\n"),
    confirmLabel: "I have saved them",
  });
}

async function startTwoFactor() {
  let r;
  try {
    r = await api("/api/auth/2fa/start", { method: "POST", body: {} });
  } catch (err) {
    showToast(err.message, "error");
    return;
  }
  const box = document.getElementById("twofa-enrol");
  const startBtn = document.getElementById("btn-2fa-on");
  if (startBtn) startBtn.classList.add("hidden");
  box.innerHTML = `<div class="twofa-enrol">
      <div class="twofa-qr" id="twofa-qr"></div>
      <div class="twofa-steps">
        <ol>
          <li>Open an authenticator app (Google or Microsoft Authenticator, Aegis, 1Password, Bitwarden).</li>
          <li>Scan the code, or add it by hand with this key:<div class="twofa-secret"><code>${escapeHtml(r.secret)}</code></div></li>
          <li>Type the 6-digit code the app shows.</li>
        </ol>
        <form id="twofa-confirm" class="twofa-confirm">
          <input type="text" id="twofa-code" inputmode="numeric" maxlength="6" autocomplete="one-time-code" placeholder="123456">
          <button type="submit" class="btn btn-primary">Turn on</button>
          <button type="button" class="btn" id="btn-2fa-cancel">Cancel</button>
        </form>
      </div>
    </div>`;
  // The SVG comes from the server's own encoder. Shown as an image, so nothing in it can run or
  // touch the page (and no markup is inserted as HTML).
  const qrBytes = new TextEncoder().encode(r.svg);
  let qrBin = "";
  qrBytes.forEach(b => { qrBin += String.fromCharCode(b); });
  const qr = document.createElement("img");
  qr.src = "data:image/svg+xml;base64," + btoa(qrBin);
  qr.width = 190;
  qr.height = 190;
  qr.alt = "QR code for your authenticator app";
  qr.style.display = "block";
  qr.style.borderRadius = "4px";
  document.getElementById("twofa-qr").replaceChildren(qr);
  document.getElementById("twofa-code").focus();
  document.getElementById("btn-2fa-cancel").addEventListener("click", () => { box.innerHTML = ""; if (startBtn) startBtn.classList.remove("hidden"); });
  document.getElementById("twofa-confirm").addEventListener("submit", async ev => {
    ev.preventDefault();
    try {
      const res = await api("/api/auth/2fa/enable", { method: "POST", body: { code: document.getElementById("twofa-code").value.trim() } });
      await showRecoveryCodes(res.recovery_codes);
      showToast("Two-factor authentication is on", "success");
      renderTwoFactor();
    } catch (err) {
      showToast(err.message, "error");
    }
  });
}

function initTwoFactor() {
  const box = document.getElementById("account-2fa");
  if (!box) return;
  box.addEventListener("click", async ev => {
    const id = ev.target.id;
    if (id === "btn-2fa-on") return startTwoFactor();
    if (id === "btn-2fa-off") {
      if (!(await confirmDialog({ title: "Turn off two-factor authentication?", danger: true, confirmLabel: "Turn off",
        message: "Logging in and sensitive changes will only ask for your password." }))) return;
      try {
        await api("/api/auth/2fa/disable", { method: "POST", body: {} });
        showToast("Two-factor authentication is off", "success");
      } catch (err) { showToast(err.message, "error"); }
      renderTwoFactor();
    }
    if (id === "btn-2fa-recovery") {
      if (!(await confirmDialog({ title: "Make new recovery codes?", confirmLabel: "Make new codes",
        message: "The codes you have now stop working." }))) return;
      try {
        const r = await api("/api/auth/2fa/recovery", { method: "POST", body: {} });
        await showRecoveryCodes(r.recovery_codes);
      } catch (err) { showToast(err.message, "error"); }
      renderTwoFactor();
    }
  });
}

// --- Forgotten password ---

let recoverTicket = null;

function showRecover(open) {
  document.getElementById("auth-form").classList.toggle("hidden", open);
  document.getElementById("recover-form").classList.toggle("hidden", !open);
  recoverTicket = null;
  document.getElementById("recover-step1").classList.remove("hidden");
  document.getElementById("recover-step2").classList.add("hidden");
  document.getElementById("recover-submit").textContent = "Send the code";
  hide(document.getElementById("recover-error"));
  if (open) {
    document.getElementById("recover-username").value = document.getElementById("auth-username").value;
    document.getElementById("recover-username").focus();
  }
}

async function recoverPost(path, body) {
  const res = await fetch(path, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || `Request failed (HTTP ${res.status})`);
  return data;
}

function initRecovery() {
  document.getElementById("auth-forgot").addEventListener("click", () => showRecover(true));
  document.getElementById("recover-back").addEventListener("click", () => showRecover(false));
  document.getElementById("recover-form").addEventListener("submit", async ev => {
    ev.preventDefault();
    const err = document.getElementById("recover-error");
    hide(err);
    const username = document.getElementById("recover-username").value.trim();
    const btn = document.getElementById("recover-submit");
    btn.disabled = true;
    try {
      if (!recoverTicket) {
        const r = await recoverPost("/api/auth/recover/start", { username, code: document.getElementById("recover-code").value.trim() });
        recoverTicket = r.ticket;
        document.getElementById("recover-step1").classList.add("hidden");
        document.getElementById("recover-step2").classList.remove("hidden");
        btn.textContent = "Set the new password";
        document.getElementById("recover-tg").focus();
        return;
      }
      const pw = document.getElementById("recover-new").value;
      if (pw !== document.getElementById("recover-new2").value) throw new Error("The new passwords do not match.");
      await recoverPost("/api/auth/recover/finish", { username, ticket: recoverTicket,
        telegram_code: document.getElementById("recover-tg").value.trim(), new: pw });
      document.getElementById("recover-new").value = document.getElementById("recover-new2").value = "";
      showRecover(false);
      document.getElementById("auth-username").value = username;
      document.getElementById("auth-password").focus();
      showToast("Password changed. Log in with the new one.", "success");
    } catch (e) {
      err.textContent = e.message;
      show(err);
    } finally {
      btn.disabled = false;
    }
  });
}

document.addEventListener("DOMContentLoaded", () => {
  initTwoFactor();
  initRecovery();
});
