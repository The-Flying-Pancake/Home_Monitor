// What's changed (changelog.py): after an upgrade, the next login shows the release notes this
// user has not read, newest first. The Guide page shows them all again ("What's changed").

window.changesDone = Promise.resolve();

/** all: every note (from the Guide); otherwise only unread ones, and nothing when there are none. */
function showChanges(all = false) {
  window.changesDone = (async () => {
    let data;
    try {
      data = await api("/api/changes");
    } catch (err) {
      return;
    }
    const list = all ? data.releases : data.releases.filter(r => data.unseen.includes(r.id));
    if (!list.length || document.querySelector(".changes-window")) return;
    await new Promise(resolve => {
      const back = document.createElement("div");
      back.className = "modal-backdrop dialog-backdrop";
      const day = d => new Date(`${d}T12:00:00`).toLocaleDateString(undefined, { day: "numeric", month: "long", year: "numeric" });
      // Grouped by version (task 295): after a restore of an older backup or an update that jumps several
      // versions there can be many. The newest two stay open, older ones fold.
      const groups = [];
      for (const r of list) {
        const last = groups[groups.length - 1];
        if (last && last.version === (r.version || "")) last.notes.push(r);
        else groups.push({ version: r.version || "", notes: [r] });
      }
      const section = r => `<section class="changes-release">
          <h3>${escapeHtml(r.title)} <span class="dim">${escapeHtml(day(r.date))}</span></h3>
          <ul>${r.items.map(i => `<li>${escapeHtml(i)}</li>`).join("")}</ul></section>`;
      const label = g => g.version ? `Version ${escapeHtml(g.version)}` : "Coming in the next version";
      const versionCount = groups.filter(g => g.version).length;
      const intro = !all && versionCount > 1
        ? `<p class="changes-intro">${versionCount} versions to catch up on, newest first. Older ones are folded: open them to read more.</p>` : "";
      back.innerHTML = `<div class="modal changes-window" role="dialog" aria-modal="true" aria-labelledby="changes-title">
        <div class="modal-header"><span id="changes-title">${all ? "What's changed" : "What's new since you last looked"}</span>
          <button type="button" class="btn" data-x aria-label="Close">&times;</button></div>
        <div class="modal-body">${intro}${groups.map((g, i) => `<details class="changes-version"${i < 2 ? " open" : ""}>
          <summary>${label(g)} <span class="dim">${g.notes.length === 1 ? "1 note" : `${g.notes.length} notes`}</span></summary>
          ${g.notes.map(section).join("")}</details>`).join("")}
          <p class="dim changes-foot">The Guide explains each part in more detail. This list is there again under Guide, What's changed.</p>
        </div>
        <div class="modal-footer"><button type="button" class="btn btn-primary" data-ok>Got it</button></div>
      </div>`;
      document.body.appendChild(back);
      const close = async () => {
        document.removeEventListener("keydown", onKey, true);
        back.remove();
        if (data.unseen.length) {
          try { await api("/api/changes/seen", { method: "POST" }); } catch (err) { /* asked again next time */ }
        }
        resolve();
      };
      const onKey = ev => { if (ev.key === "Escape") { ev.preventDefault(); ev.stopPropagation(); close(); } };
      document.addEventListener("keydown", onKey, true);
      back.querySelector("[data-x]").addEventListener("click", close);
      back.querySelector("[data-ok]").addEventListener("click", close);
      back.querySelector("[data-ok]").focus();
    });
  })();
  return window.changesDone;
}

document.addEventListener("DOMContentLoaded", () => {
  const link = document.getElementById("guide-changes");
  if (link) link.addEventListener("click", ev => { ev.preventDefault(); showChanges(true); });
});
