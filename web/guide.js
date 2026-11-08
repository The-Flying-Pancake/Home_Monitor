/* Guide: the usage guide (guide.html), one section per topic.
 *
 * #/guide shows the contents and every section; #/guide/<id> scrolls to one. The search box
 * keeps the sections whose text matches every word typed. The text lives in guide.html so it
 * can be edited without touching code; it is fetched once. The sections are sorted into the
 * chapters below (for the contents and each section's colour); a section not listed goes under
 * "More".
 */

let guideLoaded = false;

const GUIDE_CHAPTERS = [
  { id: "basics", title: "The basics", tone: "blue", blurb: "Install, add devices and find your way around",
    sections: ["start", "adding", "devices", "device", "groups", "dashboard"] },
  { id: "watching", title: "Watching the network", tone: "green", blurb: "Availability, problems, the map and what changed",
    sections: ["availability", "alerts", "maintenance", "shutdown-alerts", "inventory", "map", "logs"] },
  { id: "connected", title: "Connected systems", tone: "purple", blurb: "Proxmox, UniFi and Pi-hole",
    sections: ["proxmox", "unifi", "pihole"] },
  { id: "acting", title: "Telegram and automation", tone: "orange", blurb: "Messages, commands and workflows",
    sections: ["notifications", "automation", "host-actions"] },
  { id: "system", title: "Running the monitor", tone: "gray", blurb: "Users, HTTPS, backups and fixes",
    sections: ["users", "https", "backups", "trouble"] },
];

function guideChapterOf(id) {
  return GUIDE_CHAPTERS.find(c => c.sections.includes(id)) || { id: "more", title: "More", tone: "gray", blurb: "", sections: [] };
}

function guideBuild(body) {
  const sections = [...body.querySelectorAll("section[id]")];
  // Chapter order, then the order in the file.
  const order = id => {
    const c = GUIDE_CHAPTERS.findIndex(ch => ch.sections.includes(id));
    return c < 0 ? 999 : c * 100 + GUIDE_CHAPTERS[c].sections.indexOf(id);
  };
  sections.sort((a, b) => order(a.id) - order(b.id)).forEach((s, i) => {
    const ch = guideChapterOf(s.id);
    s.dataset.tone = ch.tone;
    s.classList.add("guide-section");
    const h2 = s.querySelector("h2");
    if (h2 && !h2.querySelector(".guide-num")) {
      h2.insertAdjacentHTML("afterbegin", `<span class="guide-num">${i + 1}</span>`);
      h2.insertAdjacentHTML("beforebegin", `<div class="guide-kicker">${escapeHtml(ch.title)}</div>`);
    }
    // Wide tables scroll inside their section instead of pushing the page sideways.
    s.querySelectorAll("table").forEach(t => {
      if (!t.parentElement.classList.contains("guide-table")) {
        const wrap = document.createElement("div");
        wrap.className = "guide-table";
        t.replaceWith(wrap);
        wrap.appendChild(t);
      }
    });
    body.appendChild(s);
  });
  const hero = document.createElement("div");
  hero.className = "guide-hero";
  hero.innerHTML = `<div class="guide-hero-text"><div class="guide-hero-title">How the monitor works</div>
      <div class="guide-hero-lead">Everything the monitor does, one page per topic. Search on the left, or start with a chapter.</div></div>
    <div class="guide-chapters">${GUIDE_CHAPTERS.map(c => `<a class="guide-chapter" data-tone="${c.tone}" href="#/guide/${c.sections[0]}">
      <span class="guide-chapter-title">${escapeHtml(c.title)}</span><span class="guide-chapter-blurb">${escapeHtml(c.blurb)}</span>
      <span class="guide-chapter-count">${c.sections.filter(id => body.querySelector(`section[id="${id}"]`)).length} topics</span></a>`).join("")}</div>`;
  body.prepend(hero);
  const byChapter = {};
  sections.forEach((s, i) => (byChapter[guideChapterOf(s.id).id] = byChapter[guideChapterOf(s.id).id] || []).push([s, i]));
  const chapters = [...GUIDE_CHAPTERS, { id: "more", title: "More", tone: "gray" }].filter(c => byChapter[c.id]);
  document.getElementById("guide-toc").innerHTML = chapters.map(c => `<div class="guide-toc-group" data-tone="${c.tone}" data-chapter="${c.id}">
      <div class="guide-toc-head">${escapeHtml(c.title)}</div>
      ${byChapter[c.id].map(([s, i]) => `<a href="#/guide/${s.id}" data-guide-link="${s.id}"><span class="guide-toc-num">${i + 1}</span>${escapeHtml(s.dataset.title || s.id)}</a>`).join("")}
    </div>`).join("");
}

async function loadGuide(sectionId) {
  const body = document.getElementById("guide-body");
  if (!guideLoaded) {
    try {
      const r = await fetch("/guide.html", { credentials: "same-origin" });
      if (!r.ok) throw new Error(`HTTP ${r.status}`);
      body.innerHTML = await r.text();
      guideLoaded = true;
    } catch (err) {
      body.innerHTML = `<div class="panel-note-bar warn">Could not load the guide: ${escapeHtml(err.message)}</div>`;
      return;
    }
    guideBuild(body);
  }
  filterGuide();
  document.querySelectorAll("#guide-toc a").forEach(a => a.classList.toggle("active", a.dataset.guideLink === sectionId));
  const target = sectionId && document.getElementById(sectionId);
  if (target && target.closest("#guide-body")) target.scrollIntoView({ block: "start" });
}

function filterGuide() {
  const words = document.getElementById("guide-search").value.toLowerCase().split(/\s+/).filter(Boolean);
  let shown = 0;
  document.querySelectorAll("#guide-body section[id]").forEach(s => {
    const hit = words.every(w => s.textContent.toLowerCase().includes(w));
    s.classList.toggle("hidden", !hit);
    const link = document.querySelector(`#guide-toc [data-guide-link="${s.id}"]`);
    if (link) link.classList.toggle("hidden", !hit);
    if (hit) shown++;
  });
  document.querySelectorAll("#guide-toc .guide-toc-group").forEach(g =>
    g.classList.toggle("hidden", !g.querySelector("a:not(.hidden)")));
  const hero = document.querySelector("#guide-body .guide-hero");
  if (hero) hero.classList.toggle("hidden", words.length > 0);
  const count = document.getElementById("guide-count");
  if (count) count.textContent = words.length ? `${shown} topic${shown === 1 ? "" : "s"} match` : "";
  document.getElementById("guide-none").classList.toggle("hidden", shown > 0);
}

function initGuide() {
  document.getElementById("guide-search").addEventListener("input", filterGuide);
}

document.addEventListener("DOMContentLoaded", initGuide);
