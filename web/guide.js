/* Guide: the usage guide (guide.html), one section per topic.
 *
 * #/guide shows the contents and every section; #/guide/<id> scrolls to one. The search box
 * reads plain questions and lists the best answers (see Search below). The text lives in guide.html so it
 * can be edited without touching code; it is fetched once. The sections are sorted into the
 * chapters below (for the contents and each section's colour); a section not listed goes under
 * "More".
 */

let guideLoaded = false;

const GUIDE_CHAPTERS = [
  { id: "basics", title: "The basics", tone: "blue", blurb: "Install, add devices and find your way around",
    sections: ["start", "adding", "devices", "device", "groups", "dashboard"] },
  { id: "watching", title: "Watching the network", tone: "green", blurb: "Availability, problems, the map and what changed",
    sections: ["availability", "alerts", "maintenance", "shutdown-alerts", "inventory", "map", "reports", "logs"] },
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
    <div class="guide-chapters">${GUIDE_CHAPTERS.map(c => `<a class="guide-chapter" data-tone="${escapeHtml(c.tone)}" href="#/guide/${escapeHtml(c.sections[0])}">
      <span class="guide-chapter-title">${escapeHtml(c.title)}</span><span class="guide-chapter-blurb">${escapeHtml(c.blurb)}</span>
      <span class="guide-chapter-count">${c.sections.filter(id => body.querySelector(`section[id="${id}"]`)).length} topics</span></a>`).join("")}</div>`;
  body.prepend(hero);
  const byChapter = {};
  sections.forEach((s, i) => (byChapter[guideChapterOf(s.id).id] = byChapter[guideChapterOf(s.id).id] || []).push([s, i]));
  const chapters = [...GUIDE_CHAPTERS, { id: "more", title: "More", tone: "gray" }].filter(c => byChapter[c.id]);
  document.getElementById("guide-toc").innerHTML = chapters.map(c => `<div class="guide-toc-group" data-tone="${escapeHtml(c.tone)}" data-chapter="${escapeHtml(c.id)}">
      <div class="guide-toc-head">${escapeHtml(c.title)}</div>
      ${byChapter[c.id].map(([s, i]) => `<a href="#/guide/${escapeHtml(s.id)}" data-guide-link="${escapeHtml(s.id)}"><span class="guide-toc-num">${Number(i) + 1}</span>${escapeHtml(s.dataset.title || s.id)}</a>`).join("")}
    </div>`).join("");
}

/* Search. Everything happens in the browser, from the guide's own text; nothing is sent anywhere.
 * A search is read as a question: filler words ("how do I") are dropped, each remaining word also
 * matches its other forms (notification, notifications) and the related words in GUIDE_RELATED
 * (SSID also finds Wi-Fi networks, stop also finds quiet and never). A topic is shown when every
 * word, or a related one, is in it. If no topic has them all, the closest topics are shown.
 * Best answers ranks single paragraphs, list items and table rows: the words typed count twice as
 * much as related ones. */

const GUIDE_STOP = new Set(("a about after all also am an and any are as at be been before but by can could did do does doing " +
  "for from get gets getting got had has have how i if in into is it its just let me my of off on once one only or our out " +
  "over please same should so some such than that the their them then there these they this those to too up us very " +
  "want wants was way ways we were what when where which while who why will with would you your " +
  "specific particular certain each every someone something thing things possible able need needs").split(" "));

// Rewritten before the words are split, so two-word phrases count as one.
const GUIDE_PHRASES = [
  [/\b(turn|switch)(ed|ing)? off\b/g, "stop"],
  [/\b(low|poor|bad) (wifi )?signal\b/g, "weak"],
  [/\b(log|sign)(ging)? (in|on)\b/g, "login"],
  [/\bback(ing)? up\b/g, "backup"],
  [/\bwifi networks?\b/g, "ssid"],
  [/\bstatus page\b/g, "availability"],
  [/\bnot working\b/g, "trouble"],
];

// Words that mean the same thing in this guide. A word typed also finds the others in its group.
const GUIDE_RELATED = [
  ["ssid", "wifi network", "guest network", "quiet network", "network name"],
  ["notification", "notify", "alert", "message", "telegram", "announce", "report", "warning", "remind"],
  ["stop", "quiet", "never", "mute", "silence", "disable", "ignore", "hide", "pause", "maintenance"],
  ["weak", "signal", "dbm"],
  ["restart", "reboot"],
  ["backup", "restore", "passphrase"],
  ["update", "upgrade", "release", "version"],
  ["login", "account", "user", "password"],
  ["2fa", "twofactor", "authenticator", "totp"],
  ["delete", "remove"],
  ["schedule", "daily", "weekly", "cron", "interval"],
  ["workflow", "automation", "automate"],
  ["vm", "container", "lxc", "proxmox", "guest"],
  ["dns", "pihole", "adblock"],
  ["map", "topology", "upstream"],
  ["uptime", "availability"],
  ["slow", "latency", "response time", "ping"],
  ["disk", "storage", "space", "full"],
  ["temperature", "hot", "sensor"],
  ["https", "certificate", "tls"],
  ["phone", "mobile"],
  ["trouble", "problem", "fix", "error", "fail", "broken"],
  ["snmp", "community", "oid"],
  ["new device", "unknown device", "inventory"],
];

let guideState = { terms: [], hits: new Map() };
let guidePending = null;

function guideStem(w) {
  for (const suf of ["ations", "ation", "ings", "ing", "ions", "ion", "ies", "es", "ed", "s"])
    if (w.length - suf.length >= 4 && w.endsWith(suf)) return w.slice(0, -suf.length);
  return w;
}

// A word as a pattern: from the start of a word, with an optional hyphen between letters, so
// "wifi" finds Wi-Fi and "pihole" finds Pi-hole.
function guidePattern(stem) {
  let out = "";
  for (const c of stem) {
    if (c === " ") { out += "[\\s-]+"; continue; }
    if (out && !out.endsWith("+")) out += "-?";
    out += c.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  }
  return out;
}

function guideRegex(stems, flags) {
  return stems.length ? new RegExp(`\\b(?:${stems.map(guidePattern).join("|")})`, flags) : null;
}

function guideQuery(raw) {
  let q = raw.toLowerCase().replace(/(\p{L})-(\p{L})/gu, "$1$2");
  GUIDE_PHRASES.forEach(([re, to]) => { q = q.replace(re, to); });
  const words = [...new Set(q.split(/[^\p{L}\p{N}]+/u).filter(w => w && !GUIDE_STOP.has(w)))];
  return words.map(word => {
    const stem = guideStem(word);
    const related = new Set();
    GUIDE_RELATED.forEach(group => {
      if (group.some(m => guideStem(m) === stem))
        group.forEach(m => { if (guideStem(m) !== stem) related.add(guideStem(m)); });
    });
    return { word, stem, related: [...related], direct: guideRegex([stem], "i"), near: guideRegex([...related], "i") };
  });
}

// 2 for the word itself, 1 for a related word, 0 for neither.
function guideMatch(term, text) {
  if (term.direct.test(text)) return 2;
  return term.near && term.near.test(text) ? 1 : 0;
}

// The pieces of a section an answer can point at: the smallest paragraphs, list items and rows.
function guideBlocks(section) {
  const all = [...section.querySelectorAll("p, li, tr, dt, dd")];
  return all.filter(el => !all.some(o => o !== el && el.contains(o)));
}

function guideHeading(el) {
  const section = el.closest("section");
  let h = null;
  section.querySelectorAll("h3").forEach(x => {
    if (x.compareDocumentPosition(el) & Node.DOCUMENT_POSITION_FOLLOWING) h = x;
  });
  const title = section.dataset.title || section.id;
  return h ? `${title}: ${h.textContent.trim()}` : title;
}

function guideUnmark() {
  document.querySelectorAll("#guide-body mark.guide-hit").forEach(m => {
    const parent = m.parentNode;
    m.replaceWith(document.createTextNode(m.textContent));
    parent.normalize();
  });
}

// Marks the words found in the shown topics: the words typed, and related words more lightly.
function guideMark(sections, terms) {
  const direct = guideRegex(terms.map(t => t.stem), "gi");
  const near = guideRegex(terms.flatMap(t => t.related), "gi");
  const rest = /^[\p{L}\p{N}]*/u;
  sections.forEach(s => {
    const walker = document.createTreeWalker(s, NodeFilter.SHOW_TEXT, {
      acceptNode: n => n.parentElement.closest(".guide-num, .guide-kicker, mark") ? NodeFilter.FILTER_REJECT : NodeFilter.FILTER_ACCEPT,
    });
    const nodes = [];
    while (walker.nextNode()) nodes.push(walker.currentNode);
    nodes.forEach(node => {
      const text = node.textContent;
      const found = [];
      [[direct, ""], [near, " near"]].forEach(([re, cls]) => {
        if (!re) return;
        re.lastIndex = 0;
        let m;
        while ((m = re.exec(text))) {
          // The whole word, not just its stem.
          const end = m.index + m[0].length + rest.exec(text.slice(m.index + m[0].length))[0].length;
          if (!found.some(f => m.index < f.end && end > f.start)) found.push({ start: m.index, end, cls });
          if (!m[0].length) re.lastIndex++;
        }
      });
      if (!found.length) return;
      found.sort((a, b) => a.start - b.start);
      const frag = document.createDocumentFragment();
      let at = 0;
      found.forEach(f => {
        frag.append(text.slice(at, f.start));
        const mark = document.createElement("mark");
        mark.className = "guide-hit" + f.cls;
        mark.textContent = text.slice(f.start, f.end);
        frag.append(mark);
        at = f.end;
      });
      frag.append(text.slice(at));
      node.replaceWith(frag);
    });
  });
}

function guideSnippet(el, terms) {
  const text = el.textContent.replace(/\s+/g, " ").trim();
  if (text.length <= 240) return text;
  let first = text.length;
  terms.forEach(t => {
    const m = t.direct.exec(text) || (t.near && t.near.exec(text));
    if (m) first = Math.min(first, m.index);
  });
  const from = first > 80 ? text.lastIndexOf(" ", first - 60) + 1 : 0;
  const cut = text.slice(from, from + 240);
  return (from ? "..." : "") + cut.slice(0, cut.lastIndexOf(" ")) + "...";
}

function guideRenderAnswers(answers, terms) {
  const box = document.getElementById("guide-answers");
  if (!answers.length) { box.classList.add("hidden"); box.innerHTML = ""; return; }
  const all = guideRegex(terms.flatMap(t => [t.stem, ...t.related]), "gi");
  const marked = text => {
    let out = "", at = 0;
    for (const m of text.matchAll(all)) {
      out += escapeHtml(text.slice(at, m.index)) + `<mark class="guide-hit">${escapeHtml(m[0])}</mark>`;
      at = m.index + m[0].length;
    }
    return out + escapeHtml(text.slice(at));
  };
  box.innerHTML = `<div class="guide-answers-head">Best answers</div>` + answers.map((a, i) => {
    const s = a.el.closest("section");
    return `<a class="guide-answer" href="#/guide/${escapeHtml(s.id)}" data-answer="${i}" data-tone="${escapeHtml(s.dataset.tone || "blue")}">
      <span class="guide-answer-topic">${escapeHtml(guideHeading(a.el))}</span>
      <span class="guide-answer-text">${marked(guideSnippet(a.el, terms))}</span></a>`;
  }).join("");
  box.classList.remove("hidden");
  box.querySelectorAll("[data-answer]").forEach(link => link.addEventListener("click", e => {
    e.preventDefault();
    const el = answers[Number(link.dataset.answer)].el;
    const href = link.getAttribute("href");
    if (location.hash === href) { guideFocus(el); return; }
    guidePending = el;
    location.hash = href;
  }));
}

// Scrolls to a paragraph and pulses it, so the eye lands on the answer.
function guideFocus(el) {
  el.scrollIntoView({ block: "center" });
  el.classList.remove("guide-pulse");
  void el.offsetWidth;
  el.classList.add("guide-pulse");
  clearTimeout(el.guidePulseTimer);
  el.guidePulseTimer = setTimeout(() => el.classList.remove("guide-pulse"), 3200);
}

function filterGuide() {
  const raw = document.getElementById("guide-search").value.trim();
  const sections = [...document.querySelectorAll("#guide-body section[id]")];
  guideUnmark();
  const typed = raw ? guideQuery(raw) : [];
  // A word found nowhere in the guide (a typo, a word it never uses) does not hide everything else.
  const terms = typed.filter(t => sections.some(s => guideMatch(t, s.textContent)));
  const searching = typed.length > 0;
  const counts = new Map(sections.map(s => [s, terms.filter(t => guideMatch(t, s.textContent)).length]));
  const most = Math.max(0, ...counts.values());
  const hit = new Set(sections.filter(s => !searching || (most > 0 && counts.get(s) === most)));
  const hits = new Map();
  const answers = [];
  if (searching) {
    hit.forEach(s => {
      const ranked = guideBlocks(s).map((el, order) => {
        const m = terms.map(t => guideMatch(t, el.textContent));
        const n = m.filter(Boolean).length;
        const score = m.reduce((a, b) => a + b, 0) + (n === terms.length && n > 1 ? 2 : 0);
        return { el, n, score, order };
      }).filter(b => b.n >= Math.min(2, terms.length)).sort((a, b) => b.score - a.score || a.order - b.order);
      hits.set(s, ranked);
      answers.push(...ranked);
    });
    answers.sort((a, b) => b.score - a.score || b.n - a.n);
  }
  guideState = { terms, hits };
  let shown = 0;
  sections.forEach(s => {
    const on = hit.has(s);
    s.classList.toggle("hidden", !on);
    const link = document.querySelector(`#guide-toc [data-guide-link="${s.id}"]`);
    if (link) link.classList.toggle("hidden", !on);
    if (on) shown++;
  });
  if (searching && terms.length) guideMark([...hit], terms);
  guideRenderAnswers(answers.slice(0, 6), terms);
  document.querySelectorAll("#guide-toc .guide-toc-group").forEach(g =>
    g.classList.toggle("hidden", !g.querySelector("a:not(.hidden)")));
  const hero = document.querySelector("#guide-body .guide-hero");
  if (hero) hero.classList.toggle("hidden", searching);
  const plural = shown === 1 ? "" : "s";
  document.getElementById("guide-count").textContent = !searching || !shown ? ""
    : most === typed.length ? `${shown} topic${plural} match` : `${shown} closest topic${plural} (none has every word)`;
  document.getElementById("guide-none").classList.toggle("hidden", shown > 0);
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
    filterGuide();
  }
  document.querySelectorAll("#guide-toc a").forEach(a => a.classList.toggle("active", a.dataset.guideLink === sectionId));
  const target = sectionId && document.getElementById(sectionId);
  const pending = guidePending;
  guidePending = null;
  if (!target || !target.closest("#guide-body")) return;
  // While searching, a topic opens at its best paragraph.
  const best = pending && target.contains(pending) ? pending : ((guideState.hits.get(target) || [])[0] || {}).el;
  if (best) guideFocus(best);
  else target.scrollIntoView({ block: "start" });
}

function initGuide() {
  document.getElementById("guide-search").addEventListener("input", filterGuide);
}

document.addEventListener("DOMContentLoaded", initGuide);
