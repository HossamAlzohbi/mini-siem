"use strict";
// All log-derived text is inserted with textContent. Never use innerHTML in this file.

const LEVELS = ["critical", "high", "medium", "low", "informational"];
const $ = (sel) => document.querySelector(sel);

function el(tag, props = {}, ...children) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(props)) {
    if (k === "class") node.className = v;
    else if (k === "text") node.textContent = v;
    else if (k.startsWith("on")) node.addEventListener(k.slice(2), v);
    else node.setAttribute(k, v);
  }
  for (const c of children) if (c != null) node.append(c);
  return node;
}

async function api(path) {
  const res = await fetch(path, { headers: { Accept: "application/json" } });
  if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error || res.statusText);
  return res.json();
}

const fmtTime = (iso) => iso.replace("T", " ").replace("Z", "");
const badge = (level) => el("span", { class: `badge lv-${level}`, text: level });

function clear(node) { while (node.firstChild) node.removeChild(node.firstChild); }
function emptyRow(tbody, cols, text) {
  tbody.append(el("tr", {}, el("td", { colspan: String(cols), class: "empty", text })));
}

// ---------------------------------------------------------------- summary
function renderTiles(s) {
  const box = $("#tiles");
  clear(box);
  const tile = (n, label, cls = "") =>
    el("div", { class: `tile ${cls}` }, el("div", { class: "n", text: String(n) }), el("div", { class: "l", text: label }));
  box.append(
    tile(s.events_total.toLocaleString(), "events stored"),
    tile(s.alerts_total, "alerts"),
    tile(s.alerts_by_level.critical, "critical", "crit"),
    tile(s.alerts_by_level.high, "high", "high"),
    tile(s.alerts_by_level.medium, "medium"),
  );
  $("#range").textContent = s.range ? `${fmtTime(s.range[0])} to ${fmtTime(s.range[1])} UTC` : "no data yet";
}

function levelColor(level) {
  return getComputedStyle(document.documentElement).getPropertyValue(`--${level}`).trim();
}

function renderTimeline(s) {
  const host = $("#timeline");
  clear(host);
  const NS = "http://www.w3.org/2000/svg";
  const W = 900, H = 190, L = 34, B = 22, T = 8;
  const svg = document.createElementNS(NS, "svg");
  svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
  svg.setAttribute("preserveAspectRatio", "none");
  const data = s.timeline;
  if (!data.length) {
    host.append(el("p", { class: "empty", text: "No alerts yet." }));
    return;
  }
  const totals = data.map((d) => LEVELS.reduce((a, l) => a + d.levels[l], 0));
  const max = Math.max(...totals, 1);
  const bw = (W - L) / data.length;
  const y = (v) => T + (H - T - B) * (1 - v / max);
  const mk = (name, attrs, text) => {
    const n = document.createElementNS(NS, name);
    for (const [k, v] of Object.entries(attrs)) n.setAttribute(k, v);
    if (text != null) n.textContent = text;
    return n;
  };
  [0, 0.5, 1].forEach((f) => {
    const v = Math.round(max * f);
    svg.append(mk("line", { x1: L, x2: W, y1: y(v), y2: y(v), stroke: "currentColor", opacity: ".12" }));
    svg.append(mk("text", { x: L - 4, y: y(v) + 3, "text-anchor": "end" }, String(v)));
  });
  data.forEach((d, i) => {
    let acc = 0;
    for (const lvl of [...LEVELS].reverse()) {
      const n = d.levels[lvl];
      if (!n) continue;
      const rect = mk("rect", { x: L + i * bw + 1, width: Math.max(bw - 2, 1), y: y(acc + n), height: y(acc) - y(acc + n), fill: levelColor(lvl) });
      rect.append(mk("title", {}, `${fmtTime(d.t)} UTC: ${n} ${lvl}`));
      svg.append(rect);
      acc += n;
    }
    if (data.length <= 24 || i % Math.ceil(data.length / 8) === 0) {
      const label = s.bucket_seconds >= 86400 ? d.t.slice(5, 10) : d.t.slice(11, 16);
      svg.append(mk("text", { x: L + i * bw + bw / 2, y: H - 6, "text-anchor": "middle" }, label));
    }
  });
  host.append(svg);
  const legend = $("#legend");
  clear(legend);
  for (const lvl of LEVELS) {
    const sw = el("span", { class: "dot" });
    sw.style.background = levelColor(lvl);
    legend.append(el("span", {}, sw, lvl));
  }
}

function renderEntities(s) {
  const ol = $("#entities");
  clear(ol);
  if (!s.top_entities.length) ol.append(el("li", { class: "empty", text: "Nothing to show." }));
  for (const e of s.top_entities) {
    ol.append(el("li", {}, el("span", {}, el("code", { text: e.entity })), el("span", {}, badge(e.worst), ` ${e.alerts}`)));
  }
}

// ---------------------------------------------------------------- alerts
let selectedId = null;

async function loadAlerts() {
  const level = $("#level").value;
  const q = $("#alert-q").value.trim();
  const rows = await api(`/api/alerts?level=${encodeURIComponent(level)}&q=${encodeURIComponent(q)}`);
  const tbody = $("#alerts-table tbody");
  clear(tbody);
  if (!rows.length) emptyRow(tbody, 5, "No alerts match.");
  for (const a of rows) {
    const group = Object.values(a.group).join(", ");
    const open = () => showDetail(a.id);
    const tr = el("tr", { tabindex: "0", "data-id": String(a.id), onclick: open,
      onkeydown: (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); open(); } } },
      el("td", {}, badge(a.level)), el("td", { text: fmtTime(a.first) }),
      el("td", {}, el("div", { text: a.title }), el("code", { class: "muted", text: a.rule })),
      el("td", { class: "num", text: String(a.count) }), el("td", {}, el("code", { text: group })));
    if (a.id === selectedId) tr.classList.add("sel");
    tbody.append(tr);
  }
  $("#alerts-note").textContent = rows.length >= 500 ? "Showing the first 500 alerts." : `${rows.length} alert(s), most severe first.`;
}

function mitreLink(tag) {
  const m = /^attack\.t(\d{4})(?:\.(\d{3}))?$/.exec(tag);
  if (!m) return el("span", { class: "chip", text: tag });
  const path = m[2] ? `${m[1]}/${m[2]}` : m[1];
  return el("a", { class: "chip", href: `https://attack.mitre.org/techniques/T${path}/`, target: "_blank", rel: "noopener noreferrer", text: tag });
}

async function showDetail(id) {
  selectedId = id;
  document.querySelectorAll("#alerts-table tbody tr").forEach((tr) => tr.classList.toggle("sel", tr.dataset.id === String(id)));
  const a = await api(`/api/alerts/${id}`);
  $("#d-title").textContent = a.title;
  $("#d-desc").textContent = a.description || "";
  const facts = $("#d-facts");
  clear(facts);
  const fact = (k, v) => facts.append(el("dt", { text: k }), el("dd", {}, v));
  fact("Level", badge(a.level));
  fact("Rule", el("code", { text: `${a.rule} (${a.kind})` }));
  fact("Window", document.createTextNode(`${fmtTime(a.first)} to ${fmtTime(a.last)} UTC`));
  fact("Triggered", document.createTextNode(`${fmtTime(a.trigger)} UTC`));
  fact("Group", el("code", { text: JSON.stringify(a.group) }));
  fact("Events", document.createTextNode(String(a.count)));
  const tags = $("#d-tags");
  clear(tags);
  a.tags.forEach((t) => tags.append(mitreLink(t)));
  const tbody = $("#d-events tbody");
  clear(tbody);
  a.events.forEach((e) => tbody.append(el("tr", {}, el("td", { text: fmtTime(e.time) }), el("td", { text: e.host }),
    el("td", {}, el("pre", { class: "raw", text: e.raw })))));
  $("#d-note").textContent = a.count > a.events_shown ? `Showing the first ${a.events_shown} of ${a.count} events.` : "";
  const panel = $("#detail");
  panel.hidden = false;
  panel.scrollIntoView({ behavior: "smooth", block: "nearest" });
}

// ---------------------------------------------------------------- events / rules
async function loadEvents() {
  const src = $("#ev-source").value;
  const q = $("#ev-q").value.trim();
  const rows = await api(`/api/events?source=${encodeURIComponent(src)}&q=${encodeURIComponent(q)}&limit=100`);
  const tbody = $("#events-table tbody");
  clear(tbody);
  if (!rows.length) emptyRow(tbody, 4, "No events match.");
  rows.forEach((e) => tbody.append(el("tr", {}, el("td", { text: fmtTime(e.time) }), el("td", { text: e.source }),
    el("td", { text: e.host }), el("td", {}, el("pre", { class: "raw", text: e.raw })))));
}

async function loadRules() {
  const rules = await api("/api/rules");
  const tbody = $("#rules-table tbody");
  clear(tbody);
  if (!rules.length) emptyRow(tbody, 5, "Rules directory not found. Start the server from the project root.");
  rules.forEach((r) => tbody.append(el("tr", {}, el("td", {}, badge(r.level)),
    el("td", {}, el("div", { text: r.title }), el("code", { class: "muted", text: r.name })),
    el("td", { text: r.type }), el("td", { text: r.description }), el("td", { class: "num", text: String(r.alerts) }))));
}

// ---------------------------------------------------------------- wiring
function debounce(fn, ms = 250) {
  let t;
  return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); };
}

function selectTab(name) {
  document.querySelectorAll(".tabs button").forEach((b) => b.setAttribute("aria-selected", String(b.dataset.tab === name)));
  for (const t of ["alerts", "events", "rules"]) $(`#tab-${t}`).hidden = t !== name;
  if (name === "events") loadEvents().catch(showError);
  if (name === "rules") loadRules().catch(showError);
}

function showError(err) {
  const note = $("#alerts-note");
  note.textContent = `Error: ${err.message}`;
}

async function init() {
  document.querySelectorAll(".tabs button").forEach((b) => b.addEventListener("click", () => selectTab(b.dataset.tab)));
  $("#level").addEventListener("change", () => loadAlerts().catch(showError));
  $("#alert-q").addEventListener("input", debounce(() => loadAlerts().catch(showError)));
  $("#ev-source").addEventListener("change", () => loadEvents().catch(showError));
  $("#ev-q").addEventListener("input", debounce(() => loadEvents().catch(showError)));
  $("#d-close").addEventListener("click", () => { $("#detail").hidden = true; selectedId = null; loadAlerts(); });
  try {
    const s = await api("/api/summary");
    renderTiles(s); renderTimeline(s); renderEntities(s);
    await loadAlerts();
  } catch (err) { showError(err); }
}
init();
