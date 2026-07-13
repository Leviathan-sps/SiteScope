// SiteScope UI — client logic. Fetches the structured report from the local
// API and renders it across separate pages (hash router), rather than one
// long scroll. No framework; small on purpose.

const $ = (id) => document.getElementById(id);
const el = (html) => { const t = document.createElement("template"); t.innerHTML = html.trim(); return t.content.firstElementChild; };

const state = { report: null, loading: false, error: null };

let history = [];
try { history = JSON.parse(localStorage.getItem("ss-history") || "[]"); } catch {}
renderHistory();

// deep scan is available on public instances too (guarded server-side:
// public targets only + rate limit), so the control stays visible.

function esc(s) {
  return String(s ?? "—").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
}
function renderHistory() {
  $("history").innerHTML = history.map((u) => `<option value="${esc(u)}">`).join("");
}

// ---------- scanning ----------

$("scan-form").addEventListener("submit", (e) => { e.preventDefault(); scan($("url-input").value.trim()); });

async function scan(url) {
  if (!url || state.loading) return;
  state.loading = true; state.error = null; state.report = null;
  $("scan-btn").disabled = true;
  $("nav").hidden = true;
  $("downloads").hidden = true;
  render();
  try {
    const qs = new URLSearchParams({ url });
    if ($("probe-input").checked) qs.set("probe", "1");
    // recon control is absent on public instances — guard against null.
    const recon = $("recon-input");
    if (recon && recon.checked) { qs.set("ports", "1"); qs.set("paths", "1"); }
    const res = await fetch("/api/analyze?" + qs);
    const data = await res.json();
    if (!res.ok) throw new Error(data.error || res.statusText);
    state.report = data;
    history = [url, ...history.filter((u) => u !== url)].slice(0, 10);
    localStorage.setItem("ss-history", JSON.stringify(history));
    renderHistory();
    $("nav").hidden = false;
    $("downloads").hidden = false;
    if (!location.hash || location.hash === "#/") location.hash = "#/overview";
  } catch (err) {
    state.error = err.message;
  } finally {
    state.loading = false;
    $("scan-btn").disabled = false;
    render();
  }
}

// ---------- downloads ----------

// idea for later: a "copy shareable link" button that copies the current
// /?url=...#/page url so a scan can be re-opened. holding off for now.
// function copyLink() {
//   navigator.clipboard.writeText(location.href);
// }

$("downloads").addEventListener("click", async (e) => {
  const fmt = e.target.dataset.dl;
  if (!fmt || !state.report) return;
  let text, mime, ext;
  if (fmt === "json") { text = JSON.stringify(state.report, null, 2); mime = "application/json"; ext = "json"; }
  else {
    const res = await fetch("/api/render?format=" + (fmt === "md" ? "md" : "html"), {
      method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(state.report),
    });
    text = await res.text(); mime = fmt === "md" ? "text/markdown" : "text/html"; ext = fmt;
  }
  let host = "report";
  try { host = new URL(state.report.meta.finalUrl).hostname; } catch {}
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([text], { type: mime }));
  a.download = `sitescope-${host}.${ext}`;
  a.click();
  URL.revokeObjectURL(a.href);
});

// ---------- router ----------

const PAGES = {
  overview: pageOverview,
  technologies: pageTech,
  infrastructure: pageInfra,
  security: pageSecurity,
  cookies: pageCookies,
  seo: pageSeo,
  network: pageNetwork,
  performance: pagePerformance,
  crawlability: pageCrawlability,
};

window.addEventListener("hashchange", render);

function currentPage() {
  const m = location.hash.match(/^#\/(\w+)/);
  return m && PAGES[m[1]] ? m[1] : "overview";
}

function render() {
  const main = $("main");
  if (state.loading) {
    main.innerHTML = "";
    main.appendChild(el(`<div class="stage"><div class="spinner"></div><p>Fetching and analyzing…</p></div>`));
    return;
  }
  if (state.error) {
    main.innerHTML = "";
    main.appendChild(el(`<div class="stage"><span class="mark">🛑</span><h1>Couldn't scan that</h1><p class="err">${esc(state.error)}</p></div>`));
    return;
  }
  if (!state.report) { renderLanding(); return; }

  const page = currentPage();
  for (const a of document.querySelectorAll("#nav a")) a.classList.toggle("active", a.dataset.page === page);
  main.innerHTML = "";
  main.appendChild(PAGES[page](state.report));
  main.scrollTop = 0;
}

function renderLanding() {
  const main = $("main");
  main.innerHTML = "";
  main.appendChild(el(`
    <div class="stage">
      <span class="mark">🔭</span>
      <h1>What's it built with?</h1>
      <p>Point SiteScope at any URL. One fetch tells you the tech stack, how secure its
         headers and cookies are, how well it's tuned for search, and every resource it loads.</p>
      <div class="examples">
        try
        <button data-ex="vercel.com">vercel.com</button>
        <button data-ex="github.com">github.com</button>
        <button data-ex="news.ycombinator.com">news.ycombinator.com</button>
      </div>
    </div>`));
  main.querySelectorAll("[data-ex]").forEach((b) =>
    b.addEventListener("click", () => { $("url-input").value = b.dataset.ex; scan(b.dataset.ex); }));
}

// ---------- helpers ----------

const scoreClass = (n) => (n >= 80 ? "good" : n >= 60 ? "mid" : "poor");
const gradeGood = (g) => (g === "A" || g === "B" ? "good" : g === "C" ? "mid" : "poor");
function head(title, lead) { return `<div class="page-head"><h1>${esc(title)}</h1><p class="lead">${esc(lead)}</p></div>`; }
function fmtBytes(n) {
  if (!n && n !== 0) return "—";
  const u = ["B", "KB", "MB", "GB"]; let i = 0;
  while (n >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(i ? 1 : 0)} ${u[i]}`;
}

// ---------- pages ----------

function pageOverview(r) {
  const wrap = document.createElement("div");
  const secGrade = r.headers.grade;
  const cookieFlags = r.cookies.issues.length;
  const score = r.score;
  wrap.innerHTML =
    head("Overview", `${r.meta.finalUrl} — status ${r.meta.status}, ${fmtBytes(r.meta.bytes)}, ${r.meta.elapsedMs}ms${r.meta.redirected ? ", redirected" : ""}.`) +
    `<div class="tiles">
      ${score && score.score != null ? `<div class="tile grade-${String(score.grade).toLowerCase()}"><div class="n">${esc(score.grade)}</div><div class="l">overall health (${score.score}/100)</div></div>` : ""}
      <a class="tile" href="#/technologies"><div class="n">${r.frameworks.length}</div><div class="l">technologies</div></a>
      <a class="tile grade-${secGrade.toLowerCase()}" href="#/security"><div class="n">${esc(secGrade)}</div><div class="l">security grade</div></a>
      <a class="tile" href="#/cookies"><div class="n ${cookieFlags ? "mid" : "good"}">${r.cookies.count}</div><div class="l">cookies${cookieFlags ? ` · ${cookieFlags} flags` : ""}</div></a>
      <a class="tile" href="#/seo"><div class="n ${scoreClass(r.seo.score)}">${r.seo.score}</div><div class="l">SEO score</div></a>
      <a class="tile" href="#/network"><div class="n">${r.network.total}</div><div class="l">resources</div></a>
      ${r.performance ? `<a class="tile" href="#/performance"><div class="n ${scoreClass(r.performance.score)}">${r.performance.score}</div><div class="l">performance</div></a>` : ""}
      ${r.crawl ? `<a class="tile" href="#/crawlability"><div class="n ${scoreClass(r.crawl.score)}">${r.crawl.score}</div><div class="l">crawlability</div></a>` : ""}
    </div>
    ${score && score.topIssues.length ? `
    <div class="card warn">
      <h2>Top issues</h2>
      <ul class="checks">${score.topIssues.map((i) => `<li class="flag">[${esc(i.source)}] ${esc(i.label)}</li>`).join("")}</ul>
    </div>` : ""}
    <div class="card accent">
      <h2>At a glance</h2>
      <dl class="kv">
        <dt>Final URL</dt><dd class="mono">${esc(r.meta.finalUrl)}</dd>
        <dt>Server</dt><dd>${esc(r.headers.server.server)}</dd>
        <dt>Powered by</dt><dd>${esc(r.headers.server.poweredBy)}</dd>
        <dt>Compression</dt><dd>${esc(r.headers.transfer.contentEncoding)}</dd>
        <dt>Top technology</dt><dd>${r.frameworks[0] ? esc(r.frameworks[0].name) + (r.frameworks[0].version ? " " + esc(r.frameworks[0].version) : "") : "—"}</dd>
        <dt>IP address</dt><dd class="mono">${esc(r.infra && r.infra.primaryIp)}</dd>
        <dt>Hosted by</dt><dd>${r.infra && r.infra.geo ? esc(r.infra.geo.org || r.infra.geo.isp) : '<span class="dim">—</span>'}${r.infra && r.infra.geo && r.infra.geo.country ? ` <span class="dim">· ${esc(r.infra.geo.country)}</span>` : ""}</dd>
        <dt>Third-party hosts</dt><dd>${r.network.thirdPartyHosts.length}</dd>
      </dl>
    </div>`;
  return wrap;
}

function pageTech(r) {
  const wrap = document.createElement("div");
  const rows = r.frameworks.map((f) => `
    <tr>
      <td><strong>${esc(f.name)}</strong></td>
      <td class="dim mono">${esc(f.version || "—")}</td>
      <td class="dim">${esc(f.category)}</td>
      <td><span class="chip conf-${esc(f.confidence)}">${esc(f.confidence)}</span></td>
      <td class="dim">${esc(f.evidence.join("; "))}</td>
    </tr>`).join("");
  wrap.innerHTML =
    head("Technologies", "Frameworks, platforms and infrastructure inferred from the HTML and response headers — each with the evidence that triggered it.") +
    `<div class="card">
      ${r.frameworks.length
        ? `<table><thead><tr><th>Technology</th><th>Version</th><th>Category</th><th>Confidence</th><th>Evidence</th></tr></thead><tbody>${rows}</tbody></table>`
        : `<p class="dim">Nothing detected. Client-only SPAs that render in JavaScript often look empty to a single fetch.</p>`}
    </div>`;
  return wrap;
}

function pageInfra(r) {
  const wrap = document.createElement("div");
  const inf = r.infra || {};
  const geo = inf.geo;
  const rec = r.recon || {};

  const ipCard = `
    <div class="card accent">
      <h2>Where it lives</h2>
      <dl class="kv">
        <dt>IP address</dt><dd class="mono">${esc(inf.primaryIp)}</dd>
        <dt>Reverse DNS</dt><dd class="mono">${esc(inf.reverse)}</dd>
        ${geo ? `<dt>Hosted by</dt><dd>${esc(geo.org || geo.isp)} ${geo.asn ? `<span class="dim">(${esc(geo.asn)})</span>` : ""}</dd>
        <dt>Location</dt><dd>${geo.flag ? geo.flag + " " : ""}${esc([geo.city, geo.region, geo.country].filter(Boolean).join(", ") || "—")}</dd>
        <dt>Timezone</dt><dd>${esc(geo.timezone)}</dd>` : `<dt>Hosting</dt><dd class="dim">geo lookup unavailable</dd>`}
      </dl>
    </div>`;

  const dnsCard = `
    <div class="card">
      <h2>DNS records</h2>
      <dl class="kv">
        <dt>All addresses</dt><dd class="mono">${(inf.addresses || []).map((a) => esc(a.ip)).join("<br>") || "—"}</dd>
        <dt>Nameservers</dt><dd class="mono">${(inf.ns || []).map(esc).join("<br>") || "—"}</dd>
        <dt>Mail (MX)</dt><dd class="mono">${(inf.mx || []).map(esc).join("<br>") || "—"}</dd>
      </dl>
    </div>`;

  // Active recon — only present if the user opted into a deep scan.
  let portsCard, pathsCard;
  if (rec.ports) {
    const p = rec.ports;
    const rows = p.open.map((port) =>
      `<tr><td class="mono">${port.port}</td><td>${esc(port.name)}</td><td class="dim">${esc(port.note)}</td><td>${port.sensitive ? '<span class="chip bad">exposed</span>' : '<span class="chip ok">open</span>'}</td></tr>`).join("");
    portsCard = `
      <div class="card ${p.exposedSensitive.length ? "bad" : "ok"}">
        <h2>Open ports <span class="hint">(${p.open.length} of ${p.scanned} common ports)</span></h2>
        ${p.open.length ? `<table><thead><tr><th>Port</th><th>Service</th><th>Note</th><th></th></tr></thead><tbody>${rows}</tbody></table>` : `<p class="pass">No common service ports responded.</p>`}
        ${p.exposedSensitive.length ? `<div class="flag bad" style="margin-top:10px">${p.exposedSensitive.length} sensitive service(s) reachable from the internet — ${esc(p.exposedSensitive.map((x) => x.name).join(", "))}</div>` : ""}
      </div>`;
  }
  if (rec.paths) {
    const pp = rec.paths;
    const rows = pp.present.map((r2) => {
      const cls = r2.kind === "sensitive" && r2.status < 400 ? "bad" : r2.status < 400 ? "ok" : "warn";
      return `<tr><td><span class="chip ${cls}">${r2.status}</span></td><td class="mono">${esc(r2.path)}</td><td class="dim">${esc(r2.kind)}</td></tr>`;
    }).join("");
    pathsCard = `
      <div class="card ${pp.exposedSensitive.length ? "bad" : ""}">
        <h2>Path discovery <span class="hint">(${pp.found.length} found of ${pp.checked} probed)</span></h2>
        ${pp.present.length ? `<table><thead><tr><th>Status</th><th>Path</th><th>Kind</th></tr></thead><tbody>${rows}</tbody></table>` : `<p class="dim">None of the probed paths were reachable.</p>`}
        ${pp.exposedSensitive.length ? `<div class="flag bad" style="margin-top:10px">${pp.exposedSensitive.length} sensitive path(s) publicly reachable — review immediately.</div>` : ""}
      </div>`;
  }

  const reconBlock = (portsCard || pathsCard)
    ? (portsCard || "") + (pathsCard || "")
    : `<div class="notice">Tick <strong>deep scan</strong> before scanning to check open ports and probe common paths on the host.
       Active scanning sends real traffic — only run it against sites you own or are authorized to test.</div>`;

  wrap.innerHTML =
    head("Infrastructure", "Where the site is hosted and how it resolves — plus optional active checks of open ports and interesting paths.") +
    ipCard + dnsCard + reconBlock;
  return wrap;
}

function pageSecurity(r) {
  const wrap = document.createElement("div");
  const h = r.headers;
  const band = gradeGood(h.grade); // good / mid / poor
  const present = h.security.filter((s) => s.status === "ok").length;

  // one row per header: a leading mark, the header name, then the note
  const rows = h.security.map((s) => {
    const mark = s.status === "ok"
      ? '<span class="yn yes">✓</span>'
      : s.status === "weak"
        ? '<span class="yn warn">▲</span>'
        : '<span class="yn no">✕</span>';
    const word = s.status === "ok" ? "present" : s.status === "weak" ? "weak" : "missing";
    return `<tr>
      <td class="ic">${mark}</td>
      <td><strong>${esc(s.label)}</strong></td>
      <td class="dim">${esc(s.note || word)}</td>
    </tr>`;
  }).join("");

  wrap.innerHTML =
    head("Security headers", "The six headers that most affect how safely a browser treats the page, graded and weighted.") +
    `<div class="card g-${band}">
      <div class="grade-banner">
        <div class="badge">${esc(h.grade)}</div>
        <div class="meat">
          <div class="score-line"><strong>${h.score}</strong><span class="dim">/100</span> · ${present} of ${h.security.length} headers in place</div>
          <div class="meter"><i class="${scoreClass(h.score)}" style="width:${h.score}%"></i></div>
        </div>
      </div>
    </div>
    <div class="card">
      <h2>Header by header</h2>
      <table class="rows"><tbody>${rows}</tbody></table>
    </div>
    <div class="card">
      <h2>Server &amp; transfer</h2>
      <dl class="kv">
        <dt>Server</dt><dd>${esc(h.server.server)}</dd>
        <dt>X-Powered-By</dt><dd>${esc(h.server.poweredBy)}</dd>
        <dt>Via</dt><dd>${esc(h.server.via)}</dd>
        <dt>Compression</dt><dd>${esc(h.transfer.contentEncoding)}</dd>
        <dt>Cache-Control</dt><dd class="mono">${esc(h.caching.cacheControl)}</dd>
        <dt>ETag</dt><dd class="mono">${esc(h.caching.etag)}</dd>
      </dl>
    </div>`;
  return wrap;
}

function pageCookies(r) {
  const wrap = document.createElement("div");
  const c = r.cookies;
  const secure = c.cookies.filter((ck) => ck.secure).length;
  // small check/cross so a long cookie table doesn't turn into a wall of pills
  const yes = '<span class="yn yes">✓</span>';
  const no = '<span class="yn no">✕</span>';
  const meh = '<span class="yn warn">✕</span>';

  const rows = c.cookies.map((ck) => `
    <tr>
      <td class="mono">${esc(ck.name)}</td>
      <td class="ic">${ck.secure ? yes : no}</td>
      <td class="ic">${ck.httpOnly ? yes : meh}</td>
      <td>${ck.sameSite ? `<span class="chip mute">${esc(ck.sameSite)}</span>` : '<span class="yn warn">unset</span>'}</td>
      <td class="dim mono">${esc(ck.domain || "—")}</td>
    </tr>`).join("");

  const summary = c.count
    ? `<div class="tiles compact">
        <div class="tile"><div class="n">${c.count}</div><div class="l">cookies</div></div>
        <div class="tile"><div class="n ${secure === c.count ? "good" : "mid"}">${secure}/${c.count}</div><div class="l">marked secure</div></div>
        <div class="tile"><div class="n ${c.issues.length ? "mid" : "good"}">${c.issues.length}</div><div class="l">flags</div></div>
      </div>`
    : "";

  wrap.innerHTML =
    head("Cookies", "Every Set-Cookie on the response, with its security attributes. Values are masked.") +
    summary +
    (c.count
      ? `<div class="card"><table class="cookie-table"><thead><tr><th>Name</th><th>Secure</th><th>HttpOnly</th><th>SameSite</th><th>Domain</th></tr></thead><tbody>${rows}</tbody></table></div>`
      : `<div class="card"><p class="dim">No cookies set on the initial response.</p></div>`) +
    (c.issues.length
      ? `<div class="card warn"><h2>${c.issues.length} flag${c.issues.length > 1 ? "s" : ""}</h2>${c.issues.map((i) => `<div class="flag">${esc(i)}</div>`).join("")}</div>`
      : c.count ? `<div class="card ok"><p class="pass">No cookie issues found.</p></div>` : "");
  return wrap;
}

// idea for later: a session-vs-persistent split in the summary strip.
// function cookieLifetimes(list) {
//   const session = list.filter((ck) => !ck.expires && !ck.maxAge).length;
//   return { session, persistent: list.length - session };
// }

function pageSeo(r) {
  const wrap = document.createElement("div");
  const s = r.seo;
  const checks = s.checks.map((c) => `<li class="${c.pass ? "pass" : "flag"}">${esc(c.label)}</li>`).join("");
  wrap.innerHTML =
    head("SEO & metadata", "On-page signals a crawler reads: title, description, canonical, headings, images, links and social cards.") +
    `<div class="card ${scoreClass(s.score) === "good" ? "ok" : scoreClass(s.score) === "mid" ? "warn" : "bad"}">
      <h2>${s.score}/100</h2>
      <div class="meter"><i class="${scoreClass(s.score)}" style="width:${s.score}%"></i></div>
    </div>
    <div class="card">
      <h2>Metadata</h2>
      <dl class="kv">
        <dt>Title</dt><dd>${esc(s.title)}</dd>
        <dt>Description</dt><dd>${esc(s.metaDescription)}</dd>
        <dt>Canonical</dt><dd class="mono">${esc(s.canonical)}</dd>
        <dt>Lang</dt><dd>${esc(s.lang)}</dd>
        <dt>Viewport</dt><dd>${esc(s.viewport)}</dd>
        <dt>Headings</dt><dd>h1:${s.headings.h1} · h2:${s.headings.h2} · h3:${s.headings.h3}</dd>
        <dt>Images</dt><dd>${s.images.total} total, ${s.images.missingAlt} missing alt</dd>
        <dt>Links</dt><dd>${s.links.internal} internal · ${s.links.external} external</dd>
        <dt>Open Graph</dt><dd>${s.openGraph.length} tags</dd>
        <dt>Twitter card</dt><dd>${s.twitter.length} tags</dd>
      </dl>
    </div>
    <div class="card"><h2>Checks</h2><ul class="checks">${checks}</ul></div>`;
  return wrap;
}

function pageNetwork(r) {
  const wrap = document.createElement("div");
  const n = r.network;
  const typeRows = Object.entries(n.byType).map(([t, c]) => `<tr><td>${esc(t)}</td><td class="num">${c}</td></tr>`).join("");
  const hostRows = Object.entries(n.byHost).slice(0, 12).map(([h, c]) =>
    `<tr><td class="mono">${esc(h)}</td><td>${h === safeHost(n) ? '<span class="chip mute">first-party</span>' : '<span class="chip warn">third-party</span>'}</td><td class="num">${c}</td></tr>`).join("");
  wrap.innerHTML =
    head("Network resources", `${n.total} sub-resources referenced by the page — ${n.firstParty} first-party, ${n.thirdParty} third-party across ${n.thirdPartyHosts.length} hosts.`) +
    `<div class="tiles">
      <div class="tile"><div class="n">${n.firstParty}</div><div class="l">first-party</div></div>
      <div class="tile"><div class="n ${n.thirdParty ? "mid" : "good"}">${n.thirdParty}</div><div class="l">third-party</div></div>
      <div class="tile"><div class="n">${n.thirdPartyHosts.length}</div><div class="l">external hosts</div></div>
      ${n.probed ? `<div class="tile"><div class="n">${fmtBytes(n.probed.totalBytes)}</div><div class="l">~sampled weight</div></div>` : ""}
    </div>
    <div class="card"><h2>By type</h2><table><thead><tr><th>Type</th><th class="num">Count</th></tr></thead><tbody>${typeRows}</tbody></table></div>
    <div class="card"><h2>By host <span class="hint">(top 12)</span></h2><table><thead><tr><th>Host</th><th>Party</th><th class="num">Count</th></tr></thead><tbody>${hostRows}</tbody></table></div>
    ${n.probed ? `<div class="notice">Probed ${n.probed.sampled} resources with HEAD requests for real sizes and status.</div>` : `<div class="notice">Tip: enable “probe sizes” to HEAD-request each resource for real byte sizes and status codes.</div>`}`;
  return wrap;
}

function pagePerformance(r) {
  const wrap = document.createElement("div");
  const p = r.performance;
  const checks = p.checks.map((c) => `<li class="${c.pass ? "pass" : "flag"}">${esc(c.label)}</li>`).join("");
  const byteRows = p.bytes
    ? Object.entries(p.bytes.byType).map(([t, n]) => `<tr><td>${esc(t)}</td><td class="num">${fmtBytes(n)}</td></tr>`).join("")
    : "";
  wrap.innerHTML =
    head("Performance budget", "Static checks against the resource map — no headless browser, so these are rule-of-thumb budgets rather than real load timing.") +
    `<div class="card ${scoreClass(p.score) === "good" ? "ok" : scoreClass(p.score) === "mid" ? "warn" : "bad"}">
      <h2>${p.score}/100</h2>
      <div class="meter"><i class="${scoreClass(p.score)}" style="width:${p.score}%"></i></div>
    </div>
    <div class="card">
      <h2>Budget</h2>
      <dl class="kv">
        <dt>Requests</dt><dd>${p.requests}</dd>
        <dt>Scripts</dt><dd>${p.jsCount}</dd>
        <dt>Stylesheets</dt><dd>${p.cssCount}</dd>
        <dt>Images</dt><dd>${p.imageCount}</dd>
        <dt>Fonts</dt><dd>${p.fontCount}</dd>
        <dt>Third-party hosts</dt><dd>${p.thirdPartyHosts}</dd>
        <dt>Render-blocking scripts</dt><dd>${p.renderBlockingScripts}</dd>
        ${p.bytes ? `<dt>Total weight</dt><dd>${fmtBytes(p.bytes.total)}</dd>` : ""}
      </dl>
    </div>
    ${p.bytes ? `<div class="card"><h2>Weight by type</h2><table><thead><tr><th>Type</th><th class="num">Bytes</th></tr></thead><tbody>${byteRows}</tbody></table></div>` : `<div class="notice">Tip: enable "probe sizes" before scanning to get real byte-weight budgets, not just resource counts.</div>`}
    <div class="card"><h2>Checks</h2><ul class="checks">${checks}</ul></div>`;
  return wrap;
}

function pageCrawlability(r) {
  const wrap = document.createElement("div");
  const cr = r.crawl;
  const checks = cr.checks.map((c) => `<li class="${c.pass ? "pass" : "flag"}">${esc(c.label)}</li>`).join("");
  wrap.innerHTML =
    head("Crawlability", "Whether robots.txt and a sitemap exist, and whether the page just scanned is actually allowed to be crawled.") +
    `<div class="card ${scoreClass(cr.score) === "good" ? "ok" : scoreClass(cr.score) === "mid" ? "warn" : "bad"}">
      <h2>${cr.score}/100</h2>
      <div class="meter"><i class="${scoreClass(cr.score)}" style="width:${cr.score}%"></i></div>
    </div>
    <div class="card">
      <h2>robots.txt</h2>
      <dl class="kv">
        <dt>Found</dt><dd>${cr.robotsTxt.present ? '<span class="chip ok">yes</span>' : '<span class="chip bad">no</span>'}</dd>
        ${cr.robotsTxt.present ? `
        <dt>Blocks entire site</dt><dd>${cr.robotsTxt.disallowsAll ? '<span class="chip bad">yes</span>' : '<span class="chip ok">no</span>'}</dd>
        <dt>Scanned page allowed</dt><dd>${cr.robotsTxt.currentPathDisallowed ? '<span class="chip bad">no</span>' : '<span class="chip ok">yes</span>'}</dd>
        <dt>Declared sitemaps</dt><dd>${cr.robotsTxt.sitemaps.length}</dd>` : ""}
      </dl>
    </div>
    <div class="card">
      <h2>Sitemap</h2>
      <dl class="kv">
        <dt>Found</dt><dd>${cr.sitemap.present ? '<span class="chip ok">yes</span>' : '<span class="chip bad">no</span>'}</dd>
        ${cr.sitemap.present ? `
        <dt>URL</dt><dd class="mono">${esc(cr.sitemap.url)}</dd>
        <dt>Type</dt><dd>${cr.sitemap.isIndex ? "sitemap index" : "urlset"}</dd>
        <dt>${cr.sitemap.isIndex ? "Child sitemaps" : "URLs listed"}</dt><dd>${cr.sitemap.urlCount ?? "—"}</dd>
        ${cr.sitemap.isIndex ? `<dt>Sampled URLs (first child)</dt><dd>${cr.sitemap.sampledChildUrlCount ?? "—"}</dd>` : ""}` : ""}
      </dl>
    </div>
    <div class="card"><h2>Checks</h2><ul class="checks">${checks}</ul></div>`;
  return wrap;
}

function safeHost(n) {
  // First-party host = the one with the most resources is a decent proxy,
  // but derive from the report meta when possible.
  try { return new URL(state.report.meta.finalUrl).host; } catch { return ""; }
}

// Deep-link support: /?url=example.com#/security auto-runs the scan on load,
// so a report view is shareable and bookmarkable.
const boot = new URLSearchParams(location.search).get("url");
if (boot) {
  $("url-input").value = boot;
  scan(boot);
} else {
  render();
}
