// renders an analysis into one of these formats:
//   - terminal  (colorized, for the cli)
//   - markdown  (for sharing / docs / github)
//   - html      (self-contained standalone report)
//   - json      (the raw analysis object)

import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const REPORT_CSS = readFileSync(join(dirname(fileURLToPath(import.meta.url)), "report.css"), "utf8");

const C = {
  reset: "\x1b[0m",
  bold: "\x1b[1m",
  dim: "\x1b[2m",
  red: "\x1b[31m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  blue: "\x1b[34m",
  cyan: "\x1b[36m",
  gray: "\x1b[90m",
};

function color(enabled) {
  if (enabled) return C;
  // no-op palette when colors are off (piped output, --no-color)
  return Object.fromEntries(Object.keys(C).map((k) => [k, ""]));
}

// a csv exporter would be a handy fifth format
// export function renderCsv(report) { ... }

// ----------------------------- TERMINAL -----------------------------

export function renderTerminal(report, { color: useColor = true } = {}) {
  const c = color(useColor);
  const lines = [];
  const h = (s) => lines.push(`\n${c.bold}${c.cyan}${s}${c.reset}`);
  const kv = (k, v) => lines.push(`  ${c.dim}${k.padEnd(16)}${c.reset} ${v ?? c.gray + "—" + c.reset}`);

  lines.push(`${c.bold}SiteScope report${c.reset} ${c.gray}— ${report.meta.finalUrl}${c.reset}`);
  lines.push(
    `${c.gray}status ${statusColor(c, report.meta.status)} · ${report.meta.bytes} bytes · ${report.meta.elapsedMs}ms${report.meta.redirected ? " · redirected" : ""}${c.reset}`
  );

  if (report.score && report.score.score != null) {
    lines.push(`${c.bold}Overall health  ${c.reset}${gradeColor(c, report.score.grade)} ${report.score.grade} (${report.score.score}/100)${c.reset}`);
  }

  h("⚙  Technologies");
  if (!report.frameworks.length) lines.push(`  ${c.gray}none detected${c.reset}`);
  for (const f of report.frameworks) {
    const conf = f.confidence === "high" ? c.green : f.confidence === "medium" ? c.yellow : c.gray;
    const name = f.version ? `${f.name} ${f.version}` : f.name;
    lines.push(
      `  ${c.bold}${name.padEnd(18)}${c.reset} ${c.dim}${f.category.padEnd(16)}${c.reset} ${conf}${f.confidence}${c.reset} ${c.gray}(${f.evidence[0]})${c.reset}`
    );
  }

  h(`🔒 Security headers  ${gradeColor(c, report.headers.grade)} ${report.headers.grade} (${report.headers.score}/100)`);
  for (const s of report.headers.security) {
    const icon = s.status === "ok" ? `${c.green}✔${c.reset}` : s.status === "weak" ? `${c.yellow}▲${c.reset}` : `${c.red}✘${c.reset}`;
    lines.push(`  ${icon} ${s.label}${s.note ? c.gray + " — " + s.note + c.reset : ""}`);
  }

  if (report.vulns) {
    const v = report.vulns;
    h(`🛡  Vulnerabilities  ${riskColor(c, v.risk)} ${v.risk} (${v.total})`);
    if (!v.total) {
      lines.push(`  ${c.gray}nothing obvious — passive check only, not a full scan${c.reset}`);
    }
    for (const f of v.findings) {
      const sev = sevColor(c, f.severity);
      lines.push(`  ${sevIcon(f.severity)} ${sev}${f.severity.toUpperCase().padEnd(9)}${c.reset} ${c.bold}${f.title}${c.reset}${f.cve ? c.gray + " · " + f.cve + c.reset : ""}`);
      lines.push(`     ${c.gray}${f.detail}${c.reset}`);
    }
  }

  h("🖥  Server");
  kv("Server", report.headers.server.server);
  kv("X-Powered-By", report.headers.server.poweredBy);
  kv("Compression", report.headers.transfer.contentEncoding);
  kv("Cache-Control", report.headers.caching.cacheControl);

  if (report.infra) {
    const inf = report.infra;
    h("🌍 Infrastructure");
    kv("IP address", inf.primaryIp);
    kv("Reverse DNS", inf.reverse);
    if (inf.addresses.length > 1) kv("All IPs", inf.addresses.map((a) => a.ip).join(", "));
    if (inf.geo) {
      kv("Hosted by", inf.geo.org || inf.geo.isp);
      kv("ASN", inf.geo.asn);
      kv("Location", [inf.geo.city, inf.geo.region, inf.geo.country].filter(Boolean).join(", ") || null);
    }
    if (inf.ns.length) kv("Nameservers", inf.ns.slice(0, 3).join(", "));
    if (inf.mx.length) kv("Mail (MX)", inf.mx.slice(0, 3).join(", "));
  }

  if (report.tls && report.tls.reachable) {
    const t = report.tls;
    h(`🔐 TLS certificate  ${scoreColor(c, t.score)} ${t.score}/100`);
    kv("Issued to", t.subject);
    kv("Issued by", t.issuer);
    kv("Expires", t.validTo ? `${t.validTo.slice(0, 10)} (${t.daysLeft} days)` : null);
    kv("Protocol", t.protocol);
    kv("Cipher", t.cipher);
    if (t.names.length > 1) kv("Also covers", `${t.names.length} names`);
    for (const ch of t.checks.filter((c2) => !c2.pass)) lines.push(`  ${c.red}✘ ${ch.label}${c.reset}`);
  }

  if (report.recon && report.recon.ports) {
    const p = report.recon.ports;
    h(`🔌 Open ports (${p.open.length}/${p.scanned})`);
    if (!p.open.length) lines.push(`  ${c.gray}no common ports responded${c.reset}`);
    for (const port of p.open) {
      const mark = port.sensitive ? `${c.red}!${c.reset}` : `${c.green}•${c.reset}`;
      lines.push(`  ${mark} ${String(port.port).padEnd(6)} ${c.bold}${port.name.padEnd(14)}${c.reset} ${c.gray}${port.note}${c.reset}`);
    }
    if (p.exposedSensitive.length) lines.push(`  ${c.yellow}▲ ${p.exposedSensitive.length} sensitive service(s) reachable from the internet${c.reset}`);
  }

  if (report.recon && report.recon.paths) {
    const pp = report.recon.paths;
    h(`🗂  Path discovery (${pp.found.length} found / ${pp.checked} checked)`);
    for (const r of pp.present) {
      const col = r.kind === "sensitive" && r.status < 400 ? c.red : r.status < 400 ? c.green : c.yellow;
      lines.push(`  ${col}${String(r.status).padEnd(4)}${c.reset} ${r.path}`);
    }
    if (pp.exposedSensitive.length) lines.push(`  ${c.red}✘ ${pp.exposedSensitive.length} sensitive path(s) publicly reachable — review these${c.reset}`);
  }

  if (report.recon && report.recon.subs) {
    const sd = report.recon.subs;
    h(`🌐 Subdomains (${sd.found.length} found / ${sd.checked} checked)`);
    if (sd.wildcard) {
      lines.push(`  ${c.gray}wildcard dns — every name resolves, so guessing tells us nothing${c.reset}`);
    } else if (!sd.found.length) {
      lines.push(`  ${c.gray}none of the common names resolved${c.reset}`);
    }
    for (const s of sd.found) {
      const col = s.kind === "sensitive" ? c.red : s.kind === "surface" ? c.yellow : c.green;
      lines.push(`  ${col}•${c.reset} ${c.bold}${s.fqdn}${c.reset} ${c.gray}${s.addresses[0]}${s.cname ? " → " + s.cname : ""}${c.reset}`);
    }
    if (sd.exposedSensitive.length) lines.push(`  ${c.yellow}▲ ${sd.exposedSensitive.length} non-production name(s) publicly resolvable${c.reset}`);
  }

  h(`🍪 Cookies (${report.cookies.count})`);
  for (const ck of report.cookies.cookies) {
    const flags = [ck.secure && "Secure", ck.httpOnly && "HttpOnly", ck.sameSite && `SameSite=${ck.sameSite}`].filter(Boolean).join(", ");
    lines.push(`  ${c.bold}${ck.name}${c.reset} ${c.gray}${flags || "no flags"}${c.reset}`);
  }
  for (const issue of report.cookies.issues) lines.push(`  ${c.yellow}▲ ${issue}${c.reset}`);

  h(`🔍 SEO  ${scoreColor(c, report.seo.score)} ${report.seo.score}/100`);
  kv("Title", report.seo.title);
  kv("Description", report.seo.metaDescription);
  kv("Canonical", report.seo.canonical);
  kv("Headings", `h1:${report.seo.headings.h1} h2:${report.seo.headings.h2} h3:${report.seo.headings.h3}`);
  kv("Images", `${report.seo.images.total} (${report.seo.images.missingAlt} missing alt)`);
  kv("Links", `${report.seo.links.internal} internal · ${report.seo.links.external} external`);
  kv("Open Graph", report.seo.openGraph.length ? `${report.seo.openGraph.length} tags` : null);
  for (const ch of report.seo.checks.filter((c2) => !c2.pass)) lines.push(`  ${c.yellow}▲ ${ch.label}${c.reset}`);

  h(`🌐 Network resources (${report.network.total})`);
  kv("First-party", String(report.network.firstParty));
  kv("Third-party", `${report.network.thirdParty} from ${report.network.thirdPartyHosts.length} hosts`);
  lines.push(`  ${c.dim}by type:${c.reset} ${Object.entries(report.network.byType).map(([t, n]) => `${t}:${n}`).join("  ")}`);
  if (report.network.probed) {
    lines.push(`  ${c.dim}sampled ${report.network.probed.sampled} resources · ~${formatBytes(report.network.probed.totalBytes)}${c.reset}`);
  }
  const topHosts = Object.entries(report.network.byHost).slice(0, 5);
  for (const [host, n] of topHosts) lines.push(`  ${c.gray}${String(n).padStart(3)}× ${host}${c.reset}`);

  if (report.performance) {
    const p = report.performance;
    h(`⚡ Performance budget  ${scoreColor(c, p.score)} ${p.score}/100`);
    kv("Requests", String(p.requests));
    kv("Scripts / styles", `${p.jsCount} / ${p.cssCount}`);
    kv("Third-party hosts", String(p.thirdPartyHosts));
    if (p.bytes) kv("Total weight", formatBytes(p.bytes.total));
    for (const ch of p.checks.filter((c2) => !c2.pass)) lines.push(`  ${c.yellow}▲ ${ch.label}${c.reset}`);
  }

  if (report.crawl) {
    const cr = report.crawl;
    h(`🤖 Crawlability  ${scoreColor(c, cr.score)} ${cr.score}/100`);
    kv("robots.txt", cr.robotsTxt.present ? "found" : "not found");
    if (cr.sitemap.present) {
      kv("Sitemap", cr.sitemap.isIndex ? `index (${cr.sitemap.urlCount} sitemaps, ~${cr.sitemap.sampledChildUrlCount ?? "?"} urls sampled)` : `${cr.sitemap.urlCount} URLs`);
    } else {
      kv("Sitemap", "not found");
    }
    for (const ch of cr.checks.filter((c2) => !c2.pass)) lines.push(`  ${c.yellow}▲ ${ch.label}${c.reset}`);
  }

  return lines.join("\n") + "\n";
}

// ----------------------------- MARKDOWN -----------------------------

export function renderMarkdown(report) {
  const L = [];
  L.push(`# SiteScope report — ${report.meta.finalUrl}`);
  L.push("");
  L.push(`> status \`${report.meta.status}\` · ${report.meta.bytes} bytes · ${report.meta.elapsedMs}ms · generated ${report.meta.generatedAt}`);
  L.push("");

  if (report.score && report.score.score != null) {
    L.push(`## Overall health — ${report.score.grade} (${report.score.score}/100)`);
    if (report.score.topIssues.length) {
      L.push("");
      L.push("**Top issues:**");
      for (const i of report.score.topIssues) L.push(`- [${i.source}] ${i.label}`);
    }
    L.push("");
  }

  L.push("## ⚙️ Technologies");
  if (!report.frameworks.length) L.push("_None detected._");
  else {
    L.push("| Technology | Version | Category | Confidence | Evidence |");
    L.push("|---|---|---|---|---|");
    for (const f of report.frameworks) L.push(`| **${f.name}** | ${f.version || "—"} | ${f.category} | ${f.confidence} | ${f.evidence.join("; ")} |`);
  }
  L.push("");

  L.push(`## 🔒 Security headers — grade ${report.headers.grade} (${report.headers.score}/100)`);
  L.push("| Header | Status | Note |");
  L.push("|---|---|---|");
  for (const s of report.headers.security) {
    const icon = s.status === "ok" ? "✅" : s.status === "weak" ? "⚠️" : "❌";
    L.push(`| ${s.label} | ${icon} ${s.status} | ${s.note || ""} |`);
  }
  L.push("");
  L.push(`**Server:** ${report.headers.server.server || "—"}  ·  **Powered by:** ${report.headers.server.poweredBy || "—"}  ·  **Compression:** ${report.headers.transfer.contentEncoding || "—"}`);
  L.push("");

  if (report.vulns) {
    const v = report.vulns;
    L.push(`## 🛡️ Vulnerabilities — ${v.risk} risk (${v.total})`);
    if (v.total) {
      L.push("| Severity | Finding | CVE | Fix |");
      L.push("|---|---|---|---|");
      for (const f of v.findings) L.push(`| ${sevIcon(f.severity)} ${f.severity} | ${f.title} — ${f.detail} | ${f.cve || "—"} | ${f.recommendation} |`);
    } else {
      L.push("_Nothing obvious. This is a passive check, not a full scan._");
    }
    L.push("");
  }

  if (report.infra) {
    const inf = report.infra;
    L.push("## 🌍 Infrastructure");
    L.push(`- **IP address:** ${inf.primaryIp || "—"}`);
    L.push(`- **Reverse DNS:** ${inf.reverse || "—"}`);
    if (inf.geo) {
      L.push(`- **Hosted by:** ${inf.geo.org || inf.geo.isp || "—"}${inf.geo.asn ? ` (${inf.geo.asn})` : ""}`);
      L.push(`- **Location:** ${[inf.geo.city, inf.geo.region, inf.geo.country].filter(Boolean).join(", ") || "—"}`);
    }
    if (inf.addresses.length > 1) L.push(`- **All IPs:** ${inf.addresses.map((a) => `\`${a.ip}\``).join(", ")}`);
    if (inf.ns.length) L.push(`- **Nameservers:** ${inf.ns.map((n) => `\`${n}\``).join(", ")}`);
    if (inf.mx.length) L.push(`- **Mail (MX):** ${inf.mx.map((n) => `\`${n}\``).join(", ")}`);
    L.push("");
  }

  if (report.tls && report.tls.reachable) {
    const t = report.tls;
    L.push(`## 🔐 TLS certificate — ${t.score}/100`);
    L.push(`- **Issued to:** ${t.subject || "—"}`);
    L.push(`- **Issued by:** ${t.issuer || "—"}`);
    if (t.validTo) L.push(`- **Expires:** ${t.validTo.slice(0, 10)} (${t.daysLeft} days)`);
    L.push(`- **Protocol:** ${t.protocol || "—"} · **Cipher:** ${t.cipher || "—"}`);
    pushIssues(L, t.checks);
    L.push("");
  }

  if (report.recon && report.recon.ports) {
    const p = report.recon.ports;
    L.push(`## 🔌 Open ports (${p.open.length}/${p.scanned})`);
    if (p.open.length) {
      L.push("| Port | Service | Note |");
      L.push("|---|---|---|");
      for (const port of p.open) L.push(`| ${port.port}${port.sensitive ? " ⚠️" : ""} | ${port.name} | ${port.note} |`);
    } else L.push("_No common ports responded._");
    L.push("");
  }

  if (report.recon && report.recon.paths) {
    const pp = report.recon.paths;
    L.push(`## 🗂️ Path discovery (${pp.found.length} found / ${pp.checked} checked)`);
    if (pp.present.length) {
      L.push("| Status | Path | Kind |");
      L.push("|---|---|---|");
      for (const r of pp.present) L.push(`| ${r.status} | \`${r.path}\` | ${r.kind}${r.kind === "sensitive" && r.status < 400 ? " ❌" : ""} |`);
    } else L.push("_None of the probed paths were reachable._");
    L.push("");
  }

  if (report.recon && report.recon.subs) {
    const sd = report.recon.subs;
    L.push(`## 🌐 Subdomains (${sd.found.length} found / ${sd.checked} checked)`);
    if (sd.wildcard) {
      L.push("_Wildcard DNS in use — every name resolves, so the check was skipped._");
    } else if (sd.found.length) {
      L.push("| Subdomain | Address | CNAME | Kind |");
      L.push("|---|---|---|---|");
      for (const s of sd.found) L.push(`| \`${s.fqdn}\` | \`${s.addresses[0]}\` | ${s.cname ? `\`${s.cname}\`` : "—"} | ${s.kind}${s.kind === "sensitive" ? " ⚠️" : ""} |`);
    } else L.push("_None of the common subdomain names resolved._");
    L.push("");
  }

  L.push(`## 🍪 Cookies (${report.cookies.count})`);
  if (report.cookies.count) {
    L.push("| Name | Secure | HttpOnly | SameSite |");
    L.push("|---|---|---|---|");
    for (const ck of report.cookies.cookies) L.push(`| ${ck.name} | ${ck.secure ? "✅" : "❌"} | ${ck.httpOnly ? "✅" : "❌"} | ${ck.sameSite || "—"} |`);
  } else L.push("_No cookies set._");
  for (const issue of report.cookies.issues) L.push(`- ⚠️ ${issue}`);
  L.push("");

  L.push(`## 🔍 SEO — ${report.seo.score}/100`);
  L.push(`- **Title:** ${report.seo.title || "—"}`);
  L.push(`- **Description:** ${report.seo.metaDescription || "—"}`);
  L.push(`- **Canonical:** ${report.seo.canonical || "—"}`);
  L.push(`- **Headings:** h1:${report.seo.headings.h1} h2:${report.seo.headings.h2} h3:${report.seo.headings.h3}`);
  L.push(`- **Images:** ${report.seo.images.total} (${report.seo.images.missingAlt} missing alt)`);
  L.push(`- **Links:** ${report.seo.links.internal} internal · ${report.seo.links.external} external`);
  L.push(`- **Open Graph:** ${report.seo.openGraph.length} tags · **Twitter:** ${report.seo.twitter.length} tags`);
  pushIssues(L, report.seo.checks);
  L.push("");

  L.push(`## 🌐 Network resources (${report.network.total})`);
  L.push(`- First-party: **${report.network.firstParty}** · Third-party: **${report.network.thirdParty}** from ${report.network.thirdPartyHosts.length} hosts`);
  L.push(`- By type: ${Object.entries(report.network.byType).map(([t, n]) => `${t} (${n})`).join(", ")}`);
  if (report.network.thirdPartyHosts.length) L.push(`- Third-party hosts: ${report.network.thirdPartyHosts.map((h) => `\`${h}\``).join(", ")}`);
  L.push("");

  if (report.performance) {
    const p = report.performance;
    L.push(`## ⚡ Performance budget — ${p.score}/100`);
    L.push(`- Requests: **${p.requests}** · Scripts: **${p.jsCount}** · Stylesheets: **${p.cssCount}** · Third-party hosts: **${p.thirdPartyHosts}**`);
    if (p.bytes) L.push(`- Total weight: **${formatBytes(p.bytes.total)}**`);
    pushIssues(L, p.checks);
    L.push("");
  }

  if (report.crawl) {
    const cr = report.crawl;
    L.push(`## 🤖 Crawlability — ${cr.score}/100`);
    L.push(`- robots.txt: ${cr.robotsTxt.present ? "found" : "not found"}`);
    L.push(`- Sitemap: ${cr.sitemap.present ? (cr.sitemap.isIndex ? `index (${cr.sitemap.urlCount} sitemaps)` : `${cr.sitemap.urlCount} URLs`) : "not found"}`);
    pushIssues(L, cr.checks);
    L.push("");
  }

  L.push("---");
  L.push("_Generated by [SiteScope](https://github.com/) — single HTML fetch analysis._");
  return L.join("\n") + "\n";
}

// ----------------------------- HTML -----------------------------

export function renderHtml(report) {
  const esc = (s) => String(s ?? "—").replace(/[&<>"]/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[ch]));
  const badge = (status) => `<span class="b b-${status}">${status}</span>`;
  // pass/fail check list, shared by the seo / performance / crawl cards
  const checkList = (checks) => `<ul class="checks">${(checks || []).map((ch) => `<li class="${ch.pass ? "ok" : "warn"}">${ch.pass ? "✓" : "▲"} ${esc(ch.label)}</li>`).join("")}</ul>`;

  const techRows = report.frameworks
    .map((f) => `<tr><td><b>${esc(f.name)}</b></td><td class="dim">${esc(f.version || "—")}</td><td>${esc(f.category)}</td><td>${badge(f.confidence)}</td><td class="dim">${esc(f.evidence.join("; "))}</td></tr>`)
    .join("");

  const secRows = report.headers.security
    .map((s) => `<tr><td>${esc(s.label)}</td><td>${badge(s.status)}</td><td class="dim">${esc(s.note || "")}</td></tr>`)
    .join("");

  const cookieRows = report.cookies.cookies
    .map((ck) => `<tr><td>${esc(ck.name)}</td><td>${ck.secure ? "✅" : "❌"}</td><td>${ck.httpOnly ? "✅" : "❌"}</td><td>${esc(ck.sameSite || "—")}</td></tr>`)
    .join("");

  const seoChecks = checkList(report.seo.checks);

  const typeRows = Object.entries(report.network.byType)
    .map(([t, n]) => `<tr><td>${esc(t)}</td><td>${n}</td></tr>`)
    .join("");

  const inf = report.infra;
  const infraSection = inf ? `
  <h2>🌍 Infrastructure</h2>
  <div class="card"><table>
    <tr><td>IP address</td><td>${esc(inf.primaryIp)}</td></tr>
    <tr><td>Reverse DNS</td><td>${esc(inf.reverse)}</td></tr>
    ${inf.geo ? `<tr><td>Hosted by</td><td>${esc(inf.geo.org || inf.geo.isp)} ${inf.geo.asn ? "(" + esc(inf.geo.asn) + ")" : ""}</td></tr>
    <tr><td>Location</td><td>${esc([inf.geo.city, inf.geo.region, inf.geo.country].filter(Boolean).join(", ") || "—")}</td></tr>` : ""}
    ${inf.addresses.length > 1 ? `<tr><td>All IPs</td><td>${esc(inf.addresses.map((a) => a.ip).join(", "))}</td></tr>` : ""}
    ${inf.ns.length ? `<tr><td>Nameservers</td><td>${esc(inf.ns.join(", "))}</td></tr>` : ""}
    ${inf.mx.length ? `<tr><td>Mail (MX)</td><td>${esc(inf.mx.join(", "))}</td></tr>` : ""}
  </table></div>` : "";

  const t = report.tls;
  const tlsSection = t && t.reachable ? `
  <h2>🔐 TLS certificate — ${t.score}/100</h2>
  <div class="card"><table>
    <tr><td>Issued to</td><td>${esc(t.subject)}</td></tr>
    <tr><td>Issued by</td><td>${esc(t.issuer)}</td></tr>
    <tr><td>Expires</td><td>${t.validTo ? esc(t.validTo.slice(0, 10)) + ` (${t.daysLeft} days)` : "—"}</td></tr>
    <tr><td>Protocol</td><td>${esc(t.protocol)}</td></tr>
    <tr><td>Cipher</td><td>${esc(t.cipher)}</td></tr>
  </table>
    ${checkList(t.checks)}
  </div>` : "";

  const rec = report.recon || {};
  const portsSection = rec.ports ? `
  <h2>🔌 Open ports (${rec.ports.open.length}/${rec.ports.scanned})</h2>
  <div class="card"><table><tr><th>Port</th><th>Service</th><th>Note</th></tr>
    ${rec.ports.open.map((p) => `<tr><td>${p.port}${p.sensitive ? " ⚠️" : ""}</td><td>${esc(p.name)}</td><td class="dim">${esc(p.note)}</td></tr>`).join("") || '<tr><td class="dim" colspan=3>No common ports responded</td></tr>'}
  </table></div>` : "";

  const pathsSection = rec.paths ? `
  <h2>🗂️ Path discovery (${rec.paths.found.length}/${rec.paths.checked})</h2>
  <div class="card"><table><tr><th>Status</th><th>Path</th><th>Kind</th></tr>
    ${rec.paths.present.map((r) => `<tr><td>${r.status}</td><td>${esc(r.path)}</td><td class="dim">${esc(r.kind)}${r.kind === "sensitive" && r.status < 400 ? " ❌" : ""}</td></tr>`).join("") || '<tr><td class="dim" colspan=3>None reachable</td></tr>'}
  </table></div>` : "";

  const subsSection = rec.subs ? `
  <h2>🌐 Subdomains (${rec.subs.found.length}/${rec.subs.checked})</h2>
  <div class="card">${rec.subs.wildcard
    ? '<p class="dim">Wildcard DNS in use — every name resolves, so the check was skipped.</p>'
    : `<table><tr><th>Subdomain</th><th>Address</th><th>CNAME</th><th>Kind</th></tr>
    ${rec.subs.found.map((s) => `<tr><td>${esc(s.fqdn)}</td><td class="dim">${esc(s.addresses[0])}</td><td class="dim">${esc(s.cname || "—")}</td><td class="dim">${esc(s.kind)}${s.kind === "sensitive" ? " ⚠️" : ""}</td></tr>`).join("") || '<tr><td class="dim" colspan=4>No common subdomain names resolved</td></tr>'}
  </table>`}</div>` : "";

  const perf = report.performance;
  const perfSection = perf ? `
  <h2>⚡ Performance budget — ${perf.score}/100</h2>
  <div class="card">
    <p class="dim">Requests: ${perf.requests} · Scripts: ${perf.jsCount} · Stylesheets: ${perf.cssCount} · Third-party hosts: ${perf.thirdPartyHosts}${perf.bytes ? ` · Total weight: ${esc(formatBytes(perf.bytes.total))}` : ""}</p>
    ${checkList(perf.checks)}
  </div>` : "";

  const cr = report.crawl;
  const crawlSection = cr ? `
  <h2>🤖 Crawlability — ${cr.score}/100</h2>
  <div class="card">
    <p class="dim">robots.txt: ${cr.robotsTxt.present ? "found" : "not found"} · Sitemap: ${cr.sitemap.present ? (cr.sitemap.isIndex ? `index (${cr.sitemap.urlCount} sitemaps)` : `${cr.sitemap.urlCount} URLs`) : "not found"}</p>
    ${checkList(cr.checks)}
  </div>` : "";

  const vuln = report.vulns;
  const vulnSection = vuln ? `
  <h2>🛡️ Vulnerabilities — ${esc(vuln.risk)} risk (${vuln.total})</h2>
  <div class="card">
    ${vuln.total
      ? `<table><tr><th>Severity</th><th>Finding</th><th>CVE</th><th>Fix</th></tr>
    ${vuln.findings.map((f) => `<tr><td><span class="b b-sev-${f.severity}">${sevIcon(f.severity)} ${esc(f.severity)}</span></td><td><b>${esc(f.title)}</b><br><span class="dim">${esc(f.detail)}</span></td><td class="dim">${esc(f.cve || "—")}</td><td class="dim">${esc(f.recommendation)}</td></tr>`).join("")}
  </table>`
      : '<p class="dim">Nothing obvious — this is a passive check, not a full scan.</p>'}
  </div>` : "";

  const score = report.score;
  const topIssuesSection = score && score.topIssues.length ? `
  <h2>🚩 Top issues</h2>
  <div class="card"><ul class="checks">${score.topIssues.map((i) => `<li class="warn">▲ <b>[${esc(i.source)}]</b> ${esc(i.label)}</li>`).join("")}</ul></div>` : "";

  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SiteScope — ${esc(report.meta.finalUrl)}</title>
<link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 64 64'%3E%3Crect width='64' height='64' rx='13' fill='%231d4ed8'/%3E%3Cg stroke-linecap='round' stroke-linejoin='round' fill='none'%3E%3Cpath d='M31 34 L24 52 M31 34 L38 52 M31 36 L31 50' stroke='%238fb0ff' stroke-width='3.4'/%3E%3Cline x1='18' y1='44' x2='45' y2='21' stroke='%23e3ecff' stroke-width='10'/%3E%3Cline x1='15' y1='47' x2='21' y2='42' stroke='%238fb0ff' stroke-width='6'/%3E%3C/g%3E%3Ccircle cx='47' cy='18' r='3.2' fill='%23ffd84d'/%3E%3C/svg%3E">
<style>
${REPORT_CSS}</style></head>
<body><div class="wrap">
  <h1>SiteScope report</h1>
  <div class="sub">${esc(report.meta.finalUrl)} · status ${esc(report.meta.status)} · ${report.meta.bytes} bytes · ${report.meta.elapsedMs}ms · ${esc(report.meta.generatedAt)}</div>

  <div class="grid">
    ${score && score.score != null ? `<div class="stat"><div class="n">${esc(score.grade)}</div><div class="l">overall health (${score.score}/100)</div></div>` : ""}
    <div class="stat"><div class="n">${report.frameworks.length}</div><div class="l">technologies</div></div>
    <div class="stat"><div class="n">${esc(report.headers.grade)}</div><div class="l">security grade</div></div>
    ${report.vulns ? `<div class="stat"><div class="n">${report.vulns.total}</div><div class="l">vuln findings (${esc(report.vulns.risk)})</div></div>` : ""}
    <div class="stat"><div class="n">${report.seo.score}</div><div class="l">SEO score</div></div>
    <div class="stat"><div class="n">${report.network.total}</div><div class="l">resources</div></div>
    <div class="stat"><div class="n">${report.cookies.count}</div><div class="l">cookies</div></div>
  </div>
  ${topIssuesSection}

  <h2>⚙️ Technologies</h2>
  <div class="card"><table><tr><th>Technology</th><th>Version</th><th>Category</th><th>Confidence</th><th>Evidence</th></tr>${techRows || '<tr><td class="dim" colspan=5>None detected</td></tr>'}</table></div>

  <h2>🔒 Security headers — ${esc(report.headers.grade)} (${report.headers.score}/100)</h2>
  <div class="card"><table><tr><th>Header</th><th>Status</th><th>Note</th></tr>${secRows}</table></div>
  ${vulnSection}

  <h2>🍪 Cookies (${report.cookies.count})</h2>
  <div class="card"><table><tr><th>Name</th><th>Secure</th><th>HttpOnly</th><th>SameSite</th></tr>${cookieRows || '<tr><td class="dim" colspan=4>No cookies</td></tr>'}</table></div>

  <h2>🔍 SEO — ${report.seo.score}/100</h2>
  <div class="card">
    <p><b>Title:</b> ${esc(report.seo.title)}<br><b>Description:</b> ${esc(report.seo.metaDescription)}<br><b>Canonical:</b> ${esc(report.seo.canonical)}</p>
    <ul class="checks">${seoChecks}</ul>
  </div>

  <h2>🌐 Network resources (${report.network.total})</h2>
  <div class="card">
    <p class="dim">First-party: ${report.network.firstParty} · Third-party: ${report.network.thirdParty} from ${report.network.thirdPartyHosts.length} hosts</p>
    <table><tr><th>Type</th><th>Count</th></tr>${typeRows}</table>
  </div>
  ${perfSection}
  ${crawlSection}
  ${infraSection}
  ${tlsSection}
  ${portsSection}
  ${pathsSection}
  ${subsSection}

  <footer>Generated by SiteScope · single HTML fetch analysis</footer>
</div></body></html>`;
}

// ----------------------------- helpers -----------------------------

function statusColor(c, s) {
  if (s >= 200 && s < 300) return c.green + s + c.reset;
  if (s >= 300 && s < 400) return c.yellow + s + c.reset;
  return c.red + s + c.reset;
}
function gradeColor(c, g) {
  return (g === "A" || g === "B" ? c.green : g === "C" ? c.yellow : c.red) + "■" + c.reset;
}
function scoreColor(c, n) {
  return (n >= 80 ? c.green : n >= 60 ? c.yellow : c.red) + "■" + c.reset;
}
function riskColor(c, risk) {
  const col = risk === "critical" || risk === "high" ? c.red : risk === "medium" ? c.yellow : risk === "low" ? c.gray : c.green;
  return col + "■" + c.reset;
}
// per-finding severity color for the terminal list
function sevColor(c, sev) {
  if (sev === "critical" || sev === "high") return c.red;
  if (sev === "medium") return c.yellow;
  return c.gray;
}
// leading severity marker — a quick spot-check colour, not decoration.
// shared by terminal / markdown / html so the ramp reads the same everywhere.
function sevIcon(sev) {
  return { critical: "🛑", high: "🔴", medium: "🟠", low: "🟡", info: "⚪" }[sev] || "•";
}
// markdown: append the failed checks as an "Issues:" bullet list, if any.
// used by seo / performance / crawlability so the block isn't copy-pasted.
function pushIssues(L, checks) {
  const failed = (checks || []).filter((c) => !c.pass);
  if (!failed.length) return;
  L.push("");
  L.push("**Issues:**");
  for (const ch of failed) L.push(`- ⚠️ ${ch.label}`);
}
function formatBytes(n) {
  if (!n) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) {
    n /= 1024;
    i++;
  }
  return `${n.toFixed(1)} ${units[i]}`;
}
