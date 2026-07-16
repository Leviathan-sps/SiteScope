// vulnerability check — a light, passive pass over what the other analyzers
// already collected. no new requests: it reasons over detected software
// versions, exposed services/paths, and headers that give too much away.
//
// this is NOT a cve feed or a full scanner (nmap it is not). it's a small,
// curated read of the issues that actually surface from a single fetch, so
// treat it as a heads-up rather than an audit.

// known-bad version ranges for the few libs whose version we can actually read
// off a cdn url or filename. "below" = first fixed version. kept short on
// purpose — a stale, half-right cve list is worse than a small honest one.
const versionRules = {
  jquery: [
    { below: "3.5.0", severity: "medium", cve: "CVE-2020-11022", issue: "xss through jquery.htmlPrefilter when untrusted html reaches dom methods" },
    { below: "3.0.0", severity: "medium", cve: "CVE-2019-11358", issue: "prototype pollution in $.extend(true, ...)" },
    { below: "1.9.0", severity: "high", cve: null, issue: "very old jquery — several known selector / xss problems" },
  ],
  bootstrap: [
    { below: "4.3.1", severity: "medium", cve: "CVE-2019-8331", issue: "xss in data-template / tooltip when an attacker controls the markup" },
    { below: "3.4.1", severity: "medium", cve: "CVE-2018-14041", issue: "xss via data-target and scrollspy" },
  ],
};

// detector tech name -> key in versionRules above
const nameMap = {
  jQuery: "jquery",
  Bootstrap: "bootstrap",
};

// alt idea: load a bundled offline cve snapshot so the ranges don't rot over
// time. left out — a snapshot needs a refresh job to stay useful, and a stale
// one just lies with more confidence.
// import knownCves from "../data/known-cves.json" assert { type: "json" };

const severityRank = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };

// run the passive checks and roll them into one findings list.
// expects the already-analyzed pieces: frameworks[], headers{}, recon{}.
export function analyzeVulns({ frameworks = [], headers = {}, recon = null } = {}) {
  const findings = [];

  // 1. outdated libraries with a known issue in their version range
  for (const f of frameworks) {
    const key = nameMap[f.name];
    if (!key || !f.version) continue;
    const rules = versionRules[key] || [];
    // report the newest fix it's still short of — updating to that covers the
    // older ones below it too, so one finding per library is enough.
    const hit = rules
      .filter((r) => versionBelow(f.version, r.below))
      .sort((a, b) => cmpVersion(b.below, a.below))[0];
    if (!hit) continue;
    findings.push({
      id: `${key}-outdated`,
      title: `${f.name} ${f.version} is outdated`,
      severity: hit.severity,
      component: `${f.name} ${f.version}`,
      detail: hit.issue,
      recommendation: `update ${f.name} to ${hit.below} or newer`,
      cve: hit.cve,
    });
  }

  // 2. sensitive services reachable straight off the internet (port scan only)
  const openServices = recon && recon.ports ? recon.ports.exposedSensitive || [] : [];
  for (const p of openServices) {
    findings.push({
      id: `port-${p.port}`,
      title: `${p.name} exposed on port ${p.port}`,
      severity: "high",
      component: `tcp/${p.port} (${p.name})`,
      detail: `${p.note}. answering directly over the public internet.`,
      recommendation: "put it behind a firewall or vpn, or bind it to localhost",
      cve: null,
    });
  }

  // 3. files that should never be served but came back 2xx (path scan only)
  const openPaths = recon && recon.paths ? recon.paths.exposedSensitive || [] : [];
  for (const r of openPaths) {
    findings.push({
      id: `path-${r.path}`,
      title: `${r.path} is publicly readable`,
      severity: "critical",
      component: r.path,
      detail: "sensitive file served with a 2xx — can leak source, secrets or config.",
      recommendation: `block ${r.path} at the web server and rotate anything it exposed`,
      cve: null,
    });
  }

  // 4. stack disclosure — low on its own, but it hands an attacker the roadmap
  for (const d of stackDisclosure(headers, frameworks)) findings.push(d);

  // worst first, so the scary stuff sits at the top of the report
  findings.sort((a, b) => severityRank[b.severity] - severityRank[a.severity]);

  const counts = tally(findings);
  return {
    scanned: true,
    findings,
    counts,
    total: findings.length,
    risk: overallRisk(counts),
  };
}

// version numbers printed in headers or generator meta tags. cheap to leak,
// annoyingly useful to whoever's fingerprinting you.
function stackDisclosure(headers, frameworks) {
  const out = [];
  const server = headers.server && headers.server.server;
  const powered = headers.server && headers.server.poweredBy;

  if (server && /\d+\.\d/.test(server)) {
    out.push(disclosure("server-version", `server banner prints a version: "${server}"`, `Server: ${server}`));
  }
  if (powered) {
    out.push(disclosure("powered-by", `x-powered-by advertises the backend: "${powered}"`, `X-Powered-By: ${powered}`));
  }
  for (const f of frameworks) {
    if (f.version && (f.category === "CMS" || f.category === "E-commerce")) {
      out.push(disclosure(`cms-${f.name}`, `${f.name} ${f.version} version is public — makes known-cve matching trivial`, f.evidence[0] || "version in page"));
    }
  }
  return out;
}

function disclosure(id, detail, evidence) {
  return {
    id,
    title: "information disclosure",
    severity: "low",
    component: evidence,
    detail,
    recommendation: "strip or generalize the version so it isn't advertised",
    cve: null,
  };
}

function tally(findings) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) if (counts[f.severity] != null) counts[f.severity]++;
  return counts;
}

// headline risk = the worst thing we found
function overallRisk(counts) {
  if (counts.critical) return "critical";
  if (counts.high) return "high";
  if (counts.medium) return "medium";
  if (counts.low || counts.info) return "low";
  return "none";
}

// true when `have` is strictly older than `want` (both dotted, e.g. 3.4.1)
function versionBelow(have, want) {
  return cmpVersion(have, want) < 0;
}

// -1 / 0 / 1 like a spaceship op. missing parts count as 0, so 3.4 == 3.4.0.
function cmpVersion(a, b) {
  const pa = String(a).split(".").map((n) => parseInt(n, 10) || 0);
  const pb = String(b).split(".").map((n) => parseInt(n, 10) || 0);
  const len = Math.max(pa.length, pb.length);
  for (let i = 0; i < len; i++) {
    const d = (pa[i] || 0) - (pb[i] || 0);
    if (d) return d < 0 ? -1 : 1;
  }
  return 0;
}
