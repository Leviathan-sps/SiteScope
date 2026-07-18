// Subdomain discovery: resolves a curated list of commonly-used hostnames
// against the target domain and reports the ones that exist.
//
// This is PASSIVE as far as the target's web server is concerned — we only
// ask DNS, we never connect to the hosts we find. Even so it maps attack
// surface, so it rides along with the deep scan. Only run it against domains
// you own or are explicitly authorized to test.
//
// The list is deliberately small and curated; this is NOT a brute-force
// wordlist. Nothing can enumerate "all subdomains" by guessing — we check the
// names that most often exist and most often matter.

import { promises as dns } from "node:dns";

const SUBDOMAINS = [
  // conventional / expected
  { name: "www", kind: "info" },
  { name: "mail", kind: "info" },
  { name: "smtp", kind: "info" },
  { name: "webmail", kind: "info" },
  { name: "ns1", kind: "info" },
  { name: "ns2", kind: "info" },
  { name: "cdn", kind: "info" },
  { name: "static", kind: "info" },
  { name: "assets", kind: "info" },
  { name: "img", kind: "info" },
  { name: "blog", kind: "info" },
  { name: "shop", kind: "info" },
  { name: "support", kind: "info" },
  { name: "docs", kind: "info" },
  // app surfaces worth knowing about
  { name: "api", kind: "surface" },
  { name: "app", kind: "surface" },
  { name: "admin", kind: "surface" },
  { name: "portal", kind: "surface" },
  { name: "dashboard", kind: "surface" },
  { name: "login", kind: "surface" },
  { name: "auth", kind: "surface" },
  { name: "sso", kind: "surface" },
  { name: "m", kind: "surface" },
  { name: "mobile", kind: "surface" },
  { name: "beta", kind: "surface" },
  { name: "status", kind: "surface" },
  // non-production or internal names — a red flag when publicly resolvable
  { name: "dev", kind: "sensitive" },
  { name: "test", kind: "sensitive" },
  { name: "staging", kind: "sensitive" },
  { name: "stage", kind: "sensitive" },
  { name: "uat", kind: "sensitive" },
  { name: "demo", kind: "sensitive" },
  { name: "internal", kind: "sensitive" },
  { name: "intranet", kind: "sensitive" },
  { name: "vpn", kind: "sensitive" },
  { name: "jenkins", kind: "sensitive" },
  { name: "gitlab", kind: "sensitive" },
  { name: "grafana", kind: "sensitive" },
  { name: "kibana", kind: "sensitive" },
  { name: "phpmyadmin", kind: "sensitive" },
  { name: "backup", kind: "sensitive" },
  { name: "old", kind: "sensitive" },
];

// label used to sniff out wildcard dns. if this resolves, the zone answers
// for everything and individual hits mean nothing.
const WILDCARD_PROBE = "sitescope-wildcard-probe-x9f2";

// alt idea: pull names from certificate transparency logs (crt.sh) for much
// better coverage, incl. names no wordlist would guess. left out because it
// sends the target domain to a third party — unlike the lookups below.
// const CT_ENDPOINT = "https://crt.sh/?output=json&q=%25.";

/**
 * @param {string} host
 * @param {{ concurrency?:number, certNames?:string[] }} [opts]
 */
export async function scanSubdomains(host, opts = {}) {
  const concurrency = opts.concurrency || 8;
  const base = baseDomain(host);
  if (!base) return empty(host);

  // if the zone has a wildcard record every guess "resolves", so the whole
  // scan is meaningless. detect it once and bail out honestly.
  const wildcard = await resolves(`${WILDCARD_PROBE}.${base}`);
  if (wildcard) return { ...empty(base), wildcard: true };

  // names lifted off the certificate are authoritative, not guesses — the
  // server told us about them. worth far more than any wordlist entry.
  const fromCert = certCandidates(opts.certNames || [], base);
  const queue = [...SUBDOMAINS, ...fromCert];

  const results = [];
  async function worker() {
    let item;
    while ((item = queue.shift())) {
      const fqdn = `${item.name}.${base}`;
      const addrs = await lookup(fqdn);
      if (addrs.length) {
        const cname = await dns.resolveCname(fqdn).then((a) => a[0] || null).catch(() => null);
        results.push({ ...item, fqdn, addresses: addrs, cname });
      }
    }
  }
  await Promise.all(Array.from({ length: concurrency }, worker));

  // preserve the declared order so reports are stable run to run; cert-sourced
  // names have no declared position so they sort to the end, alphabetically.
  const order = new Map(SUBDOMAINS.map((s, i) => [s.name, i]));
  const rank = (r) => (order.has(r.name) ? order.get(r.name) : SUBDOMAINS.length);
  results.sort((a, b) => rank(a) - rank(b) || a.name.localeCompare(b.name));

  return {
    domain: base,
    wildcard: false,
    checked: SUBDOMAINS.length + fromCert.length,
    fromCert: fromCert.length,
    found: results,
    exposedSensitive: results.filter((r) => r.kind === "sensitive"),
  };
}

// turn cert SAN entries into extra candidates. wildcards can't be resolved,
// and anything outside the base domain isn't ours to scan.
function certCandidates(names, base) {
  const known = new Set(SUBDOMAINS.map((s) => s.name));
  const suffix = `.${base}`;
  const out = new Map();
  for (const raw of names) {
    const n = String(raw || "").toLowerCase().trim();
    if (!n.endsWith(suffix) || n.startsWith("*")) continue;
    const label = n.slice(0, -suffix.length);
    if (!label || known.has(label) || out.has(label)) continue;
    out.set(label, { name: label, kind: classify(label), source: "cert" });
  }
  return [...out.values()];
}

// reuse the wordlist's judgement for cert names that look non-production
function classify(label) {
  const head = label.split(".").pop();
  const match = SUBDOMAINS.find((s) => s.name === head);
  return match ? match.kind : "info";
}

// dns.lookup goes through the OS resolver (same path as fetch), so it still
// works on networks where direct c-ares queries are firewalled.
async function lookup(fqdn) {
  return dns.lookup(fqdn, { all: true })
    .then((list) => list.map((a) => a.address))
    .catch(() => []);
}

async function resolves(fqdn) {
  return (await lookup(fqdn)).length > 0;
}

// strip a leading "www." so we scan the apex, not www.www.example.com.
// anything that looks like an IP literal has no subdomains to speak of.
function baseDomain(host) {
  if (!host || /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(":")) return "";
  return host.replace(/^www\./i, "");
}

function empty(domain) {
  return { domain, wildcard: false, checked: 0, fromCert: 0, found: [], exposedSensitive: [] };
}
