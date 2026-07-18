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
 * @param {{ concurrency?:number }} [opts]
 */
export async function scanSubdomains(host, opts = {}) {
  const concurrency = opts.concurrency || 8;
  const base = baseDomain(host);
  if (!base) return empty(host);

  // if the zone has a wildcard record every guess "resolves", so the whole
  // scan is meaningless. detect it once and bail out honestly.
  const wildcard = await resolves(`${WILDCARD_PROBE}.${base}`);
  if (wildcard) return { ...empty(base), wildcard: true };

  const queue = [...SUBDOMAINS];
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

  // preserve the declared order so reports are stable run to run
  const order = new Map(SUBDOMAINS.map((s, i) => [s.name, i]));
  results.sort((a, b) => order.get(a.name) - order.get(b.name));

  return {
    domain: base,
    wildcard: false,
    checked: SUBDOMAINS.length,
    found: results,
    exposedSensitive: results.filter((r) => r.kind === "sensitive"),
  };
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
  return { domain, wildcard: false, checked: 0, found: [], exposedSensitive: [] };
}
