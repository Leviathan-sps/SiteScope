// Infrastructure lookup: resolves the host to its IP address(es), does a
// reverse-DNS (PTR) lookup, gathers NS/MX records, and — unless disabled —
// asks a free geo/ASN service where that IP is hosted and who owns it.
//
// All DNS work is local (node:dns). The geo lookup is the only outbound
// call and sends just the resolved IP (public info about the target) to
// ipwho.is; pass { geo:false } to skip it entirely.

import { promises as dns } from "node:dns";

/**
 * @param {{finalUrl:string}} site
 * @param {{ geo?:boolean, timeout?:number }} [opts]
 */
export async function analyzeInfra(site, opts = {}) {
  const host = safeHost(site.finalUrl);
  if (!host) return { host: null, primaryIp: null, addresses: [], reverse: null, ns: [], mx: [], geo: null };

  // If the URL points straight at an IP, skip resolution.
  const literal = isIp(host);

  // dns.lookup uses the OS resolver (same path as fetch), so it works even
  // where direct c-ares queries (resolve4/6) are firewalled.
  const addresses = literal
    ? [{ ip: host, family: isIp(host) }]
    : await dns.lookup(host, { all: true })
        .then((list) => list.map((a) => ({ ip: a.address, family: a.family })))
        .catch(() => []);

  const primaryIp =
    (addresses.find((a) => a.family === 4) || addresses[0] || {}).ip || null;

  // Reverse DNS, NS and MX go through c-ares and may be unavailable in
  // locked-down networks — all best-effort, never fatal.
  const [reverse, ns, mx] = await Promise.all([
    primaryIp ? dns.reverse(primaryIp).then((a) => a[0] || null).catch(() => null) : null,
    literal ? [] : dns.resolveNs(host).catch(() => []),
    literal ? [] : dns.resolveMx(host).catch(() => []),
  ]);

  let geo = null;
  if (primaryIp && opts.geo !== false) {
    geo = await lookupGeo(primaryIp, opts.timeout || 6000).catch(() => null);
  }

  return {
    host,
    primaryIp,
    reverse,
    addresses,
    ns: ns.sort(),
    mx: mx.map((m) => m.exchange).sort(),
    geo,
  };
}

// free, key-less, https geo/asn service. returns null on any failure so the
// rest of the report is unaffected if it's unreachable or rate-limited.
// fallback provider if ipwho.is is down — ip-api.com, but it's http-only on
// the free tier so we don't use it here.
// const GEO_FALLBACK = "http://ip-api.com/json/";
async function lookupGeo(ip, timeout) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    const res = await fetch(`https://ipwho.is/${encodeURIComponent(ip)}`, { signal: controller.signal });
    const d = await res.json();
    if (!d || d.success === false) return null;
    const conn = d.connection || {};
    return {
      country: d.country || null,
      countryCode: d.country_code || null,
      region: d.region || null,
      city: d.city || null,
      latitude: d.latitude ?? null,
      longitude: d.longitude ?? null,
      org: conn.org || null,
      isp: conn.isp || null,
      asn: conn.asn ? `AS${conn.asn}` : null,
      hostingDomain: conn.domain || null,
      timezone: d.timezone?.id || null,
      flag: d.flag?.emoji || null,
    };
  } finally {
    clearTimeout(timer);
  }
}

function safeHost(url) {
  try { return new URL(url).hostname; } catch { return ""; }
}

// Returns 4, 6, or 0.
function isIp(host) {
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(host)) return 4;
  if (/:/.test(host)) return 6;
  return 0;
}
