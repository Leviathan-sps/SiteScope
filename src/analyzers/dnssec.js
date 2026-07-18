// DNS security records: the TXT/CAA entries that decide whether anyone can
// spoof mail from this domain, and who is allowed to issue certs for it.
//
// All lookups are ordinary public DNS queries (node:dns) — nothing here
// touches the target's servers. A domain with no SPF and no DMARC can be
// forged in a phishing mail by anyone, which is worth saying out loud.

import { promises as dns } from "node:dns";

// selectors worth trying when we have no better clue. dkim keys live at
// <selector>._domainkey.<domain> and there's no way to enumerate them.
const DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "mail"];

// alt idea: verify the spf record actually resolves within the 10-lookup
// limit rfc7208 imposes. that needs recursive include/redirect chasing, so
// it's a bigger job than it looks — left for later.
// const SPF_MAX_LOOKUPS = 10;

/**
 * @param {string} host
 * @param {{ timeout?:number }} [opts]
 */
export async function analyzeDns(host, opts = {}) {
  const domain = apex(host);
  if (!domain) return null;

  const [txt, dmarcTxt, caa, dkim] = await Promise.all([
    dns.resolveTxt(domain).catch(() => []),
    dns.resolveTxt(`_dmarc.${domain}`).catch(() => []),
    dns.resolveCaa(domain).catch(() => []),
    findDkim(domain),
  ]);

  const flat = txt.map((r) => r.join(""));
  const spfRecord = flat.find((r) => /^v=spf1/i.test(r)) || null;
  const dmarcRecord = dmarcTxt.map((r) => r.join("")).find((r) => /^v=DMARC1/i.test(r)) || null;

  const spf = spfRecord ? parseSpf(spfRecord) : null;
  const dmarc = dmarcRecord ? parseDmarc(dmarcRecord) : null;

  // no dnssec check here: node:dns can't query DS/DNSKEY records, and
  // guessing from anything else would be a lie. needs a real dnssec-aware
  // resolver to do honestly.
  const checks = [
    { label: "SPF record published", pass: !!spf },
    { label: "SPF ends in a hard or soft fail (not +all)", pass: !!spf && spf.all !== "+all" },
    { label: "DMARC record published", pass: !!dmarc },
    { label: "DMARC policy is not p=none", pass: !!dmarc && dmarc.policy !== "none" },
    { label: "CAA record restricts who can issue certs", pass: caa.length > 0 },
  ];

  return {
    domain,
    spf,
    dmarc,
    dkim,
    caa: caa.map(fmtCaa).filter(Boolean),
    checks,
    score: Math.round((checks.filter((c) => c.pass).length / checks.length) * 100),
  };
}

// "v=spf1 include:_spf.google.com ~all" -> mechanisms + the trailing all rule
function parseSpf(record) {
  const parts = record.split(/\s+/).filter(Boolean);
  const all = parts.find((p) => /all$/i.test(p)) || null;
  return {
    record,
    includes: parts.filter((p) => /^include:/i.test(p)).map((p) => p.slice(8)),
    all,
    // +all means "anyone may send as us" — worse than having no spf at all
    permissive: all === "+all",
  };
}

// "v=DMARC1; p=quarantine; rua=mailto:x@y" -> the bits that matter
function parseDmarc(record) {
  const tags = {};
  for (const part of record.split(";")) {
    const [k, v] = part.split("=").map((s) => (s || "").trim());
    if (k) tags[k.toLowerCase()] = v || "";
  }
  return {
    record,
    policy: (tags.p || "none").toLowerCase(),
    subdomainPolicy: tags.sp ? tags.sp.toLowerCase() : null,
    pct: tags.pct ? Number(tags.pct) : 100,
    reportTo: tags.rua || null,
  };
}

// we can only probe well-known selectors; a miss doesn't prove dkim is absent
async function findDkim(domain) {
  const hits = await Promise.all(
    DKIM_SELECTORS.map((sel) =>
      dns.resolveTxt(`${sel}._domainkey.${domain}`)
        .then((r) => (r.length ? sel : null))
        .catch(() => null)
    )
  );
  const found = hits.filter(Boolean);
  return { selectorsTried: DKIM_SELECTORS.length, found, present: found.length > 0 };
}

function fmtCaa(r) {
  if (!r || typeof r !== "object") return null;
  if (r.issue) return `issue ${r.issue}`;
  if (r.issuewild) return `issuewild ${r.issuewild}`;
  if (r.iodef) return `iodef ${r.iodef}`;
  return null;
}

// strip a leading www. so we look at the zone that actually holds the records
function apex(host) {
  if (!host || /^\d{1,3}(\.\d{1,3}){3}$/.test(host) || host.includes(":")) return "";
  return host.replace(/^www\./i, "");
}
