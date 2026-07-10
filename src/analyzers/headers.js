// http header analysis: grades security headers, flags missing ones, and
// surfaces caching / compression info

// security headers we grade. check() returns null if ok, or a warning string
const SECURITY_HEADERS = [
  {
    key: "strict-transport-security",
    label: "Strict-Transport-Security (HSTS)",
    weight: 20,
    check: (v) =>
      /max-age=\s*0\b/.test(v) ? "max-age=0 effectively disables HSTS" : null,
  },
  {
    key: "content-security-policy",
    label: "Content-Security-Policy (CSP)",
    weight: 25,
    check: (v) =>
      /unsafe-inline|unsafe-eval/i.test(v)
        ? "uses unsafe-inline/unsafe-eval (weakens CSP)"
        : null,
  },
  {
    key: "x-frame-options",
    label: "X-Frame-Options",
    weight: 15,
    check: (v) =>
      /deny|sameorigin/i.test(v) ? null : `unexpected value "${v}"`,
  },
  {
    key: "x-content-type-options",
    label: "X-Content-Type-Options",
    weight: 10,
    check: (v) => (/nosniff/i.test(v) ? null : `expected "nosniff", got "${v}"`),
  },
  {
    key: "referrer-policy",
    label: "Referrer-Policy",
    weight: 15,
    check: () => null,
  },
  {
    key: "permissions-policy",
    label: "Permissions-Policy",
    weight: 15,
    check: () => null,
  },
  // could also grade cross-origin isolation headers
  // {
  //   key: "cross-origin-opener-policy",
  //   label: "Cross-Origin-Opener-Policy",
  //   weight: 10,
  //   check: (v) => (/same-origin/i.test(v) ? null : `weak value "${v}"`),
  // },
];

// grade headers and pull out server/caching/transfer info
export function analyzeHeaders(site) {
  const headers = lowerKeys(site.headers || {});

  const security = [];
  let earned = 0;
  let possible = 0;

  for (const h of SECURITY_HEADERS) {
    possible += h.weight;
    const value = headers[h.key];
    if (value == null) {
      security.push({ label: h.label, present: false, status: "missing", note: "header not set" });
      continue;
    }
    const warning = h.check(value);
    if (warning) {
      earned += Math.round(h.weight * 0.5);
      security.push({ label: h.label, present: true, status: "weak", value, note: warning });
    } else {
      earned += h.weight;
      security.push({ label: h.label, present: true, status: "ok", value });
    }
  }

  const score = Math.round((earned / possible) * 100);

  return {
    grade: letterGrade(score),
    score,
    security,
    server: {
      server: headers["server"] || null,
      poweredBy: headers["x-powered-by"] || null,
      via: headers["via"] || null,
    },
    caching: {
      cacheControl: headers["cache-control"] || null,
      etag: headers["etag"] || null,
      lastModified: headers["last-modified"] || null,
      expires: headers["expires"] || null,
      age: headers["age"] || null,
    },
    transfer: {
      contentEncoding: headers["content-encoding"] || null, // gzip / br / etc.
      contentType: site.contentType || headers["content-type"] || null,
      transferEncoding: headers["transfer-encoding"] || null,
    },
    raw: site.headers || {},
  };
}

function letterGrade(score) {
  if (score >= 90) return "A";
  if (score >= 75) return "B";
  if (score >= 60) return "C";
  if (score >= 40) return "D";
  return "F";
}

function lowerKeys(obj) {
  const out = {};
  for (const [k, v] of Object.entries(obj)) out[k.toLowerCase()] = v;
  return out;
}
