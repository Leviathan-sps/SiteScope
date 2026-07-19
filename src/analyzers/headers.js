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

// directives that decide whether a csp actually stops anything. without
// these a policy can look long and still block nothing useful.
const KEY_DIRECTIVES = ["default-src", "script-src", "object-src", "base-uri", "frame-ancestors"];

// per spec most fetch directives inherit from default-src when absent, so a
// policy with default-src 'none' is not missing them. base-uri and
// frame-ancestors do NOT inherit — those have to be set explicitly.
const INHERITS_DEFAULT = new Set(["script-src", "object-src", "style-src", "img-src", "font-src", "connect-src", "media-src", "frame-src", "child-src", "worker-src", "manifest-src"]);

// a csp is only as strong as its weakest source list, so the header being
// present says very little on its own — this pulls it apart directive by
// directive and names what actually undermines it.
function parseCsp(value) {
  if (!value) return null;

  const directives = {};
  for (const part of value.split(";")) {
    const bits = part.trim().split(/\s+/).filter(Boolean);
    if (!bits.length) continue;
    directives[bits[0].toLowerCase()] = bits.slice(1);
  }

  const sources = Object.entries(directives)
    .filter(([name]) => name !== "report-uri" && name !== "report-to");
  const has = (token) => sources.some(([, vals]) => vals.some((v) => v.toLowerCase() === token));
  // a bare "*" or "https:" in a fetch directive allows essentially anything
  const wildcard = sources.filter(([, vals]) =>
    vals.some((v) => v === "*" || v === "https:" || v === "http:"));

  // a directive isn't "missing" if default-src is set and it inherits from it
  const missingKey = KEY_DIRECTIVES.filter((d) => {
    if (directives[d]) return false;
    return !(directives["default-src"] && INHERITS_DEFAULT.has(d));
  });

  const weaknesses = [];
  if (has("'unsafe-inline'")) weaknesses.push("allows 'unsafe-inline' — inline scripts still run");
  if (has("'unsafe-eval'")) weaknesses.push("allows 'unsafe-eval' — eval() still runs");
  if (wildcard.length) weaknesses.push(`wildcard source in ${wildcard.map(([n]) => n).join(", ")}`);
  for (const d of missingKey) weaknesses.push(`no ${d} directive`);

  return {
    raw: value,
    directives,
    count: Object.keys(directives).length,
    weaknesses,
    // nothing to complain about is the only way to call a policy strict
    strict: weaknesses.length === 0,
  };
}

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
    csp: parseCsp(headers["content-security-policy"]),
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

// grading is deliberately lenient — real-world sites rarely set every header,
// so the curve rewards a reasonable baseline rather than punishing it.
function letterGrade(score) {
  if (score >= 80) return "A";
  if (score >= 65) return "B";
  if (score >= 50) return "C";
  if (score >= 35) return "D";
  return "F";
}

function lowerKeys(obj) {
  const out = {};
  for (const [k, v] of Object.entries(obj)) out[k.toLowerCase()] = v;
  return out;
}
