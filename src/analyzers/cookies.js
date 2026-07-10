// cookie analysis: parses set-cookie headers and flags missing security
// attributes (secure, httponly, samesite) plus overly broad scope

// parse cookies and collect security issues
export function analyzeCookies(site) {
  const list = site.setCookie || [];
  const cookies = list.map(parseCookie).filter(Boolean);

  const issues = [];
  for (const c of cookies) {
    if (!c.secure) issues.push(`"${c.name}" is missing the Secure flag`);
    if (!c.httpOnly) issues.push(`"${c.name}" is missing HttpOnly (readable by JS)`);
    if (!c.sameSite) issues.push(`"${c.name}" has no SameSite attribute`);
    else if (/none/i.test(c.sameSite) && !c.secure)
      issues.push(`"${c.name}" uses SameSite=None without Secure (invalid)`);
    if (c.domain && c.domain.startsWith(".")) {
      // broad domain scope — worth noting, not necessarily wrong
      issues.push(`"${c.name}" is scoped to a broad domain (${c.domain})`);
    }
    // could also flag session cookies that never expire
    // if (!c.expires && !c.maxAge) issues.push(`"${c.name}" has no expiry (session cookie)`);
  }

  return {
    count: cookies.length,
    cookies,
    issues,
  };
}

// parse one set-cookie string into a structured object
function parseCookie(raw) {
  if (!raw || typeof raw !== "string") return null;
  const parts = raw.split(";").map((p) => p.trim());
  const [nameValue, ...attrs] = parts;
  const eq = nameValue.indexOf("=");
  if (eq === -1) return null;

  const cookie = {
    name: nameValue.slice(0, eq).trim(),
    valuePreview: maskValue(nameValue.slice(eq + 1).trim()),
    secure: false,
    httpOnly: false,
    sameSite: null,
    domain: null,
    path: null,
    expires: null,
    maxAge: null,
  };

  for (const attr of attrs) {
    const [k, v = ""] = attr.split("=");
    switch (k.toLowerCase()) {
      case "secure":
        cookie.secure = true;
        break;
      case "httponly":
        cookie.httpOnly = true;
        break;
      case "samesite":
        cookie.sameSite = v.trim() || "(empty)";
        break;
      case "domain":
        cookie.domain = v.trim();
        break;
      case "path":
        cookie.path = v.trim();
        break;
      case "expires":
        cookie.expires = v.trim();
        break;
      case "max-age":
        cookie.maxAge = v.trim();
        break;
    }
  }
  return cookie;
}

// don't echo full cookie values into reports — show length + a short prefix
function maskValue(value) {
  if (!value) return "(empty)";
  if (value.length <= 6) return "•".repeat(value.length);
  return value.slice(0, 3) + "…" + `(${value.length} chars)`;
}
