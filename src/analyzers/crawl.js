// crawlability: fetches robots.txt and the declared sitemap(s), parses both
// with plain regex (no xml/robots parser dependency), and checks whether the
// page that was just scanned is actually allowed to be crawled.
// bounded to a handful of extra requests: robots.txt, one sitemap, and (if
// that sitemap is an index) one child sitemap for a sample count.

export async function analyzeCrawl(site, opts = {}) {
  const { timeout = 8000 } = opts;
  const base = site.finalUrl;

  const robotsUrl = new URL("/robots.txt", base).toString();
  const robotsRes = await safeFetch(robotsUrl, timeout);

  const checks = [];
  const t = (cond, ok, warn) => checks.push({ pass: cond, label: cond ? ok : warn });

  let robotsTxt = { present: false, status: robotsRes.status, url: robotsUrl, sitemaps: [], groups: [], disallowsAll: false, currentPathDisallowed: null };

  if (robotsRes.ok && robotsRes.body) {
    const parsed = parseRobots(robotsRes.body);
    const group = pickGroup(parsed.groups, "*");
    const path = safePath(base);
    const disallowed = group ? isDisallowed(path, group) : false;
    const disallowsAll = group ? group.disallow.some((p) => p === "/" ) && !group.allow.length : false;

    robotsTxt = {
      present: true,
      status: robotsRes.status,
      url: robotsUrl,
      sitemaps: parsed.sitemaps,
      groups: parsed.groups,
      disallowsAll,
      currentPathDisallowed: disallowed,
    };
  }

  t(robotsTxt.present, "robots.txt found", "No robots.txt (crawlers assume everything is allowed)");
  if (robotsTxt.present) {
    t(!robotsTxt.disallowsAll, "robots.txt does not block the whole site", "robots.txt disallows / for all crawlers");
    t(!robotsTxt.currentPathDisallowed, "Scanned page is crawlable", "Scanned page is disallowed by robots.txt");
    t(robotsTxt.sitemaps.length > 0, "Sitemap declared in robots.txt", "No Sitemap: line in robots.txt");
  }

  // resolve which sitemap to check: prefer the first one robots.txt declares,
  // otherwise fall back to the conventional /sitemap.xml
  const sitemapUrl = robotsTxt.sitemaps[0] || new URL("/sitemap.xml", base).toString();
  const source = robotsTxt.sitemaps[0] ? "robots" : "default";
  const sitemapRes = await safeFetch(sitemapUrl, timeout);

  let sitemap = { present: false, status: sitemapRes.status, url: sitemapUrl, source, isIndex: false, urlCount: null, sampledChildUrlCount: null };

  if (sitemapRes.ok && sitemapRes.body) {
    const isIndex = /<sitemapindex\b/i.test(sitemapRes.body);
    const locs = extractLocs(sitemapRes.body);
    sitemap = { present: true, status: sitemapRes.status, url: sitemapUrl, source, isIndex, urlCount: locs.length, sampledChildUrlCount: null };

    if (isIndex && locs.length) {
      const childRes = await safeFetch(locs[0], timeout);
      if (childRes.ok && childRes.body) {
        sitemap.sampledChildUrlCount = extractLocs(childRes.body).length;
      }
    }
  }

  t(sitemap.present, "Sitemap is reachable", `Sitemap not found at ${source === "robots" ? "declared location" : "/sitemap.xml"}`);
  if (sitemap.present && !sitemap.isIndex) {
    t(sitemap.urlCount > 0, `Sitemap lists ${sitemap.urlCount} URL(s)`, "Sitemap is empty");
  }

  const score = Math.round((checks.filter((c) => c.pass).length / checks.length) * 100);

  return { score, robotsTxt, sitemap, checks };
}

// ---- robots.txt parsing ----

function parseRobots(text) {
  const lines = text.split(/\r?\n/);
  const groups = [];
  const sitemaps = [];
  let current = null;

  for (let raw of lines) {
    const line = raw.replace(/#.*$/, "").trim();
    if (!line) continue;
    const idx = line.indexOf(":");
    if (idx === -1) continue;
    const key = line.slice(0, idx).trim().toLowerCase();
    const value = line.slice(idx + 1).trim();

    if (key === "sitemap") {
      sitemaps.push(value);
      continue;
    }
    if (key === "user-agent") {
      // consecutive user-agent lines (before any rule) belong to the same group
      if (!current || current.rulesStarted) {
        current = { userAgents: [], disallow: [], allow: [], crawlDelay: null, rulesStarted: false };
        groups.push(current);
      }
      current.userAgents.push(value);
      continue;
    }
    if (!current) continue; // rules before any user-agent line are meaningless
    current.rulesStarted = true;
    if (key === "disallow" && value) current.disallow.push(value);
    else if (key === "allow" && value) current.allow.push(value);
    else if (key === "crawl-delay") current.crawlDelay = Number(value) || null;
  }

  for (const g of groups) delete g.rulesStarted;
  return { groups, sitemaps };
}

function pickGroup(groups, ua) {
  return (
    groups.find((g) => g.userAgents.some((u) => u.toLowerCase() === ua.toLowerCase())) ||
    groups.find((g) => g.userAgents.includes("*")) ||
    null
  );
}

// robots.txt path matching: longest-match wins, "*" is a wildcard, trailing
// "$" anchors the end — the de-facto rules most crawlers (incl. Google) use
function isDisallowed(path, group) {
  const rules = [
    ...group.disallow.map((p) => ({ p, allow: false })),
    ...group.allow.map((p) => ({ p, allow: true })),
  ];
  let best = null;
  for (const rule of rules) {
    if (!rule.p) continue;
    if (matchesRobotsPattern(path, rule.p)) {
      if (!best || rule.p.length > best.p.length) best = rule;
    }
  }
  return best ? !best.allow : false;
}

function matchesRobotsPattern(path, pattern) {
  const anchored = pattern.endsWith("$");
  const body = anchored ? pattern.slice(0, -1) : pattern;
  const re = new RegExp("^" + body.split("*").map(escapeRe).join(".*") + (anchored ? "$" : ""));
  return re.test(path);
}

function escapeRe(s) {
  return s.replace(/[.+?^${}()|[\]\\]/g, "\\$&");
}

// ---- sitemap xml parsing ----

function extractLocs(xml) {
  return [...xml.matchAll(/<loc>\s*([^<\s]+)\s*<\/loc>/gi)].map((m) => m[1]);
}

// ---- helpers ----

async function safeFetch(url, timeout) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    const res = await fetch(url, { signal: controller.signal, headers: { accept: "text/plain,application/xml,text/xml,*/*" } });
    const body = res.ok ? await res.text() : null;
    return { ok: res.ok, status: res.status, body };
  } catch (e) {
    return { ok: false, status: null, body: null };
  } finally {
    clearTimeout(timer);
  }
}

function safePath(url) {
  try {
    return new URL(url).pathname || "/";
  } catch {
    return "/";
  }
}
