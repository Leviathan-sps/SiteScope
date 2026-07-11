// Path discovery: probes a curated list of commonly-present or commonly-
// interesting paths (robots.txt, sitemaps, admin panels, exposed configs,
// VCS/dotfiles) and reports the HTTP status of each.
//
// This is ACTIVE reconnaissance — it issues real requests to the target.
// Only run it against systems you own or are explicitly authorized to test.
// The list is intentionally small and curated; this is NOT a brute-force
// wordlist scan. A single fetch cannot enumerate "all directories" — nothing
// can, without guessing — so we check the paths that most often matter.

const PATHS = [
  // Conventional / informational
  { path: "/robots.txt", kind: "info" },
  { path: "/sitemap.xml", kind: "info" },
  { path: "/.well-known/security.txt", kind: "info" },
  { path: "/humans.txt", kind: "info" },
  { path: "/favicon.ico", kind: "info" },
  // App surfaces
  { path: "/admin", kind: "surface" },
  { path: "/login", kind: "surface" },
  { path: "/dashboard", kind: "surface" },
  { path: "/wp-admin/", kind: "surface" },
  { path: "/wp-login.php", kind: "surface" },
  { path: "/api", kind: "surface" },
  { path: "/graphql", kind: "surface" },
  { path: "/status", kind: "surface" },
  { path: "/health", kind: "surface" },
  { path: "/server-status", kind: "surface" },
  // Things that should NOT be reachable — flagged if found
  { path: "/.git/HEAD", kind: "sensitive" },
  { path: "/.env", kind: "sensitive" },
  { path: "/.DS_Store", kind: "sensitive" },
  { path: "/config.json", kind: "sensitive" },
  { path: "/phpinfo.php", kind: "sensitive" },
  { path: "/backup.zip", kind: "sensitive" },
  { path: "/.htaccess", kind: "sensitive" },
  // more paths worth checking on bigger targets — kept off to keep it quick
  // { path: "/.svn/entries", kind: "sensitive" },
  // { path: "/web.config", kind: "sensitive" },
  // { path: "/.aws/credentials", kind: "sensitive" },
];

/**
 * @param {string} baseUrl
 * @param {{ timeout?:number, userAgent?:string, concurrency?:number }} [opts]
 */
export async function scanPaths(baseUrl, opts = {}) {
  const timeout = opts.timeout || 8000;
  const concurrency = opts.concurrency || 6;
  const ua = opts.userAgent || "SiteScope/1.0 (+path-check)";

  const queue = [...PATHS];
  const results = [];
  async function worker() {
    let item;
    while ((item = queue.shift())) {
      results.push(await probe(baseUrl, item, timeout, ua));
    }
  }
  await Promise.all(Array.from({ length: concurrency }, worker));

  // Preserve the declared order for stable reports.
  const order = new Map(PATHS.map((p, i) => [p.path, i]));
  results.sort((a, b) => order.get(a.path) - order.get(b.path));

  const exists = (r) => r.status && r.status < 400;
  const found = results.filter(exists);
  // 401/403 still confirm the path is *there*, just protected.
  const present = results.filter((r) => r.status && (r.status < 400 || r.status === 401 || r.status === 403));
  const exposedSensitive = results.filter((r) => r.kind === "sensitive" && exists(r));

  return {
    base: baseUrl,
    checked: results.length,
    results,
    found,
    present,
    exposedSensitive,
  };
}

async function probe(baseUrl, item, timeout, ua) {
  let url;
  try { url = new URL(item.path, baseUrl).toString(); }
  catch { return { ...item, url: item.path, status: null, error: "bad url" }; }

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  try {
    // GET (not HEAD) — many servers mishandle HEAD. We don't read the body,
    // so this stays light; redirect:manual so a catch-all 200 doesn't mask 404s.
    const res = await fetch(url, {
      method: "GET",
      redirect: "manual",
      signal: controller.signal,
      headers: { "user-agent": ua },
    });
    return {
      ...item,
      url,
      status: res.status,
      contentType: res.headers.get("content-type") || null,
      length: res.headers.get("content-length") || null,
      location: res.headers.get("location") || null,
    };
  } catch (e) {
    return { ...item, url, status: null, error: e.name === "AbortError" ? "timeout" : "unreachable" };
  } finally {
    clearTimeout(timer);
  }
}
