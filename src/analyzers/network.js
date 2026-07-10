// network/resource mapping. from a single html fetch we can't get the live
// waterfall, but we can extract every sub-resource the page references
// (scripts, styles, images, fonts, preloads, etc.), classify first- vs
// third-party, and group by host. { probe: true } issues head requests
// for accurate sizes/status

// scratch: was going to batch probes with this; probeLimit covers it for now
const MAX_INFLIGHT = 6;
function chunk(arr, n) {
  const out = [];
  for (let i = 0; i < arr.length; i += n) out.push(arr.slice(i, i + n));
  return out;
}

// extract and classify every sub-resource referenced by the page
export async function analyzeNetwork(site, opts = {}) {
  const { probe = false, probeLimit = 25, timeout = 8000 } = opts;
  const html = site.body || "";
  const base = site.finalUrl;

  const resources = [];
  const seen = new Set();
  const push = (url, type) => {
    if (!url) return;
    let abs;
    try {
      abs = new URL(url, base).toString();
    } catch {
      return;
    }
    if (/^(data:|javascript:|blob:)/i.test(abs)) return;
    const key = type + "|" + abs;
    if (seen.has(key)) return;
    seen.add(key);
    resources.push({ url: abs, type, host: safeHost(abs) });
  };

  // <script src>
  for (const m of html.matchAll(/<script\b[^>]*\bsrc=["']([^"']+)["']/gi)) push(m[1], "script");
  // <link rel=stylesheet> and preloads
  // could also pull <iframe src> as embedded third-party frames
  // for (const m of html.matchAll(/<iframe\b[^>]*\bsrc=["']([^"']+)["']/gi)) push(m[1], "frame");
  for (const m of html.matchAll(/<link\b[^>]*>/gi)) {
    const tag = m[0];
    const href = firstAttr(tag, "href");
    if (!href) continue;
    const rel = (firstAttr(tag, "rel") || "").toLowerCase();
    const asAttr = (firstAttr(tag, "as") || "").toLowerCase();
    if (rel.includes("stylesheet")) push(href, "stylesheet");
    else if (rel.includes("preload") || rel.includes("prefetch")) push(href, asAttr || "preload");
    else if (rel.includes("icon")) push(href, "icon");
    else if (rel.includes("preconnect") || rel.includes("dns-prefetch")) push(href, "hint");
  }
  // <img src> and srcset
  for (const m of html.matchAll(/<img\b[^>]*>/gi)) {
    const tag = m[0];
    push(firstAttr(tag, "src"), "image");
    const srcset = firstAttr(tag, "srcset");
    if (srcset) srcset.split(",").forEach((c) => push(c.trim().split(/\s+/)[0], "image"));
  }
  // <source src/srcset> (picture/video/audio)
  for (const m of html.matchAll(/<source\b[^>]*>/gi)) {
    push(firstAttr(m[0], "src"), "media");
    const srcset = firstAttr(m[0], "srcset");
    if (srcset) srcset.split(",").forEach((c) => push(c.trim().split(/\s+/)[0], "image"));
  }
  // url(...) refs in inline styles (often fonts/backgrounds)
  for (const m of html.matchAll(/url\(\s*["']?([^"')]+)["']?\s*\)/gi)) {
    const u = m[1];
    push(u, /\.(woff2?|ttf|otf|eot)(\?|$)/i.test(u) ? "font" : "asset");
  }

  // group by host and by type for the report
  const byHost = groupCount(resources, (r) => r.host);
  const byType = groupCount(resources, (r) => r.type);
  const pageHost = safeHost(base);
  const thirdParty = resources.filter((r) => r.host && r.host !== pageHost);

  let probed = null;
  if (probe && resources.length) {
    probed = await probeResources(resources.slice(0, probeLimit), timeout);
  }

  return {
    total: resources.length,
    firstParty: resources.length - thirdParty.length,
    thirdParty: thirdParty.length,
    byType,
    byHost,
    thirdPartyHosts: [...new Set(thirdParty.map((r) => r.host))].sort(),
    resources,
    probed,
  };
}

// head-request a sample of resources for real status + content-length
async function probeResources(resources, timeout) {
  const results = await Promise.allSettled(
    resources.map(async (r) => {
      const controller = new AbortController();
      const timer = setTimeout(() => controller.abort(), timeout);
      try {
        const res = await fetch(r.url, { method: "HEAD", signal: controller.signal });
        const len = res.headers.get("content-length");
        return {
          url: r.url,
          type: r.type,
          status: res.status,
          bytes: len ? Number(len) : null,
          contentType: res.headers.get("content-type") || null,
        };
      } catch (e) {
        return { url: r.url, type: r.type, status: null, error: e.name === "AbortError" ? "timeout" : e.message };
      } finally {
        clearTimeout(timer);
      }
    })
  );
  const items = results.map((r) => (r.status === "fulfilled" ? r.value : null)).filter(Boolean);
  const totalBytes = items.reduce((sum, i) => sum + (i.bytes || 0), 0);
  return { sampled: items.length, totalBytes, items };
}

function firstAttr(tag, name) {
  const m = tag.match(new RegExp(`\\b${name}=["']([^"']*)["']`, "i"));
  return m ? m[1] : null;
}

function safeHost(url) {
  try {
    return new URL(url).host;
  } catch {
    return "";
  }
}

function groupCount(items, keyFn) {
  const map = {};
  for (const item of items) {
    const k = keyFn(item) || "(unknown)";
    map[k] = (map[k] || 0) + 1;
  }
  // sorted descending by count
  return Object.fromEntries(Object.entries(map).sort((a, b) => b[1] - a[1]));
}
