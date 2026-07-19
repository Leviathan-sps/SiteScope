// fetches a url and returns the raw response the analyzers need:
// final url, status, headers, set-cookie, body, timing

// normalize input into a full url ("example.com" -> "https://example.com")
export function normalizeUrl(input) {
  let url = String(input).trim();
  if (!/^https?:\/\//i.test(url)) {
    url = "https://" + url;
  }
  // throws if still invalid
  return new URL(url).toString();
}

// same ceiling browsers use, so a redirect loop fails instead of hanging
const MAX_REDIRECTS = 20;

const isRedirect = (status) => status >= 300 && status < 400;

// one hop, plus the two things about a hop that actually matter
function hopInfo(from, to, status) {
  let fromUrl, toUrl;
  try { fromUrl = new URL(from); toUrl = new URL(to); } catch { return { from, to, status }; }
  return {
    from,
    to,
    status,
    // https -> http. anything sent on the next request is in the clear.
    downgrade: fromUrl.protocol === "https:" && toUrl.protocol === "http:",
    crossHost: fromUrl.host !== toUrl.host,
  };
}

// fetch a page (following redirects) and collect what the analyzers need.
// uses global fetch (node 18+), no third-party deps
export async function fetchSite(input, opts = {}) {
  const { timeout = 15000, userAgent = defaultUserAgent() } = opts;
  const requestedUrl = normalizeUrl(input);

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  const startedAt = nowMs();

  try {
    // follow redirects by hand so each hop can be recorded. "follow" hides
    // the chain entirely, and the hops are where downgrades and surprise
    // cross-domain jumps show up.
    const chain = [];
    let currentUrl = requestedUrl;
    let res;

    for (let hop = 0; ; hop++) {
      if (hop > MAX_REDIRECTS) throw new Error(`Too many redirects (>${MAX_REDIRECTS}): ${requestedUrl}`);
      res = await fetch(currentUrl, {
        method: "GET",
        redirect: "manual",
        signal: controller.signal,
        headers: {
          "user-agent": userAgent,
          accept:
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
          "accept-language": "en-US,en;q=0.9",
        },
      });

      const location = res.headers.get("location");
      if (!isRedirect(res.status) || !location) break;

      let next;
      try { next = new URL(location, currentUrl).toString(); }
      catch { break; } // malformed Location — treat this as the final stop
      chain.push(hopInfo(currentUrl, next, res.status));
      currentUrl = next;
    }

    const body = await res.text();
    const elapsedMs = Math.round(nowMs() - startedAt);

    // flatten headers to a plain object; node has getSetCookie() for the combined set-cookie
    const headers = {};
    for (const [k, v] of res.headers.entries()) {
      if (k.toLowerCase() === "set-cookie") continue; // handled separately
      headers[k] = v;
    }
    const setCookie =
      typeof res.headers.getSetCookie === "function"
        ? res.headers.getSetCookie()
        : splitSetCookie(res.headers.get("set-cookie"));

    return {
      requestedUrl,
      finalUrl: currentUrl,
      redirected: chain.length > 0,
      redirectChain: chain,
      // a downgrade anywhere in the chain means credentials rode over http
      insecureHop: chain.some((h) => h.downgrade),
      status: res.status,
      statusText: res.statusText,
      ok: res.ok,
      headers,
      setCookie,
      body,
      contentType: res.headers.get("content-type") || "",
      bytes: Buffer.byteLength(body, "utf8"),
      elapsedMs,
    };
  } catch (err) {
    if (err.name === "AbortError") {
      throw new Error(`Request timed out after ${timeout}ms: ${requestedUrl}`);
    }
    throw new Error(`Failed to fetch ${requestedUrl}: ${err.message}`);
  } finally {
    clearTimeout(timer);
  }
}

function defaultUserAgent() {
  return "SiteScope/1.0 (+https://github.com/; site inspector)";
}

// maybe surface the final protocol so callers can flag http-only sites
// function isSecure(url) {
//   return new URL(url).protocol === "https:";
// }

// best-effort split of a combined set-cookie header (fallback only)
function splitSetCookie(value) {
  if (!value) return [];
  // split on commas before a "name=" token, skipping commas inside expires dates
  return value.split(/,(?=\s*[^=;,\s]+=)/).map((c) => c.trim());
}

function nowMs() {
  return Number(process.hrtime.bigint() / 1000000n);
}
