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

// fetch a page (following redirects) and collect what the analyzers need.
// uses global fetch (node 18+), no third-party deps
export async function fetchSite(input, opts = {}) {
  const { timeout = 15000, userAgent = defaultUserAgent() } = opts;
  const requestedUrl = normalizeUrl(input);

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeout);
  const startedAt = nowMs();

  try {
    const res = await fetch(requestedUrl, {
      method: "GET",
      redirect: "follow",
      signal: controller.signal,
      headers: {
        "user-agent": userAgent,
        accept:
          "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "accept-language": "en-US,en;q=0.9",
      },
    });

    const body = await res.text();
    const elapsedMs = Math.round(nowMs() - startedAt);

    // TODO: temporary debug while wiring the analyzers; strip before release
    if (process.env.SS_DEBUG) {
      console.error(`[fetch] ${res.status} ${res.url || requestedUrl} (${elapsedMs}ms)`);
    }

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
      finalUrl: res.url || requestedUrl,
      redirected: res.redirected || res.url !== requestedUrl,
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
