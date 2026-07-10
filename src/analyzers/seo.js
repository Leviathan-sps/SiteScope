// seo / metadata analysis. pulls common on-page signals out of the html
// with lightweight regex parsing (no dom dependency) and runs basic checks

// first pass used a naive whole-html title grab; kept until the head-scoped
// extractor is proven out on more pages
// function rawTitle(html) {
//   const m = html.match(/<title>(.*?)<\/title>/i);
//   return m ? m[1].trim() : "";
// }

// extract on-page seo signals and run the checks
export function analyzeSeo(site) {
  const html = site.body || "";
  const head = extractHead(html);

  const title = firstMatch(head, /<title[^>]*>([\s\S]*?)<\/title>/i);
  const metaDescription = metaContent(head, "description");
  const canonical = linkHref(head, "canonical");
  const robots = metaContent(head, "robots");
  const viewport = metaContent(head, "viewport");
  const charset =
    firstMatch(head, /<meta[^>]+charset=["']?([\w-]+)/i) ||
    (/(application\/xhtml|charset=)/i.test(site.contentType || "") ? null : null);
  const lang = firstMatch(html, /<html[^>]+lang=["']([^"']+)["']/i);

  const openGraph = collectMeta(head, /property=["']og:([^"']+)["']/gi);
  const twitter = collectMeta(head, /name=["']twitter:([^"']+)["']/gi);

  const headings = countHeadings(html);
  const images = [...html.matchAll(/<img\b[^>]*>/gi)].map((m) => m[0]);
  const imagesMissingAlt = images.filter(
    (img) => !/\balt\s*=/i.test(img)
  ).length;

  const links = [...html.matchAll(/<a\b[^>]+href=["']([^"']+)["']/gi)].map(
    (m) => m[1]
  );
  const { internal, external } = classifyLinks(links, site.finalUrl);

  // build a list of pass/warn checks for the report
  const checks = [];
  const t = (cond, ok, warn) => checks.push({ pass: cond, label: cond ? ok : warn });

  t(!!title, "Has <title>", "Missing <title>");
  if (title) {
    const len = decodeEntities(title).trim().length;
    t(len >= 10 && len <= 65, `Title length OK (${len} chars)`, `Title length ${len} (aim for 10–65)`);
  }
  t(!!metaDescription, "Has meta description", "Missing meta description");
  if (metaDescription) {
    const len = metaDescription.length;
    t(len >= 50 && len <= 160, `Description length OK (${len})`, `Description length ${len} (aim for 50–160)`);
  }
  t(!!canonical, "Has canonical URL", "No canonical link");
  t(!!viewport, "Has viewport meta", "No viewport meta (mobile)");
  t(!!lang, "Has <html lang>", "No lang attribute on <html>");
  t(headings.h1 === 1, `Exactly one <h1>`, `Found ${headings.h1} <h1> (expected 1)`);
  t(imagesMissingAlt === 0, "All images have alt text", `${imagesMissingAlt}/${images.length} images missing alt`);
  t(openGraph.length > 0, `Open Graph tags present (${openGraph.length})`, "No Open Graph tags");
  // could also check for a json-ld structured data block
  // t(/<script[^>]+type=["']application\/ld\+json["']/i.test(head), "Has JSON-LD", "No JSON-LD structured data");

  const score = Math.round((checks.filter((c) => c.pass).length / checks.length) * 100);

  return {
    score,
    title: title ? decodeEntities(title).trim() : null,
    metaDescription,
    canonical,
    robots,
    viewport,
    charset,
    lang,
    openGraph,
    twitter,
    headings,
    images: { total: images.length, missingAlt: imagesMissingAlt },
    links: { total: links.length, internal: internal.length, external: external.length },
    checks,
  };
}

function extractHead(html) {
  const m = html.match(/<head[^>]*>([\s\S]*?)<\/head>/i);
  return m ? m[1] : html;
}

function firstMatch(s, re) {
  const m = s.match(re);
  return m ? m[1] : null;
}

function metaContent(head, name) {
  // handles both attribute orders: name before content and vice versa
  const re1 = new RegExp(
    `<meta[^>]+name=["']${name}["'][^>]+content=["']([^"']*)["']`,
    "i"
  );
  const re2 = new RegExp(
    `<meta[^>]+content=["']([^"']*)["'][^>]+name=["']${name}["']`,
    "i"
  );
  const m = head.match(re1) || head.match(re2);
  return m ? decodeEntities(m[1]).trim() : null;
}

function linkHref(head, rel) {
  const re1 = new RegExp(`<link[^>]+rel=["']${rel}["'][^>]+href=["']([^"']+)["']`, "i");
  const re2 = new RegExp(`<link[^>]+href=["']([^"']+)["'][^>]+rel=["']${rel}["']`, "i");
  const m = head.match(re1) || head.match(re2);
  return m ? m[1] : null;
}

function collectMeta(head, globalRe) {
  const out = [];
  for (const m of head.matchAll(globalRe)) {
    const key = m[1];
    // find the content for this specific tag
    const tag = head.slice(m.index, head.indexOf(">", m.index) + 1);
    const content = firstMatch(tag, /content=["']([^"']*)["']/i);
    out.push({ key, content: content ? decodeEntities(content).trim() : "" });
  }
  return out;
}

function countHeadings(html) {
  const counts = { h1: 0, h2: 0, h3: 0, h4: 0, h5: 0, h6: 0 };
  for (let i = 1; i <= 6; i++) {
    const re = new RegExp(`<h${i}\\b`, "gi");
    counts[`h${i}`] = (html.match(re) || []).length;
  }
  return counts;
}

function classifyLinks(links, baseUrl) {
  const internal = [];
  const external = [];
  let host = "";
  try {
    host = new URL(baseUrl).host;
  } catch {
    /* ignore */
  }
  for (const href of links) {
    if (/^(#|mailto:|tel:|javascript:)/i.test(href)) continue;
    try {
      const u = new URL(href, baseUrl);
      if (u.host === host) internal.push(href);
      else external.push(href);
    } catch {
      internal.push(href); // relative / malformed -> treat as internal
    }
  }
  return { internal, external };
}

// minimal html entity decoding for the handful that show up in titles/descriptions
function decodeEntities(s) {
  return String(s)
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;|&apos;/g, "'")
    .replace(/&nbsp;/g, " ");
}
