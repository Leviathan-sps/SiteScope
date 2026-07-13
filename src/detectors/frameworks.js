// framework / library / tooling detection from the raw html and headers.
// each signature is a list of regexes; any match adds the tech with a
// confidence and the evidence that triggered it. no external requests.
// signatures can also carry a version(html, headers) extractor — best-effort,
// only fills in when a version number is actually visible in a filename,
// CDN url, or generator meta tag.

const SIGNATURES = [
  // ---- meta frameworks (check before their base library so we can note both) ----
  {
    name: "Next.js",
    category: "Meta Framework",
    html: [
      { re: /<script[^>]+id=["']__NEXT_DATA__["']/i, why: "__NEXT_DATA__ script tag" },
      { re: /\/_next\/static\//i, why: "/_next/static/ asset path" },
      { re: /<div[^>]+id=["']__next["']/i, why: "#__next root element" },
    ],
    headers: [{ name: "x-powered-by", re: /next\.js/i, why: "x-powered-by: Next.js" }],
  },
  {
    name: "Nuxt.js",
    category: "Meta Framework",
    html: [
      { re: /id=["']__nuxt["']/i, why: "#__nuxt root element" },
      { re: /window\.__NUXT__/i, why: "window.__NUXT__ state" },
      { re: /\/_nuxt\//i, why: "/_nuxt/ asset path" },
    ],
  },
  {
    name: "Gatsby",
    category: "Meta Framework",
    html: [
      { re: /id=["']___gatsby["']/i, why: "#___gatsby root element" },
      { re: /\/page-data\/.+\.json/i, why: "Gatsby page-data" },
    ],
  },
  {
    name: "Remix",
    category: "Meta Framework",
    html: [
      { re: /window\.__remixContext/i, why: "__remixContext" },
      { re: /\/build\/_shared\//i, why: "Remix build path" },
    ],
  },
  {
    name: "SvelteKit",
    category: "Meta Framework",
    html: [
      { re: /\/_app\/immutable\//i, why: "/_app/immutable/ asset path" },
      { re: /__sveltekit_/i, why: "__sveltekit_ runtime" },
    ],
  },
  {
    name: "Astro",
    category: "Meta Framework",
    html: [
      { re: /<astro-island/i, why: "<astro-island> element" },
      { re: /astro-[a-z0-9]+/i, why: "astro-* scoped attribute" },
    ],
  },
  {
    name: "Qwik",
    category: "Meta Framework",
    html: [
      { re: /\bq:container\b/i, why: "q:container attribute" },
      { re: /qwikloader/i, why: "qwikloader runtime" },
    ],
  },

  // ---- base js frameworks / libraries ----
  {
    name: "React",
    category: "JS Framework",
    html: [
      { re: /data-reactroot|data-reactid/i, why: "data-react* attribute" },
      { re: /\b_?react(?:-dom)?(?:\.production|\.development)?\.min\.js/i, why: "react script bundle" },
      { re: /__REACT_DEVTOOLS_GLOBAL_HOOK__/i, why: "React DevTools hook" },
    ],
    version: (html) => versionFromCdn(html, "react"),
  },
  {
    name: "Vue.js",
    category: "JS Framework",
    html: [
      { re: /data-v-[0-9a-f]{8}/i, why: "data-v-* scoped style id" },
      { re: /<[^>]+\sv-(?:if|for|bind|on|model|show)\b/i, why: "v-* directive" },
      { re: /\bvue(?:\.runtime)?(?:\.global|\.esm-browser)?(?:\.prod)?\.js/i, why: "vue script bundle" },
      { re: /id=["']app["'][^>]*>\s*<!--\[-->/i, why: "Vue hydration markers" },
    ],
    version: (html) => versionFromCdn(html, "vue"),
  },
  {
    name: "Angular",
    category: "JS Framework",
    html: [
      { re: /\sng-version=["']([\d.]+)["']/i, why: "ng-version attribute" },
      { re: /<[^>]+\s_ngcontent-/i, why: "_ngcontent-* attribute" },
      { re: /\bzone\.js\b/i, why: "zone.js runtime" },
    ],
    version: (html) => firstMatch(html, /\sng-version=["']([\d.]+)["']/i),
  },
  {
    name: "Svelte",
    category: "JS Framework",
    html: [{ re: /\bsvelte-[0-9a-z]{6,}\b/i, why: "svelte-* scoped class" }],
  },
  {
    name: "Preact",
    category: "JS Framework",
    html: [{ re: /\bpreact(?:\.min)?\.js\b/i, why: "preact bundle" }],
    version: (html) => versionFromCdn(html, "preact"),
  },
  {
    name: "Alpine.js",
    category: "JS Framework",
    html: [
      { re: /\sx-data\b/i, why: "x-data directive" },
      { re: /\balpinejs\b/i, why: "alpinejs script" },
    ],
    version: (html) => versionFromCdn(html, "alpinejs"),
  },
  {
    name: "HTMX",
    category: "JS Library",
    html: [
      { re: /\shx-(?:get|post|put|delete|patch|boost|target|swap|trigger)\s*=/i, why: "hx-* attribute" },
      { re: /\bhtmx(?:\.min)?\.js\b/i, why: "htmx script" },
    ],
    version: (html) => versionFromCdn(html, "htmx.org") || versionFromCdn(html, "htmx"),
  },
  {
    name: "jQuery",
    category: "JS Library",
    html: [{ re: /jquery[-.]?(\d+\.\d+\.\d+)?(?:\.min)?\.js/i, why: "jquery script" }],
    version: (html) => firstMatch(html, /jquery[-.](\d+\.\d+\.\d+)(?:\.min)?\.js/i) || versionFromCdn(html, "jquery"),
  },

  // ---- cms / platforms ----
  {
    name: "WordPress",
    category: "CMS",
    html: [
      { re: /\/wp-content\//i, why: "/wp-content/ path" },
      { re: /\/wp-includes\//i, why: "/wp-includes/ path" },
      { re: /<meta[^>]+name=["']generator["'][^>]+WordPress/i, why: "generator meta" },
    ],
    version: (html) => firstMatch(html, /<meta[^>]+name=["']generator["'][^>]+content=["']WordPress\s+([\d.]+)/i),
  },
  {
    name: "Shopify",
    category: "E-commerce",
    html: [
      { re: /cdn\.shopify\.com/i, why: "cdn.shopify.com asset" },
      { re: /Shopify\.theme/i, why: "Shopify.theme object" },
    ],
  },
  {
    name: "Wix",
    category: "Website Builder",
    html: [{ re: /static\.wixstatic\.com|X-Wix-/i, why: "Wix static assets" }],
  },
  {
    name: "Webflow",
    category: "Website Builder",
    html: [{ re: /data-wf-page|data-wf-site|webflow\.js/i, why: "Webflow attributes" }],
  },
  {
    name: "Squarespace",
    category: "Website Builder",
    html: [
      { re: /static1\.squarespace\.com/i, why: "static1.squarespace.com asset" },
      { re: /<meta[^>]+name=["']generator["'][^>]+Squarespace/i, why: "generator meta" },
    ],
  },
  {
    name: "Ghost",
    category: "CMS",
    html: [
      { re: /<meta[^>]+name=["']generator["'][^>]+content=["']Ghost\s*([\d.]*)/i, why: "generator meta" },
      { re: /\/ghost\/api\//i, why: "/ghost/api/ path" },
    ],
    version: (html) => firstMatch(html, /<meta[^>]+name=["']generator["'][^>]+content=["']Ghost\s+([\d.]+)/i),
  },
  {
    name: "Drupal",
    category: "CMS",
    html: [
      { re: /<meta[^>]+name=["']generator["'][^>]+content=["']Drupal\s*([\d.]*)/i, why: "generator meta" },
      { re: /Drupal\.settings/i, why: "Drupal.settings object" },
      { re: /\/sites\/(?:default|all)\/(?:files|modules|themes)\//i, why: "Drupal sites/ path" },
    ],
    version: (html) => firstMatch(html, /<meta[^>]+name=["']generator["'][^>]+content=["']Drupal\s+([\d.]+)/i),
  },
  {
    name: "Joomla",
    category: "CMS",
    html: [{ re: /<meta[^>]+name=["']generator["'][^>]+content=["']Joomla/i, why: "generator meta" }],
  },
  {
    name: "Magento",
    category: "E-commerce",
    html: [
      { re: /Mage\.Cookies|Magento_/i, why: "Magento JS namespace" },
      { re: /\/skin\/frontend\//i, why: "/skin/frontend/ path" },
    ],
  },
  {
    name: "BigCommerce",
    category: "E-commerce",
    html: [{ re: /cdn\d*\.bigcommerce\.com/i, why: "bigcommerce cdn asset" }],
  },

  // ---- bundlers / tooling ----
  {
    name: "Vite",
    category: "Build Tool",
    html: [
      { re: /\/@vite\/client/i, why: "@vite/client (dev)" },
      { re: /type=["']module["'][^>]+\/assets\/index-[a-z0-9]+\.js/i, why: "Vite hashed module" },
    ],
  },
  {
    name: "webpack",
    category: "Build Tool",
    html: [{ re: /webpackJsonp|__webpack_require__/i, why: "webpack runtime" }],
  },

  // ---- css frameworks ----
  // distinctive, low-collision class patterns to avoid false positives
  // (generic names like "container"/"row"/"flex" are shared by many sites)
  {
    name: "Tailwind CSS",
    category: "CSS Framework",
    html: [
      // color-scale utils (bg-blue-500) and responsive prefixes (md:flex) are
      // strongly tailwind-specific; bare "flex"/"grid" are not
      { re: /\b(?:bg|text|border|ring)-(?:slate|gray|zinc|neutral|stone|red|orange|amber|yellow|lime|green|emerald|teal|cyan|sky|blue|indigo|violet|purple|fuchsia|pink|rose)-\d{2,3}\b/, why: "Tailwind color-scale utility" },
      { re: /\b(?:sm|md|lg|xl|2xl):(?:flex|grid|hidden|block|w-|h-|px-|py-|text-)/, why: "Tailwind responsive prefix" },
    ],
  },
  {
    name: "Bootstrap",
    category: "CSS Framework",
    html: [
      { re: /bootstrap(?:\.min)?\.(?:css|js)/i, why: "bootstrap asset" },
      // require the responsive grid column form (col-md-6); "container"/"row" collide too often
      { re: /class=["'][^"']*\bcol-(?:xs|sm|md|lg|xl)-\d+\b/i, why: "Bootstrap responsive grid columns" },
    ],
    version: (html) => versionFromCdn(html, "bootstrap"),
  },

  // ---- analytics / tag managers ----
  {
    name: "Google Tag Manager",
    category: "Analytics",
    html: [{ re: /googletagmanager\.com\/gtm\.js/i, why: "gtm.js loader" }],
  },
  {
    name: "Google Analytics",
    category: "Analytics",
    html: [
      { re: /googletagmanager\.com\/gtag\/js/i, why: "gtag.js loader (GA4)" },
      { re: /google-analytics\.com\/analytics\.js/i, why: "analytics.js loader (Universal Analytics)" },
    ],
  },
  {
    name: "Sentry",
    category: "Monitoring",
    html: [
      { re: /browser\.sentry-cdn\.com/i, why: "sentry-cdn asset" },
      { re: /Sentry\.init\s*\(/i, why: "Sentry.init(...) call" },
    ],
  },
  {
    name: "Stripe",
    category: "Payments",
    html: [{ re: /js\.stripe\.com/i, why: "js.stripe.com asset" }],
  },

  // ---- bot / abuse protection ----
  {
    name: "Cloudflare Turnstile",
    category: "Bot Protection",
    html: [{ re: /challenges\.cloudflare\.com\/turnstile/i, why: "turnstile script" }],
  },
  {
    name: "hCaptcha",
    category: "Bot Protection",
    html: [{ re: /hcaptcha\.com/i, why: "hcaptcha script" }],
  },
  {
    name: "reCAPTCHA",
    category: "Bot Protection",
    html: [{ re: /google\.com\/recaptcha/i, why: "recaptcha script" }],
  },

  // ---- cdns (asset delivery, distinct from hosting) ----
  {
    name: "jsDelivr",
    category: "CDN",
    html: [{ re: /cdn\.jsdelivr\.net/i, why: "cdn.jsdelivr.net asset" }],
  },
  {
    name: "unpkg",
    category: "CDN",
    html: [{ re: /unpkg\.com/i, why: "unpkg.com asset" }],
  },
  {
    name: "cdnjs",
    category: "CDN",
    html: [{ re: /cdnjs\.cloudflare\.com/i, why: "cdnjs.cloudflare.com asset" }],
  },
];

// server / hosting tech detected purely from response headers
const HEADER_TECH = [
  { name: "Cloudflare", category: "CDN", header: "server", re: /cloudflare/i },
  { name: "Vercel", category: "Hosting", header: "server", re: /vercel/i },
  { name: "Vercel", category: "Hosting", header: "x-vercel-id", re: /.+/ },
  { name: "Netlify", category: "Hosting", header: "server", re: /netlify/i },
  { name: "Nginx", category: "Web Server", header: "server", re: /nginx/i },
  { name: "Apache", category: "Web Server", header: "server", re: /apache/i },
  { name: "AWS", category: "Hosting", header: "server", re: /amazons3|awselb/i },
  { name: "Express", category: "Backend", header: "x-powered-by", re: /express/i },
  { name: "PHP", category: "Backend", header: "x-powered-by", re: /php/i },
  { name: "ASP.NET", category: "Backend", header: "x-powered-by", re: /asp\.net/i },
];

// backend tech that leaks through session-cookie naming conventions
const COOKIE_TECH = [
  { name: "Laravel", category: "Backend", re: /^(laravel_session|XSRF-TOKEN)$/i },
  { name: "Express", category: "Backend", re: /^connect\.sid$/i },
  { name: "Django", category: "Backend", re: /^(csrftoken|sessionid)$/i },
  { name: "ASP.NET", category: "Backend", re: /^ASP\.NET_SessionId$/i },
  { name: "Java / JSP", category: "Backend", re: /^JSESSIONID$/i },
  { name: "PHP", category: "Backend", re: /^PHPSESSID$/i },
];

// run all detections against the fetched site
export function detectFrameworks(site) {
  const html = site.body || "";
  const headers = lowerKeys(site.headers || {});
  const cookieNames = (site.setCookie || []).map((c) => (c.split("=")[0] || "").trim()).filter(Boolean);
  const found = new Map();

  const add = (name, category, why) => {
    const existing = found.get(name);
    if (existing) {
      if (!existing.evidence.includes(why)) existing.evidence.push(why);
      // more than one signal => bump confidence
      if (existing.evidence.length >= 2) existing.confidence = "high";
      return;
    }
    found.set(name, { name, category, confidence: "medium", evidence: [why], version: null });
  };

  for (const sig of SIGNATURES) {
    let matched = false;
    for (const { re, why } of sig.html || []) {
      if (re.test(html)) { add(sig.name, sig.category, why); matched = true; }
    }
    for (const h of sig.headers || []) {
      const val = headers[h.name];
      if (val && h.re.test(val)) {
        add(sig.name, sig.category, h.why);
        // a header signal is strong evidence on its own
        found.get(sig.name).confidence = "high";
        matched = true;
      }
    }
    if (matched && sig.version) {
      const v = sig.version(html, headers);
      if (v) found.get(sig.name).version = v;
    }
  }

  for (const t of HEADER_TECH) {
    const val = headers[t.header];
    if (val && t.re.test(val)) {
      add(t.name, t.category, `${t.header}: ${truncate(val, 40)}`);
      found.get(t.name).confidence = "high";
    }
  }

  for (const t of COOKIE_TECH) {
    const hit = cookieNames.find((n) => t.re.test(n));
    if (hit) add(t.name, t.category, `"${hit}" cookie`);
  }

  // a meta framework implies its base library — note it if not already flagged
  if (found.has("Next.js") && !found.has("React")) {
    add("React", "JS Framework", "implied by Next.js");
  }
  if ((found.has("Nuxt.js")) && !found.has("Vue.js")) {
    add("Vue.js", "JS Framework", "implied by Nuxt.js");
  }
  if (found.has("Gatsby") && !found.has("React")) {
    add("React", "JS Framework", "implied by Gatsby");
  }

  return [...found.values()].sort((a, b) => a.category.localeCompare(b.category));
}

// best-effort version sniff for libraries commonly loaded from a public CDN
// url, e.g. cdn.jsdelivr.net/npm/react@18.2.0 or unpkg.com/vue@3.4.21
function versionFromCdn(html, pkgName) {
  const re = new RegExp(`(?:jsdelivr\\.net/npm/|unpkg\\.com/|cdnjs\\.cloudflare\\.com/ajax/libs/)${pkgName}(?:@|/)([\\d.]+)`, "i");
  return firstMatch(html, re);
}

function firstMatch(s, re) {
  const m = s.match(re);
  return m && m[1] ? m[1] : null;
}

function lowerKeys(obj) {
  const out = {};
  for (const [k, v] of Object.entries(obj)) out[k.toLowerCase()] = v;
  return out;
}

function truncate(s, n) {
  return s.length > n ? s.slice(0, n - 1) + "…" : s;
}
