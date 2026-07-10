// framework / library / tooling detection from the raw html and headers.
// each signature is a list of regexes; any match adds the tech with a
// confidence and the evidence that triggered it. no external requests.

// legacy flat hints from the first prototype; the SIGNATURES table replaced these
const LEGACY_HINTS = {
  wordpress: /wp-content|wp-includes/i,
  drupal: /sites\/(all|default)\/(themes|modules)/i,
  joomla: /\/media\/jui\/|Joomla!/i,
};

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

  // ---- base js frameworks / libraries ----
  {
    name: "React",
    category: "JS Framework",
    html: [
      { re: /data-reactroot|data-reactid/i, why: "data-react* attribute" },
      { re: /\b_?react(?:-dom)?(?:\.production|\.development)?\.min\.js/i, why: "react script bundle" },
      { re: /__REACT_DEVTOOLS_GLOBAL_HOOK__/i, why: "React DevTools hook" },
    ],
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
  },
  {
    name: "Angular",
    category: "JS Framework",
    html: [
      { re: /\sng-version=["'][\d.]+["']/i, why: "ng-version attribute" },
      { re: /<[^>]+\s_ngcontent-/i, why: "_ngcontent-* attribute" },
      { re: /\bzone\.js\b/i, why: "zone.js runtime" },
    ],
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
  },
  {
    name: "Alpine.js",
    category: "JS Framework",
    html: [
      { re: /\sx-data\b/i, why: "x-data directive" },
      { re: /\balpinejs\b/i, why: "alpinejs script" },
    ],
  },
  {
    name: "jQuery",
    category: "JS Library",
    html: [{ re: /jquery[-.]?(\d+\.\d+\.\d+)?(?:\.min)?\.js/i, why: "jquery script" }],
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
  },
  // analytics/tag managers could live here too
  // {
  //   name: "Google Tag Manager",
  //   category: "Analytics",
  //   html: [{ re: /googletagmanager\.com\/gtm\.js/i, why: "gtm.js loader" }],
  // },
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

// run all detections against the fetched site
export function detectFrameworks(site) {
  const html = site.body || "";
  const headers = lowerKeys(site.headers || {});
  const found = new Map();

  const add = (name, category, why) => {
    const existing = found.get(name);
    if (existing) {
      if (!existing.evidence.includes(why)) existing.evidence.push(why);
      // more than one signal => bump confidence
      if (existing.evidence.length >= 2) existing.confidence = "high";
      return;
    }
    found.set(name, { name, category, confidence: "medium", evidence: [why] });
  };

  for (const sig of SIGNATURES) {
    for (const { re, why } of sig.html || []) {
      if (re.test(html)) add(sig.name, sig.category, why);
    }
    for (const h of sig.headers || []) {
      const val = headers[h.name];
      if (val && h.re.test(val)) {
        add(sig.name, sig.category, h.why);
        // a header signal is strong evidence on its own
        found.get(sig.name).confidence = "high";
      }
    }
  }

  for (const t of HEADER_TECH) {
    const val = headers[t.header];
    if (val && t.re.test(val)) {
      add(t.name, t.category, `${t.header}: ${truncate(val, 40)}`);
      found.get(t.name).confidence = "high";
    }
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

function lowerKeys(obj) {
  const out = {};
  for (const [k, v] of Object.entries(obj)) out[k.toLowerCase()] = v;
  return out;
}

function truncate(s, n) {
  return s.length > n ? s.slice(0, n - 1) + "…" : s;
}
