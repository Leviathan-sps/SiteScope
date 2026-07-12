# SiteScope

**Inspect any website from your terminal.** SiteScope fetches a page once and tells you what it's built with, how secure its headers and cookies are, how well it's optimized for search, and every resource it loads — then hands you a shareable report.

Zero dependencies. Pure Node.js (≥18). Runs anywhere.

```
sitescope vercel.com
```

```
SiteScope report — https://vercel.com/
status 200 · 519972 bytes · 236ms

Technologies
  Tailwind CSS       CSS Framework    high   (Tailwind color-scale utility)
  Vercel             Hosting          high   (server: Vercel)
  React              JS Framework     medium (implied by Next.js)
  Next.js            Meta Framework   high   (/_next/static/ asset path)

Security headers  ■ C (73/100)
  ✔ Strict-Transport-Security (HSTS)
  ▲ Content-Security-Policy (CSP) — uses unsafe-inline/unsafe-eval
  ✘ Permissions-Policy — header not set
  ...
```

## What it does

| Module | What you get |
|---|---|
| **Framework detection** | React, Vue, Angular, Svelte, Preact, Alpine, jQuery; meta-frameworks Next.js, Nuxt, Gatsby, Remix, SvelteKit, Astro; CMS/platforms WordPress, Shopify, Wix, Webflow; build tools Vite/webpack; CSS frameworks Tailwind/Bootstrap; plus server/hosting (Cloudflare, Vercel, Netlify, Nginx, Express…). Each match shows a **confidence** and the **evidence** that triggered it. |
| **Header analysis** | Grades the 6 key security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy) into an **A–F score**, flags weak configs (e.g. `unsafe-inline` CSP), and surfaces server, compression, and caching headers. |
| **Cookie audit** | Parses every `Set-Cookie` and flags missing `Secure` / `HttpOnly` / `SameSite`, invalid `SameSite=None`, and overly broad domain scope. Values are masked. |
| **SEO audit** | Title, meta description (with length checks), canonical, robots, viewport, `lang`, Open Graph + Twitter cards, heading structure, images missing `alt`, internal/external link counts — scored out of 100. |
| **Network map** | Extracts every sub-resource (scripts, styles, images, fonts, preloads, icons), classifies **first- vs third-party**, groups by host and type. `--probe` issues HEAD requests for real sizes & status. |
| **Infrastructure** | Resolves the host to its **IP address(es)**, reverse DNS, and — via a free geo/ASN lookup — **who hosts it and where** (org, ASN, city/country), plus NS/MX records. Runs by default; `--no-geo` skips the outbound lookup. |
| **Deep scan** *(opt-in)* | `--scan-ports` TCP-connect-checks a curated list of common service ports (and flags databases/RDP exposed to the internet); `--scan-paths` probes common/interesting paths (robots, sitemaps, admin panels, and dotfiles like `.git`/`.env` that shouldn't be reachable). **Active — see the note below.** |
| **Reports** | Output as colorized **terminal**, **JSON** (pipe to `jq`), **Markdown** (drop in a PR/doc), or a self-contained **HTML** dashboard. |

> **Deep scan sends real traffic to the target.** `--scan-ports` and `--scan-paths` (and the UI's **deep scan** checkbox) open connections and issue requests to the host. Only use them against systems you own or are explicitly authorized to test. The lists are deliberately small and curated — this is not a brute-force scanner.

## Install / run

No install needed — clone and run with Node 18+:

```bash
node bin/sitescope.js <url>
```

Or link it as a global command:

```bash
npm link          # then:
sitescope <url>
```

## Web UI

Prefer a browser over the terminal? Start the local UI:

```bash
npm run ui        # or: node bin/sitescope-ui.js
```

It opens `http://127.0.0.1:4986` — type a URL, hit **Scan**, and browse the
dashboard. Toggle **probe sizes** for real resource sizes, and download the
report as HTML, Markdown, or JSON. Recent scans are remembered in the URL
field. Options: `--port <n>`, `--no-open`. The server binds to localhost only.

## Usage

```
sitescope <url> [options]

Options:
  --format <fmt>        terminal | json | markdown | html   (default: terminal)
  -o, --output <file>   write the report to a file
  --probe               HEAD-request linked resources for real sizes & status
  --scan-ports          check common service ports on the host (active scan)
  --scan-paths          probe common/interesting paths on the host (active scan)
  --recon               shorthand for --scan-ports --scan-paths
  --no-geo              skip the IP geolocation / hosting lookup
  --timeout <ms>        request timeout in milliseconds       (default: 15000)
  --user-agent <ua>     override the User-Agent header
  --no-color            disable colored terminal output
  -h, --help            show this help
```

### Examples

```bash
# Quick look in the terminal
sitescope example.com

# Markdown report for a PR
sitescope https://vercel.com --format markdown -o report.md

# Shareable HTML dashboard, with real resource sizes
sitescope github.com --format html -o report.html --probe

# Full infrastructure + deep scan of a host you control
sitescope your-own-server.com --recon

# Pull a single field with jq
sitescope news.ycombinator.com --format json | jq '.frameworks[].name'
```

## How it works

SiteScope makes a **single GET request** for the page HTML, then runs every analyzer over that shared response — fast and polite. Framework detection works on HTML signatures + response headers; the network map is parsed statically from the markup (use `--probe` to fetch real sizes).

Because it relies on one server-rendered fetch, it sees what a crawler sees. It does **not** execute JavaScript, so client-only SPAs that render nothing in their initial HTML will show fewer signals — a headless-browser mode is on the roadmap.

## Project layout

```
bin/sitescope.js          CLI entry + arg parsing
src/index.js              orchestrator → builds the report object
src/fetcher.js            single fetch, redirects, timing, cookies
src/detectors/frameworks.js   technology signatures
src/analyzers/headers.js      security-header grading
src/analyzers/cookies.js      Set-Cookie parsing + flags
src/analyzers/seo.js          on-page SEO checks
src/analyzers/network.js      resource extraction + optional probing
src/report.js             terminal / markdown / html renderers
```

## Roadmap

- Headless-browser mode (Playwright) for SPA rendering + real request waterfall
- Lighthouse-style performance budget
- Version detection for libraries (e.g. "React 18.2")
- Compare two URLs / track changes over time
- `robots.txt` + `sitemap.xml` checks

## License

MIT
