# SiteScope

Give it any website, and it'll show you what it's built with, how secure its headers and cookies are, how well it's optimized for search engines, and every resource the page loads. Just run it once and you'll get a clean report that's easy to share with anyone.

No dependencies, just Node.js 18 or newer. Runs pretty much anywhere.

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

## What it gives

**Overall health score.** Rolls every graded module (security, SEO, cookies, performance, crawlability) into a single weighted 0–100 score with an A–F grade, plus a "top issues" list of the worst offenders across all of them.

**Framework detection.** Detects the JS/meta-frameworks, CMS, build tools, analytics, CDNs, and hosting a site runs on, and guesses the backend runtime from its cookies. Each match comes with a confidence level, the evidence behind it, and a version when one's visible.

**Header analysis.** Grades the six security headers that matter most into an A–F score and calls out weak configs like an `unsafe-inline` CSP.

**Cookie audit.** Flags missing `Secure` / `HttpOnly` / `SameSite` attributes and over-broad scoping on every `Set-Cookie`, with values masked so the report is safe to share.

**SEO audit.** Checks title, meta description, canonical, robots, Open Graph + Twitter cards, headings, missing `alt` text, and link counts, scored out of 100.

**Crawlability.** Reads `robots.txt` and its declared sitemaps to check whether the scanned page is allowed to be crawled, flagging a missing sitemap or a site-wide disallow.

**Performance budget.** A static budget read from the resource map (request, script, stylesheet, third-party, and render-blocking counts); add `--probe` for real byte weights.

**Network map.** Lists every sub-resource split first- vs third-party and grouped by host and type. `--probe` fetches the real sizes and status codes.

**Infrastructure.** Resolves the host's IPs, reverse DNS, hosting and geo/ASN (org, city/country), and NS/MX records; `--no-geo` skips the outbound call.

**Deep scan (opt-in).** `--scan-ports` checks for exposed service ports and `--scan-paths` probes sensitive paths like admin panels and `.git`/`.env`. It sends real traffic, so only run it on hosts you're allowed to test.

**Vulnerability check.** Part of the deep scan — flags outdated libraries, exposed services and files, and revealing version banners, ranked worst-first with a severity and a fix. It's a heads-up, not a real audit.

**Reports.** Terminal (colorized), JSON (pipe it to `jq`), Markdown (drop into a PR or doc), or a self-contained HTML dashboard.

## The web UI

If you'd rather stay in a browser, there's a local dashboard. Start it with:

```bash
npm run ui        # or: node bin/sitescope-ui.js
```

That opens `http://127.0.0.1:4986`. Type a URL, hit **Scan**, and click through the tabs. Toggle **probe sizes** for real resource sizes, and grab the report as HTML, Markdown, or JSON from the links up top. Recent scans stick around in the URL field. Options: `--port <n>`, `--no-open`. The server only ever binds to localhost.

An empty scan lands you here:

![SiteScope landing screen](docs/img/landing.png)

The overview tab is the tl;dr, score cards up top, the important facts underneath:

![Overview tab](docs/img/overview.png)

Technologies shows every match with the evidence that gave it away:

![Technologies tab](docs/img/technologies.png)

Infrastructure covers where the site lives and how it resolves:

![Infrastructure tab](docs/img/infrastructure.png)

And the security tab grades those six headers:

![Security headers tab](docs/img/security.png)

## Install / run

Nothing to install, clone it and run with Node 18+:

```bash
node bin/sitescope.js <url>
```

Or link it so `sitescope` works from anywhere:

```bash
npm link          # then:
sitescope <url>
```

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

SiteScope makes one GET request for the page HTML, then runs every analyzer over that same response. That keeps it fast and keeps it polite, one hit, not fifty. Framework detection works off HTML signatures plus response headers; the network map is parsed straight from the markup (pass `--probe` if you want the real sizes fetched).

Because everything hangs off that single server-rendered fetch, it sees what a crawler sees. It doesn't run JavaScript, so a client-only SPA that renders nothing in its initial HTML is going to show fewer signals than it deserves. A headless-browser mode is on the list.

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
src/analyzers/crawl.js        robots.txt + sitemap.xml checks
src/analyzers/performance.js  static performance budget
src/analyzers/vulnscan.js     passive vulnerability findings
src/analyzers/score.js        overall health score rollup
src/report.js             terminal / markdown / html renderers
```

## Roadmap

- Headless-browser mode (Playwright) for SPA rendering + a real request waterfall
- Compare two URLs, or track one over time

## License

MIT
