// orchestrates a full analysis: fetch the page once, run every analyzer
// against the shared response, return one structured report object

import { fetchSite } from "./fetcher.js";
import { detectFrameworks } from "./detectors/frameworks.js";
import { analyzeHeaders } from "./analyzers/headers.js";
import { analyzeCookies } from "./analyzers/cookies.js";
import { analyzeSeo } from "./analyzers/seo.js";
import { analyzeNetwork } from "./analyzers/network.js";
import { analyzeInfra } from "./analyzers/infra.js";
import { analyzeCrawl } from "./analyzers/crawl.js";
import { scanPorts } from "./analyzers/ports.js";
import { scanPaths } from "./analyzers/paths.js";

// run all analyzers against url and build the report
export async function analyze(url, opts = {}) {
  const site = await fetchSite(url, opts);

  // passive infra (dns + optional geo/asn), the network map, and the
  // robots.txt/sitemap check are all independent of each other
  const [network, infra, crawl] = await Promise.all([
    analyzeNetwork(site, { probe: opts.probe, timeout: opts.timeout }),
    analyzeInfra(site, { geo: opts.geo !== false }),
    analyzeCrawl(site, { timeout: opts.timeout }),
  ]);

  // active recon (ports + paths) is opt-in — it sends real traffic
  let recon = null;
  const want = opts.recon || {};
  if (want.ports || want.paths) {
    const [ports, paths] = await Promise.all([
      want.ports && infra.primaryIp ? scanPorts(infra.primaryIp) : Promise.resolve(null),
      want.paths ? scanPaths(site.finalUrl, { userAgent: opts.userAgent }) : Promise.resolve(null),
    ]);
    recon = { ports, paths };
  }

  return {
    meta: {
      requestedUrl: site.requestedUrl,
      finalUrl: site.finalUrl,
      redirected: site.redirected,
      status: site.status,
      statusText: site.statusText,
      contentType: site.contentType,
      bytes: site.bytes,
      elapsedMs: site.elapsedMs,
      // caller supplies the timestamp, keeps this fn pure-ish
      generatedAt: opts.generatedAt || new Date().toISOString(),
    },
    frameworks: detectFrameworks(site),
    headers: analyzeHeaders(site),
    cookies: analyzeCookies(site),
    seo: analyzeSeo(site),
    crawl,
    network,
    infra,
    recon,
    // could roll everything into a single 0-100 health score down the line
    // score: overallScore({ headers, seo, cookies }),
  };
}
