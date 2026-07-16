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
import { analyzePerformance } from "./analyzers/performance.js";
import { analyzeScore } from "./analyzers/score.js";
import { scanPorts } from "./analyzers/ports.js";
import { scanPaths } from "./analyzers/paths.js";
import { analyzeVulns } from "./analyzers/vulnscan.js";

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

  const frameworks = detectFrameworks(site);
  const headers = analyzeHeaders(site);
  const cookies = analyzeCookies(site);
  const seo = analyzeSeo(site);
  const performance = analyzePerformance(site, network);
  const score = analyzeScore({ headers, seo, cookies, performance, crawl });

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

  // passive vuln pass — reads what's above, sends nothing new. picks up more
  // when recon ran, since exposed ports/paths feed into it.
  const vulns = analyzeVulns({ frameworks, headers, recon });

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
    frameworks,
    headers,
    cookies,
    seo,
    performance,
    crawl,
    network,
    infra,
    recon,
    vulns,
    score,
  };
}
