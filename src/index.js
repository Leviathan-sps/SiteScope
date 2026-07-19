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
import { analyzeTls } from "./analyzers/tls.js";
import { analyzeDns } from "./analyzers/dnssec.js";
import { analyzePerformance } from "./analyzers/performance.js";
import { analyzeScore } from "./analyzers/score.js";
import { scanPorts } from "./analyzers/ports.js";
import { scanPaths } from "./analyzers/paths.js";
import { scanSubdomains } from "./analyzers/subdomains.js";
import { analyzeVulns } from "./analyzers/vulnscan.js";

function safeHostname(url) {
  try { return new URL(url).hostname; } catch { return ""; }
}

// run all analyzers against url and build the report
export async function analyze(url, opts = {}) {
  const site = await fetchSite(url, opts);

  // passive infra (dns + optional geo/asn), the network map, and the
  // robots.txt/sitemap check are all independent of each other
  // the hostname is needed before infra resolves, so pull it off the url
  const hostname = safeHostname(site.finalUrl);

  // the tls handshake and the dns record lookups are both passive and cheap,
  // so they run on every scan alongside the rest
  const [network, infra, crawl, tlsInfo, dnsRecords] = await Promise.all([
    analyzeNetwork(site, { probe: opts.probe, timeout: opts.timeout }),
    analyzeInfra(site, { geo: opts.geo !== false }),
    analyzeCrawl(site, { timeout: opts.timeout }),
    analyzeTls(site, { timeout: opts.timeout }),
    analyzeDns(hostname, { timeout: opts.timeout }),
  ]);

  const frameworks = detectFrameworks(site);
  const headers = analyzeHeaders(site);
  const cookies = analyzeCookies(site);
  const seo = analyzeSeo(site);
  const performance = analyzePerformance(site, network);
  const score = analyzeScore({ headers, seo, cookies, performance, crawl });

  // active recon (ports + paths + subdomains) is opt-in — it sends real traffic
  let recon = null;
  const want = opts.recon || {};
  if (want.ports || want.paths || want.subs) {
    const [ports, paths, subs] = await Promise.all([
      want.ports && infra.primaryIp ? scanPorts(infra.primaryIp) : Promise.resolve(null),
      want.paths ? scanPaths(site.finalUrl, { userAgent: opts.userAgent }) : Promise.resolve(null),
      want.subs && infra.host
        ? scanSubdomains(infra.host, { certNames: (tlsInfo && tlsInfo.names) || [] })
        : Promise.resolve(null),
    ]);
    recon = { ports, paths, subs };
  }

  // vuln check rides along with the deep scan — only runs when recon did.
  // it sends nothing new itself, just reads the frameworks/headers/recon above.
  const vulns = recon
    ? analyzeVulns({ frameworks, headers, recon, network, tls: tlsInfo })
    : null;

  return {
    meta: {
      requestedUrl: site.requestedUrl,
      finalUrl: site.finalUrl,
      redirected: site.redirected,
      redirectChain: site.redirectChain || [],
      insecureHop: !!site.insecureHop,
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
    tls: tlsInfo,
    dns: dnsRecords,
    recon,
    vulns,
    score,
  };
}
