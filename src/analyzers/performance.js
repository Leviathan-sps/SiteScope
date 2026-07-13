// static performance budget: no headless browser, so this works entirely off
// the resource map network.js already built (plus a head-html scan for
// render-blocking scripts). byte-based checks only run when the caller passed
// --probe, since that's the only way we know real resource sizes.

const BUDGETS = {
  requests: 80,
  jsCount: 15,
  cssCount: 5,
  thirdPartyHosts: 10,
  totalBytes: 2 * 1024 * 1024,
  jsBytes: 500 * 1024,
  imageBytes: 1024 * 1024,
};

export function analyzePerformance(site, network) {
  const html = site.body || "";
  const head = extractHead(html);

  const requests = network.total;
  const jsCount = network.byType.script || 0;
  const cssCount = network.byType.stylesheet || 0;
  const imageCount = network.byType.image || 0;
  const fontCount = network.byType.font || 0;
  const thirdPartyHosts = network.thirdPartyHosts.length;
  const renderBlockingScripts = countRenderBlockingScripts(head);

  let bytes = null;
  if (network.probed) {
    const byType = {};
    for (const item of network.probed.items) {
      if (!item.bytes) continue;
      byType[item.type] = (byType[item.type] || 0) + item.bytes;
    }
    bytes = { total: network.probed.totalBytes, byType };
  }

  const checks = [];
  const t = (cond, ok, warn) => checks.push({ pass: cond, label: cond ? ok : warn });

  t(requests <= BUDGETS.requests, `${requests} total requests (under ${BUDGETS.requests})`, `${requests} total requests (over the ${BUDGETS.requests} rule-of-thumb budget)`);
  t(jsCount <= BUDGETS.jsCount, `${jsCount} script resources`, `${jsCount} script resources (over ${BUDGETS.jsCount})`);
  t(cssCount <= BUDGETS.cssCount, `${cssCount} stylesheet resources`, `${cssCount} stylesheet resources (over ${BUDGETS.cssCount})`);
  t(thirdPartyHosts <= BUDGETS.thirdPartyHosts, `${thirdPartyHosts} third-party hosts`, `${thirdPartyHosts} third-party hosts (over ${BUDGETS.thirdPartyHosts} — each is a DNS lookup + connection)`);
  t(renderBlockingScripts === 0, "No render-blocking scripts in <head>", `${renderBlockingScripts} <head> script(s) without defer/async/module — these block first paint`);

  if (bytes) {
    t(bytes.total <= BUDGETS.totalBytes, `Total resource weight ${formatBytes(bytes.total)} (under ${formatBytes(BUDGETS.totalBytes)})`, `Total resource weight ${formatBytes(bytes.total)} (over ${formatBytes(BUDGETS.totalBytes)})`);
    const jsBytes = bytes.byType.script || 0;
    t(jsBytes <= BUDGETS.jsBytes, `JS weight ${formatBytes(jsBytes)} (under ${formatBytes(BUDGETS.jsBytes)})`, `JS weight ${formatBytes(jsBytes)} (over ${formatBytes(BUDGETS.jsBytes)})`);
    const imgBytes = bytes.byType.image || 0;
    t(imgBytes <= BUDGETS.imageBytes, `Image weight ${formatBytes(imgBytes)} (under ${formatBytes(BUDGETS.imageBytes)})`, `Image weight ${formatBytes(imgBytes)} (over ${formatBytes(BUDGETS.imageBytes)})`);
  }

  const score = Math.round((checks.filter((c) => c.pass).length / checks.length) * 100);

  return { score, requests, jsCount, cssCount, imageCount, fontCount, thirdPartyHosts, renderBlockingScripts, bytes, checks };
}

function extractHead(html) {
  const m = html.match(/<head[^>]*>([\s\S]*?)<\/head>/i);
  return m ? m[1] : html;
}

function countRenderBlockingScripts(head) {
  let count = 0;
  for (const m of head.matchAll(/<script\b[^>]*>/gi)) {
    const tag = m[0];
    if (!/\bsrc\s*=/i.test(tag)) continue; // inline scripts don't block on network
    if (/\b(defer|async)\b/i.test(tag)) continue;
    if (/type\s*=\s*["']module["']/i.test(tag)) continue; // modules are deferred by default
    count++;
  }
  return count;
}

function formatBytes(n) {
  if (!n) return "0 B";
  const units = ["B", "KB", "MB", "GB"];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) {
    n /= 1024;
    i++;
  }
  return `${n.toFixed(1)} ${units[i]}`;
}
