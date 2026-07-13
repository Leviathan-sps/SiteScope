// overall health score: a single number that rolls up every graded analyzer.
// weights favor what actually affects users/security over nice-to-haves.

const WEIGHTS = {
  headers: 0.30,
  seo: 0.20,
  cookies: 0.15,
  performance: 0.20,
  crawl: 0.15,
};

export function analyzeScore({ headers, seo, cookies, performance, crawl }) {
  const cookieScore = scoreCookies(cookies);

  const parts = {
    headers: headers.score,
    seo: seo.score,
    cookies: cookieScore,
    performance: performance.score,
    crawl: crawl.score,
  };

  let earned = 0;
  let possible = 0;
  for (const [key, weight] of Object.entries(WEIGHTS)) {
    if (parts[key] == null) continue;
    earned += parts[key] * weight;
    possible += weight;
  }
  const score = possible ? Math.round(earned / possible) : null;

  const topIssues = collectTopIssues({ headers, seo, cookies, performance, crawl });

  return { score, grade: score == null ? null : letterGrade(score), parts, topIssues };
}

// cookies has no built-in score — derive one from issue density
function scoreCookies(cookies) {
  if (!cookies.count) return 100; // no cookies, nothing to flag
  const ratio = cookies.issues.length / cookies.count;
  return Math.max(0, Math.round(100 - ratio * 40));
}

function collectTopIssues({ headers, seo, cookies, performance, crawl }) {
  const issues = [];
  for (const s of headers.security) if (s.status !== "ok") issues.push({ source: "Security", label: s.label + (s.note ? ` — ${s.note}` : ""), severity: s.status === "missing" ? 2 : 1 });
  for (const c of seo.checks) if (!c.pass) issues.push({ source: "SEO", label: c.label, severity: 1 });
  for (const c of performance.checks) if (!c.pass) issues.push({ source: "Performance", label: c.label, severity: 1 });
  for (const c of crawl.checks) if (!c.pass) issues.push({ source: "Crawlability", label: c.label, severity: 1 });
  for (const issue of cookies.issues) issues.push({ source: "Cookies", label: issue, severity: 1 });

  return issues.sort((a, b) => b.severity - a.severity).slice(0, 8);
}

function letterGrade(score) {
  if (score >= 90) return "A";
  if (score >= 75) return "B";
  if (score >= 60) return "C";
  if (score >= 40) return "D";
  return "F";
}
