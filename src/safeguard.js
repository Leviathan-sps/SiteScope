// currenly i added guardrails for internet-facing (public) instances. two jobs:
//   1. refuse targets that resolve to non-public addresses, so the scanner can't be pointed at localhost, the private lan, or cloud metadata (ssrf / internal-recon abuse).
//   2. a small per-ip rate limiter for the analyze endpoint.
// local runs don't use these — scanning your own localhost is the point there.

import { promises as dns } from "node:dns";
import net from "node:net";
import { normalizeUrl } from "./fetcher.js";

// resolve the target and require every address to be public. throws otherwise.
export async function assertPublicTarget(rawUrl) {
  // normalize the same way the fetcher does so bare "example.com" is accepted.
  let host;
  try { host = new URL(normalizeUrl(rawUrl)).hostname; } catch { throw new Error("invalid url"); }

  let ips;
  if (net.isIP(host)) ips = [host];
  else {
    try { ips = (await dns.lookup(host, { all: true })).map((a) => a.address); }
    catch { throw new Error("could not resolve host"); }
  }
  if (!ips.length) throw new Error("could not resolve host");

  for (const ip of ips) {
    if (!isPublicIp(ip)) throw new Error("this public instance only scans hosts on the public internet");
  }
  return { host, ips };
}

export function isPublicIp(ip) {
  const v = net.isIP(ip);
  if (v === 4) return isPublicV4(ip);
  if (v === 6) return isPublicV6(ip);
  return false;
}

function isPublicV4(ip) {
  const p = ip.split(".").map(Number);
  if (p.length !== 4 || p.some((n) => Number.isNaN(n) || n < 0 || n > 255)) return false;
  const [a, b] = p;
  if (a === 0 || a === 127) return false;               // this-host / loopback
  if (a === 10) return false;                            // private
  if (a === 172 && b >= 16 && b <= 31) return false;     // private
  if (a === 192 && b === 168) return false;              // private
  if (a === 169 && b === 254) return false;              // link-local + metadata
  if (a === 100 && b >= 64 && b <= 127) return false;    // cgnat
  if (a === 192 && b === 0) return false;                // ietf/test
  if (a === 198 && (b === 18 || b === 19)) return false; // benchmarking
  if (a >= 224) return false;                            // multicast / reserved
  return true;
}

function isPublicV6(ip) {
  const s = ip.toLowerCase();
  if (s === "::1" || s === "::") return false;                    // loopback / unspecified
  if (s.startsWith("fc") || s.startsWith("fd")) return false;     // fc00::/7 unique-local
  if (/^fe[89ab]/.test(s)) return false;                          // fe80::/10 link-local
  const m = s.match(/::ffff:(\d+\.\d+\.\d+\.\d+)$/);              // ipv4-mapped
  if (m) return isPublicV4(m[1]);
  return true;
}

// simple sliding-window limiter, keyed by client ip.
export function makeRateLimiter({ windowMs = 60000, max = 30 } = {}) {
  const hits = new Map();
  return function limited(ip) {
    const now = Date.now();
    const arr = (hits.get(ip) || []).filter((t) => now - t < windowMs);
    arr.push(now);
    hits.set(ip, arr);
    // opportunistic cleanup so the map doesn't grow forever
    if (hits.size > 5000) for (const [k, v] of hits) if (!v.some((t) => now - t < windowMs)) hits.delete(k);
    return arr.length > max;
  };
}
