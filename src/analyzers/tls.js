// TLS inspection: opens one real handshake to the host and reads back the
// certificate plus the negotiated protocol and cipher.
//
// This is passive — a single connection to 443, no heavier than the page
// fetch itself, and everything here is what the server volunteers to any
// normal https client. We deliberately do NOT reject bad certificates:
// an expired or self-signed cert is exactly what we want to report on.

import tls from "node:tls";

const DAY = 86400000;
// warn this far out so there's still time to renew
const EXPIRY_WARN_DAYS = 30;

// protocols we consider past it. tls 1.0/1.1 are deprecated everywhere.
const WEAK_PROTOCOLS = new Set(["TLSv1", "TLSv1.1", "SSLv3", "SSLv2"]);

/**
 * @param {{finalUrl:string}} site
 * @param {{ timeout?:number }} [opts]
 */
export async function analyzeTls(site, opts = {}) {
  const timeout = opts.timeout || 8000;

  let url;
  try { url = new URL(site.finalUrl); } catch { return null; }
  if (url.protocol !== "https:") return { https: false, reachable: false, checks: [] };

  const host = url.hostname;
  const port = Number(url.port) || 443;

  const peer = await handshake(host, port, timeout).catch(() => null);
  if (!peer) return { https: true, reachable: false, checks: [] };

  const cert = peer.cert || {};
  const validTo = cert.valid_to ? new Date(cert.valid_to) : null;
  const validFrom = cert.valid_from ? new Date(cert.valid_from) : null;
  const daysLeft = validTo ? Math.floor((validTo.getTime() - Date.now()) / DAY) : null;

  const names = sanNames(cert.subjectaltname);
  const issuer = (cert.issuer && (cert.issuer.O || cert.issuer.CN)) || null;
  const subject = (cert.subject && cert.subject.CN) || null;
  // a cert that issued itself has nothing vouching for it
  const selfSigned = !!(issuer && subject && issuer === subject) ||
    peer.authorizationError === "DEPTH_ZERO_SELF_SIGNED_CERT" ||
    peer.authorizationError === "SELF_SIGNED_CERT_IN_CHAIN";

  const expired = daysLeft != null && daysLeft < 0;
  const expiringSoon = daysLeft != null && daysLeft >= 0 && daysLeft <= EXPIRY_WARN_DAYS;
  const weakProtocol = WEAK_PROTOCOLS.has(peer.protocol);

  const checks = [
    { label: "Certificate is currently valid", pass: !expired },
    { label: `Certificate not expiring within ${EXPIRY_WARN_DAYS} days`, pass: !expiringSoon },
    { label: "Certificate chain is trusted", pass: !!peer.authorized },
    { label: "Certificate is not self-signed", pass: !selfSigned },
    { label: "Modern TLS protocol (1.2 or newer)", pass: !weakProtocol },
    { label: "Hostname matches the certificate", pass: covers(names, host) },
  ];

  return {
    https: true,
    reachable: true,
    host,
    subject,
    issuer,
    protocol: peer.protocol || null,
    cipher: (peer.cipher && peer.cipher.name) || null,
    validFrom: validFrom ? validFrom.toISOString() : null,
    validTo: validTo ? validTo.toISOString() : null,
    daysLeft,
    expired,
    expiringSoon,
    selfSigned,
    weakProtocol,
    authorized: !!peer.authorized,
    authorizationError: peer.authorizationError || null,
    // the san list doubles as a free, authoritative subdomain source
    names,
    checks,
    score: Math.round((checks.filter((c) => c.pass).length / checks.length) * 100),
  };
}

// alt idea: also grab the ocsp staple and check revocation. node exposes it
// via the "OCSPResponse" event but parsing the der response by hand is a lot
// of work for a rare signal, so it's left out.
// function ocspStapled(socket) { ... }

function handshake(host, port, timeout) {
  return new Promise((resolve, reject) => {
    const socket = tls.connect({
      host,
      port,
      servername: host,        // sni — required or shared hosts serve the wrong cert
      rejectUnauthorized: false, // we want to inspect bad certs, not bail on them
      timeout,
    });
    let settled = false;
    const finish = (fn, arg) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      fn(arg);
    };
    socket.once("secureConnect", () => {
      finish(resolve, {
        cert: socket.getPeerCertificate(true),
        protocol: socket.getProtocol(),
        cipher: socket.getCipher(),
        authorized: socket.authorized,
        authorizationError: socket.authorizationError ? String(socket.authorizationError) : null,
      });
    });
    socket.once("timeout", () => finish(reject, new Error("tls timeout")));
    socket.once("error", (e) => finish(reject, e));
  });
}

// "DNS:example.com, DNS:*.example.com" -> ["example.com", "*.example.com"]
function sanNames(san) {
  if (!san) return [];
  return san.split(",")
    .map((s) => s.trim())
    .filter((s) => s.startsWith("DNS:"))
    .map((s) => s.slice(4).toLowerCase());
}

// wildcard match is one label deep only, same as browsers do it
function covers(names, host) {
  if (!names.length) return false;
  const h = host.toLowerCase();
  return names.some((n) => {
    if (n === h) return true;
    if (!n.startsWith("*.")) return false;
    const suffix = n.slice(1); // ".example.com"
    return h.endsWith(suffix) && !h.slice(0, -suffix.length).includes(".");
  });
}
