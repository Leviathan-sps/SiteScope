// Port scan: TCP-connect check of a curated list of common service ports on
// the target's resolved IP. A "connect" success means the port is open.
//
// This is ACTIVE reconnaissance — it opens real TCP connections to the host.
// Only run it against systems you own or are explicitly authorized to test.
// Scope is deliberately limited to well-known service ports (not a full
// 1–65535 sweep) to stay fast and unobtrusive.

import net from "node:net";

const COMMON_PORTS = [
  { port: 21, name: "FTP", note: "file transfer — often plaintext" },
  { port: 22, name: "SSH", note: "remote shell" },
  { port: 25, name: "SMTP", note: "mail relay" },
  { port: 53, name: "DNS", note: "name resolution" },
  { port: 80, name: "HTTP", note: "web (cleartext)" },
  { port: 110, name: "POP3", note: "mail retrieval" },
  { port: 143, name: "IMAP", note: "mail retrieval" },
  { port: 443, name: "HTTPS", note: "web (TLS)" },
  { port: 465, name: "SMTPS", note: "mail over TLS" },
  { port: 587, name: "SMTP", note: "mail submission" },
  { port: 993, name: "IMAPS", note: "mail over TLS" },
  { port: 3306, name: "MySQL", note: "database — should not be public" },
  { port: 3389, name: "RDP", note: "remote desktop — should not be public" },
  { port: 5432, name: "PostgreSQL", note: "database — should not be public" },
  { port: 6379, name: "Redis", note: "cache/db — should not be public" },
  { port: 8080, name: "HTTP-alt", note: "proxy / app server" },
  { port: 8443, name: "HTTPS-alt", note: "app server (TLS)" },
  { port: 9200, name: "Elasticsearch", note: "search — should not be public" },
  { port: 27017, name: "MongoDB", note: "database — should not be public" },
];

// ports that being open to the internet is usually a red flag.
const SENSITIVE = new Set([3306, 3389, 5432, 6379, 9200, 27017]);

// alt idea: also probe a couple of udp services (dns, ntp, snmp). needs the
// dgram module and a different check, so left out to keep the scan simple.
// const UDP_PORTS = [
//   { port: 53, name: "DNS" },
//   { port: 123, name: "NTP" },
//   { port: 161, name: "SNMP" },
// ];

/**
 * @param {string} ip
 * @param {{ timeout?:number, concurrency?:number }} [opts]
 */
export async function scanPorts(ip, opts = {}) {
  const timeout = opts.timeout || 2000;
  const concurrency = opts.concurrency || 8;

  const queue = [...COMMON_PORTS];
  const results = [];
  async function worker() {
    let item;
    while ((item = queue.shift())) {
      const open = await checkPort(ip, item.port, timeout);
      results.push({ ...item, open, sensitive: SENSITIVE.has(item.port) });
    }
  }
  await Promise.all(Array.from({ length: concurrency }, worker));

  results.sort((a, b) => a.port - b.port);
  const open = results.filter((r) => r.open);
  return {
    target: ip,
    scanned: results.length,
    ports: results,
    open,
    exposedSensitive: open.filter((r) => r.sensitive),
  };
}

function checkPort(ip, port, timeout) {
  return new Promise((resolve) => {
    const socket = new net.Socket();
    let settled = false;
    const finish = (open) => {
      if (settled) return;
      settled = true;
      socket.destroy();
      resolve(open);
    };
    socket.setTimeout(timeout);
    socket.once("connect", () => finish(true));
    socket.once("timeout", () => finish(false));
    socket.once("error", () => finish(false)); // refused / unreachable
    try {
      socket.connect(port, ip);
    } catch {
      finish(false);
    }
  });
}
