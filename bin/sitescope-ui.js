
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";
import { fileURLToPath } from "node:url";
import { dirname, join, normalize } from "node:path";
import { exec } from "node:child_process";
import { analyze } from "../src/index.js";
import { renderHtml, renderMarkdown } from "../src/report.js";
import { assertPublicTarget, makeRateLimiter } from "../src/safeguard.js";

const __dirname = dirname(fileURLToPath(import.meta.url));
const UI_DIR = join(__dirname, "..", "src", "ui");

const DEFAULT_PORT = 4986;
const MAX_BODY = 10 * 1024 * 1024;

const PUBLIC_MODE = process.env.SITESCOPE_PUBLIC === "1";
const rateLimited = makeRateLimiter({ windowMs: 60000, max: 30 });

function clientIp(req) {
  return (
    req.headers["cf-connecting-ip"] ||
    (req.headers["x-forwarded-for"] || "").split(",")[0].trim() ||
    req.socket.remoteAddress ||
    "?"
  );
}

const MIME = {
  ".html": "text/html; charset=utf-8",
  ".css": "text/css; charset=utf-8",
  ".js": "text/javascript; charset=utf-8",
  ".svg": "image/svg+xml",
};

const server = createServer(async (req, res) => {
  const u = new URL(req.url, "http://localhost");
  try {
    // ---- API ----
    if (req.method === "GET" && u.pathname === "/api/analyze") {
      const target = u.searchParams.get("url");
      if (!target) return json(res, 400, { error: "Missing ?url=" });
      if (PUBLIC_MODE) {
        if (rateLimited(clientIp(req))) return json(res, 429, { error: "rate limit — slow down and try again in a minute" });
        // ssrf guard: refuse non-public targets before we touch them.
        try { await assertPublicTarget(target); }
        catch (e) { return json(res, 400, { error: e.message }); }
      }
      const report = await analyze(target, {
        probe: u.searchParams.get("probe") === "1",
        geo: u.searchParams.get("geo") !== "0",
        recon: {
          ports: u.searchParams.get("ports") === "1",
          paths: u.searchParams.get("paths") === "1",
          subs: u.searchParams.get("subs") === "1",
        },
        timeout: Number(u.searchParams.get("timeout")) || 15000,
      });
      return json(res, 200, report);
    }

    if (req.method === "POST" && u.pathname === "/api/render") {
      const format = u.searchParams.get("format");
      const report = JSON.parse(await readBody(req));
      if (format === "html") return send(res, 200, MIME[".html"], renderHtml(report));
      if (format === "md") return send(res, 200, "text/markdown; charset=utf-8", renderMarkdown(report));
      return json(res, 400, { error: "format must be html or md" });
    }

    // lets the page know whether to show the deep-scan control.
    if (req.method === "GET" && u.pathname === "/api/config") {
      return json(res, 200, { publicMode: PUBLIC_MODE });
    }

    // ---- static UI ----
    if (req.method === "GET") return serveStatic(res, u.pathname);

    send(res, 405, "text/plain", "Method not allowed");
  } catch (err) {
    // Analysis failures (bad host, timeout, non-HTML response) surface here.
    json(res, 502, { error: err.message });
  }
});

async function serveStatic(res, pathname) {
  const rel = pathname === "/" ? "index.html" : pathname.replace(/^\/+/, "");
  // Contain path traversal: resolved file must stay inside UI_DIR.
  const filePath = normalize(join(UI_DIR, rel));
  if (!filePath.startsWith(UI_DIR)) return send(res, 403, "text/plain", "Forbidden");
  const ext = filePath.slice(filePath.lastIndexOf("."));
  try {
    const body = await readFile(filePath);
    send(res, 200, MIME[ext] || "application/octet-stream", body);
  } catch {
    send(res, 404, "text/plain", "Not found");
  }
}

function send(res, status, type, body) {
  res.writeHead(status, { "content-type": type, "cache-control": "no-store" });
  res.end(body);
}
function json(res, status, obj) {
  send(res, status, "application/json", JSON.stringify(obj));
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0;
    const chunks = [];
    req.on("data", (c) => {
      size += c.length;
      if (size > MAX_BODY) { reject(new Error("Body too large")); req.destroy(); return; }
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

function openBrowser(url) {
  const cmd =
    process.platform === "win32" ? `start "" "${url}"` :
    process.platform === "darwin" ? `open "${url}"` :
    `xdg-open "${url}"`;
  exec(cmd, () => {}); // best effort — the printed URL is the fallback
}

// ----------------------------- startup -----------------------------

const argv = process.argv.slice(2);
const portFlag = argv.indexOf("--port");
const port = portFlag !== -1 ? Number(argv[portFlag + 1]) || DEFAULT_PORT : Number(process.env.PORT) || DEFAULT_PORT;

server.on("error", (err) => {
  if (err.code === "EADDRINUSE") {
    process.stderr.write(`Port ${port} is busy, picking a free one…\n`);
    server.listen(0, "127.0.0.1");
  } else {
    throw err;
  }
});

server.listen(port, "127.0.0.1", () => {
  const url = `http://127.0.0.1:${server.address().port}`;
  process.stdout.write(`\x1b[1mSiteScope UI\x1b[0m running at \x1b[36m${url}\x1b[0m  (Ctrl+C to stop)\n`);
  if (!argv.includes("--no-open")) openBrowser(url);
});
