#!/usr/bin/env node
// sitescope cli entry point — parses args, runs analyze(), renders output.
// see HELP below for the full option list.

import { writeFile } from "node:fs/promises";
import { analyze } from "../src/index.js";
import { renderTerminal, renderMarkdown, renderHtml } from "../src/report.js";

const HELP = `
SiteScope — inspect any website from your terminal.

Usage:
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

Active-scan note:
  --scan-ports / --scan-paths send real traffic to the target host. Only use
  them against systems you own or are explicitly authorized to test.

Examples:
  sitescope example.com
  sitescope https://vercel.com --format markdown -o report.md
  sitescope github.com --format html -o report.html --probe
  sitescope your-own-server.com --recon
  sitescope news.ycombinator.com --format json | jq .frameworks
`;

async function main() {
  const argv = process.argv.slice(2);
  const opts = parseArgs(argv);

  if (opts.help || !opts.url) {
    process.stdout.write(HELP);
    process.exit(opts.url ? 0 : 1);
  }

  let report;
  try {
    report = await analyze(opts.url, {
      probe: opts.probe,
      timeout: opts.timeout,
      userAgent: opts.userAgent,
      geo: opts.geo,
      recon: { ports: opts.scanPorts, paths: opts.scanPaths },
    });
  } catch (err) {
    process.stderr.write(`\x1b[31mError:\x1b[0m ${err.message}\n`);
    process.exit(2);
  }

  let out;
  switch (opts.format) {
    case "json":
      out = JSON.stringify(report, null, 2);
      break;
    case "markdown":
    case "md":
      out = renderMarkdown(report);
      break;
    case "html":
      out = renderHtml(report);
      break;
    case "terminal":
    default:
      out = renderTerminal(report, { color: opts.color && !opts.output });
      break;
  }

  if (opts.output) {
    await writeFile(opts.output, out, "utf8");
    process.stdout.write(`\x1b[32m✔\x1b[0m Report written to ${opts.output}\n`);
  } else {
    process.stdout.write(out);
  }
}

function parseArgs(argv) {
  const opts = {
    url: null,
    format: "terminal",
    output: null,
    probe: false,
    scanPorts: false,
    scanPaths: false,
    geo: true,
    timeout: 15000,
    userAgent: undefined,
    color: process.stdout.isTTY,
    help: false,
  };

  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    switch (a) {
      case "--help":
      case "-h":
        opts.help = true;
        break;
      case "--format":
        opts.format = argv[++i];
        break;
      case "-o":
      case "--output":
        opts.output = argv[++i];
        break;
      case "--probe":
        opts.probe = true;
        break;
      case "--scan-ports":
        opts.scanPorts = true;
        break;
      case "--scan-paths":
        opts.scanPaths = true;
        break;
      case "--recon":
        opts.scanPorts = true;
        opts.scanPaths = true;
        break;
      case "--no-geo":
        opts.geo = false;
        break;
      case "--timeout":
        opts.timeout = Number(argv[++i]) || opts.timeout;
        break;
      case "--user-agent":
        opts.userAgent = argv[++i];
        break;
      case "--no-color":
        opts.color = false;
        break;
      // a --quiet flag could suppress everything but the score line
      // case "--quiet":
      //   opts.quiet = true;
      //   break;
      default:
        if (a.startsWith("-")) {
          process.stderr.write(`Unknown option: ${a}\n`);
          opts.help = true;
        } else if (!opts.url) {
          opts.url = a;
        }
    }
  }
  return opts;
}

main();
