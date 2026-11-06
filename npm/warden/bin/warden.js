#!/usr/bin/env node
// Launcher for the warden Go binary. npm installs exactly one platform
// package (@decnutz/warden-<os>-<cpu>) through optionalDependencies, the
// same pattern esbuild uses; this script finds that binary and execs it.
// No postinstall script and no network access at install or run time.
"use strict";

const { spawn } = require("child_process");
const fs = require("fs");
const path = require("path");

const PLATFORMS = {
  "linux-x64": "@decnutz/warden-linux-x64",
  "linux-arm64": "@decnutz/warden-linux-arm64",
  "darwin-x64": "@decnutz/warden-darwin-x64",
  "darwin-arm64": "@decnutz/warden-darwin-arm64",
};

function findBinary() {
  // 1. Explicit override (e.g. a binary you built with `go build`).
  if (process.env.WARDEN_BINARY) return process.env.WARDEN_BINARY;

  const key = `${process.platform}-${process.arch}`;
  const pkg = PLATFORMS[key];
  if (!pkg) {
    fail(
      `warden has no prebuilt binary for ${key}.\n` +
        `Supported: ${Object.keys(PLATFORMS).join(", ")} (warden uses POSIX process groups; Windows is not supported yet).\n` +
        `Build from source instead: go install github.com/calasdan-sketch/warden/cmd/warden@latest`
    );
  }
  // 2. The platform package installed via optionalDependencies.
  try {
    return require.resolve(`${pkg}/bin/warden`);
  } catch (_) {
    // 3. A binary vendored next to this package (local builds / tarballs).
    const local = path.join(__dirname, "..", "vendor", key, "warden");
    if (fs.existsSync(local)) return local;
  }
  fail(
    `warden: the platform package ${pkg} is not installed.\n` +
      `This usually means npm was run with --no-optional / --omit=optional, or the\n` +
      `lockfile was created on another OS. Reinstall without omitting optional\n` +
      `dependencies, or set WARDEN_BINARY to a warden binary you built.`
  );
}

function fail(msg) {
  process.stderr.write(msg + "\n");
  process.exit(1);
}

const bin = findBinary();
const child = spawn(bin, process.argv.slice(2), { stdio: "inherit" });

// Forward termination signals so `kill <launcher pid>` (or Ctrl-C from a
// supervisor) reaches warden, which then seals its receipt before exiting.
const FORWARD = ["SIGINT", "SIGTERM", "SIGHUP", "SIGQUIT"];
const handlers = {};
for (const sig of FORWARD) {
  handlers[sig] = () => {
    try {
      child.kill(sig);
    } catch (_) {
      /* child already gone */
    }
  };
  process.on(sig, handlers[sig]);
}

child.on("error", (err) => fail(`warden: could not run ${bin}: ${err.message}`));
child.on("exit", (code, signal) => {
  for (const sig of FORWARD) process.removeListener(sig, handlers[sig]);
  if (signal) {
    // Re-raise the child's fatal signal so callers see the same exit status.
    process.kill(process.pid, signal);
    return;
  }
  process.exit(code === null ? 1 : code);
});
