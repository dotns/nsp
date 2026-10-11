#!/usr/bin/env bun
// Wrapper for the nsp e2e suite. Replaces the previous bash wrapper
// so the entire test pipeline lives under Bun.
//
// What it does:
//   1. Builds the nsp:e2e image from the repo Dockerfile (skip with NO_BUILD=1).
//   2. Generates an ephemeral 32-byte master key.
//   3. Brings up the e2e compose project (nsp + tester) on a private bridge.
//   4. Streams the tester's stdout to the parent and propagates its exit code.
//   5. Tears the compose project down — always, even on Ctrl-C / unhandled error.
//
// Run from anywhere: `bun run e2e` inside `tests/e2e/`, or
// `bun run tests/e2e/src/runner.ts` from the repo root.

import { chmod, mkdir, rm } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

// HERE       = tests/e2e/src/
// E2E_DIR    = tests/e2e/   (where docker-compose.yml lives)
// REPO_ROOT  = repository root (where the production Dockerfile lives)
const HERE = dirname(fileURLToPath(import.meta.url));
const E2E_DIR = resolve(HERE, "..");
const REPO_ROOT = resolve(E2E_DIR, "../..");
const COMPOSE_FILE = join(E2E_DIR, "docker-compose.yml");
const COMPOSE_CONTROL_OVERLAY = join(E2E_DIR, "docker-compose.control.yml");
const RESULTS_DIR = join(E2E_DIR, "results");
const PROJECT = "nsp-e2e";

/**
 * One end-to-end run. Each iteration of the runner picks ONE entry
 * from the configured matrix, brings up an isolated compose stack
 * with the listed compose files + extra env, runs the tester, and
 * tears down. The control modes get their own clean nsp boot so
 * `NSP_CONTROL_*` settings (cadence, conflict_policy, …) actually
 * take effect — they're consumed at process startup.
 */
interface E2eMode {
  /** Display tag, also used as the JUnit suffix. */
  tag: string;
  /** Compose files to layer (in order). */
  composeFiles: string[];
  /** Extra env injected into compose + tester. */
  env: Record<string, string>;
}

const MODES: Record<string, E2eMode> = {
  // Default: phases 00-12, no control center, no mock.
  default: {
    tag: "default",
    composeFiles: [COMPOSE_FILE],
    env: {},
  },
  // Phases 00-12 against the userspace (nsplane) WireGuard backend.
  // The tester's kernel WG client talks to it in phase 8.
  userspace: {
    tag: "userspace",
    composeFiles: [COMPOSE_FILE],
    env: { NSP_WG_BACKEND: "userspace" },
  },
  // Reverse-API control center, conflict_policy = keep (the
  // operator-side default). Phase 13 runs against this stack.
  "control-keep": {
    tag: "control-keep",
    composeFiles: [COMPOSE_FILE, COMPOSE_CONTROL_OVERLAY],
    env: {
      NSP_CONTROL_CONFLICT_POLICY: "keep",
      NSP_CONTROL_INTERVAL_SECS: "2",
      NSP_CONTROL_STATUS_INTERVAL_SECS: "2",
      E2E_CONTROL_MODE: "control-keep",
    },
  },
  // Reverse-API control center, conflict_policy = prune. Same
  // scenarios but the policy-tagged subset asserts that local
  // extras absent from the snapshot are deleted on full sync.
  "control-prune": {
    tag: "control-prune",
    composeFiles: [COMPOSE_FILE, COMPOSE_CONTROL_OVERLAY],
    env: {
      NSP_CONTROL_CONFLICT_POLICY: "prune",
      NSP_CONTROL_INTERVAL_SECS: "2",
      NSP_CONTROL_STATUS_INTERVAL_SECS: "2",
      E2E_CONTROL_MODE: "control-prune",
    },
  },
};

/** Resolve the requested mode string into one or more E2eMode entries. */
function resolveModes(arg: string): E2eMode[] {
  if (arg === "all") {
    return ["default", "userspace", "control-keep", "control-prune"].map(
      (k) => MODES[k]!,
    );
  }
  if (arg === "control") {
    return ["control-keep", "control-prune"].map((k) => MODES[k]!);
  }
  const m = MODES[arg];
  if (!m) {
    const known = Object.keys(MODES).concat(["control", "all"]).sort();
    throw new Error(`unknown E2E_MODE=${arg}; known: ${known.join(", ")}`);
  }
  return [m];
}

function junitPathFor(tag: string): string {
  return join(RESULTS_DIR, `junit-${tag}.xml`);
}
// Stable label every e2e container carries (set in docker-compose.yml).
// Teardown sweeps up by label so renames or new auxiliary services
// don't fall through. Anonymous volumes attached to those containers
// (e.g. the production nsp Dockerfile's `VOLUME ["/work"]`) come
// along for the ride via `docker rm -fv`.
const E2E_LABEL = "nsp.e2e=true";

interface RunResult {
  code: number;
  stdout: string;
  stderr: string;
}

interface RunOptions {
  cwd?: string;
  env?: Record<string, string>;
  /** Inherit the parent's stdio so docker output streams live. */
  inherit?: boolean;
  /** Don't care about non-zero exit (unused — caller can read code). */
  failOk?: boolean;
}

async function run(argv: string[], opts: RunOptions = {}): Promise<RunResult> {
  const proc = Bun.spawn(argv, {
    cwd: opts.cwd ?? REPO_ROOT,
    env: opts.env ?? (process.env as Record<string, string>),
    stdout: opts.inherit ? "inherit" : "pipe",
    stderr: opts.inherit ? "inherit" : "pipe",
  });
  const [stdout, stderr] = opts.inherit
    ? ["", ""]
    : await Promise.all([
        new Response(proc.stdout).text(),
        new Response(proc.stderr).text(),
      ]);
  await proc.exited;
  return { code: proc.exitCode ?? -1, stdout, stderr };
}

function header(message: string): void {
  console.log(`==> ${message}`);
}

async function checkWireguardModule(): Promise<void> {
  // `lsmod` may legitimately be missing on non-Linux hosts (macOS dev,
  // CI runners with restricted /proc). Treat that as "warn and move
  // on" — the assertion against `backend: kernel` will surface a real
  // failure if the data plane can't come up.
  const r = await run(["lsmod"]);
  if (r.code !== 0) {
    console.warn("WARNING: lsmod failed; cannot verify the wireguard module.");
    return;
  }
  const present = r.stdout
    .split("\n")
    .some((line) => line.startsWith("wireguard "));
  if (!present) {
    console.warn("WARNING: wireguard kernel module not loaded on host.");
    console.warn("         The kernel-backend assertion will fail.");
    console.warn("         Load it with: sudo modprobe wireguard");
  }
}

async function buildImage(): Promise<void> {
  if (process.env["NO_BUILD"] === "1") {
    header("NO_BUILD=1 — skipping nsp:e2e rebuild");
    return;
  }
  header(`building nsp:e2e from ${REPO_ROOT}/Dockerfile`);
  const r = await run(
    [
      "docker",
      "build",
      "--progress=plain",
      "-f",
      "Dockerfile",
      "-t",
      "nsp:e2e",
      REPO_ROOT,
    ],
    {
      inherit: true,
      env: { ...(process.env as Record<string, string>), DOCKER_BUILDKIT: "1" },
    },
  );
  if (r.code !== 0) {
    throw new Error(`docker build failed (exit ${r.code})`);
  }
}

function generateMasterKey(): string {
  const buf = new Uint8Array(32);
  crypto.getRandomValues(buf);
  return Buffer.from(buf).toString("base64");
}

/**
 * Return all docker IDs (containers, volumes, ...) carrying the e2e
 * label. The supplied `kind` is the docker resource (`ps`, `volume`,
 * `network`).
 */
async function listByLabel(kind: "ps" | "volume" | "network"): Promise<string[]> {
  const argv =
    kind === "ps"
      ? ["docker", "ps", "-aq", "--filter", `label=${E2E_LABEL}`]
      : ["docker", kind, "ls", "-q", "--filter", `label=${E2E_LABEL}`];
  const r = await run(argv);
  if (r.code !== 0) return [];
  return r.stdout
    .split("\n")
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

async function teardown(composeFiles: string[] = [COMPOSE_FILE]): Promise<void> {
  header("tearing down compose project");
  const composeArgs = composeFiles.flatMap((f) => ["-f", f]);
  await run(
    [
      "docker",
      "compose",
      ...composeArgs,
      "-p",
      PROJECT,
      "down",
      "--remove-orphans",
      "--volumes",
    ],
    { failOk: true },
  );

  // Belt-and-braces sweep by label. Catches:
  // - Containers compose missed (renamed, partial-create, etc.).
  // - Anonymous volumes attached to those containers (the production
  //   nsp Dockerfile declares `VOLUME ["/work"]`; without -fv the
  //   sealed sqlite DB persists across runs and the next bring-up
  //   fails with an `aead decrypt` error).
  const containers = await listByLabel("ps");
  if (containers.length > 0) {
    header(`force-removing ${containers.length} stale e2e container(s)`);
    await run(["docker", "rm", "-fv", ...containers], { failOk: true });
  }
  const volumes = await listByLabel("volume");
  if (volumes.length > 0) {
    await run(["docker", "volume", "rm", ...volumes], { failOk: true });
  }
}

// Active compose-file set used by the signal-handler teardown so it
// removes containers from whichever mode is currently running.
let activeComposeFiles: string[] = [COMPOSE_FILE];

function installSignalHandlers(): void {
  const onSignal = (signal: string, exitCode: number) => {
    void (async () => {
      console.log(`\n==> received ${signal}; cleaning up`);
      await teardown(activeComposeFiles);
      process.exit(exitCode);
    })();
  };
  process.on("SIGINT", () => onSignal("SIGINT", 130));
  process.on("SIGTERM", () => onSignal("SIGTERM", 143));
}

async function prepareResultsDir(): Promise<void> {
  // Wipe any prior report so a partial run can't leave a stale file
  // around. Recreate the directory so the bind mount on tester
  // succeeds even on a fresh checkout.
  //
  // chmod 0777: the oven/bun:alpine image runs as the unprivileged
  // `bun` user (uid 1000); our host-side mkdir typically runs as
  // root and would otherwise produce a write-protected mount,
  // failing `--reporter-outfile=/results/junit.xml`.
  await rm(RESULTS_DIR, { recursive: true, force: true });
  await mkdir(RESULTS_DIR, { recursive: true, mode: 0o777 });
  await chmod(RESULTS_DIR, 0o777);
}

/** Run a single mode end-to-end and stash its JUnit report. */
async function runMode(
  mode: E2eMode,
  baseEnv: Record<string, string>,
): Promise<number> {
  header(`==[ mode: ${mode.tag} ]==`);
  activeComposeFiles = mode.composeFiles;
  // Always tear down before each mode so a prior run's anonymous
  // volume (sealed sqlite DB) doesn't leak into this nsp boot.
  await teardown(mode.composeFiles);

  const env: Record<string, string> = {
    ...baseEnv,
    ...mode.env,
  };
  const composeArgs = mode.composeFiles.flatMap((f) => ["-f", f]);

  const up = await run(
    [
      "docker",
      "compose",
      ...composeArgs,
      "-p",
      PROJECT,
      "up",
      "--build",
      "--exit-code-from",
      "tester",
      "tester",
    ],
    { inherit: true, env },
  );

  if (up.code !== 0) {
    header(`mode ${mode.tag} FAILED — capturing last 200 lines of nsp logs`);
    await run(
      [
        "docker",
        "compose",
        ...composeArgs,
        "-p",
        PROJECT,
        "logs",
        "nsp",
        "--tail=200",
      ],
      { inherit: true, env, failOk: true },
    );
  }

  // Move the per-run junit.xml out of the way so the next mode's
  // tester doesn't overwrite it.
  const baseJunit = join(RESULTS_DIR, "junit.xml");
  const taggedJunit = junitPathFor(mode.tag);
  if (await Bun.file(baseJunit).exists()) {
    await Bun.write(taggedJunit, await Bun.file(baseJunit).bytes());
    await rm(baseJunit, { force: true });
    header(`JUnit report (${mode.tag}): ${taggedJunit}`);
  } else {
    console.warn(`WARNING: mode ${mode.tag} produced no JUnit report`);
  }

  await teardown(mode.composeFiles);
  return up.code;
}

async function main(): Promise<number> {
  installSignalHandlers();
  await checkWireguardModule();
  await buildImage();
  await prepareResultsDir();

  const baseEnv: Record<string, string> = {
    ...(process.env as Record<string, string>),
    NSP_MASTER_KEY: process.env["NSP_MASTER_KEY"] ?? generateMasterKey(),
    NSP_ADMIN_PASSWORD: process.env["NSP_ADMIN_PASSWORD"] ?? "changeme-e2e",
  };

  const requested = process.env["E2E_MODE"] ?? "default";
  const modes = resolveModes(requested);
  header(`requested modes: ${modes.map((m) => m.tag).join(", ")}`);

  let exit = 0;
  for (const mode of modes) {
    const code = await runMode(mode, baseEnv);
    if (code !== 0 && exit === 0) exit = code;
  }
  return exit;
}

try {
  const code = await main();
  process.exit(code);
} catch (err) {
  console.error(err instanceof Error ? err.message : String(err));
  await teardown(activeComposeFiles);
  process.exit(1);
}
