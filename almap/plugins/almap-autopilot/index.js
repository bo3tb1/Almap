/**
 * almap-autopilot — host half.
 *
 * Gives the agent full autonomy over the ALmap project (Goose language + C):
 *   - auto_build_and_test     run the Goose type check, Goose build + test run, and the C compile
 *   - auto_self_heal          parse build/type errors into exact file:line repair context
 *   - goose_syntax_lookup     grep the local Goose compiler docs for real syntax (no hallucinated Goose)
 *   - project_context_sync    read Objective.txt / README.md / git log and report the current step
 *
 * Plus: a /almap command and a read-only same-origin status endpoint consumed by the
 * left-sidebar control panel in client.js.
 *
 * Design constraints:
 *   - only node builtins are imported (the plugin resolves from the profile, not the workspace)
 *   - every child process has a timeout, a maxBuffer and ANSI stripping
 *   - the harness must never crash: all tool/command/route handlers catch everything
 */

import { exec } from "node:child_process";
import { accessSync, chmodSync, existsSync, mkdirSync, statSync, writeFileSync } from "node:fs";
import { readFile, readdir } from "node:fs/promises";
import { homedir } from "node:os";
import { basename, dirname, extname, isAbsolute, join, relative, resolve, sep } from "node:path";

export const name = "@local/almap-autopilot";
export const inject = ["tools", "systemPrompt", "webServer", "commands"];

const VERSION = "1.0.0";
const DEFAULT_WORKSPACE = "/home/honeypot/almap";
const DEFAULT_MAX_BUFFER = 8 * 1024 * 1024;
const DEFAULT_MAX_OUTPUT_CHARS = 16000;
const MAX_HISTORY = 20;
const MAX_RAW_DIAGNOSTICS = 120;
const STATUS_CACHE_MS = 8000;
const PROJECT_CACHE_MS = 15000;
const PANEL_ROUTE = "/almap-autopilot/status";
/** The step the autopilot brief targets; the repo may evidence an earlier step. */
const BRIEF_TARGET_STEP = 15;

// -------------------------------------------------------------------------------------------------
// small helpers
// -------------------------------------------------------------------------------------------------

const ANSI_OSC = /\u001b\][^\u0007]*(?:\u0007|\u001b\\)/g;
const ANSI_CSI = /\u001b\[[0-9;?]*[ -/]*[@-~]/g;

function stripAnsi(input) {
  if (typeof input !== "string" || input.indexOf("\u001b") === -1) return String(input ?? "");
  return input.replace(ANSI_OSC, "").replace(ANSI_CSI, "");
}

function clampInt(value, min, max, fallback) {
  const n = typeof value === "number" ? value : Number.parseInt(String(value ?? ""), 10);
  if (!Number.isFinite(n)) return fallback;
  return Math.min(max, Math.max(min, Math.trunc(n)));
}

function expandHome(input) {
  if (typeof input !== "string" || input.length === 0) return "";
  if (input === "~") return homedir();
  if (input.startsWith("~/")) return join(homedir(), input.slice(2));
  return input;
}

function isDirectory(p) {
  try {
    return Boolean(p) && statSync(p).isDirectory();
  } catch {
    return false;
  }
}

function isFile(p) {
  try {
    return Boolean(p) && statSync(p).isFile();
  } catch {
    return false;
  }
}

function firstDirectory(candidates, fallback) {
  for (const candidate of candidates) {
    const expanded = expandHome(candidate);
    if (!expanded) continue;
    const absolute = isAbsolute(expanded) ? expanded : resolve(expanded);
    if (isDirectory(absolute)) return absolute;
  }
  return fallback;
}

function firstExecutable(candidates) {
  for (const candidate of candidates) {
    const expanded = expandHome(candidate);
    if (!expanded) continue;
    if (expanded.includes("/") || expanded.includes(sep)) {
      const absolute = isAbsolute(expanded) ? expanded : resolve(expanded);
      if (isFile(absolute)) return absolute;
    } else if (/^[A-Za-z0-9_.+-]+$/.test(expanded)) {
      return expanded; // bare command name, resolved by PATH
    }
  }
  return "";
}

function isExecutable(p) {
  try {
    accessSync(p, 1); // X_OK
    return true;
  } catch {
    return false;
  }
}

/** Like `firstExecutable`, but only accepts absolute paths to real executable files. */
function firstExecutableFile(candidates) {
  for (const candidate of candidates) {
    const expanded = expandHome(candidate);
    if (!expanded) continue;
    if (!(expanded.includes("/") || expanded.includes(sep))) continue;
    const absolute = isAbsolute(expanded) ? expanded : resolve(expanded);
    if (isFile(absolute) && isExecutable(absolute)) return absolute;
  }
  return "";
}

const STRAT_BIN = "/bedrock/bin/strat";
const STRAT_STRATUM = "gentoo";
const STRAT_GCC = "/usr/bin/gcc";
const STRAT_ROOT = "/bedrock/strata";

/**
 * The DSH host process can see only stratum wrappers for gcc (`/bedrock/cross/bin/gcc`), and
 * those wrappers fail with `cannot execute 'cc1': posix_spawnp: No such file or directory`
 * because the real cc1 lives inside the gentoo stratum. Generate a tiny launcher that runs
 * the genuine compiler inside its native stratum, so goose and the C compile both see a
 * working toolchain. Returns "" when the host is not a Bedrock/stratum environment.
 */
function prepareStratCompiler(workspace) {
  try {
    if (!isExecutable(STRAT_BIN) || !isDirectory(join(STRAT_ROOT, STRAT_STRATUM))) return "";
    const dir = join(workspace, ".almap-autopilot", "cache", "toolchain");
    if (!ensureWritableDir(dir)) return "";
    const launcher = join(dir, "gcc");
    const body = [
      "#!/bin/bash",
      "# Generated by almap-autopilot: run the real gcc inside its native stratum.",
      `exec ${STRAT_BIN} ${STRAT_STRATUM} ${STRAT_GCC} "$@"`,
      "",
    ].join("\n");
    writeFileSync(launcher, body, { encoding: "utf8", mode: 0o755 });
    chmodSync(launcher, 0o755);
    return launcher;
  } catch {
    return "";
  }
}

/** Create `p` if needed and confirm it is writable; never throws. */
function ensureWritableDir(p) {
  if (typeof p !== "string" || p.length === 0) return false;
  try {
    mkdirSync(p, { recursive: true });
    accessSync(p, 2); // W_OK
    return true;
  } catch {
    return false;
  }
}

function shellQuote(value) {
  const s = String(value ?? "");
  if (s.length === 0) return "''";
  if (/^[A-Za-z0-9_@%+=:,./-]+$/.test(s)) return s;
  return `'${s.replace(/'/g, `'\\''`)}'`;
}

function formatDuration(ms) {
  const n = Number(ms);
  if (!Number.isFinite(n) || n < 0) return "?";
  if (n < 1000) return `${Math.round(n)}ms`;
  if (n < 60_000) return `${(n / 1000).toFixed(1)}s`;
  const minutes = Math.floor(n / 60_000);
  const seconds = Math.round((n % 60_000) / 1000);
  return `${minutes}m${String(seconds).padStart(2, "0")}s`;
}

function truncateText(text, maxChars, label = "characters") {
  const value = String(text ?? "");
  const limit = Math.max(1, maxChars | 0);
  if (value.length <= limit) return { text: value, truncated: false, originalChars: value.length };
  const headLength = Math.max(1, Math.floor(limit * 0.55));
  const tailLength = Math.max(1, limit - headLength);
  const head = value.slice(0, headLength);
  const tail = value.slice(-tailLength);
  const removed = value.length - head.length - tail.length;
  return {
    text: `${head}\n… [truncated ${removed} ${label}] …\n${tail}`,
    truncated: true,
    originalChars: value.length,
  };
}

function textBlock(text) {
  return [{ type: "text", text: String(text ?? "") }];
}

function isInside(root, target) {
  const rootResolved = resolve(root);
  const targetResolved = resolve(target);
  if (targetResolved === rootResolved) return true;
  return targetResolved.startsWith(rootResolved.endsWith(sep) ? rootResolved : rootResolved + sep);
}

function normalizeDisplayPath(workspace, file) {
  if (typeof file !== "string" || file.length === 0) return "";
  const cleaned = file.replace(/^["'`]+|["'`]+$/g, "");
  const absolute = isAbsolute(cleaned) ? cleaned : resolve(workspace, cleaned);
  if (isInside(workspace, absolute)) {
    const rel = relative(workspace, absolute);
    return rel.split(sep).join("/");
  }
  return cleaned;
}

async function readTextFile(path, maxChars = 2 * 1024 * 1024) {
  try {
    const raw = await readFile(path, "utf8");
    return raw.length > maxChars ? raw.slice(0, maxChars) : raw;
  } catch {
    return null;
  }
}

async function walkFiles(root, options = {}) {
  const maxDepth = options.maxDepth ?? 4;
  const maxFiles = options.maxFiles ?? 2500;
  const skipDirs = new Set(options.skipDirs ?? []);
  const files = [];
  const queue = [{ dir: root, depth: 0 }];
  while (queue.length > 0 && files.length < maxFiles) {
    const { dir, depth } = queue.shift();
    let entries;
    try {
      entries = await readdir(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      if (files.length >= maxFiles) break;
      const full = join(dir, entry.name);
      if (entry.isDirectory()) {
        if (depth >= maxDepth) continue;
        if (skipDirs.has(entry.name)) continue;
        queue.push({ dir: full, depth: depth + 1 });
      } else if (entry.isFile()) {
        files.push(full);
      }
    }
  }
  return files;
}

// -------------------------------------------------------------------------------------------------
// settings
// -------------------------------------------------------------------------------------------------

function resolveSettings(config) {
  const cfg = config && typeof config === "object" ? config : {};
  const home = homedir();
  const distDir = join(home, "Downloads", "goose-v2026.3-linux-x64");

  const workspace = firstDirectory(
    [cfg.workspace, process.env.ALMAP_WORKSPACE, process.env.DSH_WORKSPACE, DEFAULT_WORKSPACE, process.cwd()],
    resolve(DEFAULT_WORKSPACE),
  );

  const gooseBin = firstExecutable([
    cfg.gooseBin,
    process.env.GOOSE_BIN,
    process.env.GOOSE,
    join(distDir, "goose"),
    join(home, ".local", "bin", "goose"),
    "/usr/local/bin/goose",
    "/usr/bin/goose",
    "goose",
  ]) || "goose";

  // The harness process PATH can begin with /bedrock/cross/bin stratum wrappers whose gcc
  // fails with `cannot execute 'cc1': posix_spawnp`; resolve a real compiler binary first,
  // then fall back to a stratum-launcher that runs the genuine gcc inside its native stratum.
  const explicitCompiler = firstExecutableFile([cfg.cc, process.env.ALMAP_CC]);
  const directCompiler = firstExecutableFile(["/usr/bin/gcc", "/usr/local/bin/gcc", "/usr/bin/cc"]);
  const stratCompiler = explicitCompiler || directCompiler ? "" : prepareStratCompiler(workspace);
  const compiler = explicitCompiler || directCompiler || stratCompiler || "gcc";

  const gooseDir = gooseBin.includes("/") || gooseBin.includes(sep) ? dirname(gooseBin) : "";
  const gooseStdlib = firstDirectory(
    [
      cfg.gooseStdlib,
      process.env.GOOSE_STDLIB,
      join(distDir, "stdlib"),
      gooseDir ? join(gooseDir, "stdlib") : "",
    ],
    join(distDir, "stdlib"),
  );

  const docsDir = firstDirectory(
    [
      cfg.docsDir,
      process.env.ALMAP_DOCS_DIR,
      process.env.GOOSE_DOCS_DIR,
      join(distDir, "docs"),
      gooseDir ? join(gooseDir, "docs") : "",
    ],
    join(distDir, "docs"),
  );

  const timeouts = {
    check: clampInt(cfg.timeouts?.check, 5000, 600_000, 120_000),
    build: clampInt(cfg.timeouts?.build, 5000, 900_000, 240_000),
    run: clampInt(cfg.timeouts?.run, 5000, 600_000, 120_000),
    cCompile: clampInt(cfg.timeouts?.cCompile, 5000, 600_000, 120_000),
  };

  const maxBuffer = clampInt(cfg.maxBuffer, 64 * 1024, 32 * 1024 * 1024, DEFAULT_MAX_BUFFER);
  const maxOutputChars = clampInt(cfg.maxOutputChars, 1000, 200_000, DEFAULT_MAX_OUTPUT_CHARS);
  const testBinary = cfg.testBinary || "/tmp/test_almap";

  // GOOSE_HOME must be writable: goose aborts with "cannot create the build directory"
  // when the resolved home (default ~/.goose) is read-only. Prefer explicit overrides,
  // then a workspace-local cache, so the pipeline never depends on $HOME or /tmp.
  const defaultGooseHome = join(workspace, ".almap-autopilot", "cache", "goose-home");
  const gooseHomeCandidates = [cfg.gooseHome, process.env.ALMAP_GOOSE_HOME, process.env.GOOSE_HOME, defaultGooseHome]
    .map((candidate) => expandHome(String(candidate ?? "")))
    .filter(Boolean);
  let gooseHome = defaultGooseHome;
  for (const candidate of gooseHomeCandidates) {
    if (ensureWritableDir(candidate)) {
      gooseHome = candidate;
      break;
    }
  }

  return {
    workspace,
    gooseBin,
    gooseStdlib,
    docsDir,
    gooseHome,
    cc: compiler,
    testBinary,
    timeouts,
    maxBuffer,
    maxOutputChars,
    gooseExists: gooseBin.includes("/") ? isFile(gooseBin) : true,
    stdlibExists: isDirectory(gooseStdlib),
    docsExists: isDirectory(docsDir),
    buildFile: join(workspace, "almap.build"),
    mainFile: join(workspace, "almap.goose"),
  };
}

function buildPipelineSteps(settings) {
  const goose = shellQuote(settings.gooseBin);
  const testBinary = shellQuote(settings.testBinary);
  return [
    {
      id: "goose-check",
      label: "Goose type check",
      command: `${goose} check almap.goose`,
      timeoutMs: settings.timeouts.check,
      precheck: () =>
        existsSync(settings.mainFile)
          ? null
          : `almap.goose not found at ${settings.mainFile} (workspace resolved to ${settings.workspace})`,
    },
    {
      id: "goose-build-test",
      label: "Goose build test binary",
      command: `${goose} build tests/test_almap.goose --cc ${shellQuote(settings.cc)} -o ${testBinary}`,
      timeoutMs: settings.timeouts.build,
      precheck: () =>
        existsSync(join(settings.workspace, "tests", "test_almap.goose"))
          ? null
          : `tests/test_almap.goose not found under ${settings.workspace}`,
    },
    {
      id: "run-tests",
      label: "Run compiled ALmap test binary",
      command: testBinary,
      timeoutMs: settings.timeouts.run,
      dependsOn: ["goose-build-test"],
      precheck: () =>
        existsSync(settings.testBinary)
          ? null
          : `test binary ${settings.testBinary} does not exist; build it first (step goose-build-test)`,
    },
    {
      id: "c-compile",
      label: "C compile (gcc -c: net.c raw.c icmp.c pool.c)",
      command: `${shellQuote(settings.cc)} -std=c99 -Wall -Wextra -pthread -c c/net.c c/raw.c c/icmp.c c/pool.c`,
      timeoutMs: settings.timeouts.cCompile,
      precheck: () => {
        const sources = ["c/net.c", "c/raw.c", "c/icmp.c", "c/pool.c"];
        const missing = sources.filter((src) => !existsSync(join(settings.workspace, src)));
        return missing.length > 0 ? `missing C sources: ${missing.join(", ")}` : null;
      },
    },
  ];
}

function buildEnvironment(settings) {
  const env = { ...process.env };
  env.NO_COLOR = "1";
  env.FORCE_COLOR = "0";
  env.CLICOLOR = "0";
  env.ALMAP_AUTOPILOT = "1";
  env.ALMAP_WORKSPACE = settings.workspace;
  if (settings.stdlibExists) env.GOOSE_STDLIB = settings.gooseStdlib;
  if (settings.gooseHome) {
    ensureWritableDir(settings.gooseHome);
    env.GOOSE_HOME = settings.gooseHome;
  }
  // /bedrock/cross/bin and /bedrock/bin contain 25 KB stratum wrappers; children of this
  // harness process cannot execute them (gcc wrapper -> `cannot execute 'cc1'`). Drop them,
  // and put the real compiler (and goose) directories first so `gcc` resolves to real gcc.
  const WRAPPER_DIRS = new Set(["/bedrock/cross/bin", "/bedrock/bin"]);
  const pathParts = String(process.env.PATH ?? "")
    .split(":")
    .filter(Boolean)
    .filter((part) => !WRAPPER_DIRS.has(part.replace(/\/+$/, "")));
  const preferred = [];
  if (settings.cc && (settings.cc.includes("/") || settings.cc.includes(sep))) {
    preferred.push(dirname(settings.cc));
  }
  if (settings.gooseBin.includes("/") || settings.gooseBin.includes(sep)) {
    preferred.push(dirname(settings.gooseBin));
  }
  preferred.push("/usr/local/bin", "/usr/bin", "/bin");
  env.PATH = [...new Set([...preferred, ...pathParts])].join(":");
  return env;
}

// -------------------------------------------------------------------------------------------------
// command execution
// -------------------------------------------------------------------------------------------------

function runCommand({ command, cwd, env, timeoutMs, maxBuffer, signal }) {
  return new Promise((resolveRun) => {
    const startedAtMs = Date.now();
    const startedAt = new Date(startedAtMs).toISOString();
    let aborted = false;
    let child = null;
    let finished = false;

    const finish = (error, stdoutRaw, stderrRaw) => {
      if (finished) return;
      finished = true;
      if (signal && typeof signal.removeEventListener === "function") {
        try {
          signal.removeEventListener("abort", onAbort);
        } catch {
          /* ignore */
        }
      }
      const durationMs = Date.now() - startedAtMs;
      const stdout = stripAnsi(stdoutRaw ?? "");
      const stderr = stripAnsi(stderrRaw ?? "");
      let exitCode = 0;
      let childSignal = null;
      let errorMessage = "";
      let bufferOverflow = false;
      if (error) {
        errorMessage = String(error.message ?? error);
        bufferOverflow = error.code === "ERR_CHILD_PROCESS_STDIO_MAXBUFFER" || /maxBuffer/i.test(errorMessage);
        if (typeof error.code === "number") exitCode = error.code;
        else if (typeof error.code === "string" && /^SIG/.test(error.code)) {
          childSignal = error.code;
          exitCode = null;
        } else exitCode = 1;
        if (error.signal) childSignal = error.signal;
      }
      const timedOut =
        !aborted &&
        !bufferOverflow &&
        Boolean(error) &&
        (error.killed === true || childSignal === "SIGKILL" || childSignal === "SIGTERM") &&
        durationMs >= Math.max(1000, Math.floor(timeoutMs * 0.9));
      resolveRun({
        command,
        cwd,
        startedAt,
        finishedAt: new Date().toISOString(),
        durationMs,
        ok: !error,
        exitCode: exitCode ?? null,
        signal: childSignal,
        timedOut,
        aborted,
        bufferOverflow,
        error: errorMessage,
        stdout,
        stderr,
        stdoutBytes: Buffer.byteLength(stdout, "utf8"),
        stderrBytes: Buffer.byteLength(stderr, "utf8"),
      });
    };

    const onAbort = () => {
      aborted = true;
      try {
        if (child && typeof child.kill === "function") child.kill("SIGKILL");
      } catch {
        /* ignore */
      }
    };

    try {
      child = exec(
        command,
        {
          cwd,
          env,
          timeout: timeoutMs,
          maxBuffer,
          encoding: "utf8",
          shell: "/bin/bash",
          windowsHide: true,
          killSignal: "SIGKILL",
        },
        (error, stdout, stderr) => finish(error, stdout, stderr),
      );
    } catch (error) {
      finish(error, "", "");
      return;
    }

    if (signal) {
      if (signal.aborted) onAbort();
      else if (typeof signal.addEventListener === "function") signal.addEventListener("abort", onAbort, { once: true });
    }
  });
}

// -------------------------------------------------------------------------------------------------
// diagnostics parsing (Goose / gcc / runtime)
// -------------------------------------------------------------------------------------------------

const GCC_RE = /^(.+?\.(?:c|h|cc|cpp|cxx)):(\d+):(?:(\d+):)?\s*(fatal error|error|warning|note|hint)[:,]?\s*(.*)$/i;
const GOOSE_BASIC_RE = /^(.+?\.goose):(\d+)(?::(\d+))?:?\s*(fatal error|error|warning|note|hint)[:,]?\s*(.*)$/i;
const GOOSE_PAREN_RE = /^(.+?\.goose)\((\d+)(?:,(\d+))?\):\s*(fatal error|error|warning|note|hint)[:,]?\s*(.*)$/i;
const ARROW_RE = /^\s*-->\s*(.+?\.(?:goose|c|h|cc|cpp)):(\d+):(\d+)\s*$/i;
const BARE_SEVERITY_RE = /^(?:fatal error|error|warning|note|hint)(?:\[[^\]]*\])?\s*:\s*(.*)$/i;
const TOOL_DIAG_RE = /^([A-Za-z][A-Za-z0-9_.+-]*):\s*(fatal error|error|warning):\s*(.+)$/i;
const FAILED_WRAPPER_RE = /^(?:compiling|building|checking|running|fetching) .+ failed \(exit \d+\):?$/i;

function severityOf(raw) {
  const value = String(raw ?? "error").toLowerCase();
  if (value === "fatal error") return "error";
  if (value === "warning" || value === "note" || value === "hint" || value === "error") return value;
  return "error";
}

function parseDiagnostics(text, source, workspace) {
  const lines = String(text ?? "").split(/\r?\n/);
  const found = new Map();
  let pendingMessage = "";

  const push = (file, line, column, severity, message) => {
    const fileText = String(file ?? "").trim();
    if (!fileText && !message) return;
    const normalizedFile = fileText ? normalizeDisplayPath(workspace, fileText) : "";
    const entry = {
      file: normalizedFile,
      line: line ? Number(line) : null,
      column: column ? Number(column) : null,
      severity: severityOf(severity),
      message: stripAnsi(String(message ?? "")).trim(),
      source,
    };
    const key = `${entry.file}|${entry.line ?? ""}|${entry.column ?? ""}|${entry.severity}|${entry.message}`;
    if (!found.has(key)) found.set(key, entry);
  };

  for (let index = 0; index < lines.length; index += 1) {
    const rawLine = lines[index];
    const line = stripAnsi(rawLine).replace(/\t/g, "    ");
    if (!line.trim()) {
      pendingMessage = "";
      continue;
    }

    const gccMatch = GCC_RE.exec(line);
    if (gccMatch) {
      push(gccMatch[1], gccMatch[2], gccMatch[3], gccMatch[4], gccMatch[5]);
      continue;
    }

    const basicMatch = GOOSE_BASIC_RE.exec(line);
    if (basicMatch) {
      push(basicMatch[1], basicMatch[2], basicMatch[3], basicMatch[4], basicMatch[5]);
      continue;
    }

    const parenMatch = GOOSE_PAREN_RE.exec(line);
    if (parenMatch) {
      push(parenMatch[1], parenMatch[2], parenMatch[3], parenMatch[4], parenMatch[5]);
      continue;
    }

    const arrowMatch = ARROW_RE.exec(line);
    if (arrowMatch) {
      push(arrowMatch[1], arrowMatch[2], arrowMatch[3], "error", pendingMessage || "compiler error");
      pendingMessage = "";
      continue;
    }

    const toolMatch = TOOL_DIAG_RE.exec(line);
    if (toolMatch) {
      // ld / collect2 / ar style: "collect2: error: ld returned 1 exit status"
      push("", null, null, toolMatch[2], `${toolMatch[1]}: ${toolMatch[3]}`);
      continue;
    }

    const wrapperLine = line.trim();
    if (FAILED_WRAPPER_RE.test(wrapperLine)) {
      // goose build relays C/link failures as "compiling ... failed (exit N):" headers.
      push("", null, null, "error", wrapperLine);
      continue;
    }

    if (/^(?:cannot open file|cannot create the build directory|undefined reference to)\b/i.test(wrapperLine)) {
      push("", null, null, "error", wrapperLine);
      continue;
    }

    const bareMatch = BARE_SEVERITY_RE.exec(line.trim());
    if (bareMatch) {
      pendingMessage = bareMatch[1].trim();
      continue;
    }
  }

  const diagnostics = [...found.values()];
  if (diagnostics.length === 0) {
    // Last-resort fallback: keep the most telling output lines so self-heal is never empty.
    const interesting = lines
      .map((entry) => stripAnsi(entry).trim())
      .filter((entry) => entry.length > 0 && /error|fatal|failed|failure|assert|panic|exception|timed out/i.test(entry))
      .slice(0, 6);
    for (const entry of interesting) {
      push("", null, null, "error", entry);
    }
    if (found.size === 0) {
      const tail = lines
        .map((entry) => stripAnsi(entry).trim())
        .filter(Boolean)
        .slice(-8);
      if (tail.length > 0) push("", null, null, "error", tail.join(" | "));
    }
  }

  return [...found.values()].slice(0, MAX_RAW_DIAGNOSTICS);
}

function formatCodeSnippet(lines, startLine, endLine) {
  const width = String(endLine).length;
  const out = [];
  for (let line = startLine; line <= endLine; line += 1) {
    out.push(`${String(line).padStart(width)} | ${lines[line - 1] ?? ""}`);
  }
  return out.join("\n");
}

async function enrichDiagnostics(diagnostics, settings, options = {}) {
  const maxDiagnostics = clampInt(options.maxDiagnostics, 1, MAX_RAW_DIAGNOSTICS, 25);
  const includeSourceContext = options.includeSourceContext !== false;
  const selected = diagnostics.slice(0, maxDiagnostics);
  const enriched = [];
  for (const diagnostic of selected) {
    const copy = { ...diagnostic };
    if (includeSourceContext && copy.file && copy.line) {
      const candidate = isAbsolute(copy.file) ? copy.file : resolve(settings.workspace, copy.file);
      if (isInside(settings.workspace, candidate) && isFile(candidate)) {
        const source = await readTextFile(candidate, 1_500_000);
        if (source !== null) {
          const sourceLines = source.split(/\r?\n/);
          const line = Number(copy.line);
          if (line >= 1 && line <= sourceLines.length) {
            const start = Math.max(1, line - 4);
            const end = Math.min(sourceLines.length, line + 4);
            copy.absPath = candidate;
            copy.snippet = formatCodeSnippet(sourceLines, start, end);
            copy.snippetStartLine = start;
          }
        }
      }
    }
    enriched.push(copy);
  }
  return enriched;
}

// -------------------------------------------------------------------------------------------------
// pipeline
// -------------------------------------------------------------------------------------------------

function newRunId(state) {
  state.runCounter += 1;
  return `almap-${Date.now().toString(36)}-${state.runCounter.toString(36)}`;
}

async function runPipeline(settings, state, options = {}) {
  const startedAtMs = Date.now();
  const runId = newRunId(state);
  const definitions = buildPipelineSteps(settings);
  const requested = Array.isArray(options.steps) && options.steps.length > 0
    ? definitions.filter((step) => options.steps.includes(step.id))
    : definitions;
  const failFast = options.failFast === true;
  const maxOutputChars = clampInt(options.maxOutputChars, 500, 200_000, settings.maxOutputChars);
  const env = buildEnvironment(settings);
  const results = [];
  let failFastTriggered = false;

  for (const definition of requested) {
    if (failFastTriggered) {
      results.push({
        id: definition.id,
        label: definition.label,
        command: definition.command,
        ok: false,
        skipped: true,
        skipReason: "failFast: an earlier step failed",
        exitCode: null,
        signal: null,
        timedOut: false,
        bufferOverflow: false,
        durationMs: 0,
        stdout: "",
        stderr: "",
        stdoutBytes: 0,
        stderrBytes: 0,
      });
      continue;
    }

    const dependencyMissing = (definition.dependsOn ?? []).some((dependencyId) => {
      const dependencySelected = requested.some((step) => step.id === dependencyId);
      if (!dependencySelected) return false; // explicitly not requested: do not block
      const dependencyResult = results.find((entry) => entry.id === dependencyId);
      return !dependencyResult || dependencyResult.ok !== true;
    });

    if (dependencyMissing) {
      results.push({
        id: definition.id,
        label: definition.label,
        command: definition.command,
        ok: false,
        skipped: true,
        skipReason: `dependency not satisfied (${(definition.dependsOn ?? []).join(", ")})`,
        exitCode: null,
        signal: null,
        timedOut: false,
        bufferOverflow: false,
        durationMs: 0,
        stdout: "",
        stderr: "",
        stdoutBytes: 0,
        stderrBytes: 0,
      });
      continue;
    }

    let precheckError = "";
    if (typeof definition.precheck === "function") {
      try {
        precheckError = definition.precheck() || "";
      } catch (error) {
        precheckError = String(error?.message ?? error);
      }
    }
    if (precheckError) {
      results.push({
        id: definition.id,
        label: definition.label,
        command: definition.command,
        ok: false,
        skipped: false,
        exitCode: null,
        signal: null,
        timedOut: false,
        bufferOverflow: false,
        durationMs: 0,
        stdout: "",
        stderr: precheckError,
        stdoutBytes: 0,
        stderrBytes: Buffer.byteLength(precheckError, "utf8"),
        error: precheckError,
        precheckFailed: true,
      });
      if (failFast) failFastTriggered = true;
      continue;
    }

    const runResult = await runCommand({
      command: definition.command,
      cwd: settings.workspace,
      env,
      timeoutMs: definition.timeoutMs,
      maxBuffer: settings.maxBuffer,
      signal: options.signal,
    });

    const trimmedStdout = truncateText(runResult.stdout, maxOutputChars);
    const trimmedStderr = truncateText(runResult.stderr, maxOutputChars);
    const stepResult = {
      id: definition.id,
      label: definition.label,
      command: definition.command,
      ok: runResult.ok,
      skipped: false,
      startedAt: runResult.startedAt,
      finishedAt: runResult.finishedAt,
      durationMs: runResult.durationMs,
      exitCode: runResult.exitCode,
      signal: runResult.signal,
      timedOut: runResult.timedOut,
      aborted: runResult.aborted,
      bufferOverflow: runResult.bufferOverflow,
      error: runResult.error || "",
      stdout: trimmedStdout.text,
      stderr: trimmedStderr.text,
      stdoutBytes: runResult.stdoutBytes,
      stderrBytes: runResult.stderrBytes,
      stdoutTruncated: trimmedStdout.truncated,
      stderrTruncated: trimmedStderr.truncated,
    };
    results.push(stepResult);
    if (!runResult.ok && failFast) failFastTriggered = true;
  }

  const failedSteps = results.filter((step) => !step.ok && !step.skipped).map((step) => step.id);
  const skippedSteps = results.filter((step) => step.skipped).map((step) => step.id);
  const ok = failedSteps.length === 0;

  let diagnostics = [];
  for (const step of results) {
    if (step.ok || step.skipped) continue;
    const combined = `${step.stdout}\n${step.stderr}`;
    const parsed = parseDiagnostics(combined, step.id, settings.workspace);
    diagnostics.push(...parsed);
  }
  // de-duplicate across steps while keeping the most severe ordering
  const severityRank = { error: 0, warning: 1, note: 2, hint: 3 };
  const deduped = new Map();
  for (const diagnostic of diagnostics) {
    const key = `${diagnostic.file}|${diagnostic.line ?? ""}|${diagnostic.column ?? ""}|${diagnostic.message}`;
    const previous = deduped.get(key);
    if (!previous || severityRank[diagnostic.severity] < severityRank[previous.severity]) deduped.set(key, diagnostic);
  }
  diagnostics = [...deduped.values()]
    .sort((a, b) => (severityRank[a.severity] ?? 9) - (severityRank[b.severity] ?? 9) || (a.file || "").localeCompare(b.file || ""))
    .slice(0, MAX_RAW_DIAGNOSTICS);

  const durationMs = Date.now() - startedAtMs;
  const executed = results.filter((step) => !step.skipped);
  const result = {
    ok,
    runId,
    startedAt: new Date(startedAtMs).toISOString(),
    finishedAt: new Date().toISOString(),
    durationMs,
    workspace: settings.workspace,
    request: {
      mode: requested.length === definitions.length ? "all" : "subset",
      requestedSteps: requested.map((step) => step.id),
      failFast,
    },
    steps: results,
    failedSteps,
    failedStep: failedSteps[0] ?? null,
    skippedSteps,
    executedCount: executed.length,
    passedCount: executed.filter((step) => step.ok).length,
    diagnostics,
    environment: {
      gooseBin: settings.gooseBin,
      gooseExists: settings.gooseExists,
      gooseStdlib: settings.gooseStdlib,
      stdlibExists: settings.stdlibExists,
      gooseHome: settings.gooseHome,
      cc: settings.cc,
      docsDir: settings.docsDir,
      docsExists: settings.docsExists,
      testBinary: settings.testBinary,
      node: process.version,
      platform: `${process.platform}-${process.arch}`,
    },
    hints: buildRunHints(settings, results, failedSteps),
  };

  state.lastRun = result;
  state.history.push({
    runId: result.runId,
    startedAt: result.startedAt,
    finishedAt: result.finishedAt,
    durationMs: result.durationMs,
    ok: result.ok,
    failedStep: result.failedStep,
    failedSteps: result.failedSteps,
    passedCount: result.passedCount,
    executedCount: result.executedCount,
  });
  if (state.history.length > MAX_HISTORY) state.history.splice(0, state.history.length - MAX_HISTORY);

  return result;
}

function buildRunHints(settings, results, failedSteps) {
  const hints = [];
  const byId = new Map(results.map((step) => [step.id, step]));
  const gooseCheck = byId.get("goose-check");
  const cCompile = byId.get("c-compile");
  const runTests = byId.get("run-tests");

  if (!settings.gooseExists) {
    hints.push(`Goose binary not found at ${settings.gooseBin}. Set GOOSE_BIN or install the Goose toolchain.`);
  }
  if (!settings.stdlibExists) {
    hints.push(`Goose stdlib directory not found at ${settings.gooseStdlib}; GOOSE_STDLIB will only be exported when it exists.`);
  }
  if (gooseCheck && !gooseCheck.ok && /command not found|no such file or directory/i.test(`${gooseCheck.stderr}${gooseCheck.error}`)) {
    hints.push("The goose CLI could not be executed. Verify the binary path and permissions before editing project code.");
  }
  if (cCompile && !cCompile.ok && /command not found/i.test(`${cCompile.stderr}${cCompile.error}`)) {
    hints.push("gcc was not found on PATH; install gcc to compile the C layer.");
  }
  if (runTests && !runTests.ok && /permission denied|operation not permitted/i.test(`${runTests.stdout}${runTests.stderr}`)) {
    hints.push("The test binary needs elevated privileges for raw sockets; this is an environment limitation, not necessarily a code bug.");
  }
  if (runTests && runTests.timedOut) {
    hints.push("The test binary hit the timeout. Check for blocking network I/O or an infinite loop in the test path.");
  }
  if (failedSteps.includes("goose-check") && !failedSteps.includes("c-compile")) {
    hints.push("C sources are clean; the failure is in Goose code. Use auto_self_heal, then re-run.");
  }
  if (failedSteps.length === 0) hints.push("All steps passed. The project builds and tests cleanly.");
  return hints;
}

function summarizeRunText(run) {
  const lines = [];
  lines.push(`# auto_build_and_test — ${run.ok ? "PASS" : "FAIL"} (${formatDuration(run.durationMs)})`);
  lines.push("");
  lines.push(`run: ${run.runId}`);
  lines.push(`workspace: ${run.workspace}`);
  lines.push(`done: ${run.passedCount}/${run.executedCount} executed steps ok${run.skippedSteps.length ? `, ${run.skippedSteps.length} skipped` : ""}`);
  lines.push("");
  lines.push("## Steps");
  for (const step of run.steps) {
    if (step.skipped) {
      lines.push(`- SKIP ${step.label} (${step.skipReason})`);
      continue;
    }
    const status = step.ok ? "OK" : "FAIL";
    lines.push(
      `- ${status} ${step.label} — exit ${step.exitCode ?? "?"}${step.signal ? ` signal ${step.signal}` : ""}${
        step.timedOut ? " timeout" : ""
      }${step.bufferOverflow ? " output-overflow" : ""} (${formatDuration(step.durationMs)})`,
    );
    if (!step.ok) {
      const output = `${step.stderr || step.stdout || step.error || ""}`.trim();
      if (output) {
        const trimmed = truncateText(output, 1400);
        lines.push("```");
        lines.push(trimmed.text);
        lines.push("```");
      }
    }
  }

  if (run.diagnostics.length > 0) {
    lines.push("");
    lines.push(`## Diagnostics (${run.diagnostics.length})`);
    for (const diagnostic of run.diagnostics.slice(0, 30)) {
      lines.push(`- ${formatDiagnosticLocation(diagnostic)}: ${diagnostic.message}`);
    }
  }

  if (run.hints.length > 0) {
    lines.push("");
    lines.push("## Hints");
    for (const hint of run.hints) lines.push(`- ${hint}`);
  }

  if (!run.ok) {
    lines.push("");
    lines.push(`Next: call auto_self_heal to get the exact file:line repair context, fix it, then call auto_build_and_test again.`);
  }
  return truncateText(lines.join("\n"), 24000).text;
}

function formatDiagnosticLocation(diagnostic) {
  const file = diagnostic.file || "<output>";
  const line = diagnostic.line ?? "?";
  return `${file}:${line}${diagnostic.column ? `:${diagnostic.column}` : ""} [${diagnostic.severity}]`;
}

// -------------------------------------------------------------------------------------------------
// self-heal
// -------------------------------------------------------------------------------------------------

async function buildRepairReport(settings, state, run, options = {}) {
  const maxDiagnostics = clampInt(options.maxDiagnostics, 1, MAX_RAW_DIAGNOSTICS, 25);
  const enriched = await enrichDiagnostics(run.diagnostics, settings, {
    maxDiagnostics,
    includeSourceContext: options.includeSourceContext !== false,
  });

  const lines = [];
  lines.push(`# auto_self_heal — repair context for run ${run.runId}`);
  lines.push("");
  lines.push(`status: FAIL (${formatDuration(run.durationMs)})`);
  lines.push(`workspace: ${settings.workspace}`);
  lines.push(`failed steps: ${run.failedSteps.join(", ") || "none"}`);
  lines.push("");
  lines.push("Fix the diagnostics below in place, then call auto_build_and_test again.");
  lines.push("Do not ask the user to run commands or to paste errors: act on the file:line evidence.");
  lines.push("");

  if (enriched.length === 0) {
    lines.push("## Diagnostics unavailable");
    lines.push("The failing steps produced no parseable diagnostics. Inspect the raw step output and fix the failure.");
  } else {
    const grouped = new Map();
    for (const diagnostic of enriched) {
      const key = diagnostic.file || "<process output>";
      if (!grouped.has(key)) grouped.set(key, []);
      grouped.get(key).push(diagnostic);
    }
    for (const [file, entries] of grouped) {
      lines.push(`## ${file}`);
      for (const entry of entries) {
        lines.push(`- ${formatDiagnosticLocation(entry)}: ${entry.message}`);
        if (entry.snippet) {
          lines.push(`  source (lines ${entry.snippetStartLine}–${entry.snippetStartLine + 8}):`);
          lines.push("```");
          const codeLines = entry.snippet.split("\n");
          for (const codeLine of codeLines) lines.push(`  ${codeLine}`);
          lines.push("```");
        }
      }
      lines.push("");
    }
  }

  const failingCommands = run.steps
    .filter((step) => !step.ok && !step.skipped)
    .map((step) => `- \`${step.command}\` → exit ${step.exitCode ?? "?"}`);
  if (failingCommands.length > 0) {
    lines.push("## Failing commands");
    for (const command of failingCommands) lines.push(command);
    lines.push("");
  }

  lines.push("## Loop contract");
  lines.push("1. Edit the exact files/lines above (smallest possible diff).");
  lines.push("2. Call auto_build_and_test.");
  lines.push("3. If it still fails, call auto_self_heal again and repeat until green.");
  lines.push("4. If the same environment error persists, report it once at the end; never block on the user mid-loop.");

  const reportText = truncateText(lines.join("\n"), 30000).text;
  return {
    ok: false,
    status: "needs_repair",
    runId: run.runId,
    checkedAt: new Date().toISOString(),
    workspace: settings.workspace,
    failedSteps: run.failedSteps,
    diagnostics: enriched,
    repairPrompt: reportText,
    repairInstructions: [
      "Fix only the reported file:line locations.",
      "Then call auto_build_and_test again and iterate until it passes.",
    ],
    hints: run.hints ?? [],
  };
}

// -------------------------------------------------------------------------------------------------
// project context (Objective.txt + README.md + git)
// -------------------------------------------------------------------------------------------------

const STEP_RE = /\bstep\s+(\d{1,3})\b/gi;
const HEADING_RE = /^(#{1,6})\s+(.+?)\s*$/;

function detectStatus(text) {
  const lower = String(text ?? "").toLowerCase();
  if (/(complete|completed|done|finished|✅|\[x\])/.test(lower)) return "complete";
  if (/(in progress|in-progress|ongoing|wip|current|underway)/.test(lower)) return "in progress";
  // README "Status: Step 14 — XML Output." marks the step the project is working on.
  if (/status:\s*(?:step\s+)?\d+/.test(lower)) return "in progress";
  if (/(pending|todo|to do|not started|planned|next up)/.test(lower)) return "pending";
  return "unknown";
}

function collectStepMentions(text, sourceFile, maxMentions = 200) {
  const lines = String(text ?? "").split(/\r?\n/);
  const mentions = [];
  let currentHeading = "";
  for (let index = 0; index < lines.length; index += 1) {
    const line = lines[index].trim();
    const headingMatch = HEADING_RE.exec(line);
    if (headingMatch) currentHeading = headingMatch[2].trim();
    STEP_RE.lastIndex = 0;
    let match;
    while ((match = STEP_RE.exec(line)) !== null && mentions.length < maxMentions) {
      const stepNumber = Number.parseInt(match[1], 10);
      const context = [lines[index], lines[index + 1] ?? "", lines[index - 1] ?? ""].join(" ");
      mentions.push({
        number: stepNumber,
        line: index + 1,
        heading: currentHeading,
        text: line.length > 200 ? `${line.slice(0, 200)}…` : line,
        status: detectStatus(context),
        source: sourceFile,
      });
      if (match.index === STEP_RE.lastIndex) break;
    }
  }
  return mentions;
}

function extractReadmeDescription(readme) {
  const lines = String(readme ?? "").split(/\r?\n/).slice(0, 80);
  const paragraphs = [];
  let current = [];
  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (line.startsWith("#") || line.startsWith("```") || line.startsWith("|") || line.startsWith(">")) {
      if (current.length > 0) {
        paragraphs.push(current.join(" "));
        current = [];
      }
      continue;
    }
    if (line.length === 0) {
      if (current.length > 0) {
        paragraphs.push(current.join(" "));
        current = [];
      }
      continue;
    }
    current.push(line);
  }
  if (current.length > 0) paragraphs.push(current.join(" "));
  const paragraph = paragraphs.find((entry) => entry.length > 40) ?? paragraphs[0] ?? "";
  return paragraph.length > 400 ? `${paragraph.slice(0, 397)}…` : paragraph;
}

function readmeTitle(readme) {
  const lines = String(readme ?? "").split(/\r?\n/);
  for (const line of lines) {
    const match = /^#\s+(.+?)\s*$/.exec(line.trim());
    if (match) return match[1].trim();
  }
  return "";
}

async function readProjectContext(settings, options = {}) {
  const maxCommits = clampInt(options.maxCommits, 1, 100, 12);
  const includeGit = options.includeGit !== false;
  const warnings = [];

  const objectivePath = join(settings.workspace, "Objective.txt");
  const readmePath = join(settings.workspace, "README.md");
  const objective = await readTextFile(objectivePath, 500_000);
  const readme = await readTextFile(readmePath, 1_000_000);

  const stepMentions = [];
  if (objective) stepMentions.push(...collectStepMentions(objective, "Objective.txt"));
  if (readme) stepMentions.push(...collectStepMentions(readme, "README.md"));
  if (!objective) warnings.push("Objective.txt is missing; project intent was derived from README.md and the git log.");

  const maxMention = stepMentions.reduce(
    (best, mention) => (best === null || mention.number > best.number ? mention : best),
    null,
  );

  // Git evidence (tolerant: a non-repo workspace simply yields empty values).
  let gitLog = [];
  let modified = [];
  let untracked = [];
  let branch = "";
  let latestCommit = null;
  const gitEnv = buildEnvironment(settings);
  const gitCwd = settings.workspace;
  if (includeGit) {
    const [logResult, statusResult, branchResult] = await Promise.all([
      runCommand({
        command: `git log -n ${maxCommits} --date=short --pretty=format:%h%x09%ad%x09%s`,
        cwd: gitCwd,
        env: gitEnv,
        timeoutMs: 20_000,
        maxBuffer: 2 * 1024 * 1024,
      }),
      runCommand({
        command: "git status --porcelain",
        cwd: gitCwd,
        env: gitEnv,
        timeoutMs: 20_000,
        maxBuffer: 2 * 1024 * 1024,
      }),
      runCommand({
        command: "git branch --show-current",
        cwd: gitCwd,
        env: gitEnv,
        timeoutMs: 10_000,
        maxBuffer: 256 * 1024,
      }),
    ]);
    if (logResult.ok) {
      gitLog = logResult.stdout
        .split(/\r?\n/)
        .map((line) => line.trim())
        .filter(Boolean)
        .map((line) => {
          const [hash, date, ...subjectParts] = line.split("\t");
          return { hash, date, subject: subjectParts.join("\t") };
        })
        .filter((entry) => entry.hash && entry.subject);
      latestCommit = gitLog[0] ?? null;
    } else if (includeGit) {
      warnings.push("git log failed; the project may not be inside a git repository.");
    }
    if (statusResult.ok) {
      for (const line of statusResult.stdout.split(/\r?\n/).filter(Boolean)) {
        const code = line.slice(0, 2);
        const file = line.slice(3).trim();
        if (code === "??") untracked.push(file);
        else modified.push(file);
      }
    }
    if (branchResult.ok) branch = branchResult.stdout.trim();
  }

  if (!readme) warnings.push("README.md is missing; step detection relies on Objective.txt and the git log.");
  if (!readme && !objective) warnings.push("Neither README.md nor Objective.txt exists; project context is unknown.");

  // Highest step from docs first; fall back to the highest step named in git commit subjects.
  let step = maxMention;
  let stepSource = step ? `${step.source}:${step.line}` : "";
  if (!step && gitLog.length > 0) {
    for (const commit of gitLog) {
      const match = /\bstep\s+(\d{1,3})\b/i.exec(commit.subject);
      if (match) {
        const number = Number.parseInt(match[1], 10);
        if (!step || number > step.number) {
          step = {
            number,
            line: null,
            heading: "",
            text: commit.subject,
            status: "unknown",
            source: `git:${commit.hash}`,
          };
        }
      }
    }
    if (step) {
      stepSource = `git log:${step.source}`;
      warnings.push("No step marker in README.md/Objective.txt; the step number came from git commit subjects and may be stale.");
    }
  }
  if (step && step.number <= 0) step = null;

  const committedStepNumbers = gitLog
    .map((commit) => /\bstep\s+(\d{1,3})\b/i.exec(commit.subject))
    .filter(Boolean)
    .map((match) => Number.parseInt(match[1], 10));
  const latestCommittedStep = committedStepNumbers.length > 0 ? Math.max(...committedStepNumbers) : null;

  const counts = { gooseFiles: 0, cFiles: 0, cHeaders: 0, gooseModules: 0, tests: 0 };
  const files = await walkFiles(settings.workspace, {
    maxDepth: 4,
    maxFiles: 4000,
    skipDirs: new Set([".git", "node_modules", "target", "build", "dist", "plugins", ".dsh", "vendor"]),
  });
  for (const file of files) {
    const extension = extname(file).toLowerCase();
    if (extension === ".goose") counts.gooseFiles += 1;
    if (extension === ".c") counts.cFiles += 1;
    if (extension === ".h") counts.cHeaders += 1;
    if (isInside(join(settings.workspace, "modules"), file) && extension === ".goose") counts.gooseModules += 1;
    if (isInside(join(settings.workspace, "tests"), file) && (extension === ".goose" || extension === ".sh")) counts.tests += 1;
  }

  const description = extractReadmeDescription(readme ?? "") || readmeTitle(readme ?? "") || "";
  const stepTitle = step
    ? step.heading && !/^step\s+\d+/i.test(step.heading)
      ? step.heading
      : (step.text ?? "").replace(/^#+\s*/, "").replace(/\bstep\s+\d{1,3}\b[:\s-]*/i, "").trim()
    : "";
  const nextMentions = stepMentions
    .filter((mention) => mention.number > (step?.number ?? 0))
    .sort((a, b) => a.number - b.number);
  const nextSteps = [];
  const seenNext = new Set();
  for (const mention of nextMentions) {
    if (seenNext.has(mention.number)) continue;
    seenNext.add(mention.number);
    nextSteps.push({ number: mention.number, text: mention.text, status: mention.status, source: `${mention.source}:${mention.line}` });
    if (nextSteps.length >= 6) break;
  }
  if (nextSteps.length === 0) {
    const upcoming = stepMentions
      .filter((mention) => mention.number === (step?.number ?? 0) && mention.status !== "complete")
      .slice(0, 3);
    for (const mention of upcoming) nextSteps.push({ number: mention.number, text: mention.text, status: mention.status, source: `${mention.source}:${mention.line}` });
  }
  if (nextSteps.length === 0 && step && step.number < BRIEF_TARGET_STEP) {
    nextSteps.push({
      number: BRIEF_TARGET_STEP,
      text: `Step ${BRIEF_TARGET_STEP} (target from the autopilot brief; not yet described in README.md)`,
      status: "pending",
      source: "autopilot brief",
    });
  }

  const currentStepLabel = step ? `Step ${step.number}` : "unknown";
  const project = {
    currentStep: currentStepLabel,
    currentStepNumber: step ? step.number : null,
    targetStep: BRIEF_TARGET_STEP,
    currentStepTitle: stepTitle,
    currentStepStatus: step ? step.status : "unknown",
    stepSource: stepSource || "no step marker found",
    objectiveSource: objective ? "Objective.txt" : "README.md + git log (Objective.txt missing)",
    branch: branch || "(unknown branch)",
    lastCommit: latestCommit ? `${latestCommit.hash} ${latestCommit.subject}` : "",
    latestCommit,
    latestCommittedStep,
    description,
    readmeTitle: readmeTitle(readme ?? ""),
    counts,
    workingTree: {
      modifiedCount: modified.length,
      untrackedCount: untracked.length,
      modified: modified.slice(0, 40),
      untracked: untracked.slice(0, 40),
    },
    steps: stepMentions
      .filter((mention) => mention.line !== null)
      .slice(0, 40)
      .map((mention) => ({
        number: mention.number,
        status: mention.status,
        heading: mention.heading,
        text: mention.text,
        source: `${mention.source}:${mention.line}`,
      })),
    nextSteps,
    warnings,
  };

  const summaryLines = [];
  summaryLines.push(`# project_context_sync — ${currentStepLabel}`);
  summaryLines.push("");
  summaryLines.push(`- current step: **${currentStepLabel}**${stepTitle ? ` — ${stepTitle}` : ""}`);
  summaryLines.push(`- step status: ${project.currentStepStatus}`);
  summaryLines.push(`- step evidence: ${project.stepSource}`);
  if (step && latestCommittedStep !== null && latestCommittedStep !== step.number) {
    summaryLines.push(
      `- note: git history only goes to Step ${latestCommittedStep} while docs target ${currentStepLabel}; the uncommitted working tree is the live state.`,
    );
  }
  if (step && step.number < BRIEF_TARGET_STEP) {
    summaryLines.push(
      `- note: the autopilot brief targets Step ${BRIEF_TARGET_STEP}, but the repository only evidences ${currentStepLabel} (${project.stepSource}); report the mismatch instead of silently assuming either step.`,
    );
  }
  summaryLines.push(`- objective source: ${project.objectiveSource}`);
  summaryLines.push(`- branch: ${project.branch}`);
  summaryLines.push(`- last commit: ${project.lastCommit || "(none)"}`);
  summaryLines.push(
    `- working tree: ${project.workingTree.modifiedCount} modified, ${project.workingTree.untrackedCount} untracked`,
  );
  summaryLines.push(
    `- counts: ${counts.gooseFiles} Goose files (${counts.gooseModules} modules), ${counts.cFiles} C sources, ${counts.cHeaders} headers, ${counts.tests} test files`,
  );
  if (project.description) summaryLines.push(`- description: ${project.description}`);
  if (nextSteps.length > 0) {
    summaryLines.push("");
    summaryLines.push("## Next steps referenced by the project docs");
    for (const next of nextSteps) summaryLines.push(`- Step ${next.number} (${next.status}): ${next.text}`);
  }
  if (warnings.length > 0) {
    summaryLines.push("");
    summaryLines.push("## Context warnings");
    for (const warning of warnings) summaryLines.push(`- ${warning}`);
  }
  summaryLines.push("");
  summaryLines.push("Anchor on this step before editing. Run auto_build_and_test after changes.");

  return {
    ok: true,
    generatedAt: new Date().toISOString(),
    workspace: settings.workspace,
    project,
    summary: truncateText(summaryLines.join("\n"), 20000).text,
  };
}

// -------------------------------------------------------------------------------------------------
// goose syntax lookup
// -------------------------------------------------------------------------------------------------

const TOPIC_TERMS = {
  ffi: ["extern", "external", "ffi", "foreign", "cdecl", "extern proc", "extern type", "link_name", "c_call", "import c"],
  struct: ["struct", "record", "field", "impl", "constructor", "layout"],
  pointer: ["pointer", "ptr", "address", "address_of", "deref", "unsafe", "null", "raw pointer"],
  enum: ["enum", "variant", "tagged union", "case"],
  union: ["union", "untagged", "reinterpret"],
  generics: ["generic", "type parameter", "type_param", "template", "comptime"],
  module: ["module", "import", "package", "export", "namespace"],
  test: ["test", "assert", "describe", "expect", "suite"],
  thread: ["thread", "spawn", "threaded", "mutex", "atomic", "sync"],
  memory: ["alloc", "malloc", "free", "memory", "arena", "buffer"],
  build: ["build", "package", "manifest", "c_sources", "c_libs", "compile"],
  error: ["error", "result", "try", "catch", "panic", "optional"],
};

const LOOKUP_TOPICS = Object.keys(TOPIC_TERMS);
const DOC_EXTENSIONS = new Set([".md", ".markdown", ".txt", ".goose", ".yml", ".yaml", ".go", ".gooseh"]);

function escapeRegExp(input) {
  return String(input).replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function buildSearchTerms(args) {
  const terms = [];
  const topic = typeof args.topic === "string" ? args.topic.trim().toLowerCase() : "";
  if (topic) {
    const mapped = TOPIC_TERMS[topic] ?? [topic];
    for (const term of mapped) if (term) terms.push(term);
    terms.push(topic);
  }
  const query = typeof args.query === "string" ? args.query.trim() : "";
  if (query) {
    terms.push(query);
    for (const word of query.split(/[\s,;|]+/)) if (word.length > 1) terms.push(word);
  }
  return [...new Set(terms.filter((term) => typeof term === "string" && term.trim().length > 0))];
}

function lineHasTerm(line, term) {
  if (!term) return false;
  if (/^[A-Za-z][A-Za-z0-9_]*$/.test(term)) {
    return new RegExp(`(^|[^A-Za-z0-9_])${escapeRegExp(term)}([^A-Za-z0-9_]|$)`, "i").test(line);
  }
  return line.toLowerCase().includes(term.toLowerCase());
}

function scoreContext(context) {
  let score = 0;
  const lower = context.toLowerCase();
  if (/reference|spec|syntax|struct|pointer|ffi|extern/i.test(lower)) score += 2;
  return score;
}

async function gooseSyntaxLookup(settings, args) {
  const startedAtMs = Date.now();
  const terms = buildSearchTerms(args);
  if (terms.length === 0) {
    return {
      ok: false,
      error: "Provide a topic (ffi, struct, pointer, ...) or a query string.",
      availableTopics: LOOKUP_TOPICS,
      docsDir: settings.docsDir,
    };
  }
  const maxResults = clampInt(args.maxResults, 1, 20, 8);
  const contextLines = clampInt(args.contextLines, 0, 20, 3);
  const docsDir = settings.docsDir;
  const roots = [
    { root: docsDir, label: "docs" },
    { root: join(dirname(docsDir), "stdlib"), label: "stdlib" },
    { root: dirname(dirname(docsDir)), label: "goose-dist" },
  ].filter((entry) => isDirectory(entry.root));
  if (!isDirectory(docsDir)) {
    const dist = dirname(dirname(docsDir));
    return {
      ok: false,
      error: `Goose docs directory not found at ${docsDir}. Set ALMAP_DOCS_DIR to the extracted Goose docs directory.`,
      candidates: [docsDir, join(dist, "docs"), join(homedir(), "Downloads", "goose-v2026.3-linux-x64", "docs")],
      searchedTerms: terms,
      availableTopics: LOOKUP_TOPICS,
    };
  }

  const files = [];
  for (const entry of roots) {
    const walked = await walkFiles(entry.root, {
      maxDepth: entry.label === "goose-dist" ? 3 : 6,
      maxFiles: 900,
      skipDirs: new Set([".git", "node_modules", "site", "assets", "images", "img"]),
    });
    for (const file of walked) {
      if (!DOC_EXTENSIONS.has(extname(file).toLowerCase())) continue;
      if (files.length >= 700) break;
      files.push({ file, root: entry.root, label: entry.label });
    }
    if (files.length >= 700) break;
  }

  const matches = [];
  const codeBlocks = [];
  const fileCache = new Map();

  for (const entry of files) {
    let text = fileCache.get(entry.file);
    if (text === undefined) {
      text = await readTextFile(entry.file, 1_200_000);
      fileCache.set(entry.file, text);
    }
    if (!text) continue;
    const relativeFile = isInside(entry.root, entry.file) ? relative(entry.root, entry.file).split(sep).join("/") : basename(entry.file);
    const lines = text.split(/\r?\n/);
    let heading = "";
    let fenceOpen = false;
    let fenceStart = 0;
    let fenceHeading = "";
    let fenceText = "";
    let fenceMatched = false;

    for (let index = 0; index < lines.length; index += 1) {
      const line = lines[index];
      const headingMatch = HEADING_RE.exec(line.trim());
      if (!fenceOpen && headingMatch) heading = headingMatch[2].trim();

      if (/^\s*```/.test(line)) {
        if (!fenceOpen) {
          fenceOpen = true;
          fenceStart = index + 1;
          fenceHeading = heading;
          fenceText = "";
          fenceMatched = false;
        } else {
          if (fenceMatched && fenceText.trim().length > 0 && codeBlocks.length < 12) {
            codeBlocks.push({
              file: relativeFile,
              line: fenceStart,
              heading: fenceHeading,
              code: truncateText(fenceText, 1600).text,
            });
          }
          fenceOpen = false;
          fenceText = "";
          fenceMatched = false;
        }
        continue;
      }
      if (fenceOpen) {
        fenceText += `${line}\n`;
        if (!fenceMatched && terms.some((term) => lineHasTerm(line, term))) {
          fenceMatched = true;
          if (codeBlocks.length < 12) {
            codeBlocks.push({
              file: relativeFile,
              line: fenceStart,
              heading: fenceHeading,
              code: truncateText(fenceText, 1600).text,
            });
          }
        }
        continue;
      }

      let lineScore = 0;
      let matchedTerm = "";
      for (const term of terms) {
        if (lineHasTerm(line, term)) {
          lineScore += /^[\w-]+$/.test(term) ? 1 : 2;
          matchedTerm = matchedTerm || term;
        }
      }
      if (lineScore > 0) {
        const headingScore = heading && lineHasTerm(heading, matchedTerm) ? 3 : 0;
        const fileBoost = /reference|spec|stdlib|implementation|packages/i.test(relativeFile) ? 2 : 0;
        const start = Math.max(0, index - contextLines);
        const end = Math.min(lines.length, index + contextLines + 1);
        matches.push({
          file: relativeFile,
          absPath: entry.file,
          root: entry.label,
          line: index + 1,
          heading,
          matchedTerm,
          score: lineScore + headingScore + fileBoost + scoreContext(line),
          text: line.length > 240 ? `${line.slice(0, 240)}…` : line,
          context: lines.slice(start, end).join("\n"),
        });
      }
    }
  }

  matches.sort((a, b) => {
    if (b.score !== a.score) return b.score - a.score;
    if (a.file !== b.file) return a.file.localeCompare(b.file);
    return a.line - b.line;
  });
  const dedupeMatches = [];
  const seen = new Set();
  for (const match of matches) {
    const key = `${match.file}|${match.line}`;
    if (seen.has(key)) continue;
    seen.add(key);
    dedupeMatches.push(match);
    if (dedupeMatches.length >= maxResults) break;
  }

  const syntaxBlocks = [];
  const seenBlocks = new Set();
  for (const block of codeBlocks) {
    const key = `${block.file}|${block.line}`;
    if (seenBlocks.has(key)) continue;
    seenBlocks.add(key);
    syntaxBlocks.push(block);
    if (syntaxBlocks.length >= 6) break;
  }

  return {
    ok: true,
    generatedAt: new Date().toISOString(),
    docsDir,
    topics: args.topic ? [String(args.topic).toLowerCase()] : [],
    searchedTerms: terms,
    searchedFiles: files.length,
    durationMs: Date.now() - startedAtMs,
    matches: dedupeMatches,
    syntaxBlocks,
    availableTopics: LOOKUP_TOPICS,
    note:
      dedupeMatches.length === 0
        ? "No documentation match. Try another topic or pass an explicit query; do not invent Goose syntax."
        : "Copy the documented syntax exactly; prefer code blocks over prose.",
  };
}

// -------------------------------------------------------------------------------------------------
// status snapshot for the UI
// -------------------------------------------------------------------------------------------------

function compactDiagnostic(diagnostic) {
  return {
    file: diagnostic.file || "",
    line: diagnostic.line ?? null,
    column: diagnostic.column ?? null,
    severity: diagnostic.severity || "error",
    message: diagnostic.message || "",
    source: diagnostic.source || "",
  };
}

function compactRun(run, outputLimit = 2500) {
  if (!run) return null;
  return {
    runId: run.runId,
    startedAt: run.startedAt,
    finishedAt: run.finishedAt,
    durationMs: run.durationMs,
    ok: run.ok,
    failedStep: run.failedStep,
    failedSteps: run.failedSteps,
    passedCount: run.passedCount,
    executedCount: run.executedCount,
    steps: run.steps.map((step) => ({
      id: step.id,
      label: step.label,
      command: step.command,
      ok: step.ok,
      skipped: Boolean(step.skipped),
      exitCode: step.exitCode ?? null,
      signal: step.signal ?? null,
      timedOut: Boolean(step.timedOut),
      durationMs: step.durationMs,
      stdout: truncateText(step.stdout ?? "", outputLimit).text,
      stderr: truncateText(step.stderr ?? "", outputLimit).text,
      stdoutBytes: step.stdoutBytes ?? 0,
      stderrBytes: step.stderrBytes ?? 0,
    })),
    diagnostics: run.diagnostics.slice(0, 40).map(compactDiagnostic),
  };
}

async function getStatusSnapshot(settings, state) {
  const now = Date.now();
  if (state.statusCache && now - state.statusCacheAt < STATUS_CACHE_MS) return state.statusCache;
  let projectSnapshot;
  if (state.projectCache && now - state.projectCacheAt < PROJECT_CACHE_MS) {
    projectSnapshot = state.projectCache;
  } else {
    projectSnapshot = await readProjectContext(settings, { maxCommits: 12 });
    state.projectCache = projectSnapshot;
    state.projectCacheAt = now;
  }
  const status = {
    plugin: name,
    version: VERSION,
    generatedAt: new Date(now).toISOString(),
    workspace: settings.workspace,
    environment: {
      gooseBin: settings.gooseBin,
      gooseExists: settings.gooseExists,
      gooseStdlib: settings.gooseStdlib,
      stdlibExists: settings.stdlibExists,
      gooseHome: settings.gooseHome,
      cc: settings.cc,
      docsDir: settings.docsDir,
      docsExists: settings.docsExists,
      testBinary: settings.testBinary,
      node: process.version,
      platform: `${process.platform}-${process.arch}`,
    },
    project: projectSnapshot.project,
    projectSummary: projectSnapshot.summary,
    lastRun: compactRun(state.lastRun),
    history: state.history.slice(-10).map((entry) => ({
      runId: entry.runId,
      startedAt: entry.startedAt,
      finishedAt: entry.finishedAt,
      durationMs: entry.durationMs,
      ok: entry.ok,
      failedStep: entry.failedStep,
      failedSteps: entry.failedSteps,
      passedCount: entry.passedCount,
      executedCount: entry.executedCount,
    })),
    capabilities: [
      {
        id: "auto_build_and_test",
        title: "Build + test",
        tool: "auto_build_and_test",
        description: "Run goose check, goose build, the compiled test binary, and the gcc C compile with structured output.",
        timeoutMs: settings.timeouts.check + settings.timeouts.build + settings.timeouts.run + settings.timeouts.cCompile,
      },
      {
        id: "auto_self_heal",
        title: "Self-heal",
        tool: "auto_self_heal",
        description: "Parse build/type errors into exact file:line repair context with source snippets.",
        timeoutMs: 900_000,
      },
      {
        id: "goose_syntax_lookup",
        title: "Goose syntax",
        tool: "goose_syntax_lookup",
        description: "Grep the local Goose docs for real FFI, struct and pointer syntax before writing code.",
        timeoutMs: 60_000,
      },
      {
        id: "project_context_sync",
        title: "Project context",
        tool: "project_context_sync",
        description: "Read Objective.txt, README.md and git log to report the current step and next steps.",
        timeoutMs: 60_000,
      },
    ],
  };
  state.statusCache = status;
  state.statusCacheAt = now;
  return status;
}

// -------------------------------------------------------------------------------------------------
// plugin entry
// -------------------------------------------------------------------------------------------------

export function apply(ctx, config) {
  const settings = resolveSettings(config);
  const state = {
    runCounter: 0,
    lastRun: null,
    history: [],
    projectCache: null,
    projectCacheAt: 0,
    statusCache: null,
    statusCacheAt: 0,
  };

  const runWithOptions = async (rawOptions, exec) => {
    const options = rawOptions && typeof rawOptions === "object" ? rawOptions : {};
    const steps = Array.isArray(options.steps)
      ? options.steps.filter((step) => typeof step === "string" && ["goose-check", "goose-build-test", "run-tests", "c-compile"].includes(step))
      : [];
    return runPipeline(settings, state, {
      steps,
      failFast: options.failFast === true,
      maxOutputChars: options.maxOutputChars,
      signal: exec?.signal,
    });
  };

  const toolDefinitions = [
    {
      name: "auto_build_and_test",
      description:
        "Run ALmap's full autonomous build+test pipeline in the workspace: goose check almap.goose, goose build tests/test_almap.goose --cc gcc -o /tmp/test_almap, execute /tmp/test_almap, and gcc -std=c99 -Wall -Wextra -pthread -c c/net.c c/raw.c c/icmp.c c/pool.c. Returns every step's stdout, stderr, exit code, duration and timeout status in a structured object. By default all steps run (no fail-fast) so the agent gets every diagnostic in one pass; skipped steps (e.g. run-tests after a failed build) are reported explicitly. Call it after every meaningful edit and iterate until it passes.",
      parameters: {
        type: "object",
        additionalProperties: true,
        properties: {
          steps: {
            type: "array",
            items: { type: "string", enum: ["goose-check", "goose-build-test", "run-tests", "c-compile"] },
            description: "Optional subset of steps to run (default: all four, in order).",
          },
          failFast: {
            type: "boolean",
            description: "Stop after the first failing step (default false: run everything and report all failures).",
          },
          maxOutputChars: {
            type: "integer",
            minimum: 500,
            maximum: 200000,
            description: "Maximum characters retained per stdout/stderr stream (default 16000).",
          },
        },
      },
      output: {
        schema: { type: "object", additionalProperties: true },
        render: (_args, value) => textBlock(value && value.summary ? value.summary : summarizeRunText(value ?? {})),
      },
      timeoutMs: 900_000,
      isConcurrencySafe: false,
      execute: async (args, exec) => {
        try {
          const run = await runWithOptions(args, exec);
          return { ...run, summary: summarizeRunText(run) };
        } catch (error) {
          const message = String(error?.stack ?? error?.message ?? error);
          return { ok: false, status: "tool_error", error: message, summary: `# auto_build_and_test — TOOL ERROR\n\n${message}` };
        }
      },
    },
    {
      name: "auto_self_heal",
      description:
        "If a build/test run failed, parse the Goose/C/runtime errors and return them as exact file paths and line numbers (plus the surrounding source code and the failing commands) so the agent can fix the code immediately without asking the user. Uses the most recent auto_build_and_test run when available; pass runFirst=true to re-run the pipeline first. Returns a repairPrompt that is ready to be injected into the agent context.",
      parameters: {
        type: "object",
        additionalProperties: true,
        properties: {
          runFirst: {
            type: "boolean",
            description: "Re-run the full build+test pipeline before healing instead of using the last run (default false).",
          },
          focus: {
            type: "string",
            description: "Optional hint about what to prioritize (e.g. 'goose type errors', 'C warnings'). Recorded in the report.",
          },
          maxDiagnostics: {
            type: "integer",
            minimum: 1,
            maximum: 120,
            description: "Maximum number of diagnostics to enrich with source snippets (default 25).",
          },
          includeSourceContext: {
            type: "boolean",
            description: "Include the surrounding source lines for each diagnostic (default true).",
          },
        },
      },
      output: {
        schema: { type: "object", additionalProperties: true },
        render: (_args, value) => textBlock(value && typeof value === "object" && value.repairPrompt ? value.repairPrompt : String(value ?? "")),
      },
      timeoutMs: 1_200_000,
      isConcurrencySafe: false,
      execute: async (args, exec) => {
        try {
          const options = args && typeof args === "object" ? args : {};
          let run = state.lastRun;
          if (options.runFirst === true || !run) {
            run = await runPipeline(settings, state, { signal: exec?.signal });
          }
          if (run.ok) {
            return {
              ok: true,
              status: "healthy",
              runId: run.runId,
              checkedAt: new Date().toISOString(),
              message: "The last build+test run passed; nothing to heal. Call auto_build_and_test after new changes.",
              repairPrompt: `# auto_self_heal — healthy\n\nThe last run (${run.runId}) passed all executed steps in ${formatDuration(run.durationMs)}. No repair needed.`,
            };
          }
          const report = await buildRepairReport(settings, state, run, {
            maxDiagnostics: options.maxDiagnostics,
            includeSourceContext: options.includeSourceContext,
          });
          if (options.focus) report.focus = String(options.focus);
          return report;
        } catch (error) {
          const message = String(error?.stack ?? error?.message ?? error);
          return {
            ok: false,
            status: "tool_error",
            error: message,
            repairPrompt: `# auto_self_heal — TOOL ERROR\n\n${message}`,
          };
        }
      },
    },
    {
      name: "goose_syntax_lookup",
      description:
        "Instantly search the local Goose compiler documentation (default: /home/honeypot/Downloads/goose-v2026.3-linux-x64/docs) for exact syntax. Use it before writing FFI declarations, structs, pointers, enums, generics, modules, tests or threading so Goose code is never guessed. Returns matching doc locations with context, fenced code blocks that demonstrate the syntax, and the available topics.",
      parameters: {
        type: "object",
        additionalProperties: true,
        properties: {
          topic: {
            type: "string",
            description: `Quick topic: ${LOOKUP_TOPICS.join(", ")} (free-form strings are also accepted).`,
          },
          query: {
            type: "string",
            description: "Exact word or phrase to search for (e.g. 'extern proc', 'address_of', 'c_sources').",
          },
          maxResults: { type: "integer", minimum: 1, maximum: 20, description: "Maximum matches to return (default 8)." },
          contextLines: { type: "integer", minimum: 0, maximum: 20, description: "Context lines around each match (default 3)." },
        },
      },
      output: {
        schema: { type: "object", additionalProperties: true },
        render: (_args, value) => textBlock(renderLookupText(value ?? {})),
      },
      timeoutMs: 120_000,
      isConcurrencySafe: true,
      execute: async (args) => {
        try {
          return await gooseSyntaxLookup(settings, args && typeof args === "object" ? args : {});
        } catch (error) {
          const message = String(error?.stack ?? error?.message ?? error);
          return { ok: false, status: "tool_error", error: message, summary: `# goose_syntax_lookup — TOOL ERROR\n\n${message}` };
        }
      },
    },
    {
      name: "project_context_sync",
      description:
        "Read Objective.txt (if present), README.md and the git log to summarize exactly where the ALmap project stands: the highest step the repository actually evidences (the brief targets Step 15), its status, evidence line, latest commit, working-tree state, file counts, and the next steps referenced by the docs. Call it at the start of a work session and after a large milestone so the agent never loses the big picture.",
      parameters: {
        type: "object",
        additionalProperties: true,
        properties: {
          refresh: { type: "boolean", description: "Bypass the short cache and re-read the workspace (default false)." },
          maxCommits: { type: "integer", minimum: 1, maximum: 100, description: "How many git commits to read (default 12)." },
          includeGit: { type: "boolean", description: "Include git log/status/branch evidence (default true)." },
        },
      },
      output: {
        schema: { type: "object", additionalProperties: true },
        render: (_args, value) => textBlock(value && value.summary ? value.summary : String(value ?? "")),
      },
      timeoutMs: 120_000,
      isConcurrencySafe: true,
      execute: async (args) => {
        try {
          const options = args && typeof args === "object" ? args : {};
          const snapshot = await readProjectContext(settings, {
            maxCommits: options.maxCommits,
            includeGit: options.includeGit !== false,
          });
          state.projectCache = snapshot;
          state.projectCacheAt = Date.now();
          state.statusCache = null;
          return snapshot;
        } catch (error) {
          const message = String(error?.stack ?? error?.message ?? error);
          return { ok: false, status: "tool_error", error: message, summary: `# project_context_sync — TOOL ERROR\n\n${message}` };
        }
      },
    },
  ];

  for (const definition of toolDefinitions) {
    ctx.effect(() => ctx.tools.register(definition), `almap-autopilot/tool/${definition.name}`);
  }

  // Autonomy contract injected into the system prompt.
  ctx.effect(
    () =>
      ctx.systemPrompt.section({
        name: "almap-autopilot/autonomy",
        order: 240,
        text:
          "## ALmap Autopilot\n" +
          `You are the autonomous engineer of the ALmap project (Goose language + C) in ${settings.workspace}.\n` +
          "- At the start of a work session, and after a large milestone, call project_context_sync to re-anchor on the current step before editing. The brief targets Step 15; trust the tool's repo evidence and explicitly report any mismatch instead of assuming the step.\n" +
          "- After every meaningful edit call auto_build_and_test. If it fails, immediately call auto_self_heal and fix the exact file:line diagnostics it returns, then call auto_build_and_test again. Repeat until green. Never ask the user to run commands or paste errors for you.\n" +
          "- Before writing Goose code that uses FFI, structs, pointers, enums, generics, modules, tests or threads, call goose_syntax_lookup and copy the documented syntax exactly. Do not invent Goose syntax.\n" +
          "- Preserve the ALmap build manifest (almap.build), the C ABI and the test contracts; keep diffs minimal and focused on the failing lines.\n" +
          "- If the same environment error (missing binary, missing stdlib, permissions) persists, report it once at the end instead of blocking mid-loop.\n",
      }),
    "almap-autopilot/system-prompt",
  );

  // /almap command: a fast console equivalent of the four tools.
  const commandHandler = async (invocation) => {
    try {
      const raw = String(invocation?.rawInput ?? "").trim();
      const [subcommandRaw, ...rest] = raw.split(/\s+/);
      const subcommand = (subcommandRaw || "status").toLowerCase();
      const argument = rest.join(" ").trim();
      if (subcommand === "status") {
        const status = await getStatusSnapshot(settings, state);
        const text = [
          `# ALmap Autopilot v${VERSION}`,
          `workspace: ${status.workspace}`,
          `current step: ${status.project?.currentStep ?? "unknown"} (${status.project?.currentStepStatus ?? "unknown"})`,
          `last run: ${status.lastRun ? `${status.lastRun.runId} ${status.lastRun.ok ? "PASS" : "FAIL"} ${formatDuration(status.lastRun.durationMs)}` : "none yet"}`,
          status.lastRun && !status.lastRun.ok
            ? `failed steps: ${(status.lastRun.failedSteps ?? []).join(", ")} — run /almap fix`
            : "next: /almap run · /almap fix · /almap docs <topic> · /almap sync",
        ].join("\n");
        return { kind: "success", text: truncateText(text, 6000).text };
      }
      if (subcommand === "run" || subcommand === "build" || subcommand === "test") {
        const run = await runPipeline(settings, state, {});
        return { kind: "success", text: summarizeRunText(run) };
      }
      if (subcommand === "fix" || subcommand === "heal") {
        let run = state.lastRun;
        if (!run || run.ok) run = await runPipeline(settings, state, {});
        if (run.ok) {
          return { kind: "success", text: `All executed steps passed in ${formatDuration(run.durationMs)}; no repair needed.` };
        }
        const report = await buildRepairReport(settings, state, run, {});
        return { kind: "success", text: truncateText(report.repairPrompt, 8000).text };
      }
      if (subcommand === "docs" || subcommand === "syntax") {
        const lookup = await gooseSyntaxLookup(settings, { topic: argument });
        return { kind: "success", text: renderLookupText(lookup) };
      }
      if (subcommand === "sync" || subcommand === "context" || subcommand === "status-sync") {
        const snapshot = await readProjectContext(settings, {});
        state.projectCache = snapshot;
        state.projectCacheAt = Date.now();
        state.statusCache = null;
        return { kind: "success", text: truncateText(snapshot.summary, 8000).text };
      }
      return {
        kind: "error",
        text: `Unknown /almap subcommand "${subcommand}". Usage: /almap [status|run|fix|docs <topic>|sync]`,
      };
    } catch (error) {
      return { kind: "error", text: `almap-autopilot command failed: ${String(error?.stack ?? error?.message ?? error)}` };
    }
  };

  ctx.effect(
    () =>
      ctx.commands.register({
        name: "almap",
        description: "ALmap autopilot: status | run | fix | docs <topic> | sync",
        input: { hint: "status | run | fix | docs <topic> | sync" },
        handler: commandHandler,
      }),
    "almap-autopilot/command/almap",
  );

  // Read-only status endpoint consumed by the sidebar panel.
  ctx.effect(
    () =>
      ctx.webServer.register({
        kind: "exact",
        path: PANEL_ROUTE,
        resource: async () => {
          try {
            const snapshot = await getStatusSnapshot(settings, state);
            return new Response(JSON.stringify(snapshot), {
              status: 200,
              headers: {
                "content-type": "application/json; charset=utf-8",
                "cache-control": "no-store",
                "x-content-type-options": "nosniff",
              },
            });
          } catch (error) {
            return new Response(JSON.stringify({ error: String(error?.stack ?? error?.message ?? error) }), {
              status: 500,
              headers: { "content-type": "application/json; charset=utf-8", "cache-control": "no-store" },
            });
          }
        },
      }),
    "almap-autopilot/route/status",
  );
}

// -------------------------------------------------------------------------------------------------
// tool renderers
// -------------------------------------------------------------------------------------------------

function renderLookupText(value) {
  if (!value || typeof value !== "object") return String(value ?? "");
  if (value.ok === false) {
    const lines = [`# goose_syntax_lookup — unavailable`, "", `error: ${value.error ?? "unknown error"}`];
    if (Array.isArray(value.availableTopics)) lines.push(`topics: ${value.availableTopics.join(", ")}`);
    if (Array.isArray(value.candidates)) lines.push(`candidates: ${value.candidates.join(", ")}`);
    return truncateText(lines.join("\n"), 12000).text;
  }
  const lines = [];
  lines.push(`# goose_syntax_lookup — ${(value.searchedTerms ?? []).join(", ") || "no terms"}`);
  lines.push("");
  lines.push(`docs: ${value.docsDir} (${value.searchedFiles ?? 0} files searched in ${formatDuration(value.durationMs ?? 0)})`);
  if (Array.isArray(value.syntaxBlocks) && value.syntaxBlocks.length > 0) {
    lines.push("");
    lines.push("## Documented syntax");
    for (const block of value.syntaxBlocks) {
      lines.push("");
      lines.push(`### ${block.file}:${block.line}${block.heading ? ` — ${block.heading}` : ""}`);
      lines.push("```");
      lines.push(block.code.trimEnd());
      lines.push("```");
    }
  }
  if (Array.isArray(value.matches) && value.matches.length > 0) {
    lines.push("");
    lines.push("## Matches");
    for (const match of value.matches) {
      lines.push(`- ${match.file}:${match.line}${match.heading ? ` (${match.heading})` : ""}: ${match.text}`);
      if (match.context && match.context.trim()) {
        lines.push("```");
        lines.push(truncateText(match.context, 800).text.trimEnd());
        lines.push("```");
      }
    }
  }
  if (value.note) {
    lines.push("");
    lines.push(value.note);
  }
  return truncateText(lines.join("\n"), 24000).text;
}
