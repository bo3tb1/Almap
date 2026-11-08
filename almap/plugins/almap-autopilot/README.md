# @local/almap-autopilot

A complete DeepSeek Harness (DSH) bundle that gives the agent full autonomy over the
**ALmap** project — a network scanner written in **Goose** (a 2026 systems language) and
**C**. It exposes four host tools, a `/almap` command, and a left-sidebar control panel
that reads a same-origin status endpoint.

| Piece | What it does |
| --- | --- |
| `auto_build_and_test` | Runs the Goose type check, Goose test build + test run, and the C compile; returns structured `steps[]` (stdout/stderr/exit code/duration/timeout) plus parsed diagnostics. |
| `auto_self_heal` | Turns the last failed run into exact `file:line` repair context with source snippets and a ready-to-inject `repairPrompt`. |
| `goose_syntax_lookup` | Greps the local Goose docs (`docs/*.md`, `stdlib/`) for real FFI / struct / pointer / enum / generics / module / thread / test syntax instead of guessing. |
| `project_context_sync` | Reads `Objective.txt` (optional), `README.md` and the git log/branch/status; reports the evidenced step, status, counts, next steps and any brief/repo mismatch. |
| `/almap` | Console equivalent: `status`, `run`, `fix`, `docs <topic>`, `sync`. |
| Sidebar panel | `ALmap Autopilot` in the left sidebar; keyed `main` panel with last run, steps, diagnostics, project context, capabilities and history. |

The plugin resolves from the DSH profile, so it imports **only Node built-ins** and never
requires the workspace's `node_modules`.

## Install

The bundle is authored inside the workspace and installed through the plugin manager:

```text
plugin_manager { action: "install_bundle", target: "/home/honeypot/almap/plugins/almap-autopilot" }
```

`package.json` carries `dsh.bundle.patch` (`cordis.patch.yml` inserts one row,
`id: almap-autopilot`, `name: @local/almap-autopilot`) and `dsh.client` (web client,
`immediately: true`). After installation the host tools are visible to the agent in every
session, and the sidebar entry appears without a restart of the page.

## Configuration

No persisted config is written (the plugin keeps its state in memory). Everything is
overridable with environment variables before the harness starts:

| Variable | Default |
| --- | --- |
| `ALMAP_WORKSPACE` | `/home/honeypot/almap` (falls back to `DSH_WORKSPACE`, then cwd) |
| `GOOSE_BIN` / `GOOSE` | first existing of `$HOME/Downloads/goose-v2026.3-linux-x64/goose`, `$HOME/.local/bin/goose`, `goose` |
| `GOOSE_STDLIB` | `$HOME/Downloads/goose-v2026.3-linux-x64/stdlib` |
| `ALMAP_CC` (or config `cc`) | first executable of `/usr/bin/gcc`, `/usr/local/bin/gcc`, `/usr/bin/cc`, then the stratum launcher described below |
| `ALMAP_DOCS_DIR` / `GOOSE_DOCS_DIR` | `$HOME/Downloads/goose-v2026.3-linux-x64/docs` |
| `ALMAP_GOOSE_HOME` / `GOOSE_HOME` | first writable of `$HOME/...` candidates, then `<workspace>/.almap-autopilot/cache/goose-home` |

Per-step timeouts: check 120 s, build 240 s, run 120 s, C compile 120 s. `maxBuffer` is
8 MiB per child; stdout/stderr are ANSI-stripped, bounded (default 16 000 chars per
stream) and truncated with an explicit suffix instead of growing without limit. Every
tool `execute` is wrapped in `try/catch`, so a tool failure becomes structured JSON, not a
harness crash.

### GOOSE_HOME

Goose writes build artifacts under `GOOSE_HOME` (default `~/.goose`). In this sandbox the
home directory is read-only, so a default build dies with
`cannot create the build directory`. The host half therefore resolves a **writable**
`GOOSE_HOME` at startup (`<workspace>/.almap-autopilot/cache/goose-home` when nothing else
is writable) and exports it for every child process. `GOOSE_STDLIB` is exported when the
stdlib directory exists, because the PATH `goose` binary cannot find it on its own.

### C compiler resolution

Goose and the C compile step need a compiler that the **harness process** can actually
execute. In this Bedrock/stratum sandbox the host `PATH` starts with
`/bedrock/cross/bin`, where `gcc` is a stratum wrapper: spawned from the harness it dies
with `gcc: fatal error: cannot execute 'cc1': posix_spawnp: No such file or directory`,
and a bare `gcc` lookup fails outright once those wrappers are removed. On every run the
host half therefore resolves the compiler as:

1. `cfg.cc` / `ALMAP_CC` when it is an executable file,
2. a real absolute compiler (`/usr/bin/gcc`, `/usr/local/bin/gcc`, `/usr/bin/cc`),
3. otherwise a generated launcher at
   `<workspace>/.almap-autopilot/cache/toolchain/gcc` containing
   `exec /bedrock/bin/strat gentoo /usr/bin/gcc "$@"`.

That launcher makes the genuine Gentoo gcc run inside its native stratum, so both
`goose build --cc <launcher>` and the C compile see a real `cc1`. On a normal machine step
3 is never reached and the commands stay exactly `/usr/bin/gcc …`. The resolved binary is
reported as `environment.cc` in the status JSON, and the launcher is regenerated on each
profile start, so it always matches the installed toolchain.

## The build pipeline

Default run: all four steps, in order, **without fail-fast**, so one call returns every
diagnostic:

1. `goose check almap.goose`
2. `goose build tests/test_almap.goose --cc <resolved-cc> -o /tmp/test_almap`
3. `/tmp/test_almap`
4. `<resolved-cc> -std=c99 -Wall -Wextra -pthread -c c/net.c c/raw.c c/icmp.c c/pool.c`

`<resolved-cc>` is `gcc` on an ordinary machine and the absolute compiler/launcher described
above when a bare `gcc` is not executable from the harness process.

`run-tests` depends on `goose-build-test`; if the build fails, the run step is reported as
skipped with a reason instead of producing a misleading failure. `steps`, `failFast` and
`maxOutputChars` let the agent run a subset (e.g. only `c-compile` after a C-only edit).

Diagnostics are parsed from both text formats:

- Goose: `file.goose:LINE: error: message`
- gcc: `file.c:LINE:COL: error|warning: message`
- linkers: `collect2: error: …`, `undefined reference to …`
- Goose build wrappers: `compiling … failed (exit N):`

## Self-heal loop

`auto_self_heal` returns a `repairPrompt` that contains, per failing file, the exact
`path:line:column`, severity, message and ±4 lines of source, followed by the failing
commands and a loop contract: fix the reported lines, call `auto_build_and_test`, repeat
until it passes — never ask the user to run commands or paste errors. It uses the most
recent run; `runFirst: true` re-runs the pipeline first, and `focus` / `maxDiagnostics` /
`includeSourceContext` tune the report.

## Goose syntax lookup

`goose_syntax_lookup` accepts a `topic` (`ffi`, `extern`, `c_include`, `c_sources`,
`struct`, `pointer`/`reference`, `enum`, `union`, `generics`, `module`, `test`, `thread`,
`memory`, `build`, `error`, …), or a free-form `query`. It walks `docs/**/*.md` plus
`stdlib/*.goose`, scores headings and code fences, and returns fenced syntax blocks with
`file:line` evidence so the agent never has to invent Goose. The Goose compiler source is
not shipped with the toolchain — the docs are the normative spec.

## Project context sync

Reads `Objective.txt` when present, otherwise `README.md` + git log. It scans step
markers (`Step N`) in headings/paragraphs, reports the **highest evidenced step** with its
status, evidence `file:line`, latest commit, branch, modified/untracked counts, file
counts and the next steps referenced by the docs. Two honesty notes are included when
relevant:

- `Objective.txt` is missing, so intent comes from README + git.
- The task brief targets **Step 15** while the current repository evidence tops out at
  **Step 14 (XML output)** — the tool reports the mismatch instead of silently pretending
  either is true.

## Status endpoint (panel contract)

`GET /almap-autopilot/status` (same origin, `cache-control: no-store`, read-only) returns:

```json
{
  "plugin": "@local/almap-autopilot",
  "version": "1.0.0",
  "generatedAt": "ISO",
  "workspace": "/home/honeypot/almap",
  "environment": { "gooseBin": "...", "gooseHome": "...", "gooseStdlib": "...", "cc": "...", "docsDir": "...", "testBinary": "/tmp/test_almap" },
  "project": { "currentStep": "Step 14", "targetStep": 15, "currentStepStatus": "...", "stepSource": "...", "counts": {}, "workingTree": {}, "nextSteps": [] },
  "projectSummary": "markdown",
  "lastRun": { "runId": "...", "ok": false, "failedStep": "...", "steps": [], "diagnostics": [] },
  "history": [],
  "capabilities": []
}
```

The client polls it every 5 s (paused while the tab is hidden) and degrades to a retry
card if the host half is not reachable yet. Buttons in the panel start a new agent session
with a precise prompt (`auto_build_and_test`, self-heal, project sync, syntax lookup) via
`ctx.uiWorkspace.startSession(undefined, { prompt, whenDraftExists: "append" })`.

## Safety and limits

- Every child process is bounded by `timeout` (SIGKILL) + `maxBuffer`; abort signals from
  the tool runtime kill the child too.
- The status route is read-only and never mutates project files; the only writes are the
  writable `GOOSE_HOME` cache and the generated compiler launcher under `.almap-autopilot/`.
- The pipeline runs the required commands verbatim; the only substitution is the compiler
  binary itself when a bare `gcc` is a broken stratum wrapper (see *C compiler resolution*),
  and `goose build` is always given an explicit `-o` so it never overwrites `almap`.
- Known toolchain facts: `goose --version` is unsupported (use `goose version`); the test
  build type-checks the whole dependency graph but does not link the C sidecar (only the
  `c-compile` step covers C); `gcc -c` writes `.o` files into the current directory (the
  workspace root) exactly as the required command specifies.
- If `/tmp` is volatile in a given sandbox, the build and run steps are separate calls and
  the run step will report a clear `does not exist` precheck instead of a fake failure;
  re-run the pipeline or point `testBinary` at a persistent path.

## Verify

After install:

1. `cordis_inspect_query` → plugin row `almap-autopilot` applied, tool list contains the
   four tools, route `/almap-autopilot/status` returns JSON.
2. Open the Web UI, click the `ALmap Autopilot` sidebar entry, run the panel's pipeline
   action in a real session.
3. `/almap status` in a session, then `/almap run` — expect exit 0 for all four steps on a
   clean tree.
