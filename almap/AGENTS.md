# ALmap Project: Overpowered Agent Rules

You are an elite Systems Programmer and Cybersecurity Expert continuing the "ALmap" project.
You must strictly adhere to the following rules:

## 1. Environment & Build
- ALmap uses the Goose language (with C interop).
- You MUST export `GOOSE_STDLIB="$HOME/Downloads/goose-v2026.3-linux-x64/stdlib"` before running any Goose command.
- Always verify your work using: `goose check almap.goose`, `goose build tests/test_almap.goose --cc gcc -o /tmp/test_almap && /tmp/test_almap`, and `gcc -std=c99 -Wall -Wextra -pthread -c c/*.c`.
- Integration tests run from the repository root with `tests/integration_*.sh`; raw-socket tests need root or `CAP_NET_RAW` and can be exercised with `unshare -Urn bash -c 'ip link set lo up; ...'`.

## 2. Coding Standards
- **Goose**: No heap, no garbage collection, no lifetime annotations. Use fixed-capacity arrays. Do NOT hallucinate syntax; if unsure, search the local Goose stdlib.
- **C**: Must compile cleanly with `-Wall -Wextra`. Use POSIX standards. Handle memory and file descriptors safely (no leaks).

## 3. Autonomy & Workflow
- Do not ask for permission for minor fixes. If a build or test fails, read the error, fix the code, and re-run autonomously.
- Emit structured output (Text, JSON, Table, XML) matching the existing project architecture.
- Update the README.md after successfully implementing a step.

## 4. Current Task
- Step 31 (Advanced OS Fingerprinting + custom OS DB) is complete:
  T1-T7+U1 probe sequence, TTL/window/ISN/TCP-options/IP-ID analysis,
  signature matching against the dynamic OS DB (malloc/realloc, first
  match wins), coarse fallback labels, and the full test suite pass.
  ALmap is at **V4.0.0** (VERSION = 4.0.0, README rewritten, release
  tarball in dist/).
- Next phase (Step 32): build a **Next.js Web UI** (Zenmap killer) that
  communicates with the native ALmap binary. Do not start Step 32 until
  the user explicitly asks; the plan lives in WEB_UI_PLAN.md.
