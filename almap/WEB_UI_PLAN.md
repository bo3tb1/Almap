# WEB_UI_PLAN.md

## Architecture Proposal: ALmap Next.js Web UI

We will build a high-performance, responsive Web UI to serve as the new control plane for ALmap.

### 1. Stack Selection
- **Frontend**: [Next.js](https://nextjs.org/) (React) + Tailwind CSS + Shadcn UI.
  - Chosen for its fast development cycle, excellent routing, and ability to handle stateful dashboard components (scan progress, log streaming).
- **Backend (Bridge)**: The existing native C/Goose API (`/api/scan`, `/api/status`) remains the single source of truth.
  - The Next.js server will act as a thin proxy if needed, but the primary communication will be client-side browser requests directly to the ALmap binary's native HTTP interface.

### 2. Design Pattern
- **Single-Page Application (SPA) feel**: The dashboard will interact with ALmap via `fetch()` calls to the native binary.
- **Polling vs. WebSocket**: 
  - Since the current ALmap native HTTP server is sequential/synchronous, we will stick to polling `/api/status` or extended scan status endpoints for real-time updates.
- **Embedding**: We will maintain the ability to serve the static frontend from the ALmap binary (embedding the `dist/` build into the binary) or running the Next.js development server during local development.

### 3. Key Components
- **Dashboard**: Overview of current scans and system status.
- **Scan Configuration Form**: UI representation of all CLI flags (targets, ports, scan types, evasion, OS fingerprinting).
- **Output Terminal**: A window rendering the scan result JSON/Table/XML in real-time.
- **Configuration**: Dedicated views for managing the `signatures.db` and `os-signatures.db` files.

### 4. Integration Strategy
- **Native Binary**: The ALmap binary remains the engine. The UI project will live in a `web/` directory.
- **Workflow**:
  1. User edits scan params in Web UI.
  2. UI sends `POST` request to native binary's `/api/scan`.
  3. Binary executes, returns JSON.
  4. UI parses and renders JSON results using clean, modern components.

This plan maintains the "auditable native core" philosophy while bringing a modern UX to the project.
