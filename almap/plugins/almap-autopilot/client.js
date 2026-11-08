/**
 * @local/almap-autopilot — Client half.
 *
 * Registers the ALmap Autopilot left-sidebar entry and the central control
 * center panel. The panel polls the Host half's same-origin status endpoint
 * and turns every action into an aggressive, self-contained agent prompt.
 *
 * Only `react` may be required; no JSX, no client packages, no network calls
 * besides the same-origin status fetch.
 */
window.__ModuleLoader__.load({
  id: "@local/almap-autopilot",
  factory: (require) => {
    const React = require("react");
    const h = React.createElement;

    /** Host endpoint that reports the autopilot state. */
    const STATUS_PATH = "/almap-autopilot/status";
    /** Poll cadence while the page is visible. */
    const POLL_INTERVAL_MS = 5000;
    /** Shared launch options: append to a draft instead of discarding it. */
    const START_OPTIONS = { whenDraftExists: "append" };

    /** Theme aliases; every color resolves through the active DSH theme. */
    const T = {
      labelPrimary: "var(--dsw-alias-label-primary)",
      labelSecondary: "var(--dsw-alias-label-secondary)",
      labelTertiary: "var(--dsw-alias-label-tertiary)",
      bgBase: "var(--dsw-alias-bg-base)",
      bgLayer1: "var(--dsw-alias-bg-layer-1)",
      bgModule: "var(--dsw-alias-bg-module-platform)",
      borderL3: "var(--dsw-alias-border-l3)",
      borderL4: "var(--dsw-alias-border-l4)",
      hover: "var(--dsw-alias-interactive-bg-hover)",
      business: "var(--dsw-alias-state-business-primary)",
      error: "var(--dsw-alias-state-error-primary)",
      success: "var(--dsw-alias-state-success-primary)",
    };

    const MONO = 'ui-monospace, "SFMono-Regular", Menlo, Consolas, "Liberation Mono", monospace';
    const H2 = { margin: 0, fontSize: 15, fontWeight: 600, letterSpacing: "-0.005em" };
    const DOT = { width: 7, height: 7, borderRadius: "50%", flex: "0 0 auto" };

    /** Fallback capability catalog when the Host response omits the list. */
    const DEFAULT_CAPABILITIES = [
      {
        id: "auto_build_and_test",
        tool: "auto_build_and_test",
        label: "Build & test",
        summary: "Run the Goose type check, C build, and test suite in one pipeline pass.",
      },
      {
        id: "auto_self_heal",
        tool: "auto_self_heal",
        label: "Self-heal",
        summary: "Read a failure, repair the exact files and lines it reports, and re-run until green.",
      },
      {
        id: "goose_syntax_lookup",
        tool: "goose_syntax_lookup",
        label: "Goose syntax lookup",
        summary: "Look up exact Goose FFI syntax before writing or editing Goose code.",
      },
      {
        id: "project_context_sync",
        tool: "project_context_sync",
        label: "Project context sync",
        summary: "Re-read the README, Objective, and git state to report the current step.",
      },
    ];

    const PIPELINE_PROMPT =
      "Call the auto_build_and_test tool now, then if it fails call auto_self_heal, apply the fixes it reports, and repeat until it passes. Do not ask the user for permission. Report the final result.";

    const SYNC_PROMPT =
      "Call the project_context_sync tool now and report exactly what step the project is on and what remains to be done.";

    /** The failure-repair prompt; tolerates a missing `failedStep`. */
    function selfHealPrompt(failedStep) {
      const where =
        typeof failedStep === "string" && failedStep
          ? "It is failing at " + failedStep + "."
          : "The most recent pipeline run is not passing.";
      return (
        "Call the auto_self_heal tool now. " +
        where +
        " Read the diagnostics, fix the exact files/lines, then call auto_build_and_test again until it passes. Do not ask the user for permission."
      );
    }

    /** A precise prompt for one capability card. */
    function capabilityPrompt(capability, query) {
      const tool = capability && typeof capability.tool === "string" && capability.tool ? capability.tool : "auto_build_and_test";
      if (tool === "goose_syntax_lookup") {
        const topic = typeof query === "string" ? query.trim() : "";
        if (!topic) return "Use the goose_syntax_lookup tool to look up exact Goose FFI syntax before writing code.";
        return (
          "Use the goose_syntax_lookup tool to look up exact Goose FFI syntax for \"" +
          topic +
          "\" before writing code. Quote the binding signature and a minimal usage example."
        );
      }
      if (tool === "auto_self_heal") {
        return "Use the auto_self_heal tool to diagnose and fix the current failing build or test run. Read the diagnostics, fix the exact files and lines it reports, then re-run the pipeline until it passes. Do not ask the user for permission.";
      }
      if (tool === "project_context_sync") {
        return "Use the project_context_sync tool to report exactly what step the ALmap project is on and what remains to be done.";
      }
      if (tool === "auto_build_and_test") {
        return "Use the auto_build_and_test tool to run the full ALmap build and test pipeline, then if it fails call auto_self_heal and repeat until it passes. Do not ask the user for permission. Report the final result.";
      }
      return "Use the " + tool + " tool now and report the result. Do not ask the user for permission.";
    }

    /** Theme-derived translucent tint, used for small accent fills. */
    function tint(token, percent) {
      return "color-mix(in srgb, " + token + " " + percent + "%, transparent)";
    }

    /** Human readable duration for run and step timings. */
    function formatDuration(value) {
      const ms = Number(value);
      if (!Number.isFinite(ms) || ms < 0) return "—";
      if (ms < 1000) return Math.round(ms) + " ms";
      if (ms < 60000) return (ms / 1000).toFixed(1) + " s";
      const totalSeconds = Math.round(ms / 1000);
      const minutes = Math.floor(totalSeconds / 60);
      const seconds = totalSeconds % 60;
      return minutes + "m " + (seconds < 10 ? "0" + seconds : seconds) + "s";
    }

    function pad2(value) {
      return value < 10 ? "0" + value : String(value);
    }

    /** Local wall-clock time, with a short date when the value is not today. */
    function formatStamp(value) {
      if (!value) return "—";
      const date = new Date(value);
      if (!Number.isFinite(date.getTime())) return String(value);
      const now = new Date();
      const sameDay =
        date.getFullYear() === now.getFullYear() &&
        date.getMonth() === now.getMonth() &&
        date.getDate() === now.getDate();
      const clock = pad2(date.getHours()) + ":" + pad2(date.getMinutes()) + ":" + pad2(date.getSeconds());
      if (sameDay) return clock;
      return date.toLocaleDateString(undefined, { month: "short", day: "numeric" }) + " " + clock;
    }

    /** Sort key for run history; unparseable dates sort last. */
    function timeValue(value) {
      if (typeof value !== "string" || !value) return 0;
      const parsed = Date.parse(value);
      return Number.isFinite(parsed) ? parsed : 0;
    }

    /** Normalize the Host capability list, falling back per entry. */
    function normalizeCapabilities(raw) {
      const provided = Array.isArray(raw) ? raw.filter((entry) => entry && typeof entry === "object") : [];
      const byTool = Object.create(null);
      for (const entry of provided) {
        const tool =
          typeof entry.tool === "string" && entry.tool
            ? entry.tool
            : typeof entry.id === "string" && entry.id
              ? entry.id
              : "";
        if (tool) byTool[tool] = entry;
      }
      return DEFAULT_CAPABILITIES.map((fallback) => {
        const entry = byTool[fallback.tool];
        if (!entry) return fallback;
        return {
          id: fallback.id,
          tool: fallback.tool,
          label: typeof entry.label === "string" && entry.label ? entry.label : fallback.label,
          summary: typeof entry.summary === "string" && entry.summary ? entry.summary : fallback.summary,
        };
      });
    }

    /** A running run is either explicitly flagged or still has no finish time. */
    function isRunning(lastRun) {
      if (!lastRun) return false;
      if (lastRun.running === true) return true;
      if (lastRun.ok === true || lastRun.ok === false) return false;
      return Boolean(lastRun.startedAt) && !lastRun.finishedAt;
    }

    /** Derive the header pill and the hero headline from the payload. */
    function describeStatus(data, error, loading) {
      if (!data) {
        if (loading) {
          return { tone: "neutral", label: "CONNECTING", headline: "WAITING", running: false, failed: false, passed: false };
        }
        return { tone: "error", label: "OFFLINE", headline: "OFFLINE", running: false, failed: false, passed: false };
      }
      const lastRun = data.lastRun && typeof data.lastRun === "object" ? data.lastRun : null;
      const running = isRunning(lastRun);
      const passed = Boolean(lastRun) && !running && lastRun.ok === true;
      const failed = Boolean(lastRun) && !running && lastRun.ok === false;
      return {
        tone: running ? "business" : failed ? "error" : passed ? "success" : "neutral",
        label: running ? "RUNNING" : lastRun ? "AUTONOMOUS" : "IDLE",
        headline: running ? "RUNNING" : failed ? "FAIL" : passed ? "PASS" : "NO RUNS",
        running: running,
        failed: failed,
        passed: passed,
      };
    }

    /** One-line hero explanation that always matches the current state. */
    function heroCopy(status, lastRun) {
      if (status.running) return "A pipeline run is in progress. This panel refreshes every 5 seconds.";
      if (!lastRun) return "No pipeline run has been recorded yet. Start with the full pipeline to produce the first result.";
      if (lastRun.ok === true) {
        const steps = Array.isArray(lastRun.steps) ? lastRun.steps.length : 0;
        return "The last run passed" + (steps > 0 ? " across " + steps + (steps === 1 ? " step." : " steps.") : ".");
      }
      const failedStep = typeof lastRun.failedStep === "string" && lastRun.failedStep ? lastRun.failedStep : null;
      if (failedStep) {
        return "The last run failed at " + failedStep + ". Self-heal reads the diagnostics, repairs the exact lines, and re-runs until green.";
      }
      return "The last run did not pass. Self-heal diagnoses the failure and re-runs the pipeline until it passes.";
    }

    /**
     * Resolve a Client service without hard-injecting it.
     *
     * The panel only declares `slots` in its inject list, so `ctx.uiWorkspace`
     * would throw on direct access; the reflection store reads the same
     * implementation without the inject requirement.
     */
    function resolveService(ctx, name) {
      try {
        const direct = ctx[name];
        if (direct) return direct;
      } catch (error) {
        // Not injected: fall through to the reflection store.
      }
      try {
        const reflect = ctx.reflect;
        if (reflect && typeof reflect.get === "function") return reflect.get(name, false);
      } catch (error) {
        // Service is not registered (yet).
      }
      return undefined;
    }

    //#region primitives

    /** Small uppercase metadata label. */
    function MicroLabel({ children, style }) {
      const base = {
        fontSize: 10.5,
        fontWeight: 600,
        letterSpacing: "0.07em",
        textTransform: "uppercase",
        color: T.labelTertiary,
      };
      return h("div", { style: style ? Object.assign({}, base, style) : base }, children);
    }

    /** Rounded status pill with a colored dot. */
    function Pill({ children, tone, title }) {
      const palette = {
        neutral: T.labelSecondary,
        success: T.success,
        error: T.error,
        business: T.business,
      };
      const color = palette[tone] || palette.neutral;
      return h(
        "span",
        {
          title: title,
          style: {
            display: "inline-flex",
            alignItems: "center",
            gap: 5,
            height: 20,
            padding: "0 8px",
            borderRadius: 999,
            border: "0.5px solid " + (tone && tone !== "neutral" ? color : T.borderL3),
            color: tone && tone !== "neutral" ? color : T.labelSecondary,
            background: tone && tone !== "neutral" ? tint(color, 12) : T.bgModule,
            fontSize: 10.5,
            fontWeight: 600,
            letterSpacing: "0.07em",
            textTransform: "uppercase",
            whiteSpace: "nowrap",
            flex: "0 0 auto",
          },
        },
        h("span", { "aria-hidden": true, style: Object.assign({}, DOT, { width: 5, height: 5, background: color }) }),
        children
      );
    }

    /** Theme-aware button with a hover affordance. */
    function Button({ children, onClick, tone, disabled, title, style }) {
      const [hovered, setHovered] = React.useState(false);
      const variant = tone || "secondary";
      const tones = {
        primary: {
          borderColor: T.business,
          color: T.business,
          background: hovered && !disabled ? tint(T.business, 16) : T.bgLayer1,
        },
        secondary: {
          borderColor: T.borderL3,
          color: T.labelPrimary,
          background: hovered && !disabled ? T.hover : T.bgLayer1,
        },
        danger: {
          borderColor: T.error,
          color: T.error,
          background: hovered && !disabled ? tint(T.error, 14) : T.bgLayer1,
        },
        ghost: {
          borderColor: "transparent",
          color: T.labelSecondary,
          background: hovered && !disabled ? T.hover : "transparent",
        },
      };
      const palette = tones[variant] || tones.secondary;
      return h(
        "button",
        {
          type: "button",
          onClick: disabled ? undefined : onClick,
          disabled: disabled === true,
          title: title,
          onMouseEnter: () => setHovered(true),
          onMouseLeave: () => setHovered(false),
          style: Object.assign(
            {
              display: "inline-flex",
              alignItems: "center",
              justifyContent: "center",
              height: 32,
              padding: "0 13px",
              borderRadius: 8,
              border: "0.5px solid " + palette.borderColor,
              background: palette.background,
              color: palette.color,
              fontFamily: "inherit",
              fontSize: 13,
              fontWeight: 500,
              lineHeight: 1,
              cursor: disabled ? "default" : "pointer",
              opacity: disabled ? 0.55 : 1,
              whiteSpace: "nowrap",
              flex: "0 0 auto",
            },
            style || null
          ),
        },
        children
      );
    }

    /** Surface card used by every section of the panel. */
    function Card({ children, style }) {
      const base = {
        background: T.bgLayer1,
        border: "0.5px solid " + T.borderL3,
        borderRadius: 14,
        padding: "18px 20px",
        boxSizing: "border-box",
        minWidth: 0,
      };
      return h("section", { style: style ? Object.assign({}, base, style) : base }, children);
    }

    /** Label + value pair used in the hero and project cards. */
    function Meta({ label, value, mono, title, color }) {
      return h(
        "div",
        { style: { minWidth: 0 } },
        h("div", { style: { fontSize: 10.5, fontWeight: 600, letterSpacing: "0.05em", textTransform: "uppercase", color: T.labelTertiary, marginBottom: 3 } }, label),
        h(
          "div",
          {
            title: title,
            style: {
              fontSize: 13,
              color: color || T.labelPrimary,
              fontFamily: mono ? MONO : "inherit",
              overflow: "hidden",
              textOverflow: "ellipsis",
              whiteSpace: "nowrap",
            },
          },
          value
        )
      );
    }

    /** Numeric project stat tile. */
    function Stat({ label, value }) {
      const display = typeof value === "number" && Number.isFinite(value) ? String(value) : "—";
      return h(
        "div",
        {
          style: {
            flex: "1 1 96px",
            minWidth: 92,
            padding: "10px 12px",
            borderRadius: 10,
            background: T.bgModule,
            border: "0.5px solid " + T.borderL4,
            boxSizing: "border-box",
          },
        },
        h("div", { style: { fontSize: 20, fontWeight: 650, lineHeight: 1.2, fontVariantNumeric: "tabular-nums" } }, display),
        h("div", { style: { fontSize: 11.5, color: T.labelSecondary, marginTop: 2 } }, label)
      );
    }

    /** Calm in-card empty state. */
    function EmptyRow({ title, hint }) {
      return h(
        "div",
        { style: { display: "flex", flexDirection: "column", gap: 3, padding: "18px 0 6px" } },
        h("span", { style: { fontSize: 13, fontWeight: 500, color: T.labelSecondary } }, title),
        hint ? h("span", { style: { fontSize: 12.5, color: T.labelTertiary } }, hint) : null
      );
    }

    /** One stdout/stderr block inside an expanded step. */
    function OutputBlock({ label, text }) {
      const value = typeof text === "string" && text.trim() ? text : "(empty)";
      return h(
        "div",
        { style: { minWidth: 0 } },
        h(
          "div",
          {
            style: {
              fontSize: 10,
              fontWeight: 600,
              letterSpacing: "0.07em",
              textTransform: "uppercase",
              color: label === "stderr" ? T.labelSecondary : T.labelTertiary,
              marginBottom: 4,
            },
          },
          label
        ),
        h(
          "pre",
          {
            style: {
              margin: 0,
              maxHeight: 220,
              overflow: "auto",
              padding: "8px 10px",
              borderRadius: 8,
              border: "0.5px solid " + T.borderL4,
              background: T.bgModule,
              color: T.labelSecondary,
              fontFamily: MONO,
              fontSize: 11.5,
              lineHeight: 1.5,
              whiteSpace: "pre-wrap",
              wordBreak: "break-word",
              minHeight: 22,
              boxSizing: "border-box",
            },
          },
          value
        )
      );
    }

    //#endregion

    //#region sidebar icon

    /**
     * Target/radar glyph for the sidebar row.
     *
     * @param props - the sidebar's icon share: requested square edge and whether this panel is active.
     * @returns a decorative inline SVG that inherits the row's text color.
     */
    function AutopilotIcon({ size = 20, active = false }) {
      const accent = active ? T.business : "currentColor";
      return h(
        "svg",
        {
          width: size,
          height: size,
          viewBox: "0 0 24 24",
          fill: "none",
          role: "img",
          "aria-label": "ALmap Autopilot",
          focusable: "false",
          style: { display: "block", flex: "0 0 auto" },
        },
        h("title", { key: "title" }, "ALmap Autopilot"),
        h("circle", { cx: 12, cy: 12, r: 8.25, stroke: "currentColor", strokeWidth: 1.4, opacity: 0.9 }),
        h("circle", { cx: 12, cy: 12, r: 2, fill: accent }),
        h("path", { d: "M12 3.75v2.1M12 18.15v2.1M3.75 12h2.1M18.15 12h2.1", stroke: "currentColor", strokeWidth: 1.4, strokeLinecap: "round" }),
        h("path", { d: "M12 12l3.7-3.7", stroke: accent, strokeWidth: 1.6, strokeLinecap: "round" }),
        h("circle", { cx: 16.6, cy: 7.4, r: 1.15, fill: accent })
      );
    }

    //#endregion

    //#region sections

    /** Header row: title, state pill, primary pipeline action, refresh. */
    function PanelHeader({ status, refreshing, onRefresh, onRunPipeline }) {
      return h(
        "header",
        {
          style: {
            display: "flex",
            flexWrap: "wrap",
            alignItems: "flex-start",
            justifyContent: "space-between",
            gap: 16,
          },
        },
        h(
          "div",
          { style: { flex: "1 1 320px", minWidth: 240 } },
          h(
            "div",
            { style: { display: "flex", alignItems: "center", gap: 10, flexWrap: "wrap" } },
            h("h1", { style: { margin: 0, fontSize: 22, fontWeight: 650, letterSpacing: "-0.01em", lineHeight: 1.25 } }, "ALmap Autopilot"),
            h(Pill, { tone: status.tone }, status.label)
          ),
          h("p", { style: { margin: "6px 0 0", fontSize: 13.5, lineHeight: 1.5, color: T.labelSecondary } }, "Build, test, and self-heal ALmap without human intervention.")
        ),
        h(
          "div",
          { style: { display: "flex", alignItems: "center", gap: 8, flexWrap: "wrap" } },
          h(Button, { tone: "primary", onClick: onRunPipeline }, "Run full pipeline"),
          h(Button, { tone: "secondary", onClick: onRefresh, disabled: refreshing, title: "Re-read " + STATUS_PATH }, refreshing ? "Refreshing…" : "Refresh")
        )
      );
    }

    /** Transient action feedback banner. */
    function NoticeBanner({ tone, children }) {
      const color = tone === "error" ? T.error : T.success;
      return h(
        "div",
        {
          role: "status",
          style: {
            display: "flex",
            alignItems: "flex-start",
            gap: 8,
            padding: "8px 12px",
            borderRadius: 10,
            border: "0.5px solid " + color,
            background: tint(color, 8),
            color: T.labelSecondary,
            fontSize: 12.5,
            lineHeight: 1.5,
          },
        },
        h("span", { "aria-hidden": true, style: Object.assign({}, DOT, { width: 6, height: 6, background: color, marginTop: 5 }) }),
        h("span", null, children)
      );
    }

    /** Hero card: PASS/FAIL/NO RUNS indicator plus the one-click repair. */
    function StatusHero({ status, lastRun, onSelfHeal }) {
      const accent =
        status.tone === "success" ? T.success : status.tone === "error" ? T.error : status.tone === "business" ? T.business : T.borderL4;
      const headlineColor = status.tone === "neutral" ? T.labelPrimary : accent;
      const meta = [];
      if (lastRun) {
        meta.push({ label: "Run ID", value: lastRun.runId || "—", mono: true, title: lastRun.runId || "" });
        meta.push({ label: "Started", value: formatStamp(lastRun.startedAt) });
        meta.push({ label: "Duration", value: status.running ? "in progress" : formatDuration(lastRun.durationMs) });
        if (status.failed && lastRun.failedStep) {
          meta.push({ label: "Failed step", value: lastRun.failedStep, mono: true, color: T.error, title: lastRun.failedStep });
        }
      }
      return h(
        Card,
        { style: { boxShadow: "inset 3px 0 0 " + accent } },
        h(
          "div",
          { style: { display: "flex", flexWrap: "wrap", alignItems: "flex-start", justifyContent: "space-between", gap: 20 } },
          h(
            "div",
            { style: { flex: "1 1 280px", minWidth: 220 } },
            h(MicroLabel, null, "Last pipeline run"),
            h(
              "div",
              { style: { display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap", marginTop: 4 }, "aria-live": "polite" },
              h("span", { style: { fontSize: 36, lineHeight: 1.05, fontWeight: 700, letterSpacing: "-0.02em", color: headlineColor } }, status.headline),
              h(Pill, { tone: status.tone }, status.label)
            ),
            h("p", { style: { margin: "8px 0 0", fontSize: 13, lineHeight: 1.55, color: T.labelSecondary, maxWidth: 560 } }, heroCopy(status, lastRun))
          ),
          meta.length > 0
            ? h(
                "div",
                {
                  style: {
                    flex: "0 1 360px",
                    minWidth: 210,
                    display: "grid",
                    gridTemplateColumns: "repeat(auto-fit, minmax(132px, 1fr))",
                    gap: "10px 18px",
                  },
                },
                meta.map((item, index) => h(Meta, Object.assign({ key: item.label + index }, item)))
              )
            : null
        ),
        h(
          "div",
          {
            style: {
              display: "flex",
              flexWrap: "wrap",
              alignItems: "center",
              gap: "8px 12px",
              marginTop: 16,
              paddingTop: 14,
              borderTop: "0.5px solid " + T.borderL3,
            },
          },
          h(Button, { tone: status.failed ? "danger" : "primary", onClick: onSelfHeal }, "Self-heal now"),
          h("span", { style: { fontSize: 12, lineHeight: 1.5, color: T.labelTertiary } }, "Starts a session that reads the diagnostics, fixes the exact lines, and re-runs until green.")
        )
      );
    }

    /** Project context card: current step, git state, and file counts. */
    function ProjectCard({ project, onSync }) {
      const p = project || {};
      const counts = p.counts && typeof p.counts === "object" ? p.counts : {};
      const currentStep = p.currentStep || "Unknown step";
      const stepSource = p.stepSource || "unknown";
      const objectiveSource = p.objectiveSource || "none";
      const description = typeof p.description === "string" && p.description ? p.description : null;
      const branch = typeof p.branch === "string" && p.branch ? p.branch : "—";
      const lastCommit = typeof p.lastCommit === "string" && p.lastCommit ? p.lastCommit : "—";
      return h(
        Card,
        null,
        h(
          "div",
          { style: { display: "flex", justifyContent: "space-between", alignItems: "flex-start", gap: 12, flexWrap: "wrap" } },
          h(
            "div",
            { style: { minWidth: 220 } },
            h("h2", { style: H2 }, "Project context"),
            h(
              "div",
              { style: { display: "flex", alignItems: "baseline", gap: 10, flexWrap: "wrap", marginTop: 8 } },
              h("span", { style: { fontSize: 28, fontWeight: 650, letterSpacing: "-0.01em", lineHeight: 1.15 } }, currentStep),
              h(Pill, { tone: "neutral", title: "Step detected from " + stepSource }, "via " + stepSource)
            ),
            description
              ? h("p", { style: { margin: "8px 0 0", fontSize: 13, lineHeight: 1.5, color: T.labelSecondary, maxWidth: 620 } }, description)
              : null
          ),
          h(Button, { tone: "secondary", onClick: onSync }, "Sync project context")
        ),
        h(
          "div",
          {
            style: {
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(150px, 1fr))",
              gap: "10px 22px",
              marginTop: 16,
              paddingTop: 14,
              borderTop: "0.5px solid " + T.borderL3,
            },
          },
          h(Meta, { label: "Branch", value: branch, mono: true }),
          h(Meta, { label: "Last commit", value: lastCommit, mono: true, title: lastCommit }),
          h(Meta, { label: "Objective source", value: objectiveSource, mono: true })
        ),
        h(
          "div",
          { style: { display: "flex", flexWrap: "wrap", gap: 10, marginTop: 14 } },
          h(Stat, { label: "Goose files", value: counts.gooseFiles }),
          h(Stat, { label: "C files", value: counts.cFiles }),
          h(Stat, { label: "Tests", value: counts.tests })
        )
      );
    }

    /** One capability card; the syntax card carries a topic input. */
    function CapabilityCard({ capability, query, onQueryChange, onRun }) {
      const isLookup = capability.tool === "goose_syntax_lookup";
      return h(
        Card,
        { style: { display: "flex", flexDirection: "column", gap: 10, padding: "16px 16px", borderRadius: 12, minHeight: 150 } },
        h(
          "div",
          { style: { minWidth: 0 } },
          h("div", { style: { fontSize: 13.5, fontWeight: 600, lineHeight: 1.3 } }, capability.label),
          h(
            "code",
            {
              style: {
                display: "inline-block",
                marginTop: 4,
                fontFamily: MONO,
                fontSize: 11,
                color: T.labelSecondary,
                background: T.bgModule,
                border: "0.5px solid " + T.borderL4,
                borderRadius: 6,
                padding: "1px 6px",
                overflow: "hidden",
                textOverflow: "ellipsis",
                maxWidth: "100%",
                boxSizing: "border-box",
              },
            },
            capability.tool
          )
        ),
        h("p", { style: { margin: 0, fontSize: 12.5, lineHeight: 1.5, color: T.labelSecondary, flex: "1 1 auto" } }, capability.summary),
        isLookup
          ? h(
              "div",
              { style: { display: "flex", flexDirection: "column", gap: 8 } },
              h("input", {
                type: "text",
                value: query,
                placeholder: "Topic, e.g. slice or call_indirect",
                "aria-label": "Goose syntax topic",
                onChange: (event) => onQueryChange(event.target.value),
                onKeyDown: (event) => {
                  if (event.key === "Enter") {
                    event.preventDefault();
                    onRun(capability);
                  }
                },
                style: {
                  height: 30,
                  width: "100%",
                  boxSizing: "border-box",
                  border: "0.5px solid " + T.borderL3,
                  borderRadius: 8,
                  background: T.bgBase,
                  color: T.labelPrimary,
                  padding: "0 10px",
                  fontFamily: "inherit",
                  fontSize: 12.5,
                },
              }),
              h(Button, { tone: "secondary", onClick: () => onRun(capability) }, "Look up docs")
            )
          : h(Button, { tone: "secondary", onClick: () => onRun(capability) }, "Use")
      );
    }

    /** Four-card capability grid derived from the Host payload. */
    function CapabilitiesSection({ capabilities, query, onQueryChange, onRun }) {
      const items = normalizeCapabilities(capabilities);
      return h(
        "section",
        { style: { display: "flex", flexDirection: "column", gap: 10 } },
        h(
          "div",
          { style: { display: "flex", alignItems: "baseline", justifyContent: "space-between", gap: 12, flexWrap: "wrap" } },
          h("h2", { style: H2 }, "Autopilot capabilities"),
          h("span", { style: { fontSize: 12, color: T.labelTertiary } }, "Tools are available to the agent in every session")
        ),
        h(
          "div",
          { style: { display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(232px, 1fr))", gap: 12 } },
          items.map((capability) => h(CapabilityCard, { key: capability.id, capability: capability, query: query, onQueryChange: onQueryChange, onRun: onRun }))
        )
      );
    }

    /** One expandable pipeline step row. */
    function StepRow({ step }) {
      const ok = step.ok === true;
      const failed = step.ok === false;
      const color = failed ? T.error : ok ? T.success : T.labelTertiary;
      const label = step.label || step.id || "step";
      const command = typeof step.command === "string" ? step.command : "";
      let exitLabel;
      if (step.timedOut === true) exitLabel = "timed out";
      else if (step.signal) exitLabel = "signal " + step.signal;
      else if (step.exitCode === null || step.exitCode === undefined) exitLabel = "no exit";
      else exitLabel = "exit " + step.exitCode;
      return h(
        "details",
        { style: { borderTop: "0.5px solid " + T.borderL3, minWidth: 0 } },
        h(
          "summary",
          {
            style: {
              display: "flex",
              alignItems: "center",
              gap: 10,
              padding: "9px 0",
              cursor: "pointer",
              listStyle: "none",
              minWidth: 0,
            },
          },
          h("span", { "aria-hidden": true, style: Object.assign({}, DOT, { width: 8, height: 8, background: color }) }),
          h("span", { title: label, style: { flex: "0 1 170px", minWidth: 88, fontSize: 13, fontWeight: 500, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" } }, label),
          h(
            "code",
            {
              title: command,
              style: {
                flex: "1 1 160px",
                minWidth: 0,
                overflow: "hidden",
                textOverflow: "ellipsis",
                whiteSpace: "nowrap",
                fontFamily: MONO,
                fontSize: 11.5,
                color: T.labelSecondary,
              },
            },
            command || "—"
          ),
          h("span", { style: { flex: "0 0 auto", fontFamily: MONO, fontSize: 11.5, color: failed ? T.error : T.labelTertiary } }, exitLabel),
          h("span", { style: { flex: "0 0 62px", textAlign: "right", fontVariantNumeric: "tabular-nums", fontSize: 11.5, color: T.labelTertiary } }, formatDuration(step.durationMs))
        ),
        h(
          "div",
          { style: { display: "flex", flexDirection: "column", gap: 8, padding: "2px 0 12px 18px" } },
          h(OutputBlock, { label: "stdout", text: step.stdout }),
          h(OutputBlock, { label: "stderr", text: step.stderr })
        )
      );
    }

    /** Step list card with the no-run empty state. */
    function StepsCard({ lastRun }) {
      const steps = lastRun && Array.isArray(lastRun.steps) ? lastRun.steps : [];
      return h(
        Card,
        { style: { padding: "16px 20px" } },
        h(
          "div",
          { style: { display: "flex", alignItems: "baseline", justifyContent: "space-between", gap: 12, flexWrap: "wrap" } },
          h("h2", { style: H2 }, "Steps"),
          lastRun
            ? h("span", { style: { fontSize: 12, color: T.labelTertiary, fontVariantNumeric: "tabular-nums" } }, "total " + formatDuration(lastRun.durationMs))
            : null
        ),
        steps.length === 0
          ? h(EmptyRow, { title: "No run yet", hint: "Run the full pipeline to record step results." })
          : h(
              "div",
              { style: { marginTop: 6 } },
              steps.map((step, index) => {
                const candidate = step && typeof step === "object" ? step : {};
                const key = candidate.id || candidate.label || "step-" + index;
                return h(StepRow, { key: key, step: candidate });
              })
            )
      );
    }

    /** Diagnostic list card, shown only when the last run reported issues. */
    function DiagnosticsCard({ diagnostics }) {
      return h(
        Card,
        { style: { padding: "16px 20px" } },
        h(
          "div",
          { style: { display: "flex", alignItems: "center", justifyContent: "space-between", gap: 12, flexWrap: "wrap" } },
          h("h2", { style: H2 }, "Diagnostics"),
          h(Pill, { tone: "error" }, diagnostics.length + (diagnostics.length === 1 ? " issue" : " issues"))
        ),
        h(
          "div",
          { style: { display: "flex", flexDirection: "column", gap: 8, marginTop: 10 } },
          diagnostics.map((entry, index) => {
            const item = entry && typeof entry === "object" ? entry : {};
            const severity = typeof item.severity === "string" ? item.severity.toLowerCase() : "error";
            const color = severity === "error" ? T.error : severity === "warning" ? T.business : T.labelSecondary;
            const parts = [];
            if (item.file !== undefined && item.file !== null) parts.push(String(item.file));
            if (item.line !== undefined && item.line !== null) parts.push(String(item.line));
            if (item.column !== undefined && item.column !== null) parts.push(String(item.column));
            return h(
              "div",
              {
                key: item.file + ":" + item.line + ":" + item.column + ":" + index,
                style: {
                  display: "flex",
                  flexWrap: "wrap",
                  alignItems: "baseline",
                  gap: 8,
                  padding: "8px 10px",
                  borderRadius: 8,
                  background: T.bgModule,
                  border: "0.5px solid " + T.borderL4,
                },
              },
              h("span", { "aria-hidden": true, style: Object.assign({}, DOT, { background: color, alignSelf: "center" }) }),
              h("code", { style: { fontFamily: MONO, fontSize: 11.5, color: T.labelPrimary, whiteSpace: "nowrap" } }, parts.length > 0 ? parts.join(":") : "(no location)"),
              h("span", { style: { fontSize: 10, fontWeight: 600, letterSpacing: "0.06em", textTransform: "uppercase", color: color } }, severity),
              h("span", { style: { color: T.labelTertiary } }, "—"),
              h("span", { style: { flex: "1 1 240px", minWidth: 0, fontSize: 12.5, lineHeight: 1.5, color: T.labelSecondary } }, item.message || "(no message)")
            );
          })
        )
      );
    }

    /** Last up to five runs as compact pass/fail pills. */
    function HistoryStrip({ history }) {
      const runs = Array.isArray(history) ? history.filter((run) => run && typeof run === "object") : [];
      const ordered = runs
        .slice()
        .sort((a, b) => timeValue(b.startedAt) - timeValue(a.startedAt))
        .slice(0, 5);
      return h(
        Card,
        { style: { padding: "14px 20px" } },
        h(
          "div",
          { style: { display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap" } },
          h("h2", { style: Object.assign({}, H2, { fontSize: 13.5, flex: "0 0 auto" }) }, "Recent runs"),
          ordered.length === 0
            ? h("span", { style: { fontSize: 12.5, color: T.labelTertiary } }, "No history yet.")
            : h(
                "div",
                { style: { display: "flex", flexWrap: "wrap", gap: 8 } },
                ordered.map((run, index) =>
                  h(
                    Pill,
                    {
                      key: run.runId || "run-" + index,
                      tone: run.ok === true ? "success" : "error",
                      title: (run.runId ? "Run " + run.runId : "Run") + " · " + formatDuration(run.durationMs),
                    },
                    formatStamp(run.startedAt) + " · " + (run.ok === true ? "pass" : "fail")
                  )
                )
              )
        )
      );
    }

    /** Degraded state: calm error card with a Retry button. */
    function DegradedState({ error, onRetry, refreshing }) {
      return h(
        Card,
        { style: { display: "flex", flexDirection: "column", alignItems: "flex-start", gap: 12, padding: "28px 24px" } },
        h(
          "div",
          { style: { display: "flex", alignItems: "center", gap: 10 } },
          h("span", { "aria-hidden": true, style: Object.assign({}, DOT, { width: 10, height: 10, background: T.error }) }),
          h("h2", { style: { margin: 0, fontSize: 16, fontWeight: 600 } }, "Autopilot host is not reachable")
        ),
        h(
          "p",
          { style: { margin: 0, maxWidth: 620, fontSize: 13, lineHeight: 1.6, color: T.labelSecondary } },
          "The panel could not read the status endpoint. This usually means the Host half of the bundle is still starting, or the plugin was just installed and needs a moment."
        ),
        h(
          "code",
          {
            style: {
              maxWidth: "100%",
              boxSizing: "border-box",
              padding: "6px 10px",
              borderRadius: 8,
              border: "0.5px solid " + T.borderL4,
              background: T.bgModule,
              color: T.labelSecondary,
              fontFamily: MONO,
              fontSize: 11.5,
              overflowWrap: "anywhere",
            },
          },
          error || "Unknown error"
        ),
        h(
          "div",
          { style: { display: "flex", alignItems: "center", gap: 12, flexWrap: "wrap", marginTop: 2 } },
          h(Button, { tone: "primary", onClick: onRetry, disabled: refreshing }, refreshing ? "Retrying…" : "Retry"),
          h("span", { style: { fontSize: 12, color: T.labelTertiary } }, "Retrying automatically every 5 seconds.")
        )
      );
    }

    /** Initial loading state while the first request is in flight. */
    function LoadingCard() {
      return h(
        Card,
        { style: { display: "flex", alignItems: "center", gap: 12, padding: "26px 24px" } },
        h("span", { "aria-hidden": true, style: Object.assign({}, DOT, { width: 10, height: 10, background: T.business }) }),
        h(
          "div",
          null,
          h("div", { style: { fontSize: 14, fontWeight: 600 } }, "Contacting the autopilot host…"),
          h("div", { style: { marginTop: 3, fontSize: 12.5, color: T.labelSecondary } }, "Reading the latest pipeline result and project context.")
        )
      );
    }

    /** Footer: workspace, version, generation timestamp, and availability hint. */
    function Footer({ data, updatedAt }) {
      const workspace = data && typeof data.workspace === "string" && data.workspace ? data.workspace : "—";
      const version = data && typeof data.version === "string" && data.version ? data.version : "—";
      const generatedAt = data && data.generatedAt ? data.generatedAt : null;
      const items = [
        h("code", { key: "workspace", title: workspace, style: { fontFamily: MONO, fontSize: 11, color: T.labelSecondary } }, workspace),
        h("span", { key: "version" }, "v" + version),
        h("span", { key: "generated" }, "generated " + formatStamp(generatedAt)),
      ];
      if (updatedAt) items.push(h("span", { key: "checked" }, "last checked " + formatStamp(updatedAt)));
      return h(
        "footer",
        {
          style: {
            display: "flex",
            flexWrap: "wrap",
            alignItems: "center",
            gap: "6px 14px",
            paddingTop: 4,
            fontSize: 11.5,
            color: T.labelTertiary,
          },
        },
        ...items,
        h("span", { style: { flex: "1 1 100%", fontSize: 11.5, color: T.labelTertiary } }, "Tools are available to the agent in every session.")
      );
    }

    //#endregion

    //#region data

    /**
     * Poll the Host status endpoint while the panel is mounted.
     *
     * Polls every 5 seconds, pauses while the tab is hidden, and refreshes
     * immediately when the tab becomes visible again. The interval is always
     * cleared on unmount.
     */
    function useAutopilotStatus() {
      const [state, setState] = React.useState({ data: null, error: null, updatedAt: null, loading: true });
      const disposedRef = React.useRef(false);
      const busyRef = React.useRef(false);

      const refresh = React.useCallback(async () => {
        if (busyRef.current) return;
        busyRef.current = true;
        try {
          const response = await fetch(STATUS_PATH, { cache: "no-store" });
          if (!response.ok) {
            throw new Error("HTTP " + response.status + (response.statusText ? " " + response.statusText : ""));
          }
          const payload = await response.json();
          if (!payload || typeof payload !== "object") throw new Error("Malformed status response");
          if (disposedRef.current) return;
          setState({ data: payload, error: null, updatedAt: Date.now(), loading: false });
        } catch (error) {
          if (disposedRef.current) return;
          const message = error && error.message ? error.message : String(error);
          setState((previous) => ({ data: previous.data, error: message, updatedAt: previous.updatedAt, loading: false }));
        } finally {
          busyRef.current = false;
        }
      }, []);

      React.useEffect(() => {
        disposedRef.current = false;
        refresh();
        const timer = setInterval(() => {
          if (typeof document !== "undefined" && document.hidden) return;
          refresh();
        }, POLL_INTERVAL_MS);
        const onVisibilityChange = () => {
          if (typeof document !== "undefined" && !document.hidden) refresh();
        };
        if (typeof document !== "undefined") document.addEventListener("visibilitychange", onVisibilityChange);
        return () => {
          disposedRef.current = true;
          clearInterval(timer);
          if (typeof document !== "undefined") document.removeEventListener("visibilitychange", onVisibilityChange);
        };
      }, [refresh]);

      return { data: state.data, error: state.error, updatedAt: state.updatedAt, loading: state.loading, refresh: refresh };
    }

    //#endregion

    //#region panel

    /** Central panel: polls status and composes every section. */
    function AutopilotPanel(props) {
      const startSession = props && typeof props.startSession === "function" ? props.startSession : null;
      const { data, error, loading, updatedAt, refresh } = useAutopilotStatus();
      const [notice, setNotice] = React.useState(null);
      const [refreshing, setRefreshing] = React.useState(false);
      const [query, setQuery] = React.useState("");
      const noticeTimer = React.useRef(null);

      const announce = React.useCallback((text, tone) => {
        setNotice({ text: text, tone: tone === "error" ? "error" : "success" });
        if (noticeTimer.current !== null) clearTimeout(noticeTimer.current);
        noticeTimer.current = setTimeout(() => {
          noticeTimer.current = null;
          setNotice(null);
        }, 4000);
      }, []);

      React.useEffect(
        () => () => {
          if (noticeTimer.current !== null) {
            clearTimeout(noticeTimer.current);
            noticeTimer.current = null;
          }
        },
        []
      );

      const launch = React.useCallback(
        (prompt) => {
          if (typeof startSession !== "function") {
            announce("Session launch is unavailable in this view.", "error");
            return;
          }
          let started = false;
          try {
            started = startSession(prompt) !== false;
          } catch (launchError) {
            if (typeof console !== "undefined" && console.warn) console.warn("[almap-autopilot] failed to start a session", launchError);
          }
          announce(
            started ? "Session started. The agent is running the requested step." : "Could not start a session from this panel.",
            started ? "success" : "error"
          );
        },
        [announce, startSession]
      );

      const onRefresh = React.useCallback(() => {
        if (refreshing) return;
        setRefreshing(true);
        const done = () => setRefreshing(false);
        let result;
        try {
          result = refresh();
        } catch (refreshError) {
          done();
          return;
        }
        if (result && typeof result.then === "function") result.then(done, done);
        else done();
      }, [refresh, refreshing]);

      const status = describeStatus(data, error, loading);
      const lastRun = data && data.lastRun && typeof data.lastRun === "object" ? data.lastRun : null;
      const diagnostics = lastRun && Array.isArray(lastRun.diagnostics) ? lastRun.diagnostics : [];
      const project = data && data.project && typeof data.project === "object" ? data.project : null;

      const onSelfHeal = () => launch(selfHealPrompt(lastRun && lastRun.failedStep ? lastRun.failedStep : null));
      const onRunPipeline = () => launch(PIPELINE_PROMPT);
      const onSync = () => launch(SYNC_PROMPT);
      const onRunCapability = (capability) => launch(capabilityPrompt(capability, query));

      return h(
        "div",
        { style: { height: "100%", overflow: "auto", background: T.bgBase, color: T.labelPrimary, fontFamily: "inherit" } },
        h(
          "div",
          {
            style: {
              display: "flex",
              flexDirection: "column",
              gap: 16,
              maxWidth: 1040,
              margin: "0 auto",
              padding: "26px 28px 48px",
              boxSizing: "border-box",
            },
          },
          h(PanelHeader, { status: status, refreshing: refreshing, onRefresh: onRefresh, onRunPipeline: onRunPipeline }),
          notice ? h(NoticeBanner, { tone: notice.tone }, notice.text) : null,
          error && data ? h(NoticeBanner, { tone: "error" }, "Status refresh failed (" + error + "). Showing the last known result.") : null,
          !data
            ? loading
              ? h(LoadingCard)
              : h(DegradedState, { error: error || "The status endpoint returned no data.", onRetry: onRefresh, refreshing: refreshing })
            : h(
                React.Fragment,
                null,
                h(StatusHero, { status: status, lastRun: lastRun, onSelfHeal: onSelfHeal }),
                h(ProjectCard, { project: project, onSync: onSync }),
                h(CapabilitiesSection, {
                  capabilities: data && data.capabilities,
                  query: query,
                  onQueryChange: setQuery,
                  onRun: onRunCapability,
                }),
                h(StepsCard, { lastRun: lastRun }),
                diagnostics.length > 0 ? h(DiagnosticsCard, { diagnostics: diagnostics }) : null,
                h(HistoryStrip, { history: data && data.history }),
                h(Footer, { data: data, updatedAt: updatedAt })
              )
        )
      );
    }

    //#endregion

    const inject = ["slots", "uiWorkspace"];

    /**
     * Register the sidebar entry and the central panel.
     *
     * @param ctx - Client context carrying the slots service.
     */
    function apply(ctx) {
      const startSession = (prompt) => {
        if (typeof prompt !== "string" || !prompt) return false;
        const workspace = resolveService(ctx, "uiWorkspace");
        if (!workspace || typeof workspace.startSession !== "function") return false;
        try {
          workspace.startSession(undefined, { prompt: prompt, whenDraftExists: START_OPTIONS.whenDraftExists });
          return true;
        } catch (error) {
          if (typeof console !== "undefined" && console.warn) console.warn("[almap-autopilot] workspace.startSession failed", error);
          return false;
        }
      };

      ctx.slots.inject("sidebar.panellist", () =>
        ctx.slots.register(
          {
            name: "sidebar.panellist",
            id: "almap-autopilot",
            order: 15,
            label: "ALmap Autopilot",
          },
          AutopilotIcon
        )
      );

      ctx.slots.inject("main", () =>
        ctx.slots.register(
          {
            name: "main",
            key: "almap-autopilot",
            inject: () => ({ startSession: startSession }),
          },
          AutopilotPanel
        )
      );
    }

    return { inject, apply };
  },
});
