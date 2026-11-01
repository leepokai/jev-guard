// OpenCode 2 TUI plugin. The server half (src/opencode-v2.js) decides what needs approval, but its
// Context has no client and no UI channel: OpenCode's permission dialog renders only the action name
// for a plugin-defined action ("Call tool jev-guard" / "Tool: jev-guard"), so the assessment never
// reaches the user there. A toast is wrong too: `ui.toast` is broadcast to every TUI, it expires on
// a timer, and the plugin-facing Toast exposes only `show`. `ui.panel` cannot carry this either —
// `panel.open()` targets the session that is current when it is called and a plugin has one active
// panel, so an ask from another tab would surface in the wrong tab and vanish when you switch.
// `session.composer.top` renders per session instead: each tab shows its own pending ask above the
// input, nothing shows in tabs without one, and the asking is still OpenCode's normal permission
// prompt, so any client (desktop, mobile, Orca) can answer it.
import { Plugin } from "@opencode/plugin/tui";
import { createElement, insert, setProp } from "@opentui/solid";
import { createSignal } from "solid-js";

export const ACTION = "jev-guard";
const MAX_COMMAND_CHARS = 240;

const num = (v, digits = 2) => (typeof v === "number" && Number.isFinite(v) ? v.toFixed(digits) : undefined);

// A bare probability says nothing on its own: each score is named for what it means at the point where
// the policy acts on it (ask at 1.5 risk or 0.75 approval, deny at 2.5 risk, untrusted at 0.7, and the
// user-requested 0.85 that turns an ask into an allow).
const word = (value, bands) => bands.find((b) => value <= b.score)?.label;
const RISK = [
  { score: 0.5, label: "MINIMAL" }, { score: 1.5, label: "LOW" },
  { score: 2.5, label: "MODERATE" }, { score: 2.99, label: "SEVERE" }, { score: 3, label: "CRITICAL" },
];
const APPROVAL = [
  { score: 0.2, label: "UNLIKELY" }, { score: 0.5, label: "MAYBE" },
  { score: 0.75, label: "LIKELY" }, { score: 1, label: "SUGGESTED" },
];
const ASKED = [
  { score: 0.2, label: "NO" }, { score: 0.6, label: "UNCLEAR" },
  { score: 0.85, label: "PROBABLY" }, { score: 1, label: "YES" },
];
const UNTRUSTED = [
  { score: 0.2, label: "CLEAN" }, { score: 0.5, label: "UNLIKELY" },
  { score: 0.7, label: "SUSPICIOUS" }, { score: 1, label: "PLANTED" },
];
const CONFIDENCE = [
  { score: 0.5, label: "LOW" }, { score: 0.8, label: "MEDIUM" }, { score: 1, label: "HIGH" },
];

const SCORES = [
  ["risk", (m) => num(m.risk, 1), "0–3", RISK],
  ["approval", (m) => num(m.approval), "0–1", APPROVAL],
  ["you asked for it", (m) => num(m.userRequested), "0–1", ASKED],
  ["untrusted source", (m) => num(m.fromUntrusted), "0–1", UNTRUSTED],
  ["confidence", (m) => num(m.confidence), "0–1", CONFIDENCE],
];

// What the call is, in words, so the heading reads like a request rather than a tool name.
const VERBS = {
  shell: "a shell command", bash: "a shell command", exec: "a shell command", execute: "a shell command",
  edit: "an edit", write: "a write", multiedit: "an edit", notebookedit: "an edit",
  delete: "a delete", read: "a read", webfetch: "a fetch", websearch: "a search",
};
const verbFor = (tool) => VERBS[String(tool ?? "").toLowerCase()] ?? (tool ? `a ${tool} call` : "this call");

/** The ask as display pieces: what it is, what it touches, one bullet per Jev score, and any diff. */
export function describeAsk({ metadata = {}, resources = [], action = ACTION } = {}) {
  const tool = typeof metadata.tool === "string" ? metadata.tool : undefined;
  const full = resources[0] == null ? undefined : String(resources[0]);
  const command = full === undefined ? undefined : tool && full.startsWith(`${tool} `) ? full.slice(tool.length + 1) : full;
  const target = command?.length > MAX_COMMAND_CHARS ? `${command.slice(0, MAX_COMMAND_CHARS - 1)}…` : command;
  const diff = Array.isArray(metadata.diff) && metadata.diff.length ? metadata.diff.map(String) : undefined;
  const scores = SCORES
    .map(([label, read, range, bands]) => [label, read(metadata), range, bands])
    .filter(([, value]) => value !== undefined)
    .map(([label, value, range, bands]) => `• ${label}: ${word(value, bands)} — ${value} (${range})`);
  const verb = verbFor(tool);
  if (scores.length) return { tool, verb, what: target, scores, diff };
  const reason = typeof metadata.reason === "string" ? metadata.reason : `${action} needs approval`;
  return { tool, verb, scores, reason, what: target, diff };
}

// Plain-JS equivalents of the host's JSX helpers (same calls the bundled plugins compile to).
const element = (tag, props = {}, children = []) => {
  const node = createElement(tag);
  for (const [key, value] of Object.entries(props)) if (value !== undefined) setProp(node, key, value);
  const list = Array.isArray(children) ? children : [children];
  for (const child of list) if (child !== null && child !== undefined && child !== false) insert(node, child);
  return node;
};
const box = (props, children) => element("box", props, children);
const text = (props, children) => element("text", props, children);

/** Banner body: this session's oldest pending ask, or nothing at all. */
export function bannerView(asks, sessionID, theme = {}) {
  const warn = theme.warning ?? theme.text?.default;
  const muted = theme.text?.subdued;
  const added = theme.success ?? theme.text?.default;
  const removed = theme.error ?? theme.warning ?? theme.text?.default;
  const root = box({ width: "100%", flexDirection: "column", paddingLeft: 1 });
  insert(root, () => {
    const list = asks()[sessionID];
    const ask = list?.[0];  // the oldest pending ask is the one a reply without an id answers
    if (!ask) return null;
    const diffLine = (line) => text({ fg: line.startsWith("+") ? added : line.startsWith("-") ? removed : muted }, [line]);
    // Three visual blocks — request, evidence, report — separated by a blank line each, so the
    // banner reads at a glance instead of as one run of text.
    const request = box({ flexDirection: "column", marginTop: 1 }, [
      ask.what && text({ fg: warn }, [`What: ${ask.tool ?? "call"} — ${ask.what}`]),
      ask.diff?.length && box({ flexDirection: "column", marginTop: 1 }, ask.diff.map(diffLine)),
    ].filter(Boolean));
    const report = box({ flexDirection: "column", marginTop: 1 },
      ask.scores.length ? ask.scores.map((line) => text({ fg: muted }, [line])) : [text({ fg: muted }, [ask.reason])]);
    const closing = box({ flexDirection: "column", marginTop: 1 }, [
      list.length > 1 && text({ fg: muted }, [`${list.length - 1} more pending after this one.`]),
      text({ fg: muted }, ["Answer the permission prompt — this clears when you do."]),
    ].filter(Boolean));
    return box({ width: "100%", flexDirection: "column", marginTop: 1 }, [
      text({ fg: warn }, [`⚠ jev-guard — ${ask.verb} needs your approval`]),
      request,
      report,
      closing,
    ]);
  });
  return root;
}

export function setup(ctx) {
  const [asks, setAsks] = createSignal({});  // sessionID -> [{ id, ...describeAsk(data) }], oldest first

  const offAsk = ctx.data.on("permission.asked", ({ data }) => {
    if (data?.action !== ACTION || !data.sessionID) return;
    const entry = { id: data.id, ...describeAsk(data) };
    setAsks((prev) => {
      const list = prev[data.sessionID] ?? [];
      const next = list.some((a) => a.id === entry.id)
        ? list.map((a) => (a.id === entry.id ? entry : a))
        : [...list, entry];
      return { ...prev, [data.sessionID]: next };
    });
  });
  // A reply may carry no request id and no action. Match the id when it is there; otherwise drop the
  // oldest ask, which is the prompt the user was looking at. Parallel asks keep their own entry, so
  // answering one no longer erases the assessment of another.
  const offReply = ctx.data.on("permission.replied", ({ data }) => {
    if (!data?.sessionID) return;
    setAsks((prev) => {
      const list = prev[data.sessionID];
      if (!list?.length) return prev;
      const rest = data.requestID && list.some((a) => a.id === data.requestID)
        ? list.filter((a) => a.id !== data.requestID)
        : list.slice(1);
      const next = { ...prev };
      if (rest.length) next[data.sessionID] = rest;
      else delete next[data.sessionID];
      return next;
    });
  });
  const offSlot = ctx.ui.slot({
    prepend: "session.composer.top",
    render: (input) => bannerView(asks, input?.sessionID, ctx.theme),
  });
  return () => { offAsk?.(); offReply?.(); offSlot?.(); };
}

export default Plugin.define({ id: ACTION, setup });
