// What Jev gets to see besides the tool call itself: the user's recent words, the agent's stated intent,
// the last few decisions, and anything flagged as untrusted earlier in the session. Sources, in order:
// the session store (fed by every host's prompt/tool hooks), a Claude-style JSONL transcript when the
// host hands us one, and whatever the adapter already knows (Cursor's agent_message, pi's session entries).
import { closeSync, openSync, readSync, statSync } from "node:fs";
import { readSession } from "./session.js";

const TAIL_BYTES = 256 * 1024;
const MAX_TEXT = 700;

export function buildContext({ sessionId, transcriptPath, intent, messages } = {}) {
  const s = readSession(sessionId);
  let prompts = s.prompts.map((p) => p.text);
  let intents = s.intents.map((i) => i.text);
  if (messages) {  // adapter-supplied [{role, text}] (pi, OpenCode, ACP)
    prompts = [...prompts, ...messages.filter((m) => m.role === "user").map((m) => m.text)];
    intents = [...intents, ...messages.filter((m) => m.role === "assistant").map((m) => m.text)];
  } else if (transcriptPath) {
    const t = readTranscript(transcriptPath);
    prompts = [...prompts, ...t.user];
    intents = [...intents, ...t.assistant];
  }
  if (intent) intents.push(intent);
  const ctx = {
    user_recent_messages: dedupe(prompts).slice(-3).map(clip),
    assistant_intent: clip(intents.at(-1) ?? ""),
    recent_tool_calls: s.calls.slice(-6).map((c) => `${c.tool} ${c.preview}${c.level && c.level !== "allow" ? ` [${c.level}]` : ""}`),
    flagged_untrusted_content: s.flags.slice(-5).map((f) => `${f.kind} from ${f.source ?? f.tool ?? "unknown"}${f.p ? ` (p=${f.p})` : ""}${f.excerpt ? `: "${f.excerpt}"` : ""}`),
  };
  for (const k of Object.keys(ctx)) if (!ctx[k] || ctx[k].length === 0) delete ctx[k];
  return Object.keys(ctx).length ? ctx : undefined;
}

/** Last user texts and assistant texts from a Claude Code style JSONL transcript. Tool results are not user words. */
export function readTranscript(path) {
  const out = { user: [], assistant: [] };
  let raw, partial;
  try {
    const size = statSync(path).size;
    const fd = openSync(path, "r");
    const len = Math.min(size, TAIL_BYTES);
    const buf = Buffer.alloc(len);
    readSync(fd, buf, 0, len, size - len);
    closeSync(fd);
    raw = buf.toString("utf8");
    partial = size > len;
  } catch { return out; }
  for (const line of raw.split("\n").slice(partial ? 1 : 0)) {  // a tail read may start mid-record
    let rec;
    try { rec = JSON.parse(line); } catch { continue; }
    const role = rec.message?.role ?? rec.type ?? rec.role;
    const content = rec.message?.content ?? rec.content;
    const text = textOf(content);
    if (!text) continue;
    const isUser = role === "user" || rec.type === "USER_INPUT" || rec.source === "USER_EXPLICIT";
    const isAssistant = role === "assistant" || rec.type === "PLANNER_RESPONSE" || rec.source === "MODEL";
    if (isUser) out.user.push(text);
    else if (isAssistant) out.assistant.push(text);
  }
  return out;
}

function textOf(content) {
  if (typeof content === "string") return content.trim();
  if (!Array.isArray(content)) return "";
  return content.filter((b) => b?.type === "text" && typeof b.text === "string").map((b) => b.text.trim()).filter(Boolean).join("\n");
}

const clip = (s) => (s.length > MAX_TEXT ? s.slice(0, MAX_TEXT) + "…" : s);
const dedupe = (arr) => arr.filter((x, i) => x && arr.indexOf(x) === i);

/** Text of every user/assistant message from pi's session entries or OpenCode's session.messages(). */
export function messagesFrom(entries) {
  const out = [];
  for (const e of entries ?? []) {
    const m = e.message ?? e;                              // pi: {type:"message", message:{role, content}}
    const role = m.role ?? e.info?.role;                   // opencode: {info:{role}, parts:[{type,text}]}
    if (role !== "user" && role !== "assistant") continue;
    const text = textOf(m.content) || textOf(e.parts);
    if (text) out.push({ role, text });
  }
  return out.slice(-8);
}
