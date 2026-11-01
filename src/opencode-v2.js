// OpenCode 2 plugin. V2 loads `default.setup(ctx)` and has no `tool.execute.before` / `permission.ask` hooks:
// tool calls go through ctx.tool.hook("execute.before" / "execute.after"), and every permission check — including
// ones whose rules already allow the call — passes ctx.permission.hook("evaluate") with an effect the plugin may
// change. OpenCode's own rules are the source of truth here: a rule's allow and deny are final, and only an `ask`
// is sent to Jev, which may then allow it, deny it, or leave the human prompt in place. Nothing is assessed in
// execute.before, so an allowed call costs no Jev request and sends no file content anywhere.
import { assessAction, scanContent, collectText, preview, previewDiff, excerpt, INSTRUCTION_FILE } from "./guard.js";
import { setting } from "./jev.js";
import { scanInstructionsCached } from "./skills.js";
import { buildContext } from "./context.js";
import { readSession, remember } from "./session.js";

export const ACTION = "jev-guard";  // permission action of the prompt raised when Jev wants a human
const MAX_PENDING = 100;

/** User and assistant text from V2's ctx.session.context() messages. */
export function messagesFromV2(messages) {
  const out = [];
  for (const m of messages ?? []) {
    const text = m.type === "user" ? m.text
      : m.type === "assistant" ? (m.content ?? []).filter((p) => p.type === "text").map((p) => p.text).join("\n") : "";
    if (text?.trim()) out.push({ role: m.type, text: text.trim() });
  }
  return out.slice(-8);
}

export async function setup(ctx, { log = (m) => console.warn(m) } = {}) {
  const cwd = ctx.location?.directory;
  // The evaluate hook carries no tool input, only a source id, so execute.before records what is about to run.
  // Bounded: a session that never executes what it assesses must not grow this without limit.
  const pending = new Map();  // tool-call id → { tool, input, sessionID, messageID }
  const asking = new Map();   // tool-call id → assessment message shown by the prompt we raise
  const rememberCall = (e) => {
    pending.set(e.id, { tool: e.tool, input: e.input, sessionID: e.sessionID, messageID: e.messageID });
    if (pending.size > MAX_PENDING) pending.delete(pending.keys().next().value);
  };
  // The session's messages; empty when they can't be read, so the call is judged on its own.
  const context = async (sessionID) => {
    const messages = await ctx.session.context({ sessionID }).catch(() => []);
    return buildContext({ sessionId: sessionID, messages: messagesFromV2(messages) });
  };
  // Raise the guard's own prompt for one call: only a human allow turns it into an allow here.
  const raise = async (e, call, resource, id, message, scores = {}) => {
    asking.set(id, message);
    try {
      await ctx.permission.assert({
        sessionID: call.sessionID, agent: e.agent, action: ACTION, resources: [resource],
        metadata: { tool: call.tool, reason: message, ...scores },
        source: { type: "tool", messageID: call.messageID, id },  // both are required by AssertInput
      });
      e.effect = "allow";
    } catch (err) {
      e.effect = "deny";
      e.message = err?.message ?? "rejected";
    } finally { asking.delete(id); }
  };

  await ctx.tool.hook("execute.before", (e) => { rememberCall(e); });

  await ctx.permission.hook("evaluate", async (e) => {
    if (e.action === ACTION) {  // our own prompt: carry the assessment, never assess a prompt
      e.effect = "ask";
      const id = e.source?.type === "tool" ? e.source.id : undefined;
      if (id && asking.has(id)) e.message = asking.get(id);
      return;
    }
    if (e.effect !== "ask") return;  // a rule allowed or denied it: that is final, Jev is not consulted
    const id = e.source?.type === "tool" ? e.source.id : undefined;
    const call = id ? pending.get(id) : undefined;
    if (!call) return;  // nothing recorded to judge: the user gets the plain prompt
    // What the host is actually asking about beats our own rendering of the input: it knows the
    // exact command line or paths, and its resources are not truncated the way a preview is.
    const resource = e.resources?.length ? e.resources.join(", ") : `${call.tool} ${preview(call.input)}`;
    let r;
    try {
      r = await assessAction({ tool: call.tool, input: call.input, cwd, agent: "opencode", context: await context(call.sessionID) });
    } catch (err) {
      log(`jev-guard: ${err.message}`);
      // Fail-closed first: an unreachable API denies, and it wins over escalating.
      if (setting("JEV_GUARD_FAIL_CLOSED")) {
        e.effect = "deny";
        e.message = `jev-guard unavailable: ${err.message}`;
        return;
      }
      // Escalating still gives the user a prompt, but one that says the call was never judged.
      if (setting("JEV_GUARD_ESCALATE_CLOSED") === "1") {
        await raise(e, call, resource, id, `jev-guard: the assessment API was not available (${err.message}) — this call was not judged`);
        return;
      }
      return;  // default: the host's own prompt stands
    }
    if (!r) return;  // read-only tool, workspace write or skip list: the prompt stands as OpenCode made it
    remember(call.sessionID, "calls", { tool: call.tool, preview: preview(call.input, 100), level: r.level });
    e.message = r.message;
    if (r.level === "allow") { e.effect = "allow"; return; }
    if (r.level === "deny") { e.effect = "deny"; return; }
    // Jev wants a human, and OpenCode's own dialog shows only the operation — not our numbers and,
    // as far as 2.2.5 goes, not `e.message` either. So raise the prompt ourselves for this one
    // call; ./tui renders its metadata above the composer. The native prompt is skipped by
    // answering "allow" here once the human has allowed it, and turned into a deny if they refuse.
    await raise(e, call, resource, id, r.message, {
      risk: r.risk, approval: r.approval, userRequested: r.userRequested, fromUntrusted: r.fromUntrusted, confidence: r.confidence,
      diff: previewDiff(call.input),  // omitted by JSON for a call that changes no text
    });
  });

  await ctx.tool.hook("execute.after", async (e) => {
    pending.delete(e.id);
    // Ask-only: a result is content, not an operation, so scanning is opt-in and separate from the gate.
    if (setting("JEV_GUARD_SCAN_RESULTS") !== "1" || e.status !== "completed") return;
    const input = e.input ?? {};
    const source = input.url ?? input.filePath ?? input.path;
    const instructions = /^skill$/i.test(e.tool ?? "") || (source && INSTRUCTION_FILE.test(source));  // skill passes {name}, no path
    const text = collectText(e.result.content ?? e.result.output);
    const r = await (instructions
      ? scanInstructionsCached({ text, source: source ?? input.name ?? e.tool })
      : scanContent({ text, tool: e.tool, source: preview(input, 120), task: readSession(e.sessionID).prompts.at(-1)?.text })
    ).catch(() => null);
    if (!r?.flagged) return;
    remember(e.sessionID, "flags", { kind: r.kind, source, tool: e.tool, p: +r.p.toFixed(2), excerpt: excerpt(text), reported: true });
    log(r.message);
    e.result.content = [{ type: "text", text: `[${r.message}]` }, ...(e.result.content ?? [])];
  });
}
