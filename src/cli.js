#!/usr/bin/env node
import { readFileSync, writeFileSync, mkdirSync, existsSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const [cmd, ...rest] = process.argv.slice(2);

const USAGE = `jev-guard — prompt-injection and dangerous-action guard for coding agents, powered by Jev

  jev-guard hook [--agent codex|copilot]  Command hook (JSON on stdin → JSON on stdout) for Claude Code, Codex, Copilot CLI,
                                          Gemini CLI and Cursor; the host is detected from the payload, --agent overrides
  jev-guard acp -- <agent command...>     ACP proxy: jev-guard acp -- claude-agent-acp
  jev-guard check <tool> '<json input>'   Assess one tool call, e.g. check Bash '{"command":"rm -rf /"}'
  jev-guard scan [file]                   Scan a file (or stdin) for AI-directed instructions
  jev-guard scan-skills [paths...]        Sweep skills, plugins, rules and CLAUDE.md/AGENTS.md files (default: every
                                          agent's user dirs + the current project) for instructions their installer
                                          would not expect; cached by content hash, exit 2 if anything is flagged
  jev-guard install <agent>               Register in that agent's user config:
                                          claude | codex | copilot | gemini | agy | cursor | pi | opencode
  jev-guard key <api key>                 Save the key to ~/.jev-guard/config.json (0600); vck_… keys are
                                          treated as Vercel AI Gateway keys, sk-or-… keys as OpenRouter,
                                          anything else as TypeSafe (--gateway / --openrouter override)

Credentials are read from JEV_API_KEY / AI_GATEWAY_API_KEY / VERCEL_OIDC_TOKEN first, then from that file, then
from OPENROUTER_API_KEY. JEV_BASE_URL points at any other System One server (e.g. a local Kev) and takes precedence.`;

switch (cmd) {
  case "hook": {
    const { main } = await import("./hook.js");
    await main(rest);
    break;
  }
  case "acp": {
    const args = rest[0] === "--" ? rest.slice(1) : rest;
    if (!args.length) die("acp needs an agent command after --");
    const { runProxy } = await import("./acp.js");
    runProxy(args[0], args.slice(1));
    break;
  }
  case "check": {
    const { assessAction } = await import("./guard.js");
    const r = await assessAction({ tool: rest[0], input: rest[1] ? JSON.parse(rest[1]) : {}, cwd: process.cwd() }).catch((e) => die(`${e.message} (exit 3)`, 3));
    console.log(r ? `${r.level.toUpperCase()}  ${r.message}` : "SKIPPED  read-only tool");
    process.exitCode = r?.level === "deny" ? 2 : r?.level === "ask" ? 1 : 0;
    break;
  }
  case "scan": {
    const { scanContent } = await import("./guard.js");
    const text = rest[0] ? readFileSync(rest[0], "utf8") : readFileSync(0, "utf8");
    const r = await scanContent({ text, tool: "scan", source: rest[0] }).catch((e) => die(`${e.message} (exit 3)`, 3));
    console.log(r ? `${r.flagged ? "FLAGGED" : "CLEAN"}  ${r.message}` : "SKIPPED  too short to scan");
    process.exitCode = r?.flagged ? 2 : 0;
    break;
  }
  case "scan-skills": {
    const { findInstructionFiles, projectRoots, scanFiles, userRoots } = await import("./skills.js");
    const roots = rest.length ? rest.map((r) => resolve(r)) : [...userRoots(), ...projectRoots()];
    const files = findInstructionFiles(roots);
    if (!files.length) { console.log("jev-guard: no instruction files found"); break; }
    process.stderr.write(`jev-guard: scanning ${files.length} instruction files…\n`);
    const results = await scanFiles(files);
    const flagged = results.filter((r) => r.flagged), errors = results.filter((r) => r.error);
    for (const r of flagged) console.log(`FLAGGED  ${r.file}\n         ${r.kind.replace("_", " ")} p=${r.p}${r.cached ? " (cached)" : ""}`);
    for (const r of errors) console.log(`ERROR    ${r.file}: ${r.error}`);
    console.log(`${results.length} scanned (${results.filter((r) => r.cached).length} cached), ${flagged.length} flagged, ${errors.length} errors`);
    process.exitCode = flagged.length ? 2 : errors.length ? 3 : 0;
    break;
  }
  case "install":
    install(rest[0]);
    break;
  case "key": {
    const { CONFIG_FILE, readConfig } = await import("./jev.js");
    const key = rest.find((a) => !a.startsWith("--"));
    if (!key) die("key needs the API key as an argument");
    const kind = rest.includes("--gateway") || key.startsWith("vck_") ? "gateway"
      : rest.includes("--openrouter") || key.startsWith("sk-or-") ? "openrouter" : "typesafe";
    const field = { gateway: "aiGatewayApiKey", openrouter: "openRouterApiKey", typesafe: "jevApiKey" }[kind];
    const cfg = { ...readConfig(), [field]: key };
    mkdirSync(dirname(CONFIG_FILE), { recursive: true, mode: 0o700 });
    writeFileSync(CONFIG_FILE, JSON.stringify(cfg, null, 2) + "\n", { mode: 0o600 });
    const label = { gateway: "Vercel AI Gateway", openrouter: "OpenRouter", typesafe: "TypeSafe" }[kind];
    console.log(`jev-guard: ${label} key saved to ${CONFIG_FILE}`);
    break;
  }
  default:
    console.log(USAGE);
    process.exitCode = cmd ? 1 : 0;
}

function install(target) {
  if (ROOT.includes("/_npx/") || ROOT.includes("\\_npx\\")) die("running from the npx cache, which gets pruned; install with `npm i -g jev-guard` (or git clone) and run install from there");
  const cli = join(ROOT, "src", "cli.js");
  // Absolute node path: GUI hosts (Cursor, Zed) launched from a Dock don't have nvm/volta on PATH.
  const cmd = (extra = "") => `"${process.execPath}" "${cli}" hook${extra}`;
  const notOurs = (list) => (list ?? []).filter((g) => !JSON.stringify(g).includes("jev-guard"));
  const home = homedir();
  let file, cfg, note = "";
  switch (target) {
    case "claude":
    case "codex": {  // same group shape; Codex has no PreToolUse "ask" yet, so the flag switches ask → warning
      file = target === "claude" ? join(home, ".claude", "settings.json") : join(home, ".codex", "hooks.json");
      cfg = readJson(file);
      cfg.hooks ??= {};
      const entry = { matcher: ".*", hooks: [{ type: "command", command: cmd(target === "codex" ? " --agent codex" : ""), timeout: 30 }] };
      const events = ["PreToolUse", "PostToolUse", "UserPromptSubmit", "SessionStart", ...(target === "claude" ? ["InstructionsLoaded"] : [])];
      for (const ev of events) cfg.hooks[ev] = [...notOurs(cfg.hooks[ev]), entry];
      if (target === "codex") note = "Run /hooks inside Codex to trust them.";
      break;
    }
    case "copilot": {  // PascalCase event names give the Claude-shaped payload; output fields are top-level
      file = join(home, ".copilot", "hooks", "jev-guard.json");
      cfg = { version: 1, hooks: {} };
      for (const ev of ["PreToolUse", "PostToolUse", "UserPromptSubmit", "SessionStart"]) cfg.hooks[ev] = [{ type: "command", bash: cmd(" --agent copilot"), timeoutSec: 30 }];
      break;
    }
    case "gemini": {
      file = join(home, ".gemini", "settings.json");
      cfg = readJson(file);
      cfg.hooks ??= {};
      const entry = { hooks: [{ name: "jev-guard", type: "command", command: cmd(), timeout: 30_000 }] };
      for (const ev of ["BeforeTool", "AfterTool", "BeforeAgent", "SessionStart"]) cfg.hooks[ev] = [...notOurs(cfg.hooks[ev]), entry];
      break;
    }
    case "agy":
    case "antigravity": {
      file = join(home, ".gemini", "config", "hooks.json");
      cfg = readJson(file);
      cfg["jev-guard"] = {
        ...Object.fromEntries(Object.entries(cfg["jev-guard"] ?? {}).filter(([ev]) => !["PreToolUse", "PostToolUse", "PreInvocation"].includes(ev))),
        PreToolUse: [
          {
            matcher: "*",
            hooks: [{ type: "command", command: cmd(" --agent agy --event PreToolUse"), timeout: 30 }]
          }
        ],
        PostToolUse: [
          {
            matcher: "*",
            hooks: [{ type: "command", command: cmd(" --agent agy --event PostToolUse"), timeout: 30 }]
          }
        ],
        PreInvocation: [
          {
            type: "command",
            command: cmd(" --agent agy --event PreInvocation"),
            timeout: 30
          }
        ]
      };
      break;
    }
    case "cursor": {  // beforeShell/MCP enforce "ask"; preToolUse only for the remaining mutating tools
      file = join(home, ".cursor", "hooks.json");
      cfg = readJson(file);
      cfg.version ??= 1;
      cfg.hooks ??= {};
      const add = (ev, extra = {}) => (cfg.hooks[ev] = [...notOurs(cfg.hooks[ev]), { command: cmd(), timeout: 30, ...extra }]);
      add("beforeShellExecution"); add("beforeMCPExecution"); add("preToolUse", { matcher: "Write|Delete" }); add("postToolUse");
      add("beforeSubmitPrompt"); add("sessionStart");
      break;
    }
    case "pi": {
      file = join(home, ".pi", "agent", "settings.json");
      cfg = readJson(file);
      const ext = join(ROOT, "extensions", "jev-guard.ts");
      cfg.extensions = [...(cfg.extensions ?? []).filter((p) => !p.includes("jev-guard")), ext];
      break;
    }
    case "opencode": {  // local plugin files are loaded as-is, so the shim just re-exports from this checkout
      file = join(home, ".config", "opencode", "plugins", "jev-guard.js");
      mkdirSync(dirname(file), { recursive: true });
      writeFileSync(file, `export { JevGuard } from ${JSON.stringify(join(ROOT, "src", "opencode.js"))};\n`);
      note = 'For approval prompts, set "permission": { "bash": "ask" } in opencode.json; jev-guard then auto-approves the safe calls.';
      console.log(`jev-guard: plugin shim written to ${file}${note ? "\n" + note : ""}`);
      keyHint();
      return;
    }
    default:
      die("install target must be one of claude, codex, copilot, gemini, agy, cursor, pi, opencode (ACP is configured in the editor: see README)");
  }
  writeJson(file, cfg);
  console.log(`jev-guard: written to ${file}${note ? "\n" + note : ""}`);
  keyHint();
}

async function keyHint() {
  const { backend } = await import("./jev.js");
  if (!backend()) console.log("No API key found yet: run `jev-guard key <key>` (or export JEV_API_KEY / OPENROUTER_API_KEY / AI_GATEWAY_API_KEY, or JEV_BASE_URL for a local server). Until then the guard fails open.");
}

function readJson(file) { return existsSync(file) ? JSON.parse(readFileSync(file, "utf8")) : {}; }
function writeJson(file, obj) { mkdirSync(dirname(file), { recursive: true }); writeFileSync(file, JSON.stringify(obj, null, 2) + "\n"); }
function die(msg, code = 1) { console.error(`jev-guard: ${msg}${code === 1 ? `\n\n${USAGE}` : ""}`); process.exit(code); }
