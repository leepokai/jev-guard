#!/usr/bin/env node
import { randomBytes } from "node:crypto";
import { chmodSync, existsSync, lstatSync, mkdirSync, readFileSync, readlinkSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const [cmd, ...rest] = process.argv.slice(2);

// Model slug format: [org/]model[:variant] allowing alphanumeric, hyphens, underscores, dots;
// disallowing leading/trailing symbols in segments and directory traversal (..)
const MODEL_SEGMENT = "[a-zA-Z0-9](?:(?:[a-zA-Z0-9_-]|\\.(?!\\.))*[a-zA-Z0-9])?";
const MODEL_ID_REGEX = new RegExp(`^${MODEL_SEGMENT}(?:\\/${MODEL_SEGMENT})?(?::${MODEL_SEGMENT})*$`);

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
  jev-guard model [model_id]              View or set model in ~/.jev-guard/config.json
                                          (e.g. inception/mercury-decide:free on OpenRouter; --reset to clear)
  jev-guard backend [name]                View or set preferred backend (typesafe|openrouter|gateway|custom; --reset to clear)
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
    const { configFile } = await import("./jev.js");
    const file = configFile(process.env);
    const key = rest.find((a) => !a.startsWith("--"));
    if (!key) die("key needs the API key as an argument");
    const kind = rest.includes("--gateway") || key.startsWith("vck_") ? "gateway"
      : rest.includes("--openrouter") || key.startsWith("sk-or-") ? "openrouter" : "typesafe";
    const field = { gateway: "aiGatewayApiKey", openrouter: "openRouterApiKey", typesafe: "jevApiKey" }[kind];
    const cfg = { ...readJson(file), [field]: key };
    writeConfig(file, cfg);
    const label = { gateway: "Vercel AI Gateway", openrouter: "OpenRouter", typesafe: "TypeSafe" }[kind];
    console.log(`jev-guard: ${label} key saved to ${file}`);
    break;
  }
  case "model": {
    const { DEFAULT_MODEL, backend, configFile, readConfig } = await import("./jev.js");
    const file = configFile(process.env);
    const targetModel = rest[0];
    if (targetModel) {
      if (targetModel === "--reset" || targetModel === "default") {
        const cfg = { ...readJson(file) };
        delete cfg.model;
        delete cfg.models;
        writeConfig(file, cfg);
        console.log(`jev-guard: model reset to default in ${file}`);
      } else {
        if (targetModel.startsWith("-")) die(`unknown option: ${targetModel}`);
        if (!MODEL_ID_REGEX.test(targetModel) || targetModel.includes("..")) {
          die(`invalid model ID: ${targetModel}`);
        }
        const cfg = { ...readJson(file) };
        const { backend: b } = safeBackend(backend);
        const selectedKind = selectedBackendKind(cfg, process.env, b);
        if (selectedKind) {
          if (!Object.hasOwn(DEFAULT_MODEL, selectedKind)) {
            die(`unknown backend: ${selectedKind} (expected one of: ${Object.keys(DEFAULT_MODEL).join(", ")})`);
          }
          cfg.models = { ...(cfg.models ?? {}), [selectedKind]: targetModel };
        } else {
          cfg.model = targetModel;
        }
        writeConfig(file, cfg);
        console.log(`jev-guard: model set to ${targetModel} in ${file}`);
      }
      break;
    }
    const cfg = readConfig() ?? {};
    const { backend: b, error: backendErr } = safeBackend(backend);
    const selectedKind = selectedBackendKind(cfg, process.env, b);
    const validModel = (m) => (typeof m === "string" && m.trim() ? m.trim() : null);
    const activeKind = b?.kind ?? selectedKind;
    const defaultModel = (activeKind && Object.hasOwn(DEFAULT_MODEL, activeKind)) ? DEFAULT_MODEL[activeKind] : undefined;
    const scopedModel = (activeKind && Object.hasOwn(cfg.models ?? {}, activeKind)) ? validModel(cfg.models[activeKind]) : null;
    const fallbackModel = (activeKind === "typesafe" || activeKind === "gateway") ? null : validModel(cfg.model);
    const activeModel = validModel(process.env.JEV_MODEL)
      ?? scopedModel
      ?? fallbackModel
      ?? defaultModel
      ?? "none";
    const source = validModel(process.env.JEV_MODEL)
      ? "env JEV_MODEL"
      : scopedModel
        ? "config.json (backend-specific)"
        : fallbackModel
          ? "config.json"
          : defaultModel
            ? "default"
            : "none";
    console.log(source === "none" ? `Model: ${activeModel}` : `Model: ${activeModel} (${source})`);
    if (b) console.log(`Backend: ${b.kind}`);
    else if (backendErr && (backendErr.message.includes("is not a URL") || backendErr.message.includes("must be https") || (selectedKind && !Object.hasOwn(DEFAULT_MODEL, selectedKind)))) {
      console.log(`Backend: ${selectedKind || "invalid"} (${backendErr.message})`);
    }
    else if (selectedKind) console.log(`Backend: ${selectedKind} (no credentials configured)`);
    else console.log("Backend: none (no credentials configured)");
    break;
  }
  case "backend": {
    const { DEFAULT_MODEL, backend, configFile, readConfig, resolveBackend } = await import("./jev.js");
    const file = configFile(process.env);
    const targetBackend = rest[0];
    if (targetBackend) {
      const allowed = ["typesafe", "openrouter", "gateway", "custom"];
      if (targetBackend === "--reset" || targetBackend === "default") {
        const cfg = { ...readJson(file) };
        delete cfg.backend;
        writeConfig(file, cfg);
        console.log(`jev-guard: backend reset to default in ${file}`);
      } else {
        if (targetBackend.startsWith("-")) die(`unknown option: ${targetBackend}`);
        const normalized = targetBackend.toLowerCase();
        if (!allowed.includes(normalized)) {
          die(`unknown backend: ${targetBackend} (expected one of: ${allowed.join(", ")})`);
        }
        if (!resolveBackend(normalized)) {
          console.error(`jev-guard: no ${normalized} credentials configured yet; it will be used once configured`);
        }
        const cfg = { ...readJson(file), backend: normalized };
        writeConfig(file, cfg);
        console.log(`jev-guard: backend set to ${normalized} in ${file}`);
      }
      break;
    }
    const cfg = readConfig() ?? {};
    const { backend: b, error: backendErr } = safeBackend(backend);
    const selected = selectedBackendKind(cfg, process.env);
    const source = process.env.JEV_BACKEND ? "env JEV_BACKEND"
      : process.env.JEV_BASE_URL ? "env JEV_BASE_URL"
      : cfg.backend ? "config.json"
      : cfg.jevBaseUrl ? "config.json (jevBaseUrl)"
      : "auto-detected";
    if (b) console.log(`Backend: ${b.kind} (${source})`);
    else if (backendErr && (backendErr.message.includes("is not a URL") || backendErr.message.includes("must be https") || (selected && !Object.hasOwn(DEFAULT_MODEL, selected)))) {
      console.log(`Backend: ${selected || "invalid"} (${source}; ${backendErr.message})`);
    }
    else if (selected) console.log(`Backend: ${selected} (${source}; no credentials configured)`);
    else console.log("Backend: none (no credentials configured)");
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

function safeBackend(backendFn, env = process.env) {
  try {
    return { backend: backendFn(env), error: null };
  } catch (err) {
    if (process.env.DEBUG) console.warn(`jev-guard: backend resolution failed: ${err.message}`);
    return { backend: null, error: err };
  }
}

async function keyHint() {
  const { backend } = await import("./jev.js");
  const { backend: b } = safeBackend(backend);
  if (!b) console.log("No API key found yet: run `jev-guard key <key>` (or export JEV_API_KEY / OPENROUTER_API_KEY / AI_GATEWAY_API_KEY, or JEV_BASE_URL for a local server). Until then the guard fails open.");
}

/**
 * Resolves the selected backend kind from env, config, or active backend in priority order.
 * @param {Object} cfg - Parsed config object
 * @param {NodeJS.ProcessEnv} env - Environment variables
 * @param {Object} [b] - Resolved backend object if already determined
 * @returns {string|undefined} Normalized backend kind in lowercase, or undefined
 */
function selectedBackendKind(cfg = {}, env = process.env, b) {
  let raw;
  if (env.JEV_BACKEND) raw = env.JEV_BACKEND;
  else if (env.JEV_BASE_URL) raw = "custom";
  else if (cfg.backend) raw = cfg.backend;
  else if (cfg.jevBaseUrl) raw = "custom";
  else if (b?.kind) raw = b.kind;
  return raw ? String(raw).toLowerCase() : undefined;
}

/**
 * Resolves the ultimate target path of a symbolic link chain, preserving dangling targets.
 * Tracks visited paths to detect cycles and throws an error if a cyclic link is encountered.
 * @param {string} file - Path to potentially symbolic link
 * @returns {string} Ultimate target file path
 */
function resolveSymlinkTarget(file) {
  let cur = file;
  const seen = new Set();
  while (true) {
    try {
      if (!lstatSync(cur).isSymbolicLink()) break;
    } catch (err) {
      if (err.code === "ENOENT") break;
      throw err;
    }
    if (seen.has(cur)) throw new Error(`symlink cycle detected resolving ${file}`);
    seen.add(cur);
    const link = readlinkSync(cur);
    cur = resolve(dirname(cur), link);
  }
  return cur;
}

/**
 * Atomically writes an object as JSON to file using a temporary file, rename, and 0600 mode.
 * Preserves symbolic link destinations and cleans up temporary file if write or rename fails.
 * Atomic replacement guarantees file integrity; concurrent writes follow last-write-wins semantics.
 * Designed for single-user interactive CLI operations; concurrent multi-process environments
 * should use environment variables (e.g. JEV_BACKEND, JEV_MODEL) instead of mutating config.json.
 * @param {string} file - Destination file path
 * @param {Object} obj - Object to serialize as JSON
 */
function writeConfig(file, obj) {
  const target = resolveSymlinkTarget(file);
  mkdirSync(dirname(target), { recursive: true, mode: 0o700 });
  const tmp = `${target}.tmp.${randomBytes(16).toString("hex")}`;
  try {
    writeFileSync(tmp, JSON.stringify(obj, null, 2) + "\n", { mode: 0o600 });
    if (process.platform === "win32") {
      // Windows NTFS does not support POSIX permission bits; writeFileSync enforces initial creation attributes
    } else {
      try {
        chmodSync(tmp, 0o600);
      } catch (err) {
        if (err.code === "ENOSYS") {
          if (process.env.DEBUG) console.warn(`jev-guard: chmod unsupported on filesystem for ${tmp}`);
        } else {
          throw new Error(`failed to set permissions on ${tmp}: ${err.message}`);
        }
      }
    }
    renameSync(tmp, target);
  } finally {
    try { if (existsSync(tmp)) unlinkSync(tmp); } catch {}
  }
}

/**
 * Reads and parses a JSON file, returning an empty object only when the file is absent.
 * Propagates read and parse errors so corrupted or unreadable files are not overwritten.
 * @param {string} file - Path to JSON file
 * @returns {Object} Parsed JSON content or empty object if nonexistent
 */
function readJson(file) {
  if (!existsSync(file)) return {};
  return JSON.parse(readFileSync(file, "utf8"));
}
function writeJson(file, obj) { mkdirSync(dirname(file), { recursive: true }); writeFileSync(file, JSON.stringify(obj, null, 2) + "\n"); }
function die(msg, code = 1) { console.error(`jev-guard: ${msg}${code === 1 ? `\n\n${USAGE}` : ""}`); process.exit(code); }
