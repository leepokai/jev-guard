# Changelog

## Unreleased
- Files under `.claude/`, `.codex/`, `.gemini/` or `.cursor/` `docs/` and `reference/` count as instruction files (#1).
- OpenCode/Kilo: `skill` results are checked as instruction files, not as untrusted content (#2).
- `Task`/`Agent` results are scanned for injection; out-of-range thresholds fall back to their defaults (#3).
- `JEV_BASE_URL` accepts plain `http` on RFC 1918 private addresses (10/8, 172.16/12, 192.168/16) and all of 127/8, e.g. a Kev in Docker at 172.17.0.1 (#6).

## 0.3.1 — 2026-09-18
- Jev calls retry on 429/5xx *and* network errors inside one time budget (`JEV_GUARD_TIMEOUT_MS`, 20 s), so a hook never outlives its host's ~30 s timeout and fail-closed actually fails closed.
- Instruction-file scans share one content-hash cache across the session-start sweep, `InstructionsLoaded`, `Read`/`Skill` results and `scan-skills`; cache hits carry only Jev's answer and the verdict is rebuilt.
- An answer with no `kind` is treated as serious instead of crashing the message builder; `JEV_GUARD_SKILL_P` / `JEV_GUARD_SKILL_SERIOUS_P` documented.

## 0.3.0 — 2026-09-18
- Context: every decision now sees the user's recent prompts, the agent's stated intent, recent decisions and flagged content (`src/context.js`, `src/session.js`). Two new questions: `user_requested` (turns ask into allow when the user asked for exactly that) and `from_untrusted` (denies a call that carries out an instruction planted in something the agent read). Prompt hooks on every host feed the memory; pi, OpenCode and ACP read the session directly.
- Instruction files: skills, plugins, rules and `CLAUDE.md`/`AGENTS.md` are checked with their own questions (`INSTRUCTION_QUESTIONS`) at session start, on `InstructionsLoaded`, when a `Skill` runs, when the agent reads one, and via `jev-guard scan-skills`; results cached by content hash.
- Third-party skill/plugin/MCP installs count as level-2 (ask) actions. Instruction-file thresholds: `JEV_GUARD_SKILL_P` (0.8, unrelated side effects) and `JEV_GUARD_SKILL_SERIOUS_P` (0.45, the serious kinds); answers cached by content hash and shared by the sweep and the read/Skill hooks.
- OpenCode: expose `main` and `exports["./server"]`, which is what OpenCode's npm plugin loader resolves; `"plugin": ["jev-guard"]` now works from the registry.
- `check` / `scan` exit 3 with a one-line error instead of a stack trace when Jev is unreachable.

## 0.2.0 — 2026-09-17
- Adapters for Copilot CLI, Gemini CLI, Cursor and OpenCode; the hook script recognises each host's payload.
- Marketplace manifests: Claude Code (`.claude-plugin`), Codex (`.agents/plugins`), Copilot (Claude layout), Gemini (`gemini-extension.json`, asks for the key on install), Cursor (`.cursor-plugin`).
- `jev-guard key` stores the API key in `~/.jev-guard/config.json` for hosts that don't inherit a shell.
- `install` writes the absolute `node` path and refuses to run from the npx cache.
- Icon, works-with strip and launch video.

## 0.1.0 — 2026-09-17
- First release: PreToolUse risk Score + approval Noul (deny / ask / allow), PostToolUse injection / canary scan; Claude Code and Codex hooks, pi extension, ACP proxy; TypeSafe API or Vercel AI Gateway backend.
