# Security

jev-guard is a guardrail, not a sandbox. It sends tool calls and tool results to Jev (TypeSafe, or Vercel AI Gateway) and turns the answers into deny / ask / flag decisions. It fails **open** by default so an outage never freezes your agent; set `JEV_GUARD_FAIL_CLOSED=1` if you prefer the opposite. On OpenCode 2 that flag now denies an unassessable `ask`, `JEV_GUARD_ESCALATE_CLOSED=1` keeps the prompt but says the call was not judged, and with neither set the host's own prompt stands — the plugin can never allow on error.

Report a vulnerability privately through [GitHub security advisories](https://github.com/leepokai/jev-guard/security/advisories/new) rather than a public issue. Bypasses of the guard that come from a host's hook semantics (for example a tool path a host doesn't route through hooks) are worth reporting too; they belong in the README's limitations even when they can't be fixed here.
