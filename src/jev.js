// One fetch, four backends: any System One server at JEV_BASE_URL (e.g. a local Kev), TypeSafe's API, OpenRouter's
// System One endpoint (same request and response shape), or Vercel AI Gateway.
// Question ids are ours; types are TypeSafe's (noul / choice / score). Gateway calls noul "boolean".
const TYPESAFE_URL = "https://api.typesafe.ai/v1/systemone";
const OPENROUTER_URL = "https://openrouter.ai/api/v1/systemone";   // https://openrouter.ai/docs/guides/community/typesafe-sdk
const GATEWAY_URL = "https://ai-gateway.vercel.sh/v4/ai/evaluation-model";
const SYSTEMONE_PATH = "/v1/systemone";
const DEFAULT_MODEL = { custom: "jev-latest", typesafe: "jev-latest", openrouter: "jev-1.13", gateway: "typesafe-ai/jev" };
const LOOPBACK = new Set(["localhost", "[::1]"]);
// Plain http is fine where the traffic never leaves this machine or the private network: loopback and RFC 1918
// (e.g. a Kev in Docker at the bridge IP 172.17.0.1).
const LOCAL_NETS = new BlockList();
for (const [net, bits] of [["127.0.0.0", 8], ["10.0.0.0", 8], ["172.16.0.0", 12], ["192.168.0.0", 16]]) LOCAL_NETS.addSubnet(net, bits);
const isLocal = (host) => LOOPBACK.has(host) || (isIPv4(host) && LOCAL_NETS.check(host, "ipv4"));

import { readFileSync } from "node:fs";
import { BlockList, isIPv4 } from "node:net";
import { homedir } from "node:os";
import { join } from "node:path";

export const CONFIG_FILE = join(homedir(), ".jev-guard", "config.json");

// Env first (CLIs inherit the shell); then ~/.jev-guard/config.json written by `jev-guard key`, which is what
// GUI hosts such as Cursor or Zed need since they don't see your shell profile.
// JEV_BASE_URL wins: it is an explicit choice of server, and it only ever gets its own JEV_BASE_API_KEY (optional, since
// a local server usually needs none), never a TypeSafe, OpenRouter or gateway key meant for someone else.
export function backend(env = process.env) {
  if (env.JEV_BASE_URL) return { kind: "custom", key: env.JEV_BASE_API_KEY, url: systemOneUrl(env.JEV_BASE_URL) };
  if (env.JEV_API_KEY) return { kind: "typesafe", key: env.JEV_API_KEY };
  if (env.AI_GATEWAY_API_KEY) return { kind: "gateway", key: env.AI_GATEWAY_API_KEY, auth: "api-key" };
  if (env.VERCEL_OIDC_TOKEN) return { kind: "gateway", key: env.VERCEL_OIDC_TOKEN, auth: "oidc" };  // `vercel env pull`; expires in ~12h
  const cfg = readConfig(env);
  if (cfg.jevApiKey) return { kind: "typesafe", key: cfg.jevApiKey };
  if (cfg.openRouterApiKey) return { kind: "openrouter", key: cfg.openRouterApiKey };
  if (cfg.aiGatewayApiKey) return { kind: "gateway", key: cfg.aiGatewayApiKey, auth: "api-key" };
  // OPENROUTER_API_KEY is shared with many other tools, so it only applies when no Jev-specific key is configured.
  if (env.OPENROUTER_API_KEY) return { kind: "openrouter", key: env.OPENROUTER_API_KEY };
  return null;
}

/** `<base>/v1/systemone` for a System One server; https only, except plain http to this machine or a private address. */
export function systemOneUrl(base) {
  let u;
  try { u = new URL(base); } catch { throw new Error(`JEV_BASE_URL is not a URL: ${base}`); }
  if (u.protocol !== "https:" && !(u.protocol === "http:" && isLocal(u.hostname)))
    throw new Error(`JEV_BASE_URL must be https, or http on localhost or a private address: ${base}`);
  u.search = ""; u.hash = "";
  return u.href.replace(/\/+$/, "") + SYSTEMONE_PATH;
}

export function readConfig(env = process.env) {
  try { return JSON.parse(readFileSync(env.JEV_GUARD_CONFIG ?? CONFIG_FILE, "utf8")); } catch { return {}; }
}

/** @returns {Promise<Record<string, {p?: number, choice?: string, score?: number, probabilities?: Record<string, number>, confidence?: number}>>} */
export async function ask(state, questions, { env = process.env, fetchImpl = fetch, signal, timeoutMs } = {}) {
  const b = backend(env);
  if (!b) throw new Error("no credentials: run `jev-guard key <key>` or set JEV_API_KEY / OPENROUTER_API_KEY / AI_GATEWAY_API_KEY / JEV_BASE_URL");
  const gw = b.kind === "gateway";
  const q = gw ? mapValues(questions, (x) => (x.type === "noul" ? { ...x, type: "boolean" } : x)) : questions;
  // One budget for the whole call, retries included: every host kills a hook at ~30 s, and a hook that dies
  // never reaches the fail-closed branch. Default 20 s leaves room for process start-up.
  const budget = AbortSignal.timeout(timeoutMs ?? +(env.JEV_GUARD_TIMEOUT_MS || 20_000));
  const abort = signal ? AbortSignal.any([signal, budget]) : budget;
  const model = env.JEV_MODEL ?? DEFAULT_MODEL[b.kind];
  const url = { custom: b.url, typesafe: TYPESAFE_URL, openrouter: OPENROUTER_URL, gateway: GATEWAY_URL }[b.kind];
  const request = () => fetchImpl(url, {
    method: "POST",
    headers: gw
      ? { Authorization: `Bearer ${b.key}`, "Content-Type": "application/json", "ai-gateway-protocol-version": "0.0.1",
          "ai-gateway-auth-method": b.auth, "ai-evaluation-model-specification-version": "4", "ai-model-id": model }
      : { ...(b.key ? { Authorization: `Bearer ${b.key}` } : {}), "Content-Type": "application/json" },
    body: JSON.stringify(gw
      ? { state, questions: q, providerOptions: { gateway: { zeroDataRetention: true } } }
      : { state, model, questions: q }),
    signal: abort,
  });
  let res;
  for (let attempt = 0; ; attempt++) {
    try {
      res = await request();
      if (res.ok || (res.status !== 429 && res.status < 500) || attempt === 2) break;
      await res.text().catch(() => {});  // release the socket before retrying
    } catch (err) {
      if (abort.aborted || attempt === 2) throw err;  // network blips (ECONNRESET, DNS) retry; aborts and the last attempt don't
    }
    await sleep(600 * 2 ** attempt, abort);
  }
  if (!res.ok) throw new Error(`${b.kind} HTTP ${res.status}: ${(await res.text()).slice(0, 300)}`);
  const body = await res.json();
  const conf = body.providerMetadata?.typesafe?.confidence ?? {};
  return mapValues(body.answers, (a, id) => ({
    p: a.noul ?? a.probability, choice: a.choice, score: a.score, probabilities: a.probabilities,
    confidence: a.confidence ?? conf[id],
  }));
}

function sleep(ms, signal) {
  return new Promise((resolve, reject) => {
    if (signal.aborted) return reject(signal.reason);
    const t = setTimeout(() => { signal.removeEventListener("abort", onAbort); resolve(); }, ms);
    const onAbort = () => { clearTimeout(t); reject(signal.reason); };
    signal.addEventListener("abort", onAbort, { once: true });
  });
}

function mapValues(obj, fn) {
  return Object.fromEntries(Object.entries(obj).map(([k, v]) => [k, fn(v, k)]));
}
