import { DualLayerReplayGuard, JtiReplayCache, ReplayStoreUnavailable } from "@/lib/eudi/dpop";
import { agentError } from "./responses";
import { candidateHtus, verifySandboxDpop, type SandboxDpopResult } from "./sandbox-dpop";
import { SANDBOX_DPOP_ALGS } from "./agent-protocol";

/**
 * Shared layer of the sandbox DPoP replay guard: public.dpop_jti_replays
 * (db/0295) claimed on the database clock, so a proof used on one server
 * instance is refused on every other. Without 0295 every proof is refused.
 */
async function claimSharedJti(jtiHash: string, holdSeconds: number): Promise<boolean> {
  const { hasSchemaFeature } = await import("@/lib/schema-features.server");
  if (!(await hasSchemaFeature("0295"))) throw new ReplayStoreUnavailable("0295 missing");
  const { sql } = await import("@/lib/neon");
  const rows = (await sql`select public.rout_dpop_jti_claim(${jtiHash}, ${holdSeconds}) as ok`) as { ok: boolean }[];
  return rows[0]?.ok === true;
}

const replay = new DualLayerReplayGuard(new JtiReplayCache(), claimSharedJti);

/** Checks the request's DPoP header; `accessToken` is the presented rsk_ key (absent at registration). */
export async function sandboxDpop(request: Request, accessToken?: string): Promise<SandboxDpopResult> {
  const { publicOrigin } = await import("./agent-auth.server");
  return verifySandboxDpop({
    header: request.headers.get("dpop"),
    method: request.method,
    htus: candidateHtus(request.url, publicOrigin(request)),
    now: Date.now(),
    replay,
    accessToken,
  });
}

export function dpopFailure(result: Extract<SandboxDpopResult, { ok: false }>): Response {
  if (result.error === "replay_store_unavailable") return agentError(503, "server_error", "Proof checking is not available right now. Retry shortly.");
  const res = agentError(
    401,
    "invalid_token",
    "The DPoP proof is missing, malformed, stale, replayed, or does not match this method, URL or key. Send a fresh proof (new jti, iat now, ath = base64url(SHA-256(rsk_…))).",
  );
  res.headers.set("www-authenticate", `DPoP error="invalid_dpop_proof", algs="${SANDBOX_DPOP_ALGS.join(" ")}"`);
  return res;
}
