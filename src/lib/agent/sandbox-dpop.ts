import { checkDpopProof, type ReplayGuard } from "@/lib/eudi/dpop";

/**
 * Optional RFC 9449 binding of sandbox keys. Pure apart from the injected
 * replay guard.
 *
 * A DPoP-registered sandbox is stored under SHA-256(rsk_… + "." + thumbprint),
 * the same construction as the OID4VCI access tokens (eudi/oid4vci.server.ts),
 * so no schema change is needed: presented as a Bearer token, or with a proof
 * from any other key, the hash is simply unknown to the database.
 */

export const boundKeyHashInput = (key: string, jkt: string) => `${key}.${jkt}`;

/** The URLs a client may have addressed (public origin first, then the origin the server saw). */
export function candidateHtus(requestUrl: string, publicOrigin: string): string[] {
  const url = new URL(requestUrl);
  return [...new Set([`${publicOrigin}${url.pathname}`, `${url.origin}${url.pathname}`])];
}

export type SandboxDpopResult = { ok: true; jkt: string } | { ok: false; error: "invalid_dpop_proof" | "replay_store_unavailable" };

/**
 * Verifies one DPoP proof: ES256 or Ed25519, htm/htu/iat (60 s), ath when a
 * sandbox key is presented, no server nonce, and a jti never seen before. An
 * htu mismatch is decided before the replay guard records anything, so trying
 * the next candidate URL can never spend a proof twice.
 */
export async function verifySandboxDpop(input: {
  header: string | null;
  method: string;
  htus: string[];
  now: number;
  replay: ReplayGuard;
  accessToken?: string;
}): Promise<SandboxDpopResult> {
  for (const htu of input.htus) {
    const r = await checkDpopProof(input.header, {
      method: input.method,
      htu,
      now: input.now,
      checkNonce: async (nonce) => nonce === undefined,
      replay: input.replay,
      accessToken: input.accessToken,
    });
    if (r.ok) return { ok: true, jkt: r.jkt };
    if (r.error === "replay_store_unavailable") return { ok: false, error: "replay_store_unavailable" };
  }
  return { ok: false, error: "invalid_dpop_proof" };
}
