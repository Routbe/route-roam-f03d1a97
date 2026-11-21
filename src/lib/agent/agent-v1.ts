import { z } from "zod";
import { MAX_SANDBOX_APPS } from "./agent-protocol";
import { sandboxAppInput, sandboxProfileInput } from "./agent-sandbox";
import { SLUG_BASE_MAX } from "@/lib/workspace-slug-suffix";

/**
 * Versioned agent surface (/api/v1/agent/*): one stable contract on top of the
 * account-less sandbox engine (db/0202, 0213). Same storage, same invariants —
 * nothing is public before a human claims, OAuth clients get a secret only at
 * claim. Pure and browser-safe; the OpenAPI document is built from these schemas.
 */

export const AGENT_V1 = {
  create: "/api/v1/agent/workspace/create",
  studio: (workspaceId: string) => `/api/v1/agent/workspace/${workspaceId}/studio`,
  studioTemplate: "/api/v1/agent/workspace/{id}/studio",
  apps: "/api/v1/agent/developer/apps",
} as const;

/** `X-ROUT-Compute-Proof: <challenge>:<solution>` — exactly the string whose SHA-256 must start with difficulty_bits zero bits. */
export const COMPUTE_PROOF_HEADER = "x-rout-compute-proof";

const solution = z.string().regex(/^[0-9a-zA-Z]{1,64}$/);
const challenge = z.string().min(10).max(300);

export const agentWorkspaceCreateInput = z.strictObject({
  agent_name: z.string().trim().min(1).max(80).describe("Your name, e.g. \"Claude\"."),
  name: z.string().trim().min(1).max(120).describe("Display name of the workspace."),
  slug_base: z
    .string()
    .trim()
    .toLowerCase()
    .min(2)
    .max(SLUG_BASE_MAX)
    .regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/)
    .optional()
    .describe("Optional URL base; ROUT always appends a fresh 4-character Crockford base32 suffix (/w/<base>-<xxxx>). Derived from name when omitted."),
  description: z.string().trim().max(500).optional(),
  profile: sandboxProfileInput.optional().describe("Optional first Studio design (same shape as PATCH …/studio)."),
  apps: z.array(sandboxAppInput).max(MAX_SANDBOX_APPS).optional().describe("Optional Login-with-ROUT app specs; they become real OAuth clients for the human at claim."),
  challenge: challenge.optional().describe("Proof-of-work challenge (scope sandbox), if not sent as a header."),
  solution: solution.optional(),
});
export type AgentWorkspaceCreateInput = z.infer<typeof agentWorkspaceCreateInput>;

export type ComputeProof = { challenge: string; solution: string };
export type ComputeProofResult = { ok: true; proof: ComputeProof } | { ok: false; reason: "missing" | "malformed" | "ambiguous" };

/**
 * The proof can arrive as X-ROUT-Compute-Proof, as the X-ROUT-PoW-Challenge /
 * X-ROUT-PoW-Solution pair, or in the JSON body. Exactly one source is accepted:
 * two sources are refused rather than guessed between.
 */
export function readComputeProof(headers: Headers, body: { challenge?: string; solution?: string }): ComputeProofResult {
  const sources: ComputeProof[] = [];
  const combined = headers.get(COMPUTE_PROOF_HEADER)?.trim();
  if (combined) {
    const i = combined.lastIndexOf(":");
    if (i <= 0) return { ok: false, reason: "malformed" };
    sources.push({ challenge: combined.slice(0, i), solution: combined.slice(i + 1) });
  }
  const hc = headers.get("x-rout-pow-challenge")?.trim();
  const hs = headers.get("x-rout-pow-solution")?.trim();
  if (hc || hs) sources.push({ challenge: hc ?? "", solution: hs ?? "" });
  if (body.challenge !== undefined || body.solution !== undefined) sources.push({ challenge: body.challenge ?? "", solution: body.solution ?? "" });
  if (sources.length === 0) return { ok: false, reason: "missing" };
  if (sources.length > 1) return { ok: false, reason: "ambiguous" };
  const proof = sources[0]!;
  if (!challenge.safeParse(proof.challenge).success || !solution.safeParse(proof.solution).success) return { ok: false, reason: "malformed" };
  return { ok: true, proof };
}

export const WORKSPACE_ID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** A provisioning error that a fresh random suffix resolves. */
export function isSlugCollision(message: string): boolean {
  return message.includes("slug_taken") || message.includes("workspaces_slug_key");
}
