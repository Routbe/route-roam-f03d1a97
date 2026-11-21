/**
 * ROUT Sign, server side (server-only). The server and Neon only ever handle RSG1 ciphertext,
 * hashes and the signer binding: the document key stays in the link fragment and the browser's
 * crypto worker. Every call runs in the member's own database context through the 0290 definers;
 * before 0290 is live, ROUT Sign answers "unavailable".
 */
import { signerBinding, type SignStatus } from "./sign-rules";

export type SignRequestView = {
  envelope: Uint8Array;
  sourceSha256: string;
  status: SignStatus;
  expiresAt: string;
  minReadSeconds: number;
  isOwner: boolean;
  isSigner: boolean;
  signedEnvelope: Uint8Array | null;
  signedAt: string | null;
  /** Hybrid Ed25519 + ML-DSA-65 attestation over the signed record (null before signing or without a master key). */
  pqAttestation: import("@/lib/crypto/pq-purposes").PqAttestation | null;
};
export type SignRequestSummary = { id: string; status: SignStatus; createdAt: string; expiresAt: string; signedAt: string | null; sizeBytes: number };

export class SignError extends Error {}

async function ready(): Promise<void> {
  const { hasSchemaFeature } = await import("@/lib/schema-features.server");
  if (!(await hasSchemaFeature("0290"))) throw new SignError("unavailable");
}

async function asMember<T>(userId: string, run: (sql: typeof import("@/lib/neon").sql) => Promise<T>): Promise<T> {
  await ready();
  const { sql, withDbContext } = await import("@/lib/neon");
  return withDbContext({ userId, workspaceId: null }, () => run(sql));
}

const iso = (v: unknown) => (v instanceof Date ? v.toISOString() : v == null ? null : String(v));
const u8 = (v: unknown) => (v instanceof Uint8Array ? new Uint8Array(v) : null);

export async function createSignRequest(userId: string, envelope: Uint8Array, days: number, minRead: number): Promise<string> {
  const id = await asMember(userId, async (sql) => {
    const rows = (await sql`select public.rout_sign_request_create(${Buffer.from(envelope)}, ${days}::int, ${minRead}::int) as id`) as { id: string | null }[];
    return rows[0]?.id ?? null;
  });
  if (!id) throw new SignError("rejected");
  return id;
}

export async function openSignRequest(userId: string, id: string): Promise<SignRequestView | null> {
  const row = await asMember(userId, async (sql) =>
    ((await sql`select * from public.rout_sign_request_open(${id}::uuid)`) as Record<string, unknown>[])[0],
  );
  if (!row) return null;
  const status = String(row["status"]) as SignStatus;
  const sourceSha256 = String(row["ciphertext_sha256"]);
  const signedEnvelope = u8(row["signed_ciphertext"]);
  const signedAt = iso(row["signed_at"]);
  return {
    envelope: u8(row["ciphertext"]) ?? new Uint8Array(),
    sourceSha256,
    status,
    expiresAt: iso(row["expires_at"]) ?? "",
    minReadSeconds: Number(row["min_read_seconds"]),
    isOwner: row["is_owner"] === true,
    isSigner: row["is_signer"] === true,
    signedEnvelope,
    signedAt,
    pqAttestation: status === "signed" && signedEnvelope && signedAt ? await attestSigned(id, sourceSha256, signedEnvelope, signedAt) : null,
  };
}

/** Lines of the hybrid Sign attestation; the browser rebuilds them from what it received. */
export const signAttestationLines = (id: string, sourceSha256: string, signedSha256: string, signedAt: string) => [id, sourceSha256, signedSha256, signedAt];

async function attestSigned(id: string, sourceSha256: string, signedEnvelope: Uint8Array, signedAt: string) {
  try {
    const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", signedEnvelope as BufferSource));
    const signedSha256 = Array.from(digest, (b) => b.toString(16).padStart(2, "0")).join("");
    const { signPq } = await import("@/lib/crypto/hybrid-signer.server");
    return await signPq("sign", signAttestationLines(id, sourceSha256, signedSha256, signedAt));
  } catch {
    return null;
  }
}

export async function listMySignRequests(userId: string): Promise<SignRequestSummary[]> {
  const rows = await asMember(userId, async (sql) => (await sql`select * from public.rout_sign_requests_mine()`) as Record<string, unknown>[]);
  return rows.map((r) => ({
    id: String(r["id"]),
    status: String(r["status"]) as SignStatus,
    createdAt: iso(r["created_at"]) ?? "",
    expiresAt: iso(r["expires_at"]) ?? "",
    signedAt: iso(r["signed_at"]),
    sizeBytes: Number(r["size_bytes"]),
  }));
}

export async function revokeSignRequest(userId: string, id: string): Promise<boolean> {
  const r = await asMember(userId, async (sql) => ((await sql`select public.rout_sign_request_revoke(${id}::uuid) as r`) as { r: string }[])[0]?.r);
  return r === "ok";
}

/**
 * Records the passkey-confirmed signature (the caller already passed Sudo Mode). The binding is
 * computed here from the member's own universal nullifier, which never leaves this function.
 */
export type SignOutcome = "ok" | "no_legal_identity" | "not_found" | "not_open" | "expired" | "source_changed" | "invalid_input";

export async function recordSignature(
  userId: string,
  input: { id: string; sourceSha256: string; digest: string; signedEnvelope: Uint8Array },
): Promise<SignOutcome> {
  return asMember(userId, async (sql): Promise<SignOutcome> => {
    const claims = ((await sql`select has_legal_identity, root_nullifier from public.rout_my_identity_claims()`) as Record<string, unknown>[])[0];
    const nullifier = claims?.["root_nullifier"];
    if (claims?.["has_legal_identity"] !== true || typeof nullifier !== "string") return "no_legal_identity" as const;
    const binding = signerBinding(nullifier, input.id, input.digest);
    const rows = (await sql`select public.rout_sign_request_mark_signed(${input.id}::uuid, ${input.sourceSha256}, ${binding}, ${input.digest}, ${Buffer.from(input.signedEnvelope)}) as r`) as { r: string }[];
    return (rows[0]?.r ?? "invalid_input") as SignOutcome;
  });
}

/** Whether this member may sign (KYC legal identity); false before 0290. */
export async function signReadiness(userId: string): Promise<{ available: boolean; legalIdentity: boolean }> {
  try {
    const legal = await asMember(userId, async (sql) =>
      ((await sql`select has_legal_identity from public.rout_my_identity_claims()`) as { has_legal_identity: boolean }[])[0]?.has_legal_identity === true,
    );
    return { available: true, legalIdentity: legal };
  } catch (e) {
    if (e instanceof SignError) return { available: false, legalIdentity: false };
    throw e;
  }
}
