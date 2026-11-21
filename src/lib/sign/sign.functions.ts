import { createServerFn } from "@tanstack/react-start";
import { z } from "zod";
import { requireAuth, requireSudo } from "@/lib/auth/middleware";
import { SIGN_DAYS, SIGN_MIN_READ } from "./sign-rules";

const id = z.string().uuid();
const hex64 = z.string().regex(/^[0-9a-f]{64}$/);
// RSG1 envelopes: 8 MiB sanitized PDF max, padded to 64 KiB buckets → base64 well under 12 M chars.
const envelopeB64 = z.string().min(88).max(12_000_000).regex(/^[A-Za-z0-9+/]+={0,2}$/);

function userError(e: unknown): never {
  const code = e instanceof Error ? e.message : "";
  if (code === "unavailable") throw new Error("ROUT Sign is nog niet beschikbaar op deze server.");
  if (code === "rejected") throw new Error("Dit document kon niet worden opgeslagen. Je hebt misschien al 20 open verzoeken.");
  console.error("[sign]", e);
  throw new Error("ROUT Sign kon dit niet verwerken.");
}

/** Owner: whether ROUT Sign runs here and whether this member may sign. */
export const getSignReadiness = createServerFn({ method: "GET" })
  .middleware([requireAuth])
  .handler(async ({ context }) => {
    const { signReadiness } = await import("./sign.server");
    return signReadiness(context.userId);
  });

/** Owner: stores a browser-sealed RSG1 envelope (the key never reaches the server). */
export const createSignRequestFn = createServerFn({ method: "POST" })
  .middleware([requireAuth])
  .inputValidator((d: unknown) =>
    z.object({
      envelope: envelopeB64,
      days: z.number().int().min(SIGN_DAYS.min).max(SIGN_DAYS.max),
      minReadSeconds: z.number().int().min(SIGN_MIN_READ.min).max(SIGN_MIN_READ.max),
    }).parse(d),
  )
  .handler(async ({ data, context }) => {
    const { createSignRequest } = await import("./sign.server");
    const { b64ToBytes } = await import("./b64");
    try {
      return { id: await createSignRequest(context.userId, b64ToBytes(data.envelope), data.days, data.minReadSeconds) };
    } catch (e) {
      userError(e);
    }
  });

/** Any signed-in member with the link: the sealed document (useless without the fragment key). */
export const openSignRequestFn = createServerFn({ method: "POST" })
  .middleware([requireAuth])
  .inputValidator((d: unknown) => z.object({ id }).parse(d))
  .handler(async ({ data, context }) => {
    const { openSignRequest } = await import("./sign.server");
    const { bytesToB64 } = await import("./b64");
    try {
      const v = await openSignRequest(context.userId, data.id);
      if (!v) return null;
      return {
        envelope: bytesToB64(v.envelope),
        sourceSha256: v.sourceSha256,
        status: v.status,
        expiresAt: v.expiresAt,
        minReadSeconds: v.minReadSeconds,
        isOwner: v.isOwner,
        isSigner: v.isSigner,
        signedEnvelope: v.signedEnvelope ? bytesToB64(v.signedEnvelope) : null,
        signedAt: v.signedAt,
        pqAttestation: v.pqAttestation,
      };
    } catch (e) {
      userError(e);
    }
  });

export const listMySignRequestsFn = createServerFn({ method: "GET" })
  .middleware([requireAuth])
  .handler(async ({ context }) => {
    const { listMySignRequests } = await import("./sign.server");
    try {
      return await listMySignRequests(context.userId);
    } catch (e) {
      userError(e);
    }
  });

export const revokeSignRequestFn = createServerFn({ method: "POST" })
  .middleware([requireAuth])
  .inputValidator((d: unknown) => z.object({ id }).parse(d))
  .handler(async ({ data, context }) => {
    const { revokeSignRequest } = await import("./sign.server");
    try {
      return { ok: await revokeSignRequest(context.userId, data.id) };
    } catch (e) {
      userError(e);
    }
  });

/**
 * Signer: records a passkey-confirmed signature (Sudo Mode, 300 s) over the sanitized PDF's digest,
 * for exactly the stored envelope. Not a PAdES / qualified signature (phase 1).
 */
export const signSignRequest = createServerFn({ method: "POST" })
  .middleware([requireAuth, requireSudo("document_sign")])
  .inputValidator((d: unknown) => z.object({ id, sourceSha256: hex64, digest: hex64, signedEnvelope: envelopeB64 }).parse(d))
  .handler(async ({ data, context }) => {
    const { recordSignature } = await import("./sign.server");
    const { b64ToBytes } = await import("./b64");
    try {
      return { result: await recordSignature(context.userId, { ...data, signedEnvelope: b64ToBytes(data.signedEnvelope) }) };
    } catch (e) {
      userError(e);
    }
  });
