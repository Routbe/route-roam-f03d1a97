/**
 * ROUT Sign rules (pure). Phase 1 per the owner's decision of 2026-11-17: sanitized viewing,
 * mandatory read inspection and a passkey-confirmed signature record; no PAdES / qualified
 * signature yet, and nothing may claim one.
 */
import { blake3 } from "@noble/hashes/blake3.js";

export const SIGN_MIN_READ = { min: 10, max: 600, default: 30 } as const;
export const SIGN_DAYS = { min: 1, max: 30, default: 7 } as const;
export const HEX64 = /^[0-9a-f]{64}$/;

/** The signature button activates only after the full document was scrolled and the read time passed. */
export function maySign(input: { elapsedSeconds: number; minReadSeconds: number; scrolledToEnd: boolean; pageCount: number }): boolean {
  return input.pageCount > 0 && input.scrolledToEnd && input.elapsedSeconds >= input.minReadSeconds;
}

/**
 * Signer binding: ties the member's universal nullifier, this request and the sanitized PDF's
 * digest together, domain-separated. It proves one verified person signed this exact document
 * without revealing who to anyone who lacks the nullifier.
 */
export function signerBinding(universalNullifier: string, requestId: string, digest: string): string {
  if (!HEX64.test(universalNullifier) || !HEX64.test(digest) || !/^[0-9a-f-]{36}$/.test(requestId)) {
    throw new Error("sign_binding_input");
  }
  const msg = new TextEncoder().encode(`rout.sign.binding.v1\u0000${universalNullifier}\u0000${requestId}\u0000${digest}`);
  return [...blake3(msg)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

export type SignStatus = "open" | "signed" | "expired" | "revoked";
