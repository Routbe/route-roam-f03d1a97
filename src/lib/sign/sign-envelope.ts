/**
 * ROUT Sign document envelope "RSG1": AES-256-GCM under a fresh 32-byte document key that only
 * travels in the link fragment (#k=…), so Neon and the server at rest hold ciphertext only.
 * The plaintext is length-prefixed and zero-padded to 64 KiB buckets so the stored size does not
 * reveal the exact PDF size; the AAD binds the copy role (original | signed).
 * Runs inside the crypto worker (sign.seal / sign.open) and in server-only signing handlers.
 */
export const SIGN_MAGIC = "RSG1";
export const SIGN_BUCKET = 64 * 1024;
export const SIGN_MAX_PLAINTEXT = 12 * 1024 * 1024;
export type SignRole = "original" | "signed";

export class SignEnvelopeError extends Error {}

const aad = (role: SignRole) => new TextEncoder().encode(`rout.sign.v1\u0000${role}`);

async function importKey(key: Uint8Array): Promise<CryptoKey> {
  if (key.length !== 32) throw new SignEnvelopeError("key");
  return crypto.subtle.importKey("raw", key as BufferSource, "AES-GCM", false, ["encrypt", "decrypt"]);
}

export function newDocumentKey(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32));
}

export async function sealDocument(key: Uint8Array, pdf: Uint8Array, role: SignRole): Promise<Uint8Array> {
  if (pdf.length === 0 || pdf.length > SIGN_MAX_PLAINTEXT) throw new SignEnvelopeError("size");
  const padded = new Uint8Array(Math.ceil((pdf.length + 4) / SIGN_BUCKET) * SIGN_BUCKET);
  try {
    new DataView(padded.buffer).setUint32(0, pdf.length);
    padded.set(pdf, 4);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: aad(role) }, await importKey(key), padded));
    const out = new Uint8Array(4 + 12 + ct.length);
    out.set(new TextEncoder().encode(SIGN_MAGIC), 0);
    out.set(iv, 4);
    out.set(ct, 16);
    return out;
  } finally {
    padded.fill(0);
  }
}

export async function openDocument(key: Uint8Array, envelope: Uint8Array, role: SignRole): Promise<Uint8Array> {
  if (envelope.length < 16 + 16 + 4 || new TextDecoder().decode(envelope.subarray(0, 4)) !== SIGN_MAGIC) {
    throw new SignEnvelopeError("format");
  }
  let padded: Uint8Array;
  try {
    padded = new Uint8Array(
      await crypto.subtle.decrypt({ name: "AES-GCM", iv: envelope.subarray(4, 16) as BufferSource, additionalData: aad(role) }, await importKey(key), envelope.subarray(16) as BufferSource),
    );
  } catch {
    throw new SignEnvelopeError("decrypt");
  }
  try {
    const n = new DataView(padded.buffer).getUint32(0);
    if (n === 0 || n > padded.length - 4) throw new SignEnvelopeError("format");
    return padded.slice(4, 4 + n);
  } finally {
    padded.fill(0);
  }
}

const B64 = /^[A-Za-z0-9_-]{43}$/;
export function keyToFragment(key: Uint8Array): string {
  let s = "";
  for (const b of key) s += String.fromCharCode(b);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
export function keyFromFragment(hash: string): Uint8Array | null {
  const m = /(?:^#|&|^)k=([A-Za-z0-9_-]+)/.exec(hash);
  if (!m || !B64.test(m[1]!)) return null;
  const bin = atob(m[1]!.replace(/-/g, "+").replace(/_/g, "/") + "=");
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}
