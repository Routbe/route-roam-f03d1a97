/**
 * AEAD for supporter credentials at rest: AES-256-GCM with a key HKDF'd from ROUT_VAULT_KEK
 * (info rout.support.credential.v1), bound to the donation id as additional data, so a
 * ciphertext moved to another row does not open. No KEK = nothing is stored.
 */
const enc = new TextEncoder();
const dec = new TextDecoder();
const b64 = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes));
const unb64 = (s: string) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));

export function credentialSealConfigured(): boolean {
  return (process.env["ROUT_VAULT_KEK"] ?? "").length >= 32;
}

async function key(): Promise<CryptoKey> {
  const kek = process.env["ROUT_VAULT_KEK"] ?? "";
  if (kek.length < 32) throw new Error("support_seal_unconfigured");
  const base = await crypto.subtle.importKey("raw", enc.encode(kek), "HKDF", false, ["deriveKey"]);
  return crypto.subtle.deriveKey(
    { name: "HKDF", hash: "SHA-256", salt: enc.encode("rout.support"), info: enc.encode("rout.support.credential.v1") },
    base,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"],
  );
}

const aadFor = (donationId: string) => enc.encode(`rout.support.credential|${donationId}`);

export async function sealCredential(donationId: string, plain: string): Promise<{ ciphertext: string; iv: string }> {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv, additionalData: aadFor(donationId) }, await key(), enc.encode(plain));
  return { ciphertext: b64(new Uint8Array(ct)), iv: b64(iv) };
}

export async function openCredential(donationId: string, ciphertext: string, iv: string): Promise<string> {
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: unb64(iv), additionalData: aadFor(donationId) }, await key(), unb64(ciphertext));
  return dec.decode(pt);
}
