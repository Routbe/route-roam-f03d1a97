/**
 * bunq callback (NotificationFilterUrl, category PAYMENT): signature check and payment
 * extraction. bunq signs the raw body with RSA-SHA256 (PKCS#1 v1.5) under its server key and
 * sends it base64 in X-Bunq-Server-Signature; the key is the server_public_key returned at
 * installation (BUNQ_SERVER_PUBLIC_KEY). Payer name and IBAN are read nowhere and kept nowhere.
 */
import { createPublicKey, createVerify } from "crypto";
import { parseOgm } from "./ogm";

export function verifyBunqSignature(rawBody: string, signatureB64: string | null, serverPublicKeyPem: string): boolean {
  if (!signatureB64 || !serverPublicKeyPem) return false;
  try {
    const key = createPublicKey(serverPublicKeyPem.replace(/\\n/g, "\n"));
    const v = createVerify("RSA-SHA256");
    v.update(rawBody, "utf8");
    v.end();
    return v.verify(key, Buffer.from(signatureB64, "base64"));
  } catch {
    return false;
  }
}

export type BunqIncoming = { paymentId: string; amountCents: number; ogm: string | null };

/** Incoming EUR credit from a NotificationUrl body; null for anything else. */
export function parseBunqPayment(body: unknown): BunqIncoming | null {
  const object = (body as { NotificationUrl?: { category?: string; object?: { Payment?: Record<string, unknown> } } })?.NotificationUrl;
  if (!object || object.category !== "PAYMENT") return null;
  const payment = object.object?.Payment;
  if (!payment) return null;
  const amount = payment["amount"] as { value?: string; currency?: string } | undefined;
  if (!amount || amount.currency !== "EUR" || typeof amount.value !== "string" || !/^\d+(\.\d{1,2})?$/.test(amount.value)) return null;
  const [euros, cents = ""] = amount.value.split(".");
  const amountCents = Number(euros) * 100 + Number(cents.padEnd(2, "0"));
  if (!Number.isSafeInteger(amountCents) || amountCents <= 0) return null; // outgoing payments are negative
  const id = payment["id"];
  if (typeof id !== "number" && typeof id !== "string") return null;
  const description = typeof payment["description"] === "string" ? (payment["description"] as string) : "";
  return { paymentId: String(id), amountCents, ogm: parseOgm(description) };
}
