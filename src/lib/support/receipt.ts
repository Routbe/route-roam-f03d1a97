/**
 * Signed donation receipt: a canonical JSON record (no names, e-mail or IBAN) signed with the
 * treasury's hybrid key (Ed25519 ‖ ML-DSA-65). The PDF is drawn from this record in the
 * browser and carries the record + signatures, so anyone can re-check it offline.
 * Not a tax certificate: ROUT is not an approved institution for Belgian tax deduction.
 */
import { sha256 } from "@noble/hashes/sha2.js";
import { domainMessage, RECEIPT_DOMAIN, type HybridSignature } from "./hybrid-signature";

export const RECEIPT_VERSION = "rout.support.receipt.v1";

export type SupportReceipt = {
  v: typeof RECEIPT_VERSION;
  id: string;
  rail: "sepa" | "stripe";
  confirmedVia: "bunq" | "stripe" | "manual";
  amountCents: number;
  currency: "EUR";
  paidAt: string;
  level: 1 | 2 | 3;
  supporterIndex: string | null;
  txHash: string;
  treeSize: string | null;
  treeRoot: string | null;
};
export type SignedReceipt = { receipt: SupportReceipt; signature: HybridSignature };

const KEYS: readonly (keyof SupportReceipt)[] = ["v", "id", "rail", "confirmedVia", "amountCents", "currency", "paidAt", "level", "supporterIndex", "txHash", "treeSize", "treeRoot"];

export function canonicalReceipt(r: SupportReceipt): string {
  return JSON.stringify(KEYS.map((k) => [k, r[k] ?? null]));
}
export const receiptMessage = (r: SupportReceipt) => domainMessage(RECEIPT_DOMAIN, [canonicalReceipt(r)]);

/** SHA-256 over provider, provider transaction id, amount and time; the raw id is not kept in the receipt. */
export function transactionHash(provider: string, providerTxId: string, amountCents: number, paidAt: string): string {
  const bytes = sha256(new TextEncoder().encode(`rout.support.tx.v1\n${provider}\n${providerTxId}\n${amountCents}\n${paidAt}`));
  return Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
}
