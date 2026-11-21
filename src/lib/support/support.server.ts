/**
 * Server side of /support/donations: start a donation (SEPA with a Belgian structured
 * communication, or Stripe Checkout), confirm it from the bunq / Stripe webhooks, append the
 * Merkle leaf with a hybrid-signed root, issue the supporter SD-JWT VC and the signed receipt.
 * Everything database-side goes through the db/0293 definers; without 0293 the page shows
 * the ledger as empty and starting a donation answers `not_ready`.
 */
import { sql } from "@/lib/neon";
import { buildEpcPayload, isValidIban } from "@/lib/epc-qr";
import { formatOgm, generateOgm } from "./ogm";
import {
  fromHex, INCLUSION_PROOF_VERSION, leafCommitment, pathFor, randomNonce, siblingsFor, toHex,
  type InclusionProof, type LeafOpening, type NodeReader, type PrivacyLevel, type SignedTreeRoot,
} from "./treasury-tree";
import { treasuryRootMessage } from "./hybrid-signature";
import { RECEIPT_VERSION, receiptMessage, transactionHash, type SignedReceipt, type SupportReceipt } from "./receipt";
import { coverage, type Coverage } from "./coverage";

type Row = Record<string, unknown>;
export type Rail = "sepa" | "stripe";

export const SUPPORT_PRESETS_CENTS = [500, 1000, 2500, 5000, 10000] as const;
export const SUPPORT_MIN_CENTS = 100;
export const SUPPORT_MAX_CENTS = 500_000;

/** Whole euro cents inside the range; anything else is refused (the server decides the amount). */
export function resolveSupportAmount(requested: unknown): number | null {
  if (typeof requested !== "number" || !Number.isInteger(requested)) return null;
  return requested >= SUPPORT_MIN_CENTS && requested <= SUPPORT_MAX_CENTS ? requested : null;
}

export type TreasuryAccount = { iban: string; name: string; bic: string | null };

/** Beneficiary name when ROUT_TREASURY_NAME is not set (owner's choice, 2026-11-18). */
export const DEFAULT_TREASURY_NAME = "ROUT Sovereign Identity OS";

/** ROUT_TREASURY_IBAN / _NAME / _BIC from the server environment; null without a valid IBAN. */
export function treasuryAccountFromEnv(): TreasuryAccount | null {
  const iban = (process.env["ROUT_TREASURY_IBAN"] ?? "").replace(/\s+/g, "").toUpperCase();
  const name = (process.env["ROUT_TREASURY_NAME"] ?? "").trim() || DEFAULT_TREASURY_NAME;
  const bic = (process.env["ROUT_TREASURY_BIC"] ?? "").replace(/\s+/g, "").toUpperCase() || null;
  return iban && isValidIban(iban) ? { iban, name, bic } : null;
}

// bunq fallback, cached per worker: bunq rate-limits GETs, and a page view must not hit it each time.
const BUNQ_HIT_TTL_MS = 10 * 60_000;
const BUNQ_MISS_TTL_MS = 60_000;
let bunqTreasury: { at: number; account: TreasuryAccount | null } | null = null;
export function resetTreasuryCache(): void {
  bunqTreasury = null;
}

/**
 * Treasury account: the environment first; without ROUT_TREASURY_IBAN, the main EUR account
 * of the configured bunq user (BUNQ_API_KEY/_PRIVATE_KEY/_PUBLIC_KEY). The name stays
 * ROUT_TREASURY_NAME (default above) and the BIC only comes from ROUT_TREASURY_BIC.
 */
export async function treasuryAccount(): Promise<TreasuryAccount | null> {
  const fromEnv = treasuryAccountFromEnv();
  if (fromEnv) return fromEnv;
  const now = Date.now();
  if (bunqTreasury && now - bunqTreasury.at < (bunqTreasury.account ? BUNQ_HIT_TTL_MS : BUNQ_MISS_TTL_MS)) return bunqTreasury.account;
  let account: TreasuryAccount | null = null;
  try {
    const { bunqConfigured, listMonetaryAccounts, mainEurAccount } = await import("@/lib/bunq.server");
    if (bunqConfigured()) {
      const main = mainEurAccount(await listMonetaryAccounts());
      const iban = main?.iban?.replace(/\s+/g, "").toUpperCase() ?? "";
      if (iban && isValidIban(iban)) {
        const name = (process.env["ROUT_TREASURY_NAME"] ?? "").trim() || DEFAULT_TREASURY_NAME;
        const bic = (process.env["ROUT_TREASURY_BIC"] ?? "").replace(/\s+/g, "").toUpperCase() || null;
        account = { iban, name, bic };
      }
    }
  } catch (err) {
    console.error("[support] bunq treasury lookup failed", err instanceof Error ? err.message : "error");
  }
  bunqTreasury = { at: now, account };
  return account;
}

async function ready(): Promise<boolean> {
  const { hasSchemaFeature } = await import("@/lib/schema-features.server");
  return hasSchemaFeature("0293");
}

const hex = (bytes: Uint8Array) => Array.from(bytes, (b) => b.toString(16).padStart(2, "0")).join("");
async function sha256Hex(text: string): Promise<string> {
  return hex(new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text))));
}
const newToken = () => {
  const b = crypto.getRandomValues(new Uint8Array(32));
  return btoa(String.fromCharCode(...b)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};
const brusselsMonth = (d = new Date()) => {
  const parts = new Intl.DateTimeFormat("en-CA", { timeZone: "Europe/Brussels", year: "numeric", month: "2-digit" }).formatToParts(d);
  return `${parts.find((p) => p.type === "year")!.value}-${parts.find((p) => p.type === "month")!.value}`;
};

// ---------------------------------------------------------------- start

export type StartResult =
  | { ok: true; rail: "sepa"; id: string; token: string; ogm: string; ogmText: string; epc: string | null; account: TreasuryAccount; amountCents: number }
  | { ok: true; rail: "stripe"; id: string; token: string; url: string }
  | { ok: false; reason: "not_ready" | "invalid_amount" | "sign_in_required" | "sepa_not_configured" | "stripe_not_configured" | "failed" };

/** Runs inside the caller's DB context (rout.current_user_id) so level 1 binds the member. */
export async function startSupport(opts: { level: PrivacyLevel; rail: Rail; amountCents: number; signedIn: boolean; origin: string }): Promise<StartResult> {
  const amount = resolveSupportAmount(opts.amountCents);
  if (amount === null) return { ok: false, reason: "invalid_amount" };
  if (opts.level === 1 && !opts.signedIn) return { ok: false, reason: "sign_in_required" };
  const account = opts.rail === "sepa" ? await treasuryAccount() : null;
  if (opts.rail === "sepa" && !account) return { ok: false, reason: "sepa_not_configured" };
  const { stripeKey } = await import("@/lib/verification.server");
  const key = stripeKey();
  if (opts.rail === "stripe" && !key) return { ok: false, reason: "stripe_not_configured" };
  if (!(await ready())) return { ok: false, reason: "not_ready" };

  const token = newToken();
  const accessHash = await sha256Hex(token);
  let id: string | null = null;
  let ogm: string | null = null;
  for (let attempt = 0; attempt < 3 && !id; attempt++) {
    ogm = opts.rail === "sepa" ? generateOgm() : null;
    try {
      const rows = (await sql`select * from public.rout_support_create(${opts.level}::smallint, ${opts.rail}, ${amount}, ${ogm}, ${accessHash})`) as Row[];
      id = rows[0]?.["id"] ? String(rows[0]["id"]) : null;
      if (!id) return { ok: false, reason: opts.level === 1 ? "sign_in_required" : "failed" };
    } catch (error) {
      // A structured communication collision (unique) retries with a fresh one.
      if (!(error instanceof Error && /unique|duplicate/i.test(error.message)) || opts.rail !== "sepa") return { ok: false, reason: "failed" };
    }
  }
  if (!id) return { ok: false, reason: "failed" };

  if (opts.rail === "sepa" && account && ogm) {
    const ogmText = formatOgm(ogm);
    return {
      ok: true, rail: "sepa", id, token, ogm, ogmText, account, amountCents: amount,
      epc: buildEpcPayload({ beneficiary: account.name, iban: account.iban, bic: account.bic ?? undefined, amountCents: amount, reference: ogmText }),
    };
  }

  const origin = opts.origin.replace(/\/$/, "");
  const body = new URLSearchParams({
    mode: "payment",
    // The access token never travels in a URL: the page keeps it in sessionStorage.
    success_url: `${origin}/support/donations?d=${id}&status=success`,
    cancel_url: `${origin}/support/donations?d=${id}&status=cancel`,
    "line_items[0][quantity]": "1",
    "line_items[0][price_data][currency]": "eur",
    "line_items[0][price_data][unit_amount]": String(amount),
    "line_items[0][price_data][product_data][name]": "Steun ROUT",
    // iDEAL, Bancontact, Apple Pay, Google Pay and cards follow the methods enabled in the
    // Stripe dashboard (dynamic payment methods). No customer e-mail, no metadata about people.
    "metadata[kind]": "rout_support",
    "metadata[donation_id]": id,
    "payment_intent_data[metadata][kind]": "rout_support",
    "payment_intent_data[description]": "ROUT support",
  });
  try {
    const res = await fetch("https://api.stripe.com/v1/checkout/sessions", {
      method: "POST",
      headers: { Authorization: `Bearer ${key}`, "Content-Type": "application/x-www-form-urlencoded", "Idempotency-Key": `rout-support-${id}` },
      body,
    });
    const json = (await res.json()) as { id?: string; url?: string };
    if (!res.ok || !json.url || !json.id) return { ok: false, reason: "failed" };
    await sql`select public.rout_support_set_provider_ref(${id}::uuid, ${accessHash}, ${json.id})`;
    return { ok: true, rail: "stripe", id, token, url: json.url };
  } catch {
    return { ok: false, reason: "failed" };
  }
}

// ---------------------------------------------------------------- confirm

type Pending = { id: string; level: PrivacyLevel; rail: Rail; amountCents: number; attested: boolean; handle: string | null };

async function findPending(by: { ogm?: string; ref?: string }): Promise<Pending | null> {
  const rows = (await sql`select * from public.rout_support_pending(${by.ogm ?? null}, ${by.ref ?? null})`) as Row[];
  const r = rows[0];
  if (!r) return null;
  return {
    id: String(r["id"]), level: Number(r["privacy_level"]) as PrivacyLevel, rail: r["rail"] as Rail,
    amountCents: Number(r["amount_cents"]), attested: r["attested"] === true, handle: (r["handle"] as string | null) ?? null,
  };
}

async function treeSize(): Promise<bigint> {
  const rows = (await sql`select size from public.rout_public_treasury_summary()`) as Row[];
  return rows[0]?.["size"] == null ? 0n : BigInt(String(rows[0]["size"]));
}

async function siblingReader(index: bigint): Promise<NodeReader> {
  const rows = (await sql`select level, hash from public.rout_public_treasury_siblings(${index.toString()}::bigint)`) as Row[];
  const byLevel = new Map(rows.map((r) => [Number(r["level"]), fromHex(String(r["hash"]))]));
  return { get: (level, idx) => (idx === ((index >> BigInt(level)) ^ 1n) ? byLevel.get(level) : undefined) };
}

export type ConfirmOutcome = "ok" | "already_paid" | "unknown" | "amount_mismatch" | "not_configured" | "failed";

/** Mark paid, append the leaf, sign root + receipt, issue the credential. Idempotent per donation. */
export async function confirmDonation(pending: Pending, via: "bunq" | "stripe" | "manual", providerTxId: string, paidCents: number): Promise<ConfirmOutcome> {
  if (paidCents !== pending.amountCents) return "amount_mismatch";
  const { signHybrid, edSigner } = await import("./keys.server");
  const paidAt = new Date().toISOString();
  const opening: LeafOpening = { level: pending.level, attested: pending.attested, amountCents: pending.amountCents, month: brusselsMonth(), nonce: randomNonce() };
  const leaf = leafCommitment(opening);
  const txHash = transactionHash(via, providerTxId, paidCents, paidAt);

  for (let attempt = 0; attempt < 5; attempt++) {
    const index = await treeSize();
    const { nodes, root } = pathFor(index, leaf, siblingsFor(index, await siblingReader(index)));
    const size = (index + 1n).toString();
    const rootSig = await signHybrid(treasuryRootMessage(size, toHex(root)));
    if (!rootSig) return "not_configured";
    const receipt: SupportReceipt = {
      v: RECEIPT_VERSION, id: pending.id, rail: pending.rail, confirmedVia: via, amountCents: paidCents, currency: "EUR", paidAt,
      level: pending.level, supporterIndex: pending.level === 3 ? null : index.toString(), txHash, treeSize: size, treeRoot: toHex(root),
    };
    const receiptSig = await signHybrid(receiptMessage(receipt));
    if (!receiptSig) return "not_configured";
    const signed: SignedReceipt = { receipt, signature: receiptSig };
    const nodesJson = JSON.stringify(nodes.map((n) => ({ level: n.level, idx: n.idx.toString(), hash: toHex(n.hash) })));
    const rows = (await sql`
      select public.rout_support_mark_paid(${pending.id}::uuid, ${paidCents}, ${via}, ${txHash}, ${index.toString()}::bigint, ${toHex(leaf)},
        ${nodesJson}::jsonb, ${toHex(root)}, ${rootSig.kid}, ${rootSig.ed25519}, ${rootSig.mldsa65}, ${JSON.stringify(signed)}::jsonb) as r`) as Row[];
    const r = String(rows[0]?.["r"] ?? "failed");
    if (r === "retry") continue;
    if (r !== "ok") return r === "already_paid" || r === "unknown" || r === "amount_mismatch" ? r : "failed";

    if (pending.level !== 3) {
      const { credentialSealConfigured, sealCredential } = await import("./credential-seal.server");
      const signer = await edSigner();
      if (signer && credentialSealConfigured()) {
        const { issueSupporterVc, presentSupporterVc } = await import("./supporter-vc");
        const jti = newToken();
        const { sdJwt, exp } = await issueSupporterVc(
          {
            level: pending.level === 1 ? "public" : "pseudonymous",
            ...(pending.level === 1 && pending.handle ? { handle: `@${pending.handle}` } : {}),
            supporter_index: Number(index),
            since: opening.month,
            ...(pending.attested ? { verified_human: true } : {}),
          },
          signer,
          { jti },
        );
        const sealed = await sealCredential(pending.id, JSON.stringify({ sdJwt, opening }));
        const presentation = pending.level === 1 ? presentSupporterVc(sdJwt, ["level", "handle", "since"]) : null;
        await sql`select public.rout_support_store_credential(${pending.id}::uuid, ${await sha256Hex(jti)}, ${sealed.ciphertext}, ${sealed.iv},
          ${presentation}, ${new Date(exp * 1000).toISOString()}::timestamptz)`;
      }
    }
    return "ok";
  }
  return "failed";
}

export async function confirmByOgm(ogm: string, bunqPaymentId: string, paidCents: number): Promise<ConfirmOutcome> {
  if (!(await ready())) return "not_configured";
  const pending = await findPending({ ogm });
  return pending ? confirmDonation(pending, "bunq", bunqPaymentId, paidCents) : "unknown";
}

export async function confirmByStripeSession(sessionId: string, paymentIntent: string, paidCents: number): Promise<ConfirmOutcome> {
  if (!(await ready())) return "not_configured";
  const pending = await findPending({ ref: sessionId });
  return pending ? confirmDonation(pending, "stripe", paymentIntent || sessionId, paidCents) : "unknown";
}

// ---------------------------------------------------------------- read

async function signedRoot(): Promise<SignedTreeRoot | null> {
  const rows = (await sql`select * from public.rout_public_treasury_summary()`) as Row[];
  const r = rows[0];
  if (!r || r["size"] == null) return null;
  return { size: String(r["size"]), root: String(r["root"]), kid: String(r["kid"]), ed25519: String(r["sig_ed25519"]), mldsa65: (r["sig_mldsa65"] as string | null) ?? null };
}

async function inclusionProof(index: bigint, leafHex: string, opening: LeafOpening | null): Promise<InclusionProof | null> {
  const root = await signedRoot();
  if (!root) return null;
  const siblings = siblingsFor(index, await siblingReader(index));
  return { v: INCLUSION_PROOF_VERSION, index: index.toString(), leaf: leafHex, siblings: siblings.map(toHex), signedRoot: root, opening };
}

export type DonationView = {
  status: "pending" | "paid" | "failed" | "expired";
  level: PrivacyLevel;
  rail: Rail;
  amountCents: number;
  ogmText: string | null;
  epc: string | null;
  account: TreasuryAccount | null;
  receipt: SignedReceipt | null;
  credential: string | null;
  proof: InclusionProof | null;
};

async function credentialAndProof(id: string, level: PrivacyLevel, ct: unknown, iv: unknown, receipt: SignedReceipt | null) {
  if (typeof ct !== "string" || typeof iv !== "string") return { credential: null, proof: null };
  try {
    const { openCredential } = await import("./credential-seal.server");
    const { sdJwt, opening } = JSON.parse(await openCredential(id, ct, iv)) as { sdJwt: string; opening: LeafOpening };
    const index = receipt?.receipt.supporterIndex;
    const proof = level === 2 && index ? await inclusionProof(BigInt(index), toHex(leafCommitment(opening)), opening) : null;
    return { credential: sdJwt, proof };
  } catch {
    return { credential: null, proof: null };
  }
}

export async function readDonation(id: string, token: string): Promise<DonationView | null> {
  if (!(await ready())) return null;
  const rows = (await sql`select * from public.rout_support_by_access(${id}::uuid, ${await sha256Hex(token)})`) as Row[];
  const r = rows[0];
  if (!r) return null;
  const level = Number(r["privacy_level"]) as PrivacyLevel;
  const receipt = (r["receipt"] as SignedReceipt | null) ?? null;
  const ogm = (r["ogm"] as string | null) ?? null;
  const account = ogm ? await treasuryAccount() : null;
  const amountCents = Number(r["amount_cents"]);
  const { credential, proof } = await credentialAndProof(id, level, r["cred_ciphertext"], r["cred_iv"], receipt);
  return {
    status: r["status"] as DonationView["status"], level, rail: r["rail"] as Rail, amountCents,
    ogmText: ogm ? formatOgm(ogm) : null,
    epc: ogm && account ? buildEpcPayload({ beneficiary: account.name, iban: account.iban, bic: account.bic ?? undefined, amountCents, reference: formatOgm(ogm) }) : null,
    account: ogm ? account : null,
    receipt, credential, proof,
  };
}

export type MyDonation = { id: string; amountCents: number; status: string; rail: Rail; createdAt: string; receipt: SignedReceipt | null; credential: string | null };

/** Caller's level-1 donations (runs in the member's DB context). */
export async function readMyDonations(): Promise<MyDonation[]> {
  if (!(await ready())) return [];
  const rows = (await sql`select * from public.rout_support_mine()`) as Row[];
  const out: MyDonation[] = [];
  for (const r of rows) {
    const receipt = (r["receipt"] as SignedReceipt | null) ?? null;
    const { credential } = await credentialAndProof(String(r["id"]), 1, r["cred_ciphertext"], r["cred_iv"], receipt);
    out.push({ id: String(r["id"]), amountCents: Number(r["amount_cents"]), status: String(r["status"]), rail: r["rail"] as Rail, createdAt: new Date(String(r["created_at"])).toISOString(), receipt, credential });
  }
  return out;
}

export type LedgerEntry = { index: string | null; level: PrivacyLevel; handle: string | null; attested: boolean; amountCents: number; month: string };
export type SupportOverview = {
  ready: boolean;
  ledger: LedgerEntry[];
  monthCents: number;
  monthCount: number;
  totalCents: number;
  root: SignedTreeRoot | null;
  coverage: Coverage;
  sepa: boolean;
  stripe: boolean;
  publicKey: import("./hybrid-signature").HybridPublicKey | null;
};

export async function readOverview(): Promise<SupportOverview> {
  const { stripeKey } = await import("@/lib/verification.server");
  const { supportPublicKey } = await import("./keys.server");
  const base = { sepa: (await treasuryAccount()) !== null, stripe: Boolean(stripeKey()), publicKey: await supportPublicKey().catch(() => null) };
  const empty: SupportOverview = { ready: false, ledger: [], monthCents: 0, monthCount: 0, totalCents: 0, root: null, coverage: coverage(0), ...base };
  try {
    if (!(await ready())) return empty;
    const [ledgerRows, summaryRows] = await Promise.all([
      sql`select * from public.rout_public_treasury_ledger(50)` as Promise<Row[]>,
      sql`select * from public.rout_public_treasury_summary()` as Promise<Row[]>,
    ]);
    const s = summaryRows[0] ?? {};
    const monthCents = Number(s["month_cents"] ?? 0);
    return {
      ...base,
      ready: true,
      ledger: ledgerRows.map((r) => ({
        index: r["merkle_index"] == null ? null : String(r["merkle_index"]), level: Number(r["privacy_level"]) as PrivacyLevel,
        handle: (r["handle"] as string | null) ?? null, attested: r["attested"] === true, amountCents: Number(r["amount_cents"]), month: String(r["paid_month"]),
      })),
      monthCents,
      monthCount: Number(s["month_count"] ?? 0),
      totalCents: Number(s["total_cents"] ?? 0),
      root: s["size"] == null ? null : { size: String(s["size"]), root: String(s["root"]), kid: String(s["kid"]), ed25519: String(s["sig_ed25519"]), mldsa65: (s["sig_mldsa65"] as string | null) ?? null },
      coverage: coverage(monthCents),
    };
  } catch {
    return empty;
  }
}

export async function readSupporterPresentation(handle: string): Promise<string | null> {
  const clean = handle.replace(/^@+/, "").trim().toLowerCase();
  if (!/^[a-z0-9._-]{2,40}$/.test(clean)) return null;
  try {
    if (!(await ready())) return null;
    const rows = (await sql`select public.rout_public_supporter_presentation(${clean}) as p`) as Row[];
    return (rows[0]?.["p"] as string | null) ?? null;
  } catch {
    return null;
  }
}

/** Stripe events for support donations (metadata.kind = rout_support); null when not ours. */
export async function applySupportStripeEvent(event: { type?: string; data?: { object?: Record<string, unknown> } }): Promise<string | null> {
  const object = event.data?.object ?? {};
  const meta = (object["metadata"] ?? {}) as Record<string, string>;
  if (meta["kind"] !== "rout_support") return null;
  if (event.type !== "checkout.session.completed" && event.type !== "checkout.session.async_payment_succeeded") return "support event ignored";
  if (object["payment_status"] !== "paid") return "support awaiting payment";
  if (String(object["currency"] ?? "").toLowerCase() !== "eur") return "support currency rejected";
  const sessionId = typeof object["id"] === "string" ? object["id"] : "";
  const intent = typeof object["payment_intent"] === "string" ? object["payment_intent"] : "";
  const cents = Number(object["amount_total"]);
  if (!sessionId || !Number.isSafeInteger(cents)) return "support malformed";
  const outcome = await confirmByStripeSession(sessionId, intent, cents);
  if (outcome === "not_configured" || outcome === "failed") throw new Error(`support_${outcome}`);
  return `support ${outcome}`;
}
