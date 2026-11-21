/** Minor protection storage + parent mails (db/0174). Server-only. */
import { sql } from "@/lib/neon";
import { SITE_ORIGIN } from "@/lib/site";
import { escapeMailParam } from "@/lib/mail-param-escape";
import { isQaLevel, MINOR_AGE, PARENT_PAYMENT_HOURS, QA_LEVEL_LABELS, type QaLevel } from "./minor-safety";

type Row = Record<string, unknown>;

export function newParentToken(): string {
  const b = crypto.getRandomValues(new Uint8Array(32));
  return btoa(String.fromCharCode(...b)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export async function hashParentToken(token: string): Promise<string> {
  const d = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(token));
  return [...new Uint8Array(d)].map((x) => x.toString(16).padStart(2, "0")).join("");
}

export const isParentTokenShape = (t: string) => /^[A-Za-z0-9_-]{40,64}$/.test(t);

async function send(to: string, subject: string, html: string, tags: string[]) {
  try {
    const { sendMail } = await import("@/emails/send.server");
    const r = await sendMail({ to, subject, html, htmlFirst: true, tags });
    return r.sent;
  } catch (e) {
    console.warn("[minor-safety] mail failed", e instanceof Error ? e.message : e);
    return false;
  }
}

const shell = (body: string) => `<!doctype html><html lang="nl"><body style="margin:0;background:#ffffff;font-family:Arial,sans-serif;color:#111">
<div style="max-width:560px;margin:0 auto;padding:28px 24px">${body}
<p style="margin-top:32px;font-size:12px;color:#666">ROUT · rout.be — Je krijgt deze mail omdat iemand jouw adres opgaf als ouder of voogd.</p></div></body></html>`;
const button = (href: string, label: string) =>
  `<p><a href="${href}" style="display:inline-block;background:#111;color:#fff;padding:12px 20px;border-radius:8px;text-decoration:none;font-weight:bold">${label}</a></p>`;

/**
 * Called right after a successful local sign-up with the whole-year age floor (never the date).
 * From db/0291 only the floor is stored; before it, the legacy function gets the youngest date
 * consistent with the floor, which reveals nothing beyond the floor and fails closed.
 */
export async function recordSignupAge(email: string, ageFloor: number, parentEmail: string | null): Promise<{ minor: boolean; mailed: boolean }> {
  const { isAgeFloor, legacyDateForFloor } = await import("@/lib/age/age-floor");
  if (!isAgeFloor(ageFloor)) return { minor: false, mailed: false };
  const minor = ageFloor < MINOR_AGE;
  const token = minor ? newParentToken() : null;
  const hash = token ? await hashParentToken(token) : null;
  const { hasSchemaFeature } = await import("@/lib/schema-features.server");
  const rows = (await hasSchemaFeature("0291"))
    ? ((await sql`select public.rout_record_signup_age_floor(${email}, ${ageFloor}::smallint, ${minor ? parentEmail : null}, ${hash}) as id`) as Row[])
    : ((await sql`select public.rout_record_signup_age(${email}, ${legacyDateForFloor(ageFloor)}::date, ${minor ? parentEmail : null}, ${hash}) as id`) as Row[]);
  if (!rows[0]?.["id"] || !minor || !token || !parentEmail) return { minor, mailed: false };
  return { minor, mailed: await mailParentConsent(email, parentEmail, token) };
}

/** The consent mail to the parent of a minor (sign-up and the age sheet). */
export async function mailParentConsent(email: string, parentEmail: string, token: string): Promise<boolean> {
  const link = `${SITE_ORIGIN}/parent/control/${token}`;
  const child = escapeMailParam(email);
  const html = shell(`
<h1 style="font-size:22px">Je kind wil een ROUT-account aanmaken</h1>
<p><strong>${child}</strong> gaf aan jonger dan 16 te zijn en jouw e-mailadres op als ouder of voogd. Zonder jouw toestemming blijft het account beperkt.</p>
${button(link, "Toestemming geven en instellingen beheren")}
<h2 style="font-size:16px;margin-top:28px">Veiligheids- en privacybijlage voor minderjarigen</h2>
<ul style="padding-left:18px;line-height:1.6">
<li>Anonieme berichten van bezoekers zonder account staan standaard <strong>uit</strong>. Alleen geverifieerde ROUT-accounts kunnen berichten sturen.</li>
<li>Elke betaling (upgrade, domein) moet eerst door jou goedgekeurd en betaald worden via een aparte link die 48 uur geldig is.</li>
<li>We bewaren geen geboortedatum: enkel de leeftijd in hele jaren, om deze beschermingen toe te passen. Die tonen we nooit publiek.</li>
<li>Met de knop hierboven beheer je de berichtinstellingen, ook later, zonder zelf een ROUT-account te hebben. Bewaar deze mail.</li>
<li>Je kunt altijd vragen om het account en alle gegevens te verwijderen via rout.be/contact.</li>
</ul>
<p style="font-size:13px;color:#555">Heb je hier niets mee te maken? Dan hoef je niets te doen.</p>`);
  return send(parentEmail, "Toestemming gevraagd voor een ROUT-account", html, ["parental-consent"]);
}

export type ParentView = {
  action: "consent" | "payment";
  status: "pending" | "approved" | "expired";
  expiresAt: string;
  childEmail: string;
  consent: "none" | "pending" | "approved";
  qaLevel: QaLevel;
  product: { label?: string; amountCents?: number; kind?: string } ;
};

function maskChild(e: string) {
  const [u = "", d = ""] = e.split("@");
  return `${u.slice(0, 2)}${"•".repeat(Math.max(1, u.length - 2))}@${d}`;
}

async function lookup(token: string): Promise<(ParentView & { childId: string }) | null> {
  if (!isParentTokenShape(token)) return null;
  const rows = (await sql`select * from public.rout_parent_lookup(${await hashParentToken(token)})`) as Row[];
  const r = rows[0];
  if (!r) return null;
  const pd = (r["product_details"] ?? {}) as Record<string, unknown>;
  return {
    action: r["action_type"] as ParentView["action"],
    status: r["status"] as ParentView["status"],
    expiresAt: new Date(String(r["expires_at"])).toISOString(),
    childEmail: maskChild(String(r["child_email"] ?? "")),
    consent: r["consent"] as ParentView["consent"],
    qaLevel: isQaLevel(r["qa_level"]) ? r["qa_level"] : "verified_only",
    product: { label: typeof pd["label"] === "string" ? pd["label"] : undefined, amountCents: Number(pd["amountCents"]) || undefined, kind: typeof pd["kind"] === "string" ? pd["kind"] : undefined },
    childId: String(r["child_id"]),
  };
}

export async function parentView(token: string): Promise<ParentView | null> {
  const v = await lookup(token);
  if (!v) return null;
  const { childId: _c, ...rest } = v;
  return rest;
}

export async function approveConsent(token: string): Promise<boolean> {
  if (!isParentTokenShape(token)) return false;
  const rows = (await sql`select public.rout_parent_approve_consent(${await hashParentToken(token)}) as ok`) as Row[];
  return rows[0]?.["ok"] === true;
}

export async function setQaLevel(token: string, level: QaLevel): Promise<boolean> {
  if (!isParentTokenShape(token)) return false;
  const rows = (await sql`select public.rout_parent_set_qa_level(${await hashParentToken(token)}, ${level}::public.qa_permission_level) as ok`) as Row[];
  return rows[0]?.["ok"] === true;
}

/**
 * Whether the signed-in member still has to give their age (db/0291): true only when the database
 * knows neither a self-declared floor nor a KYC floor. Before 0291 nothing is asked (fails open to
 * "no sheet"; the older sign-up path still records its age).
 */
export async function myAgeFloorMissing(userId: string): Promise<boolean> {
  const { hasSchemaFeature } = await import("@/lib/schema-features.server");
  if (!(await hasSchemaFeature("0291"))) return false;
  const { withDbContext } = await import("@/lib/neon");
  const rows = await withDbContext({ userId, workspaceId: null }, async () =>
    (await sql`select public.rout_my_age_floor() as f`) as Row[]);
  return rows[0]?.["f"] === null || rows[0]?.["f"] === undefined;
}

export type MyAgeOutcome = "ok" | "already_set" | "dob_invalid" | "parent_required" | "parent_email_same" | "unavailable";

/**
 * The post-sign-in age sheet. The date arrives only in this request and is turned into a whole-year
 * floor by ageFloorFromBirthDate (which wipes its byte copy); only the floor reaches Neon.
 */
export async function recordMyAge(userId: string, ownEmail: string, ageFloor: number | null, parentEmail: string | null): Promise<MyAgeOutcome> {
  const { isAgeFloor } = await import("@/lib/age/age-floor");
  if (!isAgeFloor(ageFloor)) return "dob_invalid";
  const { hasSchemaFeature } = await import("@/lib/schema-features.server");
  if (!(await hasSchemaFeature("0291"))) return "unavailable";
  const minor = ageFloor < MINOR_AGE;
  const parent = minor ? (parentEmail ?? "").trim().toLowerCase() : null;
  const token = minor ? newParentToken() : null;
  const hash = token ? await hashParentToken(token) : null;
  const { withDbContext } = await import("@/lib/neon");
  const rows = await withDbContext({ userId, workspaceId: null }, async () =>
    (await sql`select public.rout_record_my_age_floor(${ageFloor}::smallint, ${parent}, ${hash}) as r`) as Row[]);
  const r = String(rows[0]?.["r"] ?? "unavailable");
  if (r === "ok") {
    if (minor && token && parent) await mailParentConsent(ownEmail, parent, token);
    return "ok";
  }
  if (r === "already_set" || r === "parent_required" || r === "parent_email_same") return r;
  return r === "invalid_input" ? "dob_invalid" : "unavailable";
}

export async function isMinorUser(userId: string): Promise<boolean> {
  const rows = (await sql`select public.rout_user_is_minor(${userId}) as m`) as Row[];
  return rows[0]?.["m"] === true;
}

/** Diverts a minor's paid action to the parent: 48-hour link by email. */
export async function requestParentPayment(userId: string, product: { kind: string; label: string; amountCents: number }): Promise<boolean> {
  const token = newParentToken();
  const rows = (await sql`select public.rout_parent_request_payment(${userId}, ${await hashParentToken(token)}, ${JSON.stringify(product)}::jsonb) as parent`) as Row[];
  const parent = rows[0]?.["parent"] as string | null;
  if (!parent) return false;
  const euros = (product.amountCents / 100).toFixed(2).replace(".", ",");
  const html = shell(`
<h1 style="font-size:22px">Je kind vraagt een betaling op ROUT</h1>
<p>Gevraagd: <strong>${escapeMailParam(product.label)}</strong> — € ${euros}.</p>
<p>Niets wordt aangerekend zonder jouw actie. Bekijk het overzicht en betaal zelf als je akkoord gaat. Deze link is ${PARENT_PAYMENT_HOURS} uur geldig.</p>
${button(`${SITE_ORIGIN}/pay/auth/${token}`, "Overzicht bekijken")}`);
  return send(parent, "Betaling ter goedkeuring — ROUT", html, ["parental-payment"]);
}

/** Parent pays: starts the normal checkout for the child's account. */
export async function startParentCheckout(token: string, origin: string): Promise<{ ok: true; url: string } | { ok: false; reason: string }> {
  const v = await lookup(token);
  if (!v || v.action !== "payment") return { ok: false, reason: "not_found" };
  if (v.status !== "pending") return { ok: false, reason: v.status };
  if (v.product.kind !== "wallet_topup" || !v.product.amountCents) return { ok: false, reason: "unsupported" };
  const { startWalletTopup } = await import("./wallet.server");
  const res = await startWalletTopup({ userId: v.childId, amountCents: v.product.amountCents, origin });
  if (res.ok) await sql`select public.rout_parent_mark_payment(${await hashParentToken(token)})`;
  return res;
}

export async function profileQaLevel(handle: string): Promise<QaLevel> {
  const rows = (await sql`select public.rout_profile_qa_level(${handle}) as l`) as Row[];
  const l = rows[0]?.["l"];
  return isQaLevel(l) ? l : "public_unrestricted";
}

export { QA_LEVEL_LABELS };
