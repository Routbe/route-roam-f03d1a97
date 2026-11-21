/**
 * Tweede pagina bij verificatie.
 *
 * Zodra een account betaald én geverifieerd is, hoort het twee publieke
 * adressen te hebben:
 *   • het gratis aliasprofiel   → rout.be/u/<oude naam>
 *   • het geverifieerde profiel → rout.be/voornaam.achternaam
 *
 * Standaard is dat `voornaam.achternaam`. Is die naam bezet, dan schuift het
 * door naar de varianten uit de bestaande naambouwer (jdelplanche,
 * delplanchej, jona.d …). Het lid kan de vorm achteraf altijd zelf wijzigen.
 */

import { sql } from "@/lib/neon";
import {
  DEFAULT_BUILDER_CONFIG,
  buildHandle,
  parseLegalName,
  toStorageHandle,
  type HandleBuilderConfig,
} from "./verified-handle-builder";
import { isReservedSlug } from "./reserved-slugs";

type Row = Record<string, unknown>;

/** Volgorde van voorkeur: eerst voornaam.achternaam, dan kortere varianten. */
const VARIANTS: Partial<HandleBuilderConfig>[] = [
  { fullness: "all-full", separator: "." },
  { fullness: "all-full", separator: "" },
  { fullness: "all-full", separator: "-" },
  { fullness: "first-short", separator: "", surnameShortStyle: "initials" },
  { fullness: "surname-short", separator: "", surnameShortStyle: "initials" },
  { order: "surname-first", fullness: "first-short", separator: "" },
];

export function verifiedHandleCandidates(legalName: string): string[] {
  const parsed = parseLegalName(legalName);
  if (!parsed) return [];
  const out: string[] = [];
  for (const variant of VARIANTS) {
    const handle = toStorageHandle(buildHandle(parsed, { ...DEFAULT_BUILDER_CONFIG, ...variant }));
    if (handle.length >= 5 && !isReservedSlug(handle) && !out.includes(handle)) out.push(handle);
  }
  // Laatste redmiddel: dezelfde naam met een klein volgnummer.
  const base = out[0];
  if (base) for (let i = 2; i <= 9; i += 1) out.push(`${base}${i}`);
  return out;
}

/**
 * Activeert de geverifieerde pagina. Bewaart eerst de gratis naam op `/u/` en
 * hernoemt daarna de roothandle. Doet niets wanneer de huidige roothandle al
 * uit de wettelijke naam is opgebouwd of wanneer er geen naam bekend is.
 */
export async function activateVerifiedRootHandle(
  userId: string,
  legalName: string | null | undefined,
): Promise<{ ok: boolean; handle: string | null; aliasHandle: string | null }> {
  const name = String(legalName ?? "").trim();
  if (!name) return { ok: false, handle: null, aliasHandle: null };

  const rows = (await sql`
    select username from public.profiles where id = ${userId} limit 1
  `) as Row[];
  const current = (rows[0]?.["username"] as string | null) ?? null;

  const candidates = verifiedHandleCandidates(name);
  if (candidates.length === 0) return { ok: false, handle: null, aliasHandle: null };

  // Draagt het lid al een handle uit zijn wettelijke naam? Dan niets wijzigen.
  if (current && candidates.includes(current.toLowerCase())) {
    return { ok: true, handle: current, aliasHandle: null };
  }

  const { isHandleAvailableFor } = await import("./handle-namespace.server");
  let chosen: string | null = null;
  for (const candidate of candidates) {
    if (await isHandleAvailableFor(candidate, userId)) {
      chosen = candidate;
      break;
    }
  }
  if (!chosen) return { ok: false, handle: current, aliasHandle: null };

  // De oude (gratis) naam blijft bestaan als /u/-pagina.
  const { preserveFreeAliasHandle, ensureFreeAliasProfile } = await import(
    "./alias-profile.server"
  );
  const preserved = await preserveFreeAliasHandle(userId, current);
  if (!preserved.ok) await ensureFreeAliasProfile(userId, { seed: name });

  try {
    await sql`
      update public.profiles
         set username = ${chosen}, updated_at = now()
       where id = ${userId}
    `;
  } catch (error) {
    console.error("[verified-handle:rename:failed]", error);
    return { ok: false, handle: current, aliasHandle: preserved.handle };
  }

  return { ok: true, handle: chosen, aliasHandle: preserved.handle };
}

/* ------------------------------------------------------------------------- *
 * Prioriteit 3: keuzescherm na Didit en atomaire claim (db/0298).
 * De varianten komen uit de verzegelde Didit-naam (alleen in dit proces geopend);
 * de gekozen handle wordt server-side opnieuw tegen die set gevalideerd en daarna
 * in één databasetransactie geclaimd (public.rout_claim_verified_root_handle).
 * ------------------------------------------------------------------------- */

import type { HandleCandidate, LegalHandleTiers, VerifiedHandleRejection } from "./verified-handle-builder";

export type VerifiedHandleOptions =
  | {
      ok: true;
      options: HandleCandidate[];
      currentRootHandle: string | null;
      /** Toon de eenmalige keuze "blanco / links kopiëren" (alleen met een gevuld /u/-profiel). */
      offerCopyLinks: boolean;
      hasAlias: boolean;
    }
  | { ok: false; reason: "identity_required" | "name_unavailable" | "not_ready" };

export type ClaimVerifiedHandleResult =
  | { ok: true; handle: string }
  | { ok: false; reason: VerifiedHandleRejection | "identity_required" | "name_unavailable" | "not_ready" | "cooldown" | "failed" };

async function registryReady(): Promise<boolean> {
  const { hasSchemaFeature } = await import("@/lib/schema-features.server");
  return hasSchemaFeature("0298");
}

async function takenRootHandles(handles: string[]): Promise<Set<string>> {
  if (handles.length === 0) return new Set();
  const rows = (await sql`select h from public.rout_handles_taken('root_verified', ${handles}::text[]) as h`) as { h: string }[];
  return new Set(rows.map((r) => r.h));
}

async function tiersFromSealedName(userId: string): Promise<LegalHandleTiers | null> {
  const { withOwnLegalNameParts } = await import("./kyc/legal-name-vault.server");
  const { legalHandleTiers } = await import("./verified-handle-builder");
  return withOwnLegalNameParts(userId, (name) => legalHandleTiers(name));
}

function allHandles(t: LegalHandleTiers): string[] {
  return [...t.tier1, ...t.tier2, ...t.tier3, ...t.tier4].slice(0, 200);
}

function aliasHasLinks(blocks: unknown): boolean {
  return Array.isArray(blocks) && blocks.length > 0;
}

/** Vrije varianten voor het keuzescherm. Alleen na een geslaagde Didit-verificatie. */
export async function listVerifiedHandleOptions(userId: string): Promise<VerifiedHandleOptions> {
  if (!(await registryReady())) return { ok: false, reason: "not_ready" };
  const { memberMayHoldRootHandle } = await import("./kyc/root-handle-gate.server");
  if (!(await memberMayHoldRootHandle(userId))) return { ok: false, reason: "identity_required" };
  const tiers = await tiersFromSealedName(userId);
  if (!tiers) return { ok: false, reason: "name_unavailable" };
  const taken = await takenRootHandles(allHandles(tiers));
  const { isProtectedPublicSlug, isReservedSlug } = await import("./reserved-slugs");
  const rows = (await sql`
    select p.username, a.handle as alias_handle, a.blocks as alias_blocks
      from public.profiles p left join public.alias_profiles a on a.user_id = p.id
     where p.id = ${userId}::uuid limit 1
  `) as Row[];
  const row = rows[0] ?? {};
  const aliasHandle = ((row["alias_handle"] as string | null) ?? "").toLowerCase();
  const options = candidatesFromTiers(tiers, (h) => taken.has(h) || h === aliasHandle, (h) => isReservedSlug(h) || isProtectedPublicSlug(h));
  const currentRaw = (row["username"] as string | null) ?? null;
  const current = currentRaw && (await memberMayHoldRootHandle(userId)) ? currentRaw : null;
  return {
    ok: true,
    options,
    currentRootHandle: current,
    offerCopyLinks: !current && aliasHasLinks(row["alias_blocks"]),
    hasAlias: Boolean(aliasHandle),
  };
}

function candidatesFromTiers(t: LegalHandleTiers, isTaken: (h: string) => boolean, isReserved: (h: string) => boolean): HandleCandidate[] {
  const free = (h: string) => !isTaken(h) && !isReserved(h);
  const normal: HandleCandidate[] = [
    ...t.tier1.map((handle) => ({ handle, tier: 1 as const })),
    ...t.tier2.map((handle) => ({ handle, tier: 2 as const })),
    ...t.tier3.map((handle) => ({ handle, tier: 3 as const })),
  ].filter((c) => free(c.handle));
  if (normal.length > 0) return normal;
  return t.tier4.filter(free).map((handle) => ({ handle, tier: 4 as const }));
}

const CLAIM_ERRORS: Record<string, ClaimVerifiedHandleResult> = {
  root_handle_identity_required: { ok: false, reason: "identity_required" },
  handle_reserved: { ok: false, reason: "HANDLE_RESERVED" },
  handle_invalid: { ok: false, reason: "HANDLE_INVALID" },
  handle_taken: { ok: false, reason: "HANDLE_TAKEN" },
  handle_cooling_down: { ok: false, reason: "HANDLE_TAKEN" },
  handle_matches_own_alias: { ok: false, reason: "HANDLE_TAKEN" },
  root_handle_cooldown: { ok: false, reason: "cooldown" },
};

/**
 * Slaat de gekozen geverifieerde handle op. Vertrouwt de browser niet: de handle moet in de
 * toegestane set van de verzegelde Didit-naam staan, niet gereserveerd en vrij zijn; de database
 * controleert Didit, reservering en bezetting nog eens onder een slot in dezelfde transactie.
 */
export async function claimVerifiedRootHandle(
  userId: string,
  rawHandle: string,
  opts: { copyLinks: boolean; hideAlias: boolean },
): Promise<ClaimVerifiedHandleResult> {
  if (!(await registryReady())) return { ok: false, reason: "not_ready" };
  const { memberMayHoldRootHandle } = await import("./kyc/root-handle-gate.server");
  if (!(await memberMayHoldRootHandle(userId))) return { ok: false, reason: "identity_required" };
  const tiers = await tiersFromSealedName(userId);
  if (!tiers) return { ok: false, reason: "name_unavailable" };
  const taken = await takenRootHandles(allHandles(tiers));
  const { validateChosenFromTiers } = await import("./verified-handle-builder");
  const { isProtectedPublicSlug, isReservedSlug } = await import("./reserved-slugs");
  const verdict = validateChosenFromTiers(tiers, rawHandle, {
    isTaken: (h) => taken.has(h),
    isReserved: (h) => isReservedSlug(h) || isProtectedPublicSlug(h),
  });
  if (!verdict.ok) return { ok: false, reason: verdict.code };
  const handle = String(rawHandle).trim().replace(/^@/, "").toLowerCase();

  // Een oude (niet-geverifieerde) roothandle blijft bestaan als /u/-naam wanneer er nog geen alias is.
  const rows = (await sql`select username from public.profiles where id = ${userId}::uuid limit 1`) as Row[];
  const current = (rows[0]?.["username"] as string | null) ?? null;
  if (current && current.toLowerCase() !== handle) {
    const { preserveFreeAliasHandle } = await import("./alias-profile.server");
    await preserveFreeAliasHandle(userId, current).catch(() => undefined);
  }

  try {
    const out = (await sql`select public.rout_claim_verified_root_handle(${handle}, ${opts.copyLinks}, ${opts.hideAlias}) as h`) as { h: string }[];
    return { ok: true, handle: out[0]?.h ?? handle };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    for (const [key, result] of Object.entries(CLAIM_ERRORS)) if (message.includes(key)) return result;
    console.error("[verified-handle:claim:failed]", error instanceof Error ? error.name : "error");
    return { ok: false, reason: "failed" };
  }
}
