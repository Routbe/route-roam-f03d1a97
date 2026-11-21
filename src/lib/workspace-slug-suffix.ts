/**
 * Free workspaces live at /w/<name>-<suffix>. The suffix is 4 characters of
 * Crockford base32 in lowercase (no i, l, o, u: nothing to misread or spell
 * by accident), 20 bits of CSPRNG entropy. db/0297 generates the same
 * alphabet in the database trigger; migration-0297.test.ts pins both to this
 * constant. Pure and browser-safe.
 */

export const CROCKFORD_SUFFIX_ALPHABET = "0123456789abcdefghjkmnpqrstvwxyz";
export const SLUG_SUFFIX_LENGTH = 4;
/** workspaces_slug_check allows 40 characters: base (≤ 35) + "-" + 4. */
export const SLUG_BASE_MAX = 35;

/** <base>-<4 Crockford characters>; the base is a-z0-9 words joined by single hyphens. */
export const SUFFIXED_WORKSPACE_SLUG = /^[a-z0-9]+(?:-[a-z0-9]+)*-[0-9a-hjkmnp-tv-z]{4}$/;

type Rnd = (n: number) => Uint8Array;
const cryptoRnd: Rnd = (n) => crypto.getRandomValues(new Uint8Array(n));

/** 4 suffix characters; 256 is a multiple of 32, so `byte & 31` is uniform. */
export function crockfordSuffix(rnd: Rnd = cryptoRnd): string {
  const bytes = rnd(SLUG_SUFFIX_LENGTH);
  let out = "";
  for (let i = 0; i < SLUG_SUFFIX_LENGTH; i++) out += CROCKFORD_SUFFIX_ALPHABET[(bytes[i] ?? 0) & 31];
  return out;
}

/** A URL-safe base from any display name ("Café Zoë & Co" → "cafe-zoe-co"), or null when nothing usable is left. */
export function slugBaseFrom(input: string): string | null {
  const base = input
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, SLUG_BASE_MAX)
    .replace(/-+$/g, "");
  return base.length >= 2 ? base : null;
}

export function suffixedWorkspaceSlug(base: string, rnd: Rnd = cryptoRnd): string {
  return `${base}-${crockfordSuffix(rnd)}`;
}
