/**
 * Belgian structured communication (OGM/VCS, "gestructureerde mededeling"): 10 digits plus a
 * 2-digit check = base mod 97 (97 when the remainder is 0), shown as +++123/4567/89002+++.
 * Banks validate the check digits, so a typo is refused before the money leaves the payer.
 */
const OGM_IN_TEXT = /(?:\+{3}|\*{3})\s*(\d{3})\s*\/\s*(\d{4})\s*\/\s*(\d{5})\s*(?:\+{3}|\*{3})/;
const BARE = /(?:^|\D)(\d{12})(?:\D|$)/;

export function ogmCheck(base10: string): string {
  if (!/^\d{10}$/.test(base10)) throw new RangeError("ogm_base_invalid");
  const r = Number(BigInt(base10) % 97n);
  return String(r === 0 ? 97 : r).padStart(2, "0");
}

/** True for 12 digits whose last two are the mod-97 check of the first ten. */
export function isValidOgm(digits: string): boolean {
  return /^\d{12}$/.test(digits) && ogmCheck(digits.slice(0, 10)) === digits.slice(10);
}

export function formatOgm(digits: string): string {
  if (!isValidOgm(digits)) throw new RangeError("ogm_invalid");
  return `+++${digits.slice(0, 3)}/${digits.slice(3, 7)}/${digits.slice(7)}+++`;
}

/** A fresh random OGM (12 digits). The base never starts with 0 so banks never strip it. */
export function generateOgm(random: (n: number) => Uint8Array = (n) => crypto.getRandomValues(new Uint8Array(n))): string {
  for (;;) {
    const bytes = random(8);
    let v = 0n;
    for (const b of bytes) v = (v << 8n) | BigInt(b);
    const base = (v % 9_000_000_000n) + 1_000_000_000n; // 1000000000..9999999999
    const base10 = base.toString();
    if (base10.length === 10) return base10 + ogmCheck(base10);
  }
}

/** Finds a valid OGM in a bank description (+++/***, spaces, or 12 bare digits); null otherwise. */
export function parseOgm(text: string): string | null {
  if (typeof text !== "string" || text.length > 2000) return null;
  const m = OGM_IN_TEXT.exec(text);
  const digits = m ? `${m[1]}${m[2]}${m[3]}` : BARE.exec(text.replace(/[\s/]/g, ""))?.[1] ?? null;
  return digits && isValidOgm(digits) ? digits : null;
}
