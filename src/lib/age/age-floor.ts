/**
 * Whole-year age floor from a date of birth (owner rule 2026-11-17: a raw date of birth is never
 * stored). Pure and browser-safe; the server is the only caller that persists anything, and it
 * persists only the returned number (db-pending/0291 `users.age_floor`).
 *
 * The date is read from bytes that are zero-filled before return, together with the parsed
 * year/month/day. A JavaScript string the date arrived in cannot be wiped; callers never copy,
 * log or store it and drop it right after this call.
 */
export const AGE_FLOOR_MAX = 21;

const DASH = 0x2d;
const ZERO = 0x30;

function digits(bytes: Uint8Array, from: number, to: number): number {
  let n = 0;
  for (let i = from; i < to; i++) {
    const c = bytes[i]! - ZERO;
    if (c < 0 || c > 9) return -1;
    n = n * 10 + c;
  }
  return n;
}

/**
 * Age in whole years on `today` (UTC) for `YYYY-MM-DD` bytes, capped at 21; null when the bytes are
 * not a real calendar date between 1900-01-01 and today. Always zero-fills `bytes`.
 */
export function ageFloorFromDobBytes(bytes: Uint8Array, today: Date = new Date()): number | null {
  const ymd = new Uint16Array(3);
  try {
    if (bytes.length !== 10 || bytes[4] !== DASH || bytes[7] !== DASH) return null;
    const y = digits(bytes, 0, 4), m = digits(bytes, 5, 7), d = digits(bytes, 8, 10);
    if (y < 0 || m < 0 || d < 0) return null;
    ymd[0] = y; ymd[1] = m; ymd[2] = d;
    const dt = new Date(Date.UTC(ymd[0]!, ymd[1]! - 1, ymd[2]!));
    if (dt.getUTCFullYear() !== ymd[0] || dt.getUTCMonth() !== ymd[1]! - 1 || dt.getUTCDate() !== ymd[2]) return null;
    const ty = today.getUTCFullYear(), tm = today.getUTCMonth() + 1, td = today.getUTCDate();
    if (ymd[0]! < 1900 || dt.getTime() > Date.UTC(ty, tm - 1, td)) return null;
    let age = ty - ymd[0]!;
    if (tm < ymd[1]! || (tm === ymd[1] && td < ymd[2]!)) age -= 1;
    return Math.min(AGE_FLOOR_MAX, age);
  } finally {
    bytes.fill(0);
    ymd.fill(0);
  }
}

/** Same for a `YYYY-MM-DD` value; the encoded copy is wiped inside. */
export function ageFloorFromBirthDate(raw: unknown, today: Date = new Date()): number | null {
  if (typeof raw !== "string" || raw.length !== 10) return null;
  return ageFloorFromDobBytes(new TextEncoder().encode(raw), today);
}

export function isAgeFloor(v: unknown): v is number {
  return typeof v === "number" && Number.isInteger(v) && v >= 0 && v <= AGE_FLOOR_MAX;
}

/**
 * The latest calendar day consistent with a floor on `today` (UTC). Only for databases that do not
 * have 0291 yet, whose sign-up function still takes a date: it reveals nothing beyond the floor and
 * makes the member look as young as the floor allows, so protections fail closed.
 */
export function legacyDateForFloor(floor: number, today: Date = new Date()): string {
  const y = today.getUTCFullYear() - floor;
  const m = today.getUTCMonth() + 1, d = today.getUTCDate();
  const safeD = m === 2 && d === 29 && new Date(Date.UTC(y, 1, 29)).getUTCMonth() !== 1 ? 28 : d;
  return `${String(y).padStart(4, "0")}-${String(m).padStart(2, "0")}-${String(safeD).padStart(2, "0")}`;
}
