/**
 * Zero-knowledge age-threshold vector (db/0290 `age_threshold_vector`). Pure and tested.
 *
 * Bit i (i = 0..8) is set when the member is at least AGE_THRESHOLDS[i] years old (13..21).
 * The date of birth is parsed into a short-lived Uint16Array that is zero-filled before this
 * function returns; only the vector leaves it. Ages only grow, so a vector from an older
 * attestation can only under-state the age: an "over N" answer from a stale vector fails closed.
 * (The date string itself is a JavaScript string and cannot be wiped; it is never copied, stored
 * or logged, and the decision object holding it is dropped right after reading.)
 */
export const AGE_GATE_MIN = 13;
export const AGE_GATE_MAX = 21;
export const AGE_THRESHOLDS: readonly number[] = Array.from({ length: AGE_GATE_MAX - AGE_GATE_MIN + 1 }, (_, i) => AGE_GATE_MIN + i);
export const AGE_VECTOR_MAX = (1 << AGE_THRESHOLDS.length) - 1; // 511

const ISO_DATE = /^(\d{4})-(\d{2})-(\d{2})$/;

/** The vector for an ISO date of birth (YYYY-MM-DD) at `now` (UTC); null when unusable. */
export function ageVectorFromBirthDate(dob: unknown, now: Date = new Date()): number | null {
  if (typeof dob !== "string") return null;
  const m = ISO_DATE.exec(dob.trim());
  if (!m) return null;
  const ymd = Uint16Array.of(Number(m[1]), Number(m[2]), Number(m[3]));
  try {
    const [y, mo, d] = [ymd[0]!, ymd[1]!, ymd[2]!];
    const birth = new Date(Date.UTC(y, mo - 1, d));
    // Reject impossible calendar dates such as 2001-02-30.
    if (birth.getUTCFullYear() !== y || birth.getUTCMonth() !== mo - 1 || birth.getUTCDate() !== d) return null;
    if (birth.getTime() > now.getTime()) return null;
    let years = now.getUTCFullYear() - y;
    if (now.getUTCMonth() < mo - 1 || (now.getUTCMonth() === mo - 1 && now.getUTCDate() < d)) years -= 1;
    if (years < 0 || years > 130) return null;
    let v = 0;
    AGE_THRESHOLDS.forEach((t, i) => { if (years >= t) v |= 1 << i; });
    years = 0;
    return v;
  } finally {
    ymd.fill(0);
  }
}

/** The named booleans of a vector (is_over_13 … is_over_21), for display and tests. */
export function ageVectorFlags(vector: number | null | undefined): Record<string, boolean> {
  const out: Record<string, boolean> = {};
  for (const [i, t] of AGE_THRESHOLDS.entries()) out[`is_over_${t}`] = isValidVector(vector) && ((vector as number) & (1 << i)) !== 0;
  return out;
}

/** A well-formed vector is monotone: being over N implies being over every lower threshold. */
export function isValidVector(v: unknown): v is number {
  if (typeof v !== "number" || !Number.isInteger(v) || v < 0 || v > AGE_VECTOR_MAX) return false;
  return (v & (v + 1)) === 0; // only the low bits set: 0, 1, 3, 7, … 511
}

/** True only when the attested vector proves the member is at least `min` (13..21) years old. */
export function ageGatePasses(vector: number | null | undefined, min: number): boolean {
  const i = AGE_THRESHOLDS.indexOf(min);
  if (i < 0 || !isValidVector(vector)) return false;
  return (vector & (1 << i)) !== 0;
}

/** Bridge for the pending db/0290 `age_floor` column (whole years, capped at 21). */
export function ageVectorFromFloor(floor: number): number {
  if (!Number.isInteger(floor) || floor < AGE_GATE_MIN) return 0;
  return (1 << (Math.min(floor, AGE_GATE_MAX) - AGE_GATE_MIN + 1)) - 1;
}

/** Inverse bridge: the floor a vector proves (12 = under 13), or null without a vector. */
export function ageFloorFromVector(vector: number | null | undefined): number | null {
  if (!isValidVector(vector)) return null;
  let bits = 0;
  for (let v = vector; v; v >>= 1) bits++;
  return AGE_GATE_MIN - 1 + bits;
}
