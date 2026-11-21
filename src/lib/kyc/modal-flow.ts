/** Pure polling schedule for the Didit modal (tested). */
export type KycPhase = "idle" | "starting" | "waiting" | "verified" | "failed" | "error";

/** Stop polling after 20 minutes; the status stays visible on the settings page afterwards. */
export const POLL_DEADLINE_MS = 20 * 60_000;

/** 3 s for the first two minutes, then 10 s, then 30 s after ten minutes. */
export function nextPollDelay(elapsedMs: number): number {
  if (elapsedMs < 2 * 60_000) return 3_000;
  if (elapsedMs < 10 * 60_000) return 10_000;
  return 30_000;
}
