import { afterEach, describe, expect, it, vi } from "vitest";
import { AUTH_WARMUP_GUARD_MS, isWarmingUp, withWarmupGuard } from "./warmup-guard";

afterEach(() => { vi.useRealTimers(); });

describe("requireAuth warm-up guard", () => {
  it("is 6000 ms", () => {
    expect(AUTH_WARMUP_GUARD_MS).toBe(6_000);
  });
  it("fails with warming_up (503) when the session lookup outlives 6000 ms", async () => {
    vi.useFakeTimers();
    vi.spyOn(console, "warn").mockImplementation(() => {});
    const slow = new Promise<string>((r) => setTimeout(() => r("late"), 7_000));
    const guarded = withWarmupGuard(slow);
    const caught = guarded.catch((e: unknown) => e);
    await vi.advanceTimersByTimeAsync(6_000);
    const error = await caught;
    expect(isWarmingUp(error)).toBe(true);
    expect((error as { statusCode?: number }).statusCode).toBe(503);
  });
  it("passes a lookup that answers within 6000 ms through unchanged", async () => {
    vi.useFakeTimers();
    const fast = new Promise<string>((r) => setTimeout(() => r("user"), 5_999));
    const guarded = withWarmupGuard(fast);
    await vi.advanceTimersByTimeAsync(5_999);
    await expect(guarded).resolves.toBe("user");
  });
  it("keeps a real auth failure as it is", async () => {
    await expect(withWarmupGuard(Promise.reject(new Error("Unauthorized")))).rejects.toThrow("Unauthorized");
  });
});
