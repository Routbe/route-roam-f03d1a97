import { describe, expect, it } from "vitest";
import { effectivePasswordMode, isTouchDevice } from "./touch-input";

describe("touch fallback for careful typing", () => {
  it("detects touch from ontouchstart or maxTouchPoints", () => {
    expect(isTouchDevice({ hasTouchEvent: true, maxTouchPoints: 0 })).toBe(true);
    expect(isTouchDevice({ hasTouchEvent: false, maxTouchPoints: 5 })).toBe(true);
    expect(isTouchDevice({ hasTouchEvent: false, maxTouchPoints: 0 })).toBe(false);
  });
  it("uses the native password field on touch devices even when careful typing is on", () => {
    expect(effectivePasswordMode("paranoid", true)).toBe("normal");
    expect(effectivePasswordMode("paranoid", false)).toBe("paranoid");
  });
});
