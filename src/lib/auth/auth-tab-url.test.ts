import { describe, expect, it, vi } from "vitest";
import { authTabFromKey, authTabPath, syncAuthTabUrl } from "./auth-tab-url";

describe("auth card tabs", () => {
  it("pairs /login with the sign-in tab and /register with the sign-up tab", () => {
    expect(authTabPath("/login", "signup")).toBe("/register");
    expect(authTabPath("/register", "signin")).toBe("/login");
    expect(authTabPath("/auth/sign-in", "signup")).toBeNull();
  });

  it("swaps the address in place, keeping query and hash", () => {
    const replace = vi.fn();
    expect(syncAuthTabUrl("signup", { pathname: "/login", search: "?redirect=/studio", hash: "#x" }, replace)).toBe(true);
    expect(replace).toHaveBeenCalledWith("/register?redirect=/studio#x");
  });

  it("uses the native replaceState and keeps the router's history state", () => {
    window.history.pushState({ __TSR_key: "k1" }, "", "/login");
    const patched = vi.fn();
    const original = window.history.replaceState;
    window.history.replaceState = patched as typeof window.history.replaceState;
    try {
      expect(syncAuthTabUrl("signup")).toBe(true);
    } finally {
      window.history.replaceState = original;
    }
    expect(patched).not.toHaveBeenCalled();
    expect(window.location.pathname).toBe("/register");
    expect(window.history.state).toEqual({ __TSR_key: "k1" });
  });

  it("leaves the address alone on other routes or when already right", () => {
    const replace = vi.fn();
    expect(syncAuthTabUrl("signup", { pathname: "/auth/sign-in", search: "", hash: "" }, replace)).toBe(false);
    expect(syncAuthTabUrl("signup", { pathname: "/register", search: "", hash: "" }, replace)).toBe(false);
    expect(replace).not.toHaveBeenCalled();
  });

  it("arrow keys switch tabs (wrapping); Home and End jump to the first and last tab", () => {
    expect(authTabFromKey("ArrowRight", "signin")).toBe("signup");
    expect(authTabFromKey("ArrowRight", "signup")).toBe("signin");
    expect(authTabFromKey("ArrowLeft", "signin")).toBe("signup");
    expect(authTabFromKey("Home", "signup")).toBe("signin");
    expect(authTabFromKey("End", "signin")).toBe("signup");
    expect(authTabFromKey("Enter", "signin")).toBeNull();
  });
});
