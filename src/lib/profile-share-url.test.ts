import { describe, expect, it } from "vitest";
import { getProfileShareUrl } from "./profile-url";

describe("getProfileShareUrl", () => {
  it("verified root profile is rout.be/<handle>, never under /u/", () => {
    expect(getProfileShareUrl({ type: "root", handle: "jona", verified: true })).toBe("https://rout.be/jona");
    expect(getProfileShareUrl({ type: "root", handle: "@Jona", verified: true, urlStyle: "u" })).toBe("https://rout.be/jona");
  });
  it("verified root keeps the member's @ choice", () => {
    expect(getProfileShareUrl({ type: "root", handle: "jona", verified: true, urlStyle: "clean_at" })).toBe("https://rout.be/@jona");
  });
  it("unverified root folds back to /u/", () => {
    expect(getProfileShareUrl({ type: "root", handle: "jona", verified: false })).toBe("https://rout.be/u/jona");
  });
  it("private alias is rout.be/u/<alias>", () => {
    expect(getProfileShareUrl({ type: "alias", handle: "nachtuil" })).toBe("https://rout.be/u/nachtuil");
  });
  it("workspace is rout.be/w/<slug>", () => {
    expect(getProfileShareUrl({ type: "workspace", slug: "kyc-club" })).toBe("https://rout.be/w/kyc-club");
  });
  it("uses the given origin without a double slash", () => {
    expect(getProfileShareUrl({ type: "workspace", slug: "a" }, "http://localhost:8080/")).toBe("http://localhost:8080/w/a");
  });
});
