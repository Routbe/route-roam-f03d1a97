import { describe, expect, it } from "vitest";
import { canIssueDeveloperCredentials, canUseDeveloperConsole } from "./console-access-rules";

describe("canUseDeveloperConsole", () => {
  it("allows a verified member", () => expect(canUseDeveloperConsole({ verified: true })).toBe(true));
  it("allows a Pro (paid) member", () => expect(canUseDeveloperConsole({ isPaid: true })).toBe(true));
  it("allows a claimed root handle", () =>
    expect(canUseDeveloperConsole({ hasClaimedRootHandle: true })).toBe(true));
  it("allows a full admin", () => expect(canUseDeveloperConsole({ isAdmin: true })).toBe(true));
  it("blocks a free alias without any signal", () => expect(canUseDeveloperConsole({})).toBe(false));
  it("blocks a banned verified member", () =>
    expect(canUseDeveloperConsole({ verified: true, isBanned: true })).toBe(false));
  it("blocks a suspended member", () =>
    expect(canUseDeveloperConsole({ isPaid: true, isSuspended: true })).toBe(false));
});

describe("canIssueDeveloperCredentials", () => {
  it("allows a member with a KYC legal identity", () => expect(canIssueDeveloperCredentials({ legalIdentity: true })).toBe(true));
  it("refuses without a legal identity, whatever else the member has", () => {
    expect(canIssueDeveloperCredentials({ legalIdentity: false })).toBe(false);
    expect(canIssueDeveloperCredentials({})).toBe(false);
    expect(canIssueDeveloperCredentials(null)).toBe(false);
  });
  it("refuses a banned or suspended member even with a legal identity", () => {
    expect(canIssueDeveloperCredentials({ legalIdentity: true, isBanned: true })).toBe(false);
    expect(canIssueDeveloperCredentials({ legalIdentity: true, isSuspended: true })).toBe(false);
  });
});
