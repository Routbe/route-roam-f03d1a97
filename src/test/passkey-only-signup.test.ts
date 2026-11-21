// @vitest-environment node
import { describe, expect, it, vi } from "vitest";
import { isApprovedAccountCreation, isPasskeyAccountCreation, runOpaqueAccountCreation, runPasskeyAccountCreation } from "@/lib/auth/account-creation-scope";
import { finalizeEnrollment } from "@/lib/auth/passkey-enrollment.server";
import { signSignupTicket } from "@/lib/auth/signup-ticket";

vi.mock("@/lib/minor-safety.server", () => ({ recordSignupAge: async () => undefined }));

const SECRET = "x".repeat(48);

describe("passkey-only account creation", () => {
  it("is refused outside the passkey sign-up ceremony", () => {
    expect(isPasskeyAccountCreation()).toBe(false);
  });

  it("is allowed only inside the passkey sign-up scope", async () => {
    expect(await runPasskeyAccountCreation(async () => isPasskeyAccountCreation())).toBe(true);
    expect(isPasskeyAccountCreation()).toBe(false);
  });

  it("accepts exactly two creation scopes: passkey sign-up and OPAQUE password sign-up", async () => {
    expect(isApprovedAccountCreation()).toBe(false);
    expect(await runPasskeyAccountCreation(async () => isApprovedAccountCreation())).toBe(true);
    expect(await runOpaqueAccountCreation(async () => isApprovedAccountCreation())).toBe(true);
    // An OPAQUE scope is not a passkey scope (passkey enrollment stays separate).
    expect(await runOpaqueAccountCreation(async () => isPasskeyAccountCreation())).toBe(false);
    expect(isApprovedAccountCreation()).toBe(false);
  });

  it("creates the account from a verified sign-up ticket inside the passkey scope", async () => {
    const ticket = await signSignupTicket(
      SECRET,
      { email: "new@example.com", name: "New", ageFloor: 21, parentEmail: null, consent: "test" } as never,
      Math.floor(Date.now() / 1000),
    );
    let scopedDuringCreate = false;
    const adapter = {
      findUserByEmail: async () => null,
      createUser: async () => {
        scopedDuringCreate = isPasskeyAccountCreation();
        return { id: "11111111-1111-4111-8111-111111111111" };
      },
    };
    await expect(finalizeEnrollment(SECRET, adapter, ticket)).resolves.toEqual({ userId: "11111111-1111-4111-8111-111111111111" });
    expect(scopedDuringCreate).toBe(true);
  });

  it("a social onboarding ticket creates the account and links the provider only after the passkey", async () => {
    const ticket = await signSignupTicket(
      SECRET,
      { email: "new@example.com", name: "New", ageFloor: 21, parentEmail: null, consent: "test", social: { provider: "github", accountId: "42" } },
      Math.floor(Date.now() / 1000),
    );
    const calls: string[] = [];
    const adapter = {
      findUserByEmail: async () => null,
      findAccountByKey: async () => null,
      createUser: async (u: { emailVerified: boolean }) => {
        calls.push(`create:${u.emailVerified}:${isPasskeyAccountCreation()}`);
        return { id: "22222222-2222-4222-8222-222222222222" };
      },
      linkAccount: async (a: { userId: string; providerId: string; accountId: string }) => { calls.push(`link:${a.userId}:${a.providerId}:${a.accountId}`); },
    };
    await expect(finalizeEnrollment(SECRET, adapter, ticket)).resolves.toEqual({ userId: "22222222-2222-4222-8222-222222222222" });
    expect(calls).toEqual(["create:true:true", "link:22222222-2222-4222-8222-222222222222:github:42"]);
  });

  it("refuses a social ticket whose provider account already belongs to someone", async () => {
    const ticket = await signSignupTicket(
      SECRET,
      { email: "new@example.com", name: "", ageFloor: 21, parentEmail: null, consent: "test", social: { provider: "google", accountId: "9" } },
      Math.floor(Date.now() / 1000),
    );
    const createUser = vi.fn(async () => ({ id: "x" }));
    const adapter = { findUserByEmail: async () => null, findAccountByKey: async () => ({ id: "acc" }), createUser, linkAccount: async () => undefined };
    await expect(finalizeEnrollment(SECRET, adapter, ticket)).rejects.toThrow("account_exists");
    expect(createUser).not.toHaveBeenCalled();
  });

  it("refuses enrollment without a sign-up ticket or recovery token", async () => {
    const adapter = { findUserByEmail: async () => null, createUser: async () => ({ id: "x" }) };
    await expect(finalizeEnrollment(SECRET, adapter, "bogus")).rejects.toThrow("passkey_enrollment_required");
  });
});
