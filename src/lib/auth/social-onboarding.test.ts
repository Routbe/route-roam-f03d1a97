// @vitest-environment node
import { describe, expect, it, vi } from "vitest";
import {
  ONBOARDING_PROVIDERS, PENDING_PASSKEY_SETUP, SOCIAL_ONBOARD_COOKIE, SOCIAL_ONBOARD_PATH, SOCIAL_ONBOARD_TTL_S,
  onboardingFromProfile, readOnboardingCookie, signSocialOnboarding, verifySocialOnboarding,
} from "./social-onboarding";
import { capturingProvider, runSocialCallback } from "./social-onboarding-capture.server";
import { signSignupTicket } from "./signup-ticket";

const SECRET = "s".repeat(48);
vi.mock("@/lib/better-auth.server", () => ({ resolveAuthSecret: () => ({ secret: "s".repeat(48) }) }));
const now = 1_800_000_000;
const DATA = { provider: "google", accountId: "1234567890", email: "new@example.com", name: "New Member" };

describe("social onboarding ticket (pending_passkey_setup)", () => {
  it("only Google, GitHub and GitLab can start an account", () => {
    expect([...ONBOARDING_PROVIDERS].sort()).toEqual(["github", "gitlab", "google"]);
  });

  it("round-trips in state pending_passkey_setup and expires after 10 minutes", async () => {
    const t = await signSocialOnboarding(SECRET, DATA, now);
    expect(await verifySocialOnboarding(SECRET, t, now)).toMatchObject({ ...DATA, status: PENDING_PASSKEY_SETUP });
    expect(SOCIAL_ONBOARD_TTL_S).toBe(600);
    expect(await verifySocialOnboarding(SECRET, t, now + 601)).toBeNull();
  });

  it("rejects a tampered ticket, another secret and a sign-up ticket", async () => {
    const t = await signSocialOnboarding(SECRET, DATA, now);
    const [body, sig] = t.slice(3).split(".");
    const forged = JSON.parse(Buffer.from(body!, "base64url").toString());
    forged.email = "victim@example.com";
    expect(await verifySocialOnboarding(SECRET, `so.${Buffer.from(JSON.stringify(forged)).toString("base64url")}.${sig}`, now)).toBeNull();
    expect(await verifySocialOnboarding("o".repeat(48), t, now)).toBeNull();
    const su = await signSignupTicket(SECRET, { email: "a@b.co", name: "", ageFloor: 21, parentEmail: null, consent: "x" }, now);
    expect(await verifySocialOnboarding(SECRET, su, now)).toBeNull();
  });

  it("needs an e-mail the provider itself verified", () => {
    expect(onboardingFromProfile({ provider: "github", user: { id: 42, email: "A@Example.com", emailVerified: true, name: "A" } }))
      .toEqual({ provider: "github", accountId: "42", email: "a@example.com", name: "A" });
    expect(onboardingFromProfile({ provider: "github", user: { id: 42, email: "a@example.com", emailVerified: false } })).toBeNull();
    expect(onboardingFromProfile({ provider: "apple", user: { id: "x", email: "a@example.com", emailVerified: true } })).toBeNull();
    expect(onboardingFromProfile({ provider: "google", user: { email: "a@example.com", emailVerified: true } })).toBeNull();
  });

  it("reads the ticket from the HttpOnly cookie", () => {
    expect(readOnboardingCookie(`a=1; ${SOCIAL_ONBOARD_COOKIE}=so.x.y; b=2`)).toBe("so.x.y");
    expect(readOnboardingCookie("a=1")).toBeNull();
  });

  it("notes the provider profile only inside the callback scope", async () => {
    const factory = () => ({ id: "gitlab", getUserInfo: async () => ({ user: { id: 7, email: "g@example.com", emailVerified: true } }) });
    const opts = capturingProvider(factory as never, { clientId: "c" }) as unknown as { getUserInfo: (t: never) => Promise<unknown> };
    await opts.getUserInfo({} as never); // outside a scope: nothing kept
    const { profile } = await runSocialCallback(() => opts.getUserInfo({} as never));
    expect(profile).toEqual({ provider: "gitlab", user: { id: 7, email: "g@example.com", emailVerified: true } });
  });
});

describe("OAuth callback hand-off", () => {
  const refused = (error: string) => new Response(null, { status: 302, headers: { location: `/auth/sign-up?error=${error}` } });
  const profile = { provider: "google", user: { id: "1234567890", email: "new@example.com", emailVerified: true, name: "New" } };

  it("sends a new verified member to the onboarding instead of an error", async () => {
    const { socialOnboardingHandoff } = await import("@/routes/api_.auth.$");
    const res = await socialOnboardingHandoff(refused("signup_disabled"), new Request("https://rout.be/api/auth/callback/google"), profile);
    expect(res?.status).toBe(302);
    expect(res?.headers.get("location")).toBe(SOCIAL_ONBOARD_PATH);
    const cookie = res!.headers.getSetCookie().find((c) => c.startsWith(`${SOCIAL_ONBOARD_COOKIE}=`))!;
    expect(cookie).toMatch(/HttpOnly/);
    const ticket = await verifySocialOnboarding(SECRET, readOnboardingCookie(cookie.split(";")[0]), Math.floor(Date.now() / 1000));
    expect(ticket).toMatchObject({ status: PENDING_PASSKEY_SETUP, email: "new@example.com", provider: "google" });
  });

  it("leaves every other callback result untouched", async () => {
    const { socialOnboardingHandoff } = await import("@/routes/api_.auth.$");
    const req = new Request("https://rout.be/api/auth/callback/google");
    expect(await socialOnboardingHandoff(refused("account_not_linked"), req, profile)).toBeNull();
    expect(await socialOnboardingHandoff(refused("signup_disabled"), req, null)).toBeNull();
    expect(await socialOnboardingHandoff(refused("signup_disabled"), req, { ...profile, user: { ...profile.user, emailVerified: false } })).toBeNull();
  });
});
