import { createFileRoute } from "@tanstack/react-router";

/**
 * Social onboarding (pending_passkey_setup), after a Google/GitHub/GitLab callback for an
 * address without a ROUT account (social-onboarding.ts):
 *   GET    → which provider and e-mail are waiting (from the HttpOnly ticket cookie);
 *   POST   → step 1: consent + date of birth → whole-year age floor, returns a signed
 *            sign-up ticket bound to the provider identity for step 2 (passkey);
 *   DELETE → abandon: drops the ticket cookie.
 * No account, session or database row exists until the passkey ceremony verifies.
 */
const noStore = { "cache-control": "no-store" };

async function pending(request: Request) {
  const { readOnboardingCookie, verifySocialOnboarding } = await import("@/lib/auth/social-onboarding");
  const { resolveAuthSecret } = await import("@/lib/better-auth.server");
  const secret = resolveAuthSecret()?.secret;
  if (!secret) return { secret: null, ticket: null };
  return { secret, ticket: await verifySocialOnboarding(secret, readOnboardingCookie(request.headers.get("cookie")), Math.floor(Date.now() / 1000)) };
}

export const Route = createFileRoute("/api_/auth-passkey/social")({
  server: {
    handlers: {
      GET: async ({ request }) => {
        const { ticket } = await pending(request);
        if (!ticket) return Response.json({ status: "none" }, { headers: noStore });
        return Response.json({ status: ticket.status, provider: ticket.provider, email: ticket.email, name: ticket.name, expiresAt: ticket.exp }, { headers: noStore });
      },
      DELETE: async () => {
        const { clearOnboardingCookie } = await import("@/lib/auth/social-onboarding");
        return new Response(null, { status: 204, headers: { ...noStore, "set-cookie": clearOnboardingCookie() } });
      },
      POST: async ({ request }) => {
        const { appMode } = await import("@/lib/app-mode");
        if (appMode() === "admin") return Response.json({ code: "signup_disabled", message: "Aanmelden kan niet op het beheerportaal." }, { status: 403, headers: noStore });
        const body = (await request.json().catch(() => null)) as Record<string, unknown> | null;
        // The date is read only here, in memory: the wiped-bytes helper turns it into whole years.
        const { ageFloorFromBirthDate } = await import("@/lib/age/age-floor");
        const ageFloor = ageFloorFromBirthDate(body?.["dob"]);
        if (body) delete body["dob"];
        const { secret, ticket } = await pending(request);
        if (!secret) return Response.json({ code: "missing_secret", message: "Aanmelden is tijdelijk niet beschikbaar." }, { status: 503, headers: noStore });
        if (!ticket) return Response.json({ code: "onboarding_expired", message: "Deze aanmelding is verlopen. Kies opnieuw je account." }, { status: 410, headers: noStore });
        const { SIGNUP_CONSENT_VERSION } = await import("@/lib/signup-consent");
        if (body?.["consent"] !== SIGNUP_CONSENT_VERSION) {
          return Response.json({ code: "consent_required", message: "Ga akkoord met de Algemene Voorwaarden en het Privacybeleid." }, { status: 400, headers: noStore });
        }
        const parentEmail = typeof body?.["parentEmail"] === "string" ? body["parentEmail"].trim().toLowerCase() : "";
        const { signupFloorProblem, MINOR_AGE } = await import("@/lib/minor-safety");
        const problem = signupFloorProblem({ ageFloor, parentEmail, email: ticket.email });
        if (problem) {
          return Response.json({ code: problem, message: problem === "dob_invalid" ? "Vul een geldige geboortedatum in." : "Vul het e-mailadres van je ouder of voogd in (niet je eigen adres)." }, { status: 400, headers: noStore });
        }
        const { hitRateLimit, clientIp } = await import("@/lib/rate-limit-db.server");
        const { RATE_RULES, tooManyRequests } = await import("@/lib/rate-limit-rules");
        const limit = await hitRateLimit("auth", `${clientIp(request)}:/passkey-social-signup`, RATE_RULES.authAttempt);
        if (!limit.ok) return tooManyRequests(limit.retryAfter);

        const { signSignupTicket } = await import("@/lib/auth/signup-ticket");
        const signup = await signSignupTicket(
          secret,
          {
            email: ticket.email,
            name: ticket.name,
            ageFloor: ageFloor!,
            parentEmail: ageFloor! < MINOR_AGE ? parentEmail : null,
            consent: SIGNUP_CONSENT_VERSION,
            social: { provider: ticket.provider, accountId: ticket.accountId },
          },
          Math.floor(Date.now() / 1000),
        );
        return Response.json({ status: ticket.status, ticket: signup }, { headers: noStore });
      },
    },
  },
});
