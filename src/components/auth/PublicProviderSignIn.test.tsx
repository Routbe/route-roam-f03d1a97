import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import { AUTH_ERROR_CODES } from "@/lib/auth/post-auth";

const social = vi.fn(async (_o: unknown) => ({ data: null, error: { message: "x" } }));
vi.mock("@/lib/auth-client", () => ({ authClient: { signIn: { social: (o: unknown) => social(o) } } }));
vi.mock("react-i18next", () => ({ useTranslation: () => ({ t: (k: string, o?: { name?: string }) => (o?.name ? `${k}:${o.name}` : k) }) }));
vi.mock("sonner", () => ({ toast: { error: vi.fn() } }));
import { PublicProviderSignIn } from "./PublicProviderSignIn";

afterEach(cleanup);
const READY = { ready: true } as never;

describe("social login grid on the auth card", () => {
  it("shows the passkey tile next to Google, GitHub and GitLab and runs its action", () => {
    const onSelect = vi.fn();
    render(<PublicProviderSignIn configured={["google", "github", "gitlab"]} readiness={READY} disabled={false} passkey={{ label: "Passkey", onSelect }} />);
    const tiles = screen.getAllByRole("button", { name: "Passkey" });
    expect(tiles.length).toBeGreaterThan(0);
    for (const name of ["Google", "GitHub", "GitLab"]) {
      expect(screen.getAllByRole("button", { name: `auth.provider.continue:${name}` })[0]!.hasAttribute("disabled")).toBe(false);
    }
    fireEvent.click(tiles[0]!);
    expect(onSelect).toHaveBeenCalledTimes(1);
  });

  it("sends a failed sign-up to the sign-up page, where Better Auth appends the error code", async () => {
    render(<PublicProviderSignIn configured={["google"]} readiness={READY} disabled={false} errorPath="/auth/sign-up" />);
    fireEvent.click(screen.getAllByRole("button", { name: "auth.provider.continue:Google" })[0]!);
    await waitFor(() => expect(social).toHaveBeenCalled());
    expect(social.mock.calls[0]![0]).toMatchObject({ provider: "google", errorCallbackURL: "/auth/sign-up" });
  });

  it("the blocked social sign-up code is a known sign-in error", () => {
    expect(AUTH_ERROR_CODES).toContain("signup_disabled");
  });
});
