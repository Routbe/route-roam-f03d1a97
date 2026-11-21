import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";

vi.mock("react-i18next", () => ({ useTranslation: () => ({ t: (k: string) => k }) }));
vi.mock("sonner", () => ({ toast: { error: vi.fn(), success: vi.fn() } }));
vi.mock("@tanstack/react-router", () => ({ Link: ({ children }: { children: React.ReactNode }) => <a>{children}</a> }));
import { SocialOnboardingDialog } from "./SocialOnboardingDialog";

// Radix checkbox measures itself; jsdom has no ResizeObserver.
globalThis.ResizeObserver ??= class { observe() {} unobserve() {} disconnect() {} } as never;

afterEach(() => { cleanup(); vi.unstubAllGlobals(); });


describe("unified social onboarding dialog", () => {
  it("asks the age first, then the passkey, and hands the signed ticket to the passkey ceremony", async () => {
    const posts: unknown[] = [];
    vi.stubGlobal("fetch", vi.fn(async (_url: string, init?: RequestInit) => {
      if (init?.method === "POST") {
        posts.push(JSON.parse(String(init.body)));
        return new Response(JSON.stringify({ status: "pending_passkey_setup", ticket: "su.ticket" }), { status: 200 });
      }
      return new Response(JSON.stringify({ status: "pending_passkey_setup", provider: "google", email: "new@example.com", name: "N" }), { status: 200 });
    }));
    const onEnroll = vi.fn(async () => undefined);
    render(<SocialOnboardingDialog onEnroll={onEnroll} />);
    await screen.findByText("auth.onboard.title");
    expect(screen.queryByText("auth.onboard.passkeyCta")).toBeNull();

    fireEvent.change(screen.getByLabelText("auth.pk.dob"), { target: { value: "1990-05-01" } });
    fireEvent.click(screen.getByRole("checkbox"));
    fireEvent.click(screen.getByRole("button", { name: "auth.onboard.next" }));
    const cta = await screen.findByRole("button", { name: /auth.onboard.passkeyCta/ });
    expect(posts[0]).toMatchObject({ dob: "1990-05-01" });
    expect(onEnroll).not.toHaveBeenCalled();

    fireEvent.click(cta);
    await waitFor(() => expect(onEnroll).toHaveBeenCalledWith("su.ticket"));
  });

  it("shows nothing without a pending onboarding", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify({ status: "none" }), { status: 200 })));
    render(<SocialOnboardingDialog onEnroll={vi.fn()} />);
    await new Promise((r) => setTimeout(r, 20));
    expect(screen.queryByTestId("social-onboarding")).toBeNull();
  });
});
