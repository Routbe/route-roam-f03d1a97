import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor } from "@testing-library/react";
import nl from "@/locales/nl.json";
import { ProfileBadge } from "./ProfileBadge";

const dict = nl as unknown as Record<string, string>;
vi.mock("@/lib/i18n", () => ({ useI18n: () => ({ locale: "nl", t: (k: string) => dict[k] ?? k }) }));
const verify = vi.fn(async (_att: unknown, _shown: unknown): Promise<"valid" | "invalid" | "unavailable"> => "valid");
vi.mock("@/lib/identity/badge-verify", () => ({ verifyBadgeAttestation: (a: unknown, s: unknown) => verify(a, s) }));
const ATT = { kid: "0123456789abcdef", payload: "{}", sig: "A".repeat(86) };
afterEach(cleanup);

function open(name: string) {
  fireEvent.click(screen.getByRole("button", { name }));
  return screen.getByRole("dialog");
}

describe("verification card behind the profile marks", () => {
  it("blue mark verified by the ROUT team shows name, country, month and the team text", () => {
    render(<ProfileBadge type="verified" method="team" legalName="Jona Delplanche" country="be" verifiedAt="2026-10-10T08:16:00Z" size="sm" />);
    const card = open("KYC Attested — identiteit bevestigd");
    expect(card.textContent).toContain("KYC Attested — identiteit bevestigd");
    expect(card.textContent).toContain("Jona Delplanche · BE");
    expect(card.textContent).toContain("Geverifieerd in oktober 2026");
    expect(card.textContent).toContain("Geverifieerd door het ROUT-team");
    expect(card.textContent).toContain("Officiële identiteitscontrole (KYC) via een identiteitsdocument.");
  });

  it("blue mark from Didit says it was validated through Didit", () => {
    render(<ProfileBadge type="verified" method="didit" legalName="Anna Peeters" country="BE" verifiedAt="2026-11-02T10:00:00Z" size="sm" />);
    const card = open("KYC Attested — identiteit bevestigd");
    expect(card.textContent).toContain("Anna Peeters · BE");
    expect(card.textContent).toContain("Geverifieerd in november 2026");
    expect(card.textContent).toContain("Geverifieerd via ROUT met Didit");
    expect(card.textContent).not.toContain("ROUT-team");
  });

  it("white mark on a private alias never shows a name or country", () => {
    render(<ProfileBadge type="linked" legalName="Jona Delplanche" country="BE" verifiedAt="2026-10-10T08:16:00Z" size="sm" />);
    const card = open("Gekoppeld aan geverifieerd hoofdaccount");
    expect(card.textContent).toContain("Echt mens met geverifieerd hoofdprofiel");
    expect(card.textContent).toContain("Anonimiteit gegarandeerd");
    expect(card.textContent).not.toContain("Jona");
    expect(card.textContent).not.toContain("BE");
  });

  it("green shield explains the zero-knowledge proof without personal data", () => {
    render(<ProfileBadge type="human" legalName="Jona Delplanche" country="BE" size="sm" />);
    const card = open("Geverifieerd mens");
    expect(card.textContent).toContain("Cryptografisch ZK-menselijkheidsbewijs");
    expect(card.textContent).not.toContain("Jona");
  });
});

describe("blue-mark card: keyboard, animation and signature", () => {
  it("trigger reports aria-expanded, has a 44 px tap target and Escape closes the card", async () => {
    render(<ProfileBadge type="verified" method="team" legalName="Jona Delplanche" country="BE" verifiedAt="2026-10-10T08:16:00Z" size="sm" />);
    const trigger = screen.getByRole("button", { name: "KYC Attested — identiteit bevestigd" });
    expect(trigger.getAttribute("aria-expanded")).toBe("false");
    expect(trigger.className).toContain("tap-badge");
    expect(trigger.className).toContain("focus-visible:ring-2");
    fireEvent.click(trigger);
    expect(trigger.getAttribute("aria-expanded")).toBe("true");
    const card = screen.getByRole("dialog");
    expect(card.querySelector('[data-testid="badge-card-shield"]')).not.toBeNull();
    expect(card.className).toContain("zoom-in-95");
    fireEvent.keyDown(card, { key: "Escape" });
    await waitFor(() => expect(screen.queryByRole("dialog")).toBeNull());
    expect(trigger.getAttribute("aria-expanded")).toBe("false");
  });

  it("shows the Ed25519 line once the signature checks out", async () => {
    verify.mockResolvedValueOnce("valid");
    render(<ProfileBadge type="verified" method="team" legalName="Jona Delplanche" country="BE" verifiedAt="2026-10-10T08:16:00Z" attestation={ATT} handle="jdelplanche" size="sm" />);
    const card = open("KYC Attested — identiteit bevestigd");
    await waitFor(() => expect(card.textContent).toContain("Enclave-handtekening valide • Ed25519"));
    expect(verify).toHaveBeenCalledWith(ATT, expect.objectContaining({ handle: "jdelplanche", name: "Jona Delplanche", country: "BE" }));
  });

  it("says so when the signature does not match", async () => {
    verify.mockResolvedValueOnce("invalid");
    render(<ProfileBadge type="verified" method="didit" legalName="Jona D." country="BE" verifiedAt="2026-10-10T08:16:00Z" attestation={ATT} handle="jdelplanche" size="sm" />);
    const card = open("KYC Attested — identiteit bevestigd");
    await waitFor(() => expect(card.textContent).toContain("Handtekening klopt niet"));
    expect(card.textContent).not.toContain("handtekening valide");
  });

  it("a minor's masked name is shown as given: first name and initial", () => {
    render(<ProfileBadge type="verified" method="didit" legalName="Jona D." country="BE" verifiedAt="2026-10-10T08:16:00Z" size="sm" />);
    const card = open("KYC Attested — identiteit bevestigd");
    expect(card.textContent).toContain("Jona D. · BE");
    expect(card.textContent).not.toContain("Delplanche");
  });

  it("no signature line without an attestation, and never on the white alias mark", () => {
    render(<ProfileBadge type="linked" attestation={ATT} size="sm" />);
    const card = open("Gekoppeld aan geverifieerd hoofdaccount");
    expect(card.querySelector("[data-signature]")).toBeNull();
  });
});
