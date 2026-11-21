import { cleanup, fireEvent, render, screen, within } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("react-i18next", () => ({ useTranslation: () => ({ i18n: { language: "nl" }, t: (k: string) => k }) }));
import { ProviderDiscoveryHub } from "./ProviderDiscoveryHub";

afterEach(cleanup);
const activeCards = () => within(screen.getByRole("region", { name: "Actieve providers" }));
const upcomingNames = () =>
  within(screen.getByRole("region", { name: "Toekomstige integraties" })).getAllByRole("article").map((a) => a.getAttribute("aria-label"));

describe("Provider Discovery Hub", () => {
  it("shows only Didit and W Identity as active cards and starts only a live engine", () => {
    const start = vi.fn();
    render(<ProviderDiscoveryHub active={new Set(["didit"])} busy={null} onStart={start} />);
    expect(activeCards().getAllByRole("article").map((a) => a.getAttribute("aria-label")).sort()).toEqual(["Didit", "W Identity"]);
    fireEvent.click(within(activeCards().getByRole("article", { name: "Didit" })).getByRole("button", { name: /Start verificatie/ }));
    expect(start).toHaveBeenCalledWith("didit");
    expect(within(activeCards().getByRole("article", { name: "W Identity" })).getByRole("button", { name: "Nog niet actief" })).toBeDisabled();
  });

  it("folds every provider without an engine into the upcoming grid, without start buttons", () => {
    render(<ProviderDiscoveryHub active={new Set(["didit", "w_identity"])} busy={null} onStart={() => {}} />);
    const names = upcomingNames();
    for (const n of ["itsme®", "DigiD", "eID / eIDAS", "France Identité", "MitID", "CIE", "IDnow", "Trulioo", "World ID"]) expect(names).toContain(n);
    expect(names).not.toContain("Didit");
    expect(within(screen.getByRole("region", { name: "Toekomstige integraties" })).queryAllByRole("button")).toEqual([]);
  });

  it("filters with the search bar and the chips", () => {
    render(<ProviderDiscoveryHub active={new Set()} busy={null} onStart={() => {}} />);
    expect(screen.getByPlaceholderText("Zoek provider, land of documenttype (bijv. itsme, DigiD, IDnow)...")).toBeInTheDocument();
    fireEvent.change(screen.getByRole("searchbox", { name: "Zoek een provider" }), { target: { value: "DigiD" } });
    expect(upcomingNames()).toEqual(["DigiD"]);
    expect(screen.queryByRole("region", { name: "Actieve providers" })).toBeNull();
    fireEvent.change(screen.getByRole("searchbox"), { target: { value: "" } });
    fireEvent.click(screen.getByRole("button", { name: "🛡️ Zero-Knowledge" }));
    expect(screen.getByRole("button", { name: "🛡️ Zero-Knowledge" })).toHaveAttribute("aria-pressed", "true");
    expect(activeCards().getAllByRole("article").map((a) => a.getAttribute("aria-label"))).toEqual(["W Identity"]);
    expect(upcomingNames()).toEqual(["World ID"]);
    fireEvent.change(screen.getByRole("searchbox"), { target: { value: "qqqq" } });
    expect(screen.getByText("Geen provider gevonden. Probeer een andere zoekterm.")).toBeInTheDocument();
  });

  it("shows the privacy ratings", () => {
    render(<ProviderDiscoveryHub active={new Set()} busy={null} onStart={() => {}} />);
    expect(within(screen.getByRole("region", { name: "Toekomstige integraties" }).querySelector('[aria-label="itsme®"]') as HTMLElement).getByText("EU eIDAS Hoog")).toBeInTheDocument();
    expect(within(activeCards().getByRole("article", { name: "Didit" })).getByText(/Biometrisch/)).toBeInTheDocument();
  });
});
