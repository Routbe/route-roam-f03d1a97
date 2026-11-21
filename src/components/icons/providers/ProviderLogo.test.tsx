import { cleanup, fireEvent, render } from "@testing-library/react";
import { existsSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { IDENTITY_PROVIDERS as PROVIDERS } from "@/lib/kyc/providers";
import { ProviderLogo } from "./ProviderLogo";
import { INLINE_PROVIDER_LOGOS, PROVIDER_LOGO_FILES } from "./provider-logos";

afterEach(cleanup);
const PUBLIC = join(__dirname, "..", "..", "..", "..", "public");

describe("ProviderLogo", () => {
  it("maps only to same-origin files that exist in public/logos", () => {
    for (const [id, path] of Object.entries(PROVIDER_LOGO_FILES)) {
      expect(path, id).toMatch(/^\/logos\/[a-z0-9-]+\.(svg|png)$/);
      expect(existsSync(join(PUBLIC, path)), path).toBe(true);
    }
  });

  it("stored SVG marks carry no script and no external reference", () => {
    for (const path of Object.values(PROVIDER_LOGO_FILES).filter((p) => p.endsWith(".svg"))) {
      const svg = readFileSync(join(PUBLIC, path), "utf8");
      expect(svg, path).not.toMatch(/<script|\son[a-z]+\s*=|<foreignObject/i);
      expect(svg.match(/(?:href|src)\s*=\s*["'](?!#)[^"']*/gi) ?? [], path).toEqual([]);
    }
  });

  it("covers every provider: inline vector, local file, or the eID fallback", () => {
    const missing = PROVIDERS.map((p) => p.id).filter((id) => !(id in PROVIDER_LOGO_FILES) && !(INLINE_PROVIDER_LOGOS as readonly string[]).includes(id));
    expect(missing).toEqual(["eid"]);
  });

  it("draws Didit and W Identity inline, without any image element", () => {
    for (const id of INLINE_PROVIDER_LOGOS) {
      const { container } = render(<ProviderLogo name={id} size="lg" />);
      expect(container.querySelector("img")).toBeNull();
      expect(container.querySelector("svg[role=img]")).not.toBeNull();
      cleanup();
    }
  });

  it("falls back to the neutral Building2 icon without a file and when the file fails", () => {
    const none = render(<ProviderLogo name="eid" />);
    expect(none.container.querySelector("[data-fallback]")).not.toBeNull();
    none.unmount();
    const { container } = render(<ProviderLogo name="digid" />);
    const img = container.querySelector("img")!;
    expect(img.getAttribute("src")).toBe("/logos/digid.svg");
    fireEvent.error(img);
    expect(container.querySelector("img")).toBeNull();
    expect(container.querySelector("[data-fallback]")).not.toBeNull();
  });

  it("keeps a fixed square box (32 px small, 40 px large)", () => {
    const { container } = render(<><ProviderLogo name="itsme" /><ProviderLogo name="itsme" size="lg" /></>);
    const [sm, lg] = [...container.querySelectorAll("[data-provider-logo]")];
    expect(sm!.className).toMatch(/\bh-8 w-8\b/);
    expect(lg!.className).toMatch(/\bh-10 w-10\b/);
  });
});
