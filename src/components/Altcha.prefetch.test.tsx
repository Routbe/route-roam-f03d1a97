import { afterEach, describe, expect, it, vi } from "vitest";
import { cleanup, render } from "@testing-library/react";

const prefetchProof = vi.fn(() => Promise.resolve("proof"));
vi.mock("@/lib/altcha-client", () => ({ prefetchProof: () => prefetchProof() }));
vi.mock("react-i18next", () => ({ useTranslation: () => ({ t: (k: string) => k }) }));
import { Altcha } from "./Altcha";

afterEach(() => { cleanup(); prefetchProof.mockClear(); });

describe("silent ALTCHA pre-fetch", () => {
  it("solves nothing while inactive and starts as soon as it is activated (e-mail focus)", () => {
    const { rerender } = render(<Altcha active={false} />);
    expect(prefetchProof).not.toHaveBeenCalled();
    rerender(<Altcha active />);
    expect(prefetchProof).toHaveBeenCalledTimes(1);
  });

  it("other forms keep solving on mount", () => {
    render(<Altcha />);
    expect(prefetchProof).toHaveBeenCalledTimes(1);
  });
});
