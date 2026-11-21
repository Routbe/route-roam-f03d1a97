import { describe, expect, it } from "vitest";
import { keyFromFragment, keyToFragment, newDocumentKey, openDocument, sealDocument, SIGN_BUCKET } from "./sign-envelope";

describe("RSG1 document envelope", () => {
  it("round-trips and pads to 64 KiB buckets", async () => {
    const key = newDocumentKey();
    const pdf = new TextEncoder().encode("%PDF-1.7 hello");
    const env = await sealDocument(key, pdf, "original");
    expect(env.length).toBe(16 + SIGN_BUCKET + 16);
    expect(Array.from(await openDocument(key, env, "original"))).toEqual(Array.from(pdf));
  });
  it("binds the copy role and the key", async () => {
    const key = newDocumentKey();
    const env = await sealDocument(key, new Uint8Array([1, 2, 3]), "original");
    await expect(openDocument(key, env, "signed")).rejects.toThrow("decrypt");
    await expect(openDocument(newDocumentKey(), env, "original")).rejects.toThrow("decrypt");
  });
  it("keeps the key in a 43-character fragment", () => {
    const key = newDocumentKey();
    const f = keyToFragment(key);
    expect(f).toMatch(/^[A-Za-z0-9_-]{43}$/);
    expect(Array.from(keyFromFragment(`#k=${f}`)!)).toEqual(Array.from(key));
    expect(keyFromFragment("#k=short")).toBeNull();
  });
});
