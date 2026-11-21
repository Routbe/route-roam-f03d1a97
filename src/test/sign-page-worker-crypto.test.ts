import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

// ROUT Sign browser pages: every cryptographic step (seal, open, attest, envelope hash) runs in the
// crypto worker (src/lib/crypto-enclave), never through main-thread WebCrypto.
const SIGN_UI_FILES = ["src/routes/sign.$requestId.tsx", "src/routes/_authenticated/sign.index.tsx"];

describe("ROUT Sign pages use the crypto worker only", () => {
  for (const file of SIGN_UI_FILES) {
    it(`${file} makes no main-thread crypto.subtle call`, () => {
      const src = readFileSync(file, "utf8");
      expect(src).not.toMatch(/crypto\s*\.\s*subtle|\bsubtle\s*\.\s*(digest|encrypt|decrypt|sign|verify|importKey|deriveKey|deriveBits)\b/);
    });
  }

  it("the signed-record check hashes the envelope through the worker op", () => {
    const src = readFileSync("src/routes/sign.$requestId.tsx", "utf8");
    expect(src).toContain("enclave.sign.envelopeSha256(");
  });
});
