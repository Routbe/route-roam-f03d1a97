import { describe, expect, it } from "vitest";
import { MAX_PDF_BYTES, sanitizePdf, stripHiddenText } from "./pdf-sanitizer";

const enc = (s: string) => Uint8Array.from(s, (c) => c.charCodeAt(0) & 0xff);
const dec = (b: Uint8Array) => Array.from(b, (x) => String.fromCharCode(x)).join("");

async function deflate(text: string): Promise<string> {
  const src = new ReadableStream<BufferSource>({ start(c) { c.enqueue(enc(text)); c.close(); } });
  const cs = src.pipeThrough(new CompressionStream("deflate"));
  return dec(new Uint8Array(await new Response(cs).arrayBuffer()));
}

/** Minimal valid PDF: objects are "<<dict>>" strings or { dict, data } streams. */
function pdf(objects: (string | { dict: string; data: string; length?: number })[], trailerExtra = ""): Uint8Array {
  let out = "%PDF-1.7\n%\xe2\xe3\xcf\xd3\n";
  const offs: number[] = [];
  objects.forEach((o, i) => {
    offs.push(out.length);
    if (typeof o === "string") out += `${i + 1} 0 obj\n${o}\nendobj\n`;
    else out += `${i + 1} 0 obj\n<<${o.dict} /Length ${o.length ?? o.data.length}>>\nstream\n${o.data}\nendstream\nendobj\n`;
  });
  const xref = out.length;
  out += `xref\n0 ${objects.length + 1}\n0000000000 65535 f \n`;
  for (const off of offs) out += `${String(off).padStart(10, "0")} 00000 n \n`;
  out += `trailer\n<< /Size ${objects.length + 1} /Root 1 0 R${trailerExtra} >>\nstartxref\n${xref}\n%%EOF\n`;
  return enc(out);
}

const PAGE = (contents: string) => [
  "<< /Type /Catalog /Pages 2 0 R >>",
  "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
  `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 300] /Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>`,
  contents,
  "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
];

const HIDDEN = "BT /F1 12 Tf 20 200 Td 3 Tr (secret) Tj ET BT /F1 12 Tf 20 180 Td 0 Tr 1 1 1 rg (white) Tj ET BT /F1 12 Tf 20 160 Td 0 g (visible) Tj ET BT /F1 1 Tf 20 140 Td (tiny) Tj ET";

async function pageText(bytes: Uint8Array): Promise<string> {
  const pdfjs = await import("pdfjs-dist/legacy/build/pdf.mjs");
  const doc = await pdfjs.getDocument({ data: bytes.slice(), isEvalSupported: false, useSystemFonts: false, disableFontFace: true }).promise;
  const page = await doc.getPage(1);
  const tc = await page.getTextContent();
  return tc.items.map((i) => ("str" in i ? i.str : "")).join(" ");
}

describe("sanitizePdf", () => {
  it("neutralises JavaScript and launch actions in place", async () => {
    const objs = PAGE(`<< /Length 0 >>`).slice();
    objs[0] = "<< /Type /Catalog /Pages 2 0 R /OpenAction << /S /JavaScript /JS (app.alert(1)) >> /AA << /O << /S /Launch /F (calc.exe) >> >> >>";
    objs[3] = { dict: "", data: "" } as never;
    const res = await sanitizePdf(pdf(objs));
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    const text = dec(res.bytes);
    for (const bad of ["/OpenAction", "/JavaScript", "/JS ", "/Launch", "/AA "]) expect(text).not.toContain(bad);
    expect(res.neutralized).toEqual(expect.arrayContaining(["OpenAction", "JavaScript", "JS", "AA", "Launch"]));
    expect(res.bytes.length).toBe(pdf(objs).length);
  });

  it("catches names hidden with # escapes", async () => {
    const objs = PAGE("") as unknown[];
    objs[0] = "<< /Type /Catalog /Pages 2 0 R /Open#41ction << /S /Java#53cript /JS (x) >> >>";
    objs[3] = { dict: "", data: "" };
    const res = await sanitizePdf(pdf(objs as never));
    expect(res.ok && res.neutralized).toEqual(expect.arrayContaining(["OpenAction", "JavaScript"]));
  });

  it("removes invisible, white and tiny text and keeps visible text, as a valid PDF", async () => {
    const input = pdf(PAGE({ dict: "", data: HIDDEN } as never) as never);
    const objs = PAGE("") as unknown[];
    objs[3] = { dict: "", data: HIDDEN };
    const original = pdf(objs as never);
    expect(await pageText(original)).toContain("secret");
    const res = await sanitizePdf(original);
    expect(res.ok).toBe(true);
    if (!res.ok) return;
    expect(res.removedText).toEqual({ invisible: 1, white: 1, tiny: 1 });
    const shown = await pageText(res.bytes);
    expect(shown).toContain("visible");
    for (const gone of ["secret", "white", "tiny"]) expect(shown).not.toContain(gone);
    const again = await sanitizePdf(res.bytes);
    expect(again.ok && again.removedText).toEqual({ invisible: 0, white: 0, tiny: 0 });
    expect(input.length).toBeGreaterThan(0);
  });

  it("cleans Flate-compressed content streams too", async () => {
    const objs = PAGE("") as unknown[];
    objs[3] = { dict: " /Filter /FlateDecode", data: await deflate(HIDDEN) };
    const res = await sanitizePdf(pdf(objs as never));
    expect(res.ok && res.removedText).toEqual({ invisible: 1, white: 1, tiny: 1 });
    if (res.ok) expect(await pageText(res.bytes)).not.toContain("secret");
  });

  it("refuses dangerous names inside compressed object streams", async () => {
    const objs = PAGE("") as unknown[];
    objs[3] = { dict: " /Type /ObjStm /N 1 /First 4 /Filter /FlateDecode", data: await deflate("9 0 << /S /JavaScript /JS (x) >>") };
    expect(await sanitizePdf(pdf(objs as never))).toEqual({ ok: false, reason: "hidden_in_object_stream" });
  });

  it("scans the data of a stream whose /Length lies", async () => {
    const objs = PAGE("") as unknown[];
    objs[3] = { dict: "", data: "BT ET\nendstream\nendobj\n9 0 obj << /S /Launch /F (x) >> endobj\n% ", length: 5 };
    const res = await sanitizePdf(pdf(objs as never));
    expect(res.ok && res.neutralized).toContain("Launch");
  });

  it("refuses encrypted, non-PDF and oversized input", async () => {
    const objs = PAGE("") as unknown[];
    objs[3] = { dict: "", data: "" };
    expect(await sanitizePdf(pdf(objs as never, " /Encrypt 9 0 R"))).toEqual({ ok: false, reason: "encrypted" });
    expect(await sanitizePdf(enc("hello"))).toEqual({ ok: false, reason: "not_pdf" });
    expect(await sanitizePdf(new Uint8Array(MAX_PDF_BYTES + 1))).toEqual({ ok: false, reason: "too_large" });
  });
});

describe("stripHiddenText", () => {
  it("keeps the render mode across text objects, as PDF does", () => {
    expect(stripHiddenText("BT 3 Tr (a) Tj ET BT (b) Tj ET").removed.invisible).toBe(2);
  });
  it("leaves ordinary text untouched", () => {
    const c = "BT /F1 11 Tf 0 0 0 rg 72 700 Td (Contract) Tj ET";
    expect(stripHiddenText(c).text).toBe(c);
  });
  it("uses the text matrix and CTM for the effective size", () => {
    expect(stripHiddenText("BT /F1 1 Tf 12 0 0 12 0 0 Tm (big) Tj ET").removed.tiny).toBe(0);
    expect(stripHiddenText("q 0.1 0 0 0.1 0 0 cm BT /F1 12 Tf (small) Tj ET Q").removed.tiny).toBe(1);
  });
  it("keeps inline image data intact", () => {
    const c = "BI /W 1 /H 1 ID \x00\xff(Tj EI BT /F1 12 Tf (ok) Tj ET";
    expect(stripHiddenText(c).text).toBe(c);
  });
});
