/**
 * Minimal PDF 1.4 writer for the donation receipt (Helvetica, A4, text only). Drawn in the
 * browser from the signed record, so no server ever renders or stores a receipt document.
 */
import { canonicalReceipt, type SignedReceipt } from "./receipt";

const ascii = (s: string) =>
  s.normalize("NFKD").replace(/[\u0300-\u036f]/g, "").replace(/[^\x20-\x7e]/g, "?");
const esc = (s: string) => ascii(s).replace(/\\/g, "\\\\").replace(/\(/g, "\\(").replace(/\)/g, "\\)");

function wrap(text: string, width: number): string[] {
  const out: string[] = [];
  for (let i = 0; i < text.length; i += width) out.push(text.slice(i, i + width));
  return out.length ? out : [""];
}

export type ReceiptLabels = { title: string; amount: string; date: string; method: string; level: string; index: string; tx: string; root: string; notTax: string; verify: string; levelNames: Record<1 | 2 | 3, string> };

export function receiptLines(s: SignedReceipt, l: ReceiptLabels): { text: string; size: number }[] {
  const r = s.receipt;
  const euro = `EUR ${(r.amountCents / 100).toFixed(2)}`;
  const lines: { text: string; size: number }[] = [
    { text: "ROUT", size: 20 },
    { text: l.title, size: 14 },
    { text: "", size: 10 },
    { text: `${l.amount}: ${euro}`, size: 11 },
    { text: `${l.date}: ${r.paidAt}`, size: 11 },
    { text: `${l.method}: ${r.rail === "sepa" ? "SEPA" : "Stripe"} (${r.confirmedVia})`, size: 11 },
    { text: `${l.level}: ${l.levelNames[r.level]}`, size: 11 },
  ];
  if (r.supporterIndex !== null) lines.push({ text: `${l.index}: #${r.supporterIndex}`, size: 11 });
  lines.push({ text: `${l.tx}: ${r.txHash}`, size: 8 });
  if (r.treeRoot) lines.push({ text: `${l.root} (${r.treeSize}): ${r.treeRoot}`, size: 8 });
  lines.push({ text: "", size: 10 }, { text: l.notTax, size: 9 }, { text: l.verify, size: 9 }, { text: "", size: 8 });
  for (const w of wrap(canonicalReceipt(r), 110)) lines.push({ text: w, size: 7 });
  lines.push({ text: `kid ${s.signature.kid}`, size: 7 }, { text: "Ed25519:", size: 7 });
  for (const w of wrap(s.signature.ed25519, 110)) lines.push({ text: w, size: 7 });
  if (s.signature.mldsa65) {
    lines.push({ text: "ML-DSA-65 (FIPS 204):", size: 7 });
    for (const w of wrap(s.signature.mldsa65, 110)) lines.push({ text: w, size: 7 });
  }
  return lines;
}

/** PDF bytes for the given lines; pages break automatically. */
export function buildPdf(lines: { text: string; size: number }[]): Uint8Array {
  const pages: string[] = [];
  let ops: string[] = [];
  let y = 800;
  const flush = () => {
    pages.push(ops.join("\n"));
    ops = [];
    y = 800;
  };
  for (const line of lines) {
    const lead = line.size + 4;
    if (y - lead < 40) flush();
    y -= lead;
    if (line.text) ops.push(`BT /F1 ${line.size} Tf 50 ${y} Td (${esc(line.text)}) Tj ET`);
  }
  flush();

  const objects: string[] = [];
  const pageIds = pages.map((_, i) => 4 + i * 2);
  objects[1] = "<< /Type /Catalog /Pages 2 0 R >>";
  objects[2] = `<< /Type /Pages /Kids [${pageIds.map((id) => `${id} 0 R`).join(" ")}] /Count ${pages.length} >>`;
  objects[3] = "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>";
  pages.forEach((content, i) => {
    const pageId = pageIds[i]!;
    objects[pageId] = `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 3 0 R >> >> /Contents ${pageId + 1} 0 R >>`;
    objects[pageId + 1] = `<< /Length ${content.length} >>\nstream\n${content}\nendstream`;
  });

  let out = "%PDF-1.4\n";
  const offsets: number[] = [];
  for (let id = 1; id < objects.length; id++) {
    offsets[id] = out.length;
    out += `${id} 0 obj\n${objects[id]}\nendobj\n`;
  }
  const xref = out.length;
  out += `xref\n0 ${objects.length}\n0000000000 65535 f \n`;
  for (let id = 1; id < objects.length; id++) out += `${String(offsets[id]).padStart(10, "0")} 00000 n \n`;
  out += `trailer\n<< /Size ${objects.length} /Root 1 0 R >>\nstartxref\n${xref}\n%%EOF\n`;
  return new TextEncoder().encode(out);
}
