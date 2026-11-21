/**
 * ROUT Sign PDF sanitizer (pure TypeScript, runs in the browser and on the server).
 *
 * What it guarantees for the returned bytes, or it refuses the file:
 * - Active content is neutralised in place: every live name token that starts an action or
 *   carries code (/JavaScript, /JS, /Launch, /OpenAction, /AA, /EmbeddedFile(s), /RichMedia,
 *   /SubmitForm, /ImportData, /GoToR, /GoToE, /XFA, /Sound, /Movie) is overwritten with an inert
 *   name of the same length, so offsets and the xref stay valid.
 * - Hidden text is removed from every live content stream: text drawn with an invisible render
 *   mode (3 or 7), in white fill, or at an effective size below 4 pt. The cleaned streams are
 *   written as an incremental update, so what the signer sees is exactly what is signed.
 * - Encrypted PDFs, names hidden inside compressed object streams, and streams with filters other
 *   than FlateDecode that could hold content or objects are refused, never passed through.
 *
 * It is a defensive filter, not a full PDF parser: anything it cannot reason about is refused.
 */

export const MAX_PDF_BYTES = 8 * 1024 * 1024;
export const MIN_VISIBLE_PT = 4;

const DANGEROUS = new Set([
  "JavaScript", "JS", "Launch", "OpenAction", "AA", "EmbeddedFile", "EmbeddedFiles", "RichMedia",
  "SubmitForm", "ImportData", "GoToR", "GoToE", "XFA", "Sound", "Movie",
]);

export type HiddenKind = "invisible" | "white" | "tiny";
export type SanitizeRefusal = "not_pdf" | "too_large" | "encrypted" | "hidden_in_object_stream" | "unsupported_stream" | "malformed";
export type SanitizeResult =
  | { ok: true; bytes: Uint8Array; neutralized: string[]; removedText: Record<HiddenKind, number> }
  | { ok: false; reason: SanitizeRefusal };

const latin1 = (b: Uint8Array) => {
  let s = "";
  for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode(...b.subarray(i, i + 0x8000));
  return s;
};
const fromLatin1 = (s: string) => {
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i) & 0xff;
  return out;
};
const DELIM = /[\s()<>\[\]{}\/%]/;
const decodeName = (raw: string) => raw.replace(/#([0-9a-fA-F]{2})/g, (_, h: string) => String.fromCharCode(parseInt(h, 16)));

type StreamObj = { num: number; gen: number; dict: string; dataStart: number; dataEnd: number; objStart: number };

/** Every `N G obj << … >> stream … endstream` in file order. */
function findStreams(s: string): StreamObj[] {
  const out: StreamObj[] = [];
  const re = /(\d+)\s+(\d+)\s+obj\b/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(s))) {
    const objStart = m.index;
    const end = s.indexOf("endobj", re.lastIndex);
    if (end < 0) break;
    const body = s.slice(re.lastIndex, end);
    const st = /\bstream(\r\n|\n|\r)/.exec(body);
    if (st && body.slice(0, st.index).trimStart().startsWith("<<")) {
      const dataStart = re.lastIndex + st.index + st[0].length;
      const es = s.lastIndexOf("endstream", end);
      if (es > dataStart) {
        let dataEnd = es;
        if (s[dataEnd - 1] === "\n") dataEnd--;
        if (s[dataEnd - 1] === "\r") dataEnd--;
        out.push({ num: Number(m[1]), gen: Number(m[2]), dict: body.slice(0, st.index), dataStart, dataEnd, objStart });
      }
    }
    re.lastIndex = end + 6;
  }
  return out;
}

async function inflate(data: Uint8Array): Promise<Uint8Array | null> {
  try {
    const ds = new DecompressionStream("deflate");
    const stream = new ReadableStream<BufferSource>({
      start(c) {
        c.enqueue(data as BufferSource);
        c.close();
      },
    }).pipeThrough(ds);
    return new Uint8Array(await new Response(stream).arrayBuffer());
  } catch {
    return null;
  }
}

function filters(dict: string): string[] | null {
  const m = /\/Filter\s*(\/[A-Za-z0-9]+|\[[^\]]*\])/.exec(dict);
  if (!m) return [];
  const names = m[1]!.match(/\/[A-Za-z0-9]+/g) ?? [];
  return names.map((n) => n.slice(1));
}

const has = (dict: string, re: RegExp) => re.test(dict);

type Tok = { t: "num" | "op" | "other"; v: string; start: number; end: number };

/** Content-stream tokenizer: skips strings, hex strings, arrays' brackets, dicts and inline images. */
function tokenize(c: string): Tok[] {
  const toks: Tok[] = [];
  let i = 0;
  const n = c.length;
  while (i < n) {
    const ch = c[i]!;
    if (/\s/.test(ch)) { i++; continue; }
    const start = i;
    if (ch === "%") { while (i < n && c[i] !== "\n" && c[i] !== "\r") i++; continue; }
    if (ch === "(") {
      let depth = 1; i++;
      while (i < n && depth > 0) { if (c[i] === "\\") i += 2; else { if (c[i] === "(") depth++; else if (c[i] === ")") depth--; i++; } }
      toks.push({ t: "other", v: "(", start, end: i }); continue;
    }
    if (ch === "<" && c[i + 1] === "<") { toks.push({ t: "other", v: "<<", start, end: i + 2 }); i += 2; continue; }
    if (ch === ">" && c[i + 1] === ">") { toks.push({ t: "other", v: ">>", start, end: i + 2 }); i += 2; continue; }
    if (ch === "<") { const e = c.indexOf(">", i); i = e < 0 ? n : e + 1; toks.push({ t: "other", v: "<", start, end: i }); continue; }
    if (ch === "[" || ch === "]" || ch === "{" || ch === "}") { toks.push({ t: "other", v: ch, start, end: i + 1 }); i++; continue; }
    if (ch === "/") { i++; while (i < n && !DELIM.test(c[i]!)) i++; toks.push({ t: "other", v: c.slice(start, i), start, end: i }); continue; }
    while (i < n && !DELIM.test(c[i]!)) i++;
    if (i === start) { i++; continue; }
    const v = c.slice(start, i);
    if (/^[+-]?(\d+\.?\d*|\.\d+)$/.test(v)) toks.push({ t: "num", v, start, end: i });
    else {
      toks.push({ t: "op", v, start, end: i });
      if (v === "ID") {
        const e = c.slice(i).search(/\sEI(\s|$)/);
        i = e < 0 ? n : i + e + 3;
      }
    }
  }
  return toks;
}

type Gs = { fillWhite: boolean; ctmScale: number; tr: number; fontSize: number; tmScale: number };

/**
 * Removes hidden text-showing operations from one content stream. Returns the cleaned text and
 * what was removed; unchanged input returns the same string.
 */
export function stripHiddenText(content: string): { text: string; removed: Record<HiddenKind, number> } {
  const toks = tokenize(content);
  const removed: Record<HiddenKind, number> = { invisible: 0, white: 0, tiny: 0 };
  const cut: { a: number; b: number; nextLine: boolean }[] = [];
  const stack: Gs[] = [];
  let gs: Gs = { fillWhite: false, ctmScale: 1, tr: 0, fontSize: 12, tmScale: 1 };
  let operandStart = -1;
  let nums: number[] = [];
  for (const tk of toks) {
    if (tk.t !== "op") {
      if (operandStart < 0) operandStart = tk.start;
      if (tk.t === "num") nums.push(Number(tk.v));
      continue;
    }
    const op = tk.v;
    switch (op) {
      case "q": stack.push({ ...gs }); break;
      case "Q": gs = stack.pop() ?? gs; break;
      case "cm": if (nums.length >= 6) gs.ctmScale *= Math.hypot(nums[nums.length - 4]!, nums[nums.length - 3]!) || 1; break;
      case "rg": if (nums.length >= 3) gs.fillWhite = nums.slice(-3).every((x) => x >= 0.98); break;
      case "g": if (nums.length >= 1) gs.fillWhite = nums[nums.length - 1]! >= 0.98; break;
      case "k": if (nums.length >= 4) gs.fillWhite = nums.slice(-4).every((x) => x <= 0.02); break;
      case "sc": case "scn": case "cs": gs.fillWhite = false; break;
      case "Tr": if (nums.length) gs.tr = nums[nums.length - 1]!; break;
      case "Tf": if (nums.length) gs.fontSize = Math.abs(nums[nums.length - 1]!); break;
      case "BT": gs.tmScale = 1; break;
      case "Tm": if (nums.length >= 6) gs.tmScale = Math.hypot(nums[nums.length - 4]!, nums[nums.length - 3]!) || 0; break;
      case "Tj": case "TJ": case "'": case "\"": {
        const kind: HiddenKind | null = gs.tr === 3 || gs.tr === 7 ? "invisible" : gs.fillWhite ? "white"
          : gs.fontSize * gs.tmScale * gs.ctmScale < MIN_VISIBLE_PT ? "tiny" : null;
        if (kind) {
          removed[kind]++;
          // ' and " also move to the next line: keep the move, drop the text.
          cut.push({ a: operandStart < 0 ? tk.start : operandStart, b: tk.end, nextLine: op === "'" || op === "\"" });
        }
        break;
      }
    }
    operandStart = -1;
    nums = [];
  }
  if (!cut.length) return { text: content, removed };
  let out = "";
  let last = 0;
  for (const c of cut) {
    out += content.slice(last, c.a) + (c.nextLine ? " T* " : " ");
    last = c.b;
  }
  return { text: out + content.slice(last), removed };
}

const isContentCandidate = (dict: string) =>
  !has(dict, /\/Subtype\s*\/Image\b/) && !has(dict, /\/Type\s*\/(XRef|ObjStm|Metadata|EmbeddedFile|XObject\s*\/Subtype\s*\/Image)\b/) &&
  !has(dict, /\/Length[123]\b/) && !has(dict, /\/Subtype\s*\/(Type1C|CIDFontType0C|OpenType|XML)\b/) && !has(dict, /\/N\s+[134]\b[^]*\/Alternate|\/Alternate[^]*\/N\s+[134]\b/);

/** Removes `/Key value` pairs (one PDF value each) from a dictionary's text. */
function stripKeys(dict: string, keys: string[]): string {
  const toks = tokenize(dict);
  const cuts: [number, number][] = [];
  for (let i = 0; i < toks.length; i++) {
    const tk = toks[i]!;
    if (!keys.includes(tk.v)) continue;
    let j = i + 1;
    let depth = 0;
    for (; j < toks.length; j++) {
      const v = toks[j]!.v;
      if (v === "[" || v === "<<") depth++;
      else if (v === "]" || v === ">>") depth--;
      if (depth === 0) {
        if (toks[j]!.t === "num" && toks[j + 2]?.v === "R") j += 2;
        break;
      }
    }
    cuts.push([tk.start, toks[j]?.end ?? tk.end]);
    i = j;
  }
  let out = "";
  let last = 0;
  for (const [a, b] of cuts) { out += dict.slice(last, a) + " "; last = b; }
  return out + dict.slice(last);
}

/** Direct or indirect (`N G R`) integer /Length of a stream dictionary, else null. */
function streamLength(s: string, dict: string): number | null {
  const direct = /\/Length\s+(\d+)(?!\d)(?!\s+\d+\s+R)/.exec(dict);
  if (direct) return Number(direct[1]);
  const ref = /\/Length\s+(\d+)\s+(\d+)\s+R/.exec(dict);
  if (!ref) return null;
  const def = [...s.matchAll(new RegExp(`(?:^|[^0-9])${ref[1]}\\s+${ref[2]}\\s+obj\\s*(\\d+)\\s*endobj`, "g"))].pop();
  return def ? Number(def[1]) : null;
}

/** Overwrites dangerous name tokens in s[from, to) inside `chars` with an inert name of equal length. */
function neutralizeNames(s: string, from: number, to: number, chars: string[], found: string[]): void {
  const re = /\/([^\s()<>\[\]{}\/%]+)/g;
  re.lastIndex = from;
  let m: RegExpExecArray | null;
  while ((m = re.exec(s)) && m.index < to) {
    const name = decodeName(m[1]!);
    if (!DANGEROUS.has(name)) continue;
    found.push(name);
    chars[m.index + 1] = "N";
    for (let k = 2; k <= m[1]!.length; k++) chars[m.index + k] = "x";
  }
}

export async function sanitizePdf(input: Uint8Array): Promise<SanitizeResult> {
  if (input.length > MAX_PDF_BYTES) return { ok: false, reason: "too_large" };
  const head = latin1(input.subarray(0, 1024));
  if (!head.includes("%PDF-")) return { ok: false, reason: "not_pdf" };
  let s = latin1(input);
  if (/\/Encrypt\s*(\d+\s+\d+\s+R|<<)/.test(s)) return { ok: false, reason: "encrypted" };
  const sx = /startxref\s+(\d+)\s+%%EOF\s*$/.exec(s.slice(-2048));
  const root = [...s.matchAll(/\/Root\s+(\d+\s+\d+\s+R)/g)].pop();
  if (!sx || !root) return { ok: false, reason: "malformed" };

  const streams = findStreams(s);
  // The last definition of an object is the live one (incremental updates).
  const live = new Map<number, StreamObj>();
  for (const st of streams) live.set(st.num, st);

  // 1. Active content: neutralise dangerous names in place everywhere a reader could parse objects.
  // Stream data is skipped only where the stream's /Length agrees with our boundaries, so a
  // stream that lies about its length can never hide objects from the scan.
  const trusted = streams
    .filter((st) => streamLength(s, st.dict) === st.dataEnd - st.dataStart)
    .map((st) => [st.dataStart, st.dataEnd] as const);
  const neutralized: string[] = [];
  const chars = s.split("");
  let segStart = 0;
  for (const [a, b] of [...trusted, [s.length, s.length] as const]) {
    neutralizeNames(s, segStart, a, chars, neutralized);
    segStart = b;
  }
  s = chars.join("");
  const dictOf = (st: StreamObj) => s.slice(st.objStart, st.dataStart);

  // 2. Live streams: object streams may not hide dangerous names; content streams lose hidden text.
  const removedText: Record<HiddenKind, number> = { invisible: 0, white: 0, tiny: 0 };
  const rewritten: { num: number; gen: number; dict: string; data: string }[] = [];
  for (const st of live.values()) {
    const f = filters(st.dict);
    const isObjStm = has(st.dict, /\/Type\s*\/ObjStm\b/);
    if (!isObjStm && !isContentCandidate(st.dict)) continue;
    const raw = input.subarray(st.dataStart, st.dataEnd);
    let data: Uint8Array | null;
    if (f === null || f.length === 0) data = raw;
    else if (f.length === 1 && f[0] === "FlateDecode" && !has(st.dict, /\/DecodeParms/)) data = await inflate(raw);
    else if (isObjStm) return { ok: false, reason: "unsupported_stream" };
    else if (f.some((x) => x === "DCTDecode" || x === "JPXDecode" || x === "JBIG2Decode" || x === "CCITTFaxDecode")) continue;
    else return { ok: false, reason: "unsupported_stream" };
    if (!data) return { ok: false, reason: "unsupported_stream" };
    const text = latin1(data);
    if (isObjStm) {
      const probe: string[] = [];
      neutralizeNames(text, 0, text.length, text.split(""), probe);
      if (probe.length) return { ok: false, reason: "hidden_in_object_stream" };
      continue;
    }
    if (!/\bBT\b/.test(text)) continue;
    const res = stripHiddenText(text);
    if (res.text === text) continue;
    for (const k of Object.keys(removedText) as HiddenKind[]) removedText[k] += res.removed[k];
    const head = dictOf(st);
    const dictText = head.slice(head.search(/<</), head.lastIndexOf(">>") + 2);
    const dict = stripKeys(dictText, ["/Length", "/Filter", "/DecodeParms"]).trim();
    rewritten.push({ num: st.num, gen: st.gen, dict, data: res.text });
  }

  let out = s;
  if (rewritten.length) {
    const sizeMatch = [...s.matchAll(/\/Size\s+(\d+)\b/g)].pop();
    const info = [...s.matchAll(/\/Info\s+(\d+\s+\d+\s+R)/g)].pop();
    const maxNum = Math.max(...[...live.keys()], ...rewritten.map((r) => r.num));
    const size = Math.max(Number(sizeMatch?.[1] ?? 0), maxNum + 1);
    if (!out.endsWith("\n")) out += "\n";
    const offsets: { num: number; gen: number; off: number }[] = [];
    for (const r of rewritten.sort((a, b) => a.num - b.num)) {
      offsets.push({ num: r.num, gen: r.gen, off: out.length });
      const inner = r.dict.replace(/^<<|>>$/g, "");
      out += `${r.num} ${r.gen} obj\n<<${inner} /Length ${r.data.length}>>\nstream\n${r.data}\nendstream\nendobj\n`;
    }
    const xrefAt = out.length;
    out += "xref\n";
    for (const o of offsets) out += `${o.num} 1\n${String(o.off).padStart(10, "0")} ${String(o.gen).padStart(5, "0")} n \n`;
    out += `trailer\n<< /Size ${size} /Root ${root[1]}${info ? ` /Info ${info[1]}` : ""} /Prev ${sx[1]} >>\nstartxref\n${xrefAt}\n%%EOF\n`;
  }
  return { ok: true, bytes: fromLatin1(out), neutralized, removedText };
}

/** Hex SHA-256 (WebCrypto, browser and server). */
export async function sha256Hex(bytes: Uint8Array): Promise<string> {
  const d = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes as BufferSource));
  return [...d].map((b) => b.toString(16).padStart(2, "0")).join("");
}
