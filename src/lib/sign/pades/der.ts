/**
 * Minimal DER (X.690) encoder / reader for the PAdES engine. Pure, runs in the browser, the worker
 * and workerd. Only definite lengths; the reader refuses anything else instead of guessing.
 */

export class DerError extends Error {}

export type Node = {
  tag: number; // first identifier octet (class | constructed | number < 31)
  start: number; // offset of the identifier octet
  headerLen: number;
  len: number; // content length
  bytes: Uint8Array; // the whole buffer
};

export const content = (n: Node) => n.bytes.subarray(n.start + n.headerLen, n.start + n.headerLen + n.len);
export const raw = (n: Node) => n.bytes.subarray(n.start, n.start + n.headerLen + n.len);

export function read(bytes: Uint8Array, at = 0): Node {
  if (at + 2 > bytes.length) throw new DerError("truncated");
  const tag = bytes[at]!;
  if ((tag & 0x1f) === 0x1f) throw new DerError("high_tag");
  let l = bytes[at + 1]!;
  let headerLen = 2;
  if (l & 0x80) {
    const n = l & 0x7f;
    if (n === 0 || n > 4) throw new DerError("length");
    if (at + 2 + n > bytes.length) throw new DerError("truncated");
    l = 0;
    for (let i = 0; i < n; i++) l = l * 256 + bytes[at + 2 + i]!;
    headerLen += n;
  }
  if (at + headerLen + l > bytes.length) throw new DerError("truncated");
  return { tag, start: at, headerLen, len: l, bytes };
}

/** The children of a constructed node. */
export function children(n: Node): Node[] {
  if (!(n.tag & 0x20)) throw new DerError("not_constructed");
  const out: Node[] = [];
  let at = n.start + n.headerLen;
  const end = at + n.len;
  while (at < end) {
    const c = read(n.bytes, at);
    out.push(c);
    at = c.start + c.headerLen + c.len;
  }
  if (at !== end) throw new DerError("overrun");
  return out;
}

export function child(n: Node, i: number, tag?: number): Node {
  const c = children(n)[i];
  if (!c || (tag !== undefined && c.tag !== tag)) throw new DerError("shape");
  return c;
}

/** Parses exactly one top-level element covering the whole input. */
export function parse(bytes: Uint8Array): Node {
  const n = read(bytes, 0);
  if (n.headerLen + n.len !== bytes.length) throw new DerError("trailing");
  return n;
}

// ---- encoding ------------------------------------------------------------------------------

export function concat(parts: readonly Uint8Array[]): Uint8Array {
  let len = 0;
  for (const p of parts) len += p.length;
  const out = new Uint8Array(len);
  let o = 0;
  for (const p of parts) { out.set(p, o); o += p.length; }
  return out;
}

export function tlv(tag: number, body: Uint8Array | readonly Uint8Array[]): Uint8Array {
  const b = body instanceof Uint8Array ? body : concat(body);
  const l = b.length;
  let head: number[];
  if (l < 0x80) head = [tag, l];
  else if (l < 0x100) head = [tag, 0x81, l];
  else if (l < 0x10000) head = [tag, 0x82, l >> 8, l & 0xff];
  else if (l < 0x1000000) head = [tag, 0x83, l >> 16, (l >> 8) & 0xff, l & 0xff];
  else head = [tag, 0x84, (l >>> 24) & 0xff, (l >> 16) & 0xff, (l >> 8) & 0xff, l & 0xff];
  return concat([Uint8Array.from(head), b]);
}

export const seq = (...items: Uint8Array[]) => tlv(0x30, items);
export const set = (...items: Uint8Array[]) => tlv(0x31, sortSet(items));
export const octets = (b: Uint8Array) => tlv(0x04, b);
export const nul = () => Uint8Array.of(0x05, 0x00);
export const bool = (v: boolean) => Uint8Array.of(0x01, 0x01, v ? 0xff : 0x00);
/** [n] EXPLICIT */
export const ctx = (n: number, ...items: Uint8Array[]) => tlv(0xa0 | n, items);

/** DER SET OF: elements sorted by their encodings (X.690 11.6). */
function sortSet(items: Uint8Array[]): Uint8Array[] {
  return [...items].sort((a, b) => {
    const n = Math.min(a.length, b.length);
    for (let i = 0; i < n; i++) if (a[i] !== b[i]) return a[i]! - b[i]!;
    return a.length - b.length;
  });
}

export function int(v: number | bigint | Uint8Array): Uint8Array {
  if (v instanceof Uint8Array) {
    // Unsigned big-endian magnitude → minimal two's complement.
    let i = 0;
    while (i < v.length - 1 && v[i] === 0) i++;
    const m = v.subarray(i);
    return tlv(0x02, m[0]! & 0x80 ? concat([Uint8Array.of(0), m]) : m);
  }
  let n = BigInt(v);
  if (n < 0n) throw new DerError("negative");
  const out: number[] = [];
  do { out.unshift(Number(n & 0xffn)); n >>= 8n; } while (n > 0n);
  if (out[0]! & 0x80) out.unshift(0);
  return tlv(0x02, Uint8Array.from(out));
}

export function oid(dotted: string): Uint8Array {
  const parts = dotted.split(".").map((x) => BigInt(x));
  if (parts.length < 2) throw new DerError("oid");
  const out: number[] = [];
  const first = parts[0]! * 40n + parts[1]!;
  for (const p of [first, ...parts.slice(2)]) {
    const stack: number[] = [];
    let x = p;
    stack.unshift(Number(x & 0x7fn));
    x >>= 7n;
    while (x > 0n) { stack.unshift(Number((x & 0x7fn) | 0x80n)); x >>= 7n; }
    out.push(...stack);
  }
  return tlv(0x06, Uint8Array.from(out));
}

export function oidString(n: Node): string {
  if (n.tag !== 0x06) throw new DerError("not_oid");
  const c = content(n);
  const parts: bigint[] = [];
  let x = 0n;
  for (const b of c) {
    x = (x << 7n) | BigInt(b & 0x7f);
    if (!(b & 0x80)) { parts.push(x); x = 0n; }
  }
  const f = parts.shift() ?? 0n;
  const a = f < 80n ? f / 40n : 2n;
  return [a, f - a * 40n, ...parts].join(".");
}

/** GeneralizedTime YYYYMMDDHHMMSSZ (UTC, whole seconds). */
export function generalizedTime(d: Date): Uint8Array {
  const p = (n: number, w = 2) => String(n).padStart(w, "0");
  const s = `${p(d.getUTCFullYear(), 4)}${p(d.getUTCMonth() + 1)}${p(d.getUTCDate())}${p(d.getUTCHours())}${p(d.getUTCMinutes())}${p(d.getUTCSeconds())}Z`;
  return tlv(0x18, new TextEncoder().encode(s));
}

export const equalBytes = (a: Uint8Array, b: Uint8Array) => a.length === b.length && a.every((x, i) => x === b[i]);

export const OID = {
  sha1: "1.3.14.3.2.26",
  sha256: "2.16.840.1.101.3.4.2.1",
  sha384: "2.16.840.1.101.3.4.2.2",
  sha512: "2.16.840.1.101.3.4.2.3",
  rsaEncryption: "1.2.840.113549.1.1.1",
  sha256WithRSA: "1.2.840.113549.1.1.11",
  sha384WithRSA: "1.2.840.113549.1.1.12",
  sha512WithRSA: "1.2.840.113549.1.1.13",
  rsaPss: "1.2.840.113549.1.1.10",
  ecPublicKey: "1.2.840.10045.2.1",
  ecdsaWithSHA256: "1.2.840.10045.4.3.2",
  ecdsaWithSHA384: "1.2.840.10045.4.3.3",
  ecdsaWithSHA512: "1.2.840.10045.4.3.4",
  p256: "1.2.840.10045.3.1.7",
  p384: "1.3.132.0.34",
  p521: "1.3.132.0.35",
  data: "1.2.840.113549.1.7.1",
  signedData: "1.2.840.113549.1.7.2",
  contentType: "1.2.840.113549.1.9.3",
  messageDigest: "1.2.840.113549.1.9.4",
  signingCertificateV2: "1.2.840.113549.1.9.16.2.47",
  signatureTimeStampToken: "1.2.840.113549.1.9.16.2.14",
  tstInfo: "1.2.840.113549.1.9.16.1.4",
  authorityInfoAccess: "1.3.6.1.5.5.7.1.1",
  ocsp: "1.3.6.1.5.5.7.48.1",
  caIssuers: "1.3.6.1.5.5.7.48.2",
  crlDistributionPoints: "2.5.29.31",
  ocspBasic: "1.3.6.1.5.5.7.48.1.1",
} as const;
