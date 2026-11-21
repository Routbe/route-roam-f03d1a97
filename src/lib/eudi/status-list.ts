/**
 * Token Status List (draft-ietf-oauth-status-list), 1 bit per credential: 0 = VALID, 1 = INVALID.
 * Bit i lives in byte floor(i/8) at position i % 8 (least significant bit first); the byte array is
 * compressed with DEFLATE in the zlib format (RFC 1950) and base64url-encoded as `lst`.
 * Every index without an active credential is published as INVALID. Browser- and worker-safe.
 */
import { b64uDecode, b64uEncode } from "@/lib/support/hybrid-signature";

export const STATUS_LIST_SIZE = 131072;
export const STATUS_LIST_ID = "rout-1";
export const STATUS_LIST_TYP = "statuslist+jwt";

async function pipe(bytes: Uint8Array, stream: CompressionStream | DecompressionStream): Promise<Uint8Array> {
  const out = new Response(new Blob([bytes as BlobPart]).stream().pipeThrough(stream));
  return new Uint8Array(await out.arrayBuffer());
}

/** Bits for `size` indices: everything INVALID except the active ones. */
export function statusBits(active: Iterable<number>, size = STATUS_LIST_SIZE): Uint8Array {
  const bytes = new Uint8Array(size / 8).fill(0xff);
  for (const i of active) {
    if (!Number.isInteger(i) || i < 0 || i >= size) continue;
    bytes[i >> 3]! &= ~(1 << (i & 7));
  }
  return bytes;
}

export async function encodeStatusList(bits: Uint8Array): Promise<string> {
  return b64uEncode(await pipe(bits, new CompressionStream("deflate")));
}

export async function decodeStatusList(lst: string, maxBytes = STATUS_LIST_SIZE / 8): Promise<Uint8Array> {
  const bytes = await pipe(b64uDecode(lst), new DecompressionStream("deflate"));
  if (bytes.length > maxBytes) throw new RangeError("status_list_size");
  return bytes;
}

/** 0 = VALID, 1 = INVALID; an index outside the list counts as INVALID. */
export function statusAt(bits: Uint8Array, idx: number): 0 | 1 {
  if (!Number.isInteger(idx) || idx < 0 || idx >= bits.length * 8) return 1;
  return ((bits[idx >> 3]! >> (idx & 7)) & 1) as 0 | 1;
}
