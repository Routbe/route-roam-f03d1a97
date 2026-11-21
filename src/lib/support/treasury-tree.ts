/**
 * Treasury ledger: an index-keyed sparse Merkle tree of depth 32 over Poseidon (the rout-zk
 * x5_255_3 instance in src/lib/kyc/poseidon.ts, node hash = hash2(TAG_MERKLE_2, left, right),
 * empty leaf = 0). Every paid donation appends one leaf at the next index.
 *
 * A leaf is a commitment to (privacy level, verified-human flag, amount, month, nonce). The
 * nonce is 31 random bytes that only the donor's proof file and the sealed credential hold,
 * so the leaf itself reveals nothing; opening it shows amount and month, never a person.
 *
 * Honest scope: an inclusion proof is a Merkle proof, not a zero-knowledge proof. A verifier
 * learns the index and the opened values, but nothing that names the donor.
 */
import { poseidonHash2, TAG_MERKLE_2 } from "@/lib/kyc/poseidon";

export const TREE_DEPTH = 32;
export const MAX_LEAVES = 2n ** BigInt(TREE_DEPTH);
/** ASCII "SUPPORT" as the capacity tag of leaf commitments (domain-separated from nodes). */
export const TAG_SUPPORT_LEAF = 0x53555050_4f5254n;
export const INCLUSION_PROOF_VERSION = "rout.treasury.inclusion.v1";

const HEX64 = /^[0-9a-f]{64}$/;
const NONCE_HEX = /^[0-9a-f]{62}$/;
const MONTH = /^(\d{4})-(0[1-9]|1[0-2])$/;

export const toHex = (v: bigint): string => {
  if (v < 0n) throw new RangeError("negative");
  return v.toString(16).padStart(64, "0");
};
export const fromHex = (h: string): bigint => {
  if (typeof h !== "string" || !HEX64.test(h)) throw new RangeError("hex_invalid");
  return BigInt(`0x${h}`);
};
export const hashNode = (left: bigint, right: bigint): bigint => poseidonHash2(TAG_MERKLE_2, left, right);

let zeros: bigint[] | null = null;
/** zeros[l] = root of an empty subtree of height l; zeros[0] = 0 (empty leaf). */
export function zeroHashes(): readonly bigint[] {
  if (!zeros) {
    const z = [0n];
    for (let l = 0; l < TREE_DEPTH; l++) z.push(hashNode(z[l]!, z[l]!));
    zeros = z;
  }
  return zeros;
}
export const emptyRoot = (): bigint => zeroHashes()[TREE_DEPTH]!;

export type PrivacyLevel = 1 | 2 | 3;
export type LeafOpening = {
  level: PrivacyLevel;
  /** Paid while signed in with a Didit-attested identity (stored as a flag, never the person). */
  attested: boolean;
  amountCents: number;
  /** YYYY-MM of the payment. */
  month: string;
  /** 31 random bytes, hex. */
  nonce: string;
};

export function randomNonce(): string {
  return Array.from(crypto.getRandomValues(new Uint8Array(31)), (b) => b.toString(16).padStart(2, "0")).join("");
}

export function checkOpening(o: unknown): LeafOpening {
  const v = o as Partial<LeafOpening> | null;
  if (!v || typeof v !== "object") throw new RangeError("opening_invalid");
  if (v.level !== 1 && v.level !== 2 && v.level !== 3) throw new RangeError("opening_level");
  if (typeof v.attested !== "boolean") throw new RangeError("opening_attested");
  if (!Number.isInteger(v.amountCents) || v.amountCents! < 1 || v.amountCents! > 100_000_000) throw new RangeError("opening_amount");
  if (typeof v.month !== "string" || !MONTH.test(v.month)) throw new RangeError("opening_month");
  if (typeof v.nonce !== "string" || !NONCE_HEX.test(v.nonce)) throw new RangeError("opening_nonce");
  return { level: v.level, attested: v.attested, amountCents: v.amountCents!, month: v.month, nonce: v.nonce };
}

/** leaf = H(H(level', amount), H(month#, nonce)) under TAG_SUPPORT_LEAF; level' = level + 16·attested. */
export function leafCommitment(input: LeafOpening): bigint {
  const o = checkOpening(input);
  const m = MONTH.exec(o.month)!;
  const monthNumber = BigInt(Number(m[1]) * 12 + Number(m[2]) - 1);
  const levelCode = BigInt(o.level + (o.attested ? 16 : 0));
  const a = poseidonHash2(TAG_SUPPORT_LEAF, levelCode, BigInt(o.amountCents));
  const b = poseidonHash2(TAG_SUPPORT_LEAF, monthNumber, BigInt(`0x${o.nonce}`));
  const leaf = poseidonHash2(TAG_SUPPORT_LEAF, a, b);
  if (leaf === 0n) throw new RangeError("leaf_zero");
  return leaf;
}

function checkIndex(index: bigint): bigint {
  if (typeof index !== "bigint" || index < 0n || index >= MAX_LEAVES) throw new RangeError("index_out_of_range");
  return index;
}

export interface NodeReader {
  /** Stored hash at (level, idx); undefined = empty subtree. */
  get(level: number, idx: bigint): bigint | undefined;
}

/** The 32 sibling hashes from the leaf up. */
export function siblingsFor(index: bigint, read: NodeReader): bigint[] {
  checkIndex(index);
  const z = zeroHashes();
  const out: bigint[] = [];
  for (let l = 0; l < TREE_DEPTH; l++) out.push(read.get(l, (index >> BigInt(l)) ^ 1n) ?? z[l]!);
  return out;
}

export type TreeNode = { level: number; idx: bigint; hash: bigint };

/** Every node on the path (level 0 = leaf … level 32 = root) after placing `leaf` at `index`. */
export function pathFor(index: bigint, leaf: bigint, siblings: readonly bigint[]): { nodes: TreeNode[]; root: bigint } {
  checkIndex(index);
  if (siblings.length !== TREE_DEPTH) throw new RangeError("siblings_length");
  const nodes: TreeNode[] = [{ level: 0, idx: index, hash: leaf }];
  let h = leaf;
  for (let l = 0; l < TREE_DEPTH; l++) {
    const right = ((index >> BigInt(l)) & 1n) === 1n;
    h = right ? hashNode(siblings[l]!, h) : hashNode(h, siblings[l]!);
    nodes.push({ level: l + 1, idx: index >> BigInt(l + 1), hash: h });
  }
  return { nodes, root: h };
}

export function verifyInclusion(root: bigint, index: bigint, leaf: bigint, siblings: readonly bigint[]): boolean {
  try {
    if (leaf === 0n) return false;
    return pathFor(index, leaf, siblings).root === root;
  } catch {
    return false;
  }
}

/** In-memory tree (tests, and rebuilding a proof from stored nodes). */
export class MemoryTree implements NodeReader {
  private nodes = new Map<string, bigint>();
  size = 0n;
  get(level: number, idx: bigint) {
    return this.nodes.get(`${level}:${idx}`);
  }
  root(): bigint {
    return this.get(TREE_DEPTH, 0n) ?? emptyRoot();
  }
  append(leaf: bigint): bigint {
    if (leaf === 0n) throw new RangeError("leaf_zero");
    const index = this.size;
    const { nodes } = pathFor(index, leaf, siblingsFor(index, this));
    for (const n of nodes) this.nodes.set(`${n.level}:${n.idx}`, n.hash);
    this.size += 1n;
    return index;
  }
  proof(index: bigint): bigint[] {
    if (index >= this.size) throw new RangeError("index_unknown");
    return siblingsFor(index, this);
  }
}

export type SignedTreeRoot = {
  size: string;
  root: string;
  kid: string;
  ed25519: string;
  mldsa65: string | null;
};

export type InclusionProof = {
  v: typeof INCLUSION_PROOF_VERSION;
  index: string;
  leaf: string;
  siblings: string[];
  signedRoot: SignedTreeRoot;
  opening: LeafOpening | null;
};

/** Structure + Merkle math (+ opening → leaf). The root signature is checked separately. */
export function checkInclusionProof(p: unknown): { ok: true; proof: InclusionProof } | { ok: false; reason: string } {
  try {
    const v = p as InclusionProof;
    if (!v || v.v !== INCLUSION_PROOF_VERSION) return { ok: false, reason: "version" };
    if (typeof v.index !== "string" || !/^\d{1,10}$/.test(v.index)) return { ok: false, reason: "index" };
    if (!Array.isArray(v.siblings) || v.siblings.length !== TREE_DEPTH) return { ok: false, reason: "siblings" };
    const index = BigInt(v.index);
    const size = BigInt(v.signedRoot?.size ?? "x");
    if (index >= size) return { ok: false, reason: "index_beyond_size" };
    const leaf = fromHex(v.leaf);
    if (v.opening && leafCommitment(v.opening) !== leaf) return { ok: false, reason: "opening_mismatch" };
    if (!verifyInclusion(fromHex(v.signedRoot.root), index, leaf, v.siblings.map(fromHex))) return { ok: false, reason: "merkle_mismatch" };
    return { ok: true, proof: v };
  } catch {
    return { ok: false, reason: "malformed" };
  }
}
