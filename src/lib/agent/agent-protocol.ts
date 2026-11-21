import { POW_BITS, POW_CHALLENGE_HEADER, POW_CHALLENGE_TTL_S, POW_SOLUTION_HEADER } from "@/lib/pow/pow";

/**
 * The one canonical definition of ROUT's account-less agent protocol. Pure and
 * browser-safe. Every machine-readable manifest (rout-agent.json,
 * ai-manifest.json, MCP descriptions, error messages) is built from these
 * values, and contract tests pin them to the database functions (db/0213) and
 * to the static llms.txt / about pages, so no two documents can disagree.
 */

export const AGENT_PROTOCOL_VERSION = "2026-11-20";

/** Sandbox keys, unclaimed workspaces and claim links all expire together (db/0213 CHECK constraints). */
export const SANDBOX_TTL_HOURS = 24;
/** rout_agent_sandbox_register refuses the sixth sandbox per network within 24 hours. */
export const SANDBOXES_PER_NETWORK_PER_DAY = 5;
export const WORKSPACES_PER_SANDBOX = 1;
export const MAX_SANDBOX_APPS = 3;
export const SANDBOX_DPOP_ALGS = ["ES256", "Ed25519"] as const;

export function sandboxLimits() {
  return {
    sandbox_ttl_hours: SANDBOX_TTL_HOURS,
    sandboxes_per_network_per_day: SANDBOXES_PER_NETWORK_PER_DAY,
    workspaces_per_sandbox: WORKSPACES_PER_SANDBOX,
    apps_per_workspace: MAX_SANDBOX_APPS,
  };
}

/**
 * Ready-to-run solvers, each verified by agent-protocol.test.ts against the
 * server's own verifier. Pass the challenge and difficulty_bits as arguments;
 * the printed line is the solution. Perl ships with almost every Linux
 * container (git depends on it), so a shell without Python or Node still works.
 */
export const POW_SOLVERS = {
  node: `node -e 'const[c,b]=process.argv.slice(1),h=require("crypto");for(let i=0;;i++){const s=i.toString(36),d=h.createHash("sha256").update(c+":"+s).digest();let z=0;for(const x of d){if(x){z+=Math.clz32(x)-24;break}z+=8}if(z>=+b){console.log(s);break}}' "$CHALLENGE" "$BITS"`,
  bun: `bun -e 'const[c,b]=process.argv.slice(1),h=require("crypto");for(let i=0;;i++){const s=i.toString(36),d=h.createHash("sha256").update(c+":"+s).digest();let z=0;for(const x of d){if(x){z+=Math.clz32(x)-24;break}z+=8}if(z>=+b){console.log(s);break}}' "$CHALLENGE" "$BITS"`,
  python: `python3 -c 'import hashlib,sys\nc,b=sys.argv[1],int(sys.argv[2]);i=0\nwhile int.from_bytes(hashlib.sha256(f"{c}:{i:x}".encode()).digest(),"big")>>(256-b):i+=1\nprint(f"{i:x}")' "$CHALLENGE" "$BITS"`,
  perl: `perl -MDigest::SHA=sha256 -e '($c,$b)=@ARGV;$i=0;$i++ while unpack("B$b",sha256("$c:".sprintf("%x",$i)))=~/1/;printf "%x\\n",$i' "$CHALLENGE" "$BITS"`,
  webcrypto_js: `async function solve(c,b){for(let i=0;;i++){const s=i.toString(36),d=new Uint8Array(await crypto.subtle.digest("SHA-256",new TextEncoder().encode(c+":"+s)));let z=0;for(const x of d){if(x){z+=Math.clz32(x)-24;break}z+=8}if(z>=b)return s}}`,
} as const;

export function powSpec() {
  return {
    algorithm: "Find solution matching [0-9A-Za-z]{1,64} such that SHA-256(challenge + \":\" + solution) starts with difficulty_bits zero bits.",
    difficulty_bits: { ...POW_BITS },
    expected_hashes: 2 ** POW_BITS.sandbox,
    typical_seconds: "about 1 s in Node, Bun, Python or Perl",
    challenge_ttl_s: POW_CHALLENGE_TTL_S,
    single_use: true,
    challenge_format: "v2.<scope>.<expires unix s>.<bits>.<nonce>.<hmac> (HMAC-signed by ROUT; scope-bound, so a challenge for one operation never unlocks another)",
    headers_for_heavy_operations: { challenge: POW_CHALLENGE_HEADER, solution: POW_SOLUTION_HEADER },
    solvers: POW_SOLVERS,
  };
}

/** Optional RFC 9449 key binding for sandbox keys. */
export function sandboxDpopSpec(origin: string) {
  return {
    optional: true,
    rfc: "RFC 9449",
    algs: [...SANDBOX_DPOP_ALGS],
    how: [
      `Generate an ES256 (P-256) or Ed25519 key pair and keep the private key in memory.`,
      `Register with a DPoP header (htm POST, htu ${origin}/api/agent/sandbox, fresh jti, iat now, no ath).`,
      "The answer has token_type DPoP: the sandbox key is now bound to your key's RFC 7638 thumbprint.",
      "Every later call sends Authorization: DPoP rsk_… plus a new DPoP proof with htm, htu (no query), iat, a unique jti and ath = base64url(SHA-256(rsk_…)).",
    ],
    guarantees: "ROUT stores only SHA-256(rsk_… + \".\" + thumbprint): a leaked key, request log or proxy trace is useless without your private key, each proof is single-use (shared replay ledger, 60 s window), and the key never works as a Bearer token.",
    mcp_note: "The MCP endpoint forwards sandbox keys as Bearer tokens: use unbound keys there.",
  };
}

/** The sandbox lifecycle as one state machine; each invariant names the place that enforces it. */
export const SANDBOX_LIFECYCLE = {
  states: ["challenged", "sandbox_active", "workspace_staged", "claimed", "expired_and_purged"],
  transitions: [
    { from: "none", to: "challenged", by: "GET /api/agent/sandbox (HMAC-signed proof-of-work challenge, scope sandbox)" },
    { from: "challenged", to: "sandbox_active", by: "POST /api/agent/sandbox with a valid solution (each challenge registers at most one sandbox)" },
    { from: "sandbox_active", to: "workspace_staged", by: "POST /api/agent/sandbox/workspace with a fresh scope=workspace proof-of-work" },
    { from: "workspace_staged", to: "claimed", by: "a signed-in human opens the claim link or enters the claim code" },
    { from: "sandbox_active|workspace_staged", to: "expired_and_purged", by: `expires ${SANDBOX_TTL_HOURS} hours after registration; deleted by the next registration or the purge job` },
  ],
  invariants: [
    { id: "claim_once", rule: "A workspace binds exactly one owner: the claim row is locked (SELECT … FOR UPDATE) and a second claim raises claim_used." },
    { id: "agent_key_dies_at_claim", rule: "After the claim the sandbox key resolves to nothing: every later agent call answers invalid_token." },
    { id: "time_decay", rule: `Nothing is claimable or editable after ${SANDBOX_TTL_HOURS} hours; database CHECK constraints pin expires_at = created_at + ${SANDBOX_TTL_HOURS} h.` },
    { id: "nothing_public_before_claim", rule: "Drafts and login-app specs are sealed (AES-256-GCM) until claim; no profile, login app or e-mail exists before a human owns it." },
    { id: "secrets_hashed", rule: "Sandbox keys, claim tokens and claim codes are stored only as SHA-256 hashes." },
  ],
} as const;
