/**
 * DNSSEC status of partner/supplier domains, asked from a validating resolver over
 * DNS-over-HTTPS in RFC 8484 wire format with the EDNS0 DO bit set: DNS4EU first, Cloudflare
 * only when DNS4EU does not answer (Quad9 refuses HTTP/1.1 clients).
 * "valid" = the resolver validated the chain and set AD; "unsigned" = answer without AD (no
 * DNSSEC); "unknown" = the lookup failed. Cached per isolate for an hour. The resolver is
 * trusted for this check; the page says so.
 */
export type DnssecState = "valid" | "unsigned" | "unknown";

const TTL_MS = 60 * 60 * 1000;
const cache = new Map<string, { state: DnssecState; at: number }>();
const DOMAIN_RE = /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/;

/** SOA query, RD set, one EDNS0 OPT record with DO (RFC 3225). */
export function dnsQuery(domain: string): Uint8Array {
  const labels = domain.split(".").flatMap((l) => [l.length, ...Array.from(new TextEncoder().encode(l))]);
  return new Uint8Array([
    0, 0, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 1, // header: id 0 (RFC 8484 §4.1), RD, 1 question, 1 additional
    ...labels, 0, 0, 6, 0, 1, // QNAME, QTYPE SOA, QCLASS IN
    0, 0, 41, 0x04, 0xd0, 0, 0, 0x80, 0, 0, 0, // OPT: root, type 41, udp 1232, ext-rcode/version 0, DO, rdlen 0
  ]);
}

export function dnssecFromWire(bytes: Uint8Array): DnssecState {
  if (bytes.length < 12) return "unknown";
  if ((bytes[2]! & 0x80) === 0) return "unknown"; // not a response
  if ((bytes[3]! & 0x0f) !== 0) return "unknown"; // RCODE ≠ NOERROR (SERVFAIL on a bogus chain)
  return (bytes[3]! & 0x20) !== 0 ? "valid" : "unsigned";
}

const RESOLVERS = ["https://unfiltered.joindns4.eu/dns-query", "https://cloudflare-dns.com/dns-query"] as const;
const b64url = (b: Uint8Array) => btoa(String.fromCharCode(...b)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

export async function dnssecStatus(domain: string, fetcher: typeof fetch = fetch): Promise<DnssecState> {
  const d = domain.trim().toLowerCase();
  if (!DOMAIN_RE.test(d)) return "unknown";
  const hit = cache.get(d);
  if (hit && Date.now() - hit.at < TTL_MS) return hit.state;
  let state: DnssecState = "unknown";
  for (const resolver of RESOLVERS) {
    try {
      const res = await fetcher(`${resolver}?dns=${b64url(dnsQuery(d))}`, {
        headers: { accept: "application/dns-message" },
        signal: AbortSignal.timeout(3000),
      });
      if (!res.ok) continue;
      state = dnssecFromWire(new Uint8Array(await res.arrayBuffer()));
      if (state !== "unknown") break;
    } catch {
      /* next resolver */
    }
  }
  cache.set(d, { state, at: Date.now() });
  return state;
}
