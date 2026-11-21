/**
 * /support/partners. Owner decision 2026-11-18: suppliers are shown as "infrastructure we use",
 * never as partners; the partner/attested label is reserved for organisations that agreed to it.
 * Funds and academic alliances stay empty until there is a real grant or agreement.
 */
export type PartnerGroup = "funds" | "infrastructure" | "academic";
export type Partner = {
  id: string;
  name: string;
  domain: string;
  /** ISO 3166-1 alpha-2 of the company's seat (jurisdiction), not of a data centre. */
  country: string;
  group: PartnerGroup;
  relationship: "partner" | "supplier";
  /** Key into the page copy (what ROUT uses it for). */
  role: "mail" | "storage" | "database" | "identity" | "bank";
};

export const PARTNERS: readonly Partner[] = [
  { id: "infomaniak", name: "Infomaniak", domain: "infomaniak.com", country: "CH", group: "infrastructure", relationship: "supplier", role: "mail" },
  { id: "scaleway", name: "Scaleway", domain: "scaleway.com", country: "FR", group: "infrastructure", relationship: "supplier", role: "storage" },
  { id: "brevo", name: "Brevo", domain: "brevo.com", country: "FR", group: "infrastructure", relationship: "supplier", role: "mail" },
  { id: "bunq", name: "bunq", domain: "bunq.com", country: "NL", group: "infrastructure", relationship: "supplier", role: "bank" },
  { id: "didit", name: "Didit", domain: "didit.me", country: "ES", group: "infrastructure", relationship: "supplier", role: "identity" },
  { id: "neon", name: "Neon", domain: "neon.tech", country: "US", group: "infrastructure", relationship: "supplier", role: "database" },
];

export const partnersIn = (group: PartnerGroup) => PARTNERS.filter((p) => p.group === group);
export const partnerDomains = () => PARTNERS.map((p) => p.domain);
