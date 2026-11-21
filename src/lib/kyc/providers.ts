/**
 * Identity provider catalogue for the Provider Discovery Hub (pure, client-safe, tested).
 * Only providers with an engine are startable; the others are listed as planned so members see
 * the roadmap without a button that does nothing. Nothing here is a claim of partnership.
 */
export type ProviderCategory = "national_eid" | "passport_nfc" | "zero_knowledge";
export type PrivacyRating = "eidas_high" | "eidas_substantial" | "zk_enclave" | "biometric";
export type DocumentKind = "passport" | "id_card" | "residence_permit" | "driving_licence" | "eid_app" | "selfie" | "zk_proof";
export type ProviderEngine = "didit" | "w_identity";

export type IdentityProviderEntry = {
  id: string;
  name: string;
  monogram: string;
  /** ISO 3166-1 alpha-2 countries the provider is native to; "EU" = every EU/EEA state, "GLOBAL" = worldwide. */
  regions: readonly string[];
  categories: readonly ProviderCategory[];
  documents: readonly DocumentKind[];
  ratings: readonly PrivacyRating[];
  engine: ProviderEngine | null;
  /** Extra search words (document names, national numbers). */
  keywords: readonly string[];
};

export const IDENTITY_PROVIDERS: readonly IdentityProviderEntry[] = [
  { id: "didit", name: "Didit", monogram: "Di", regions: ["GLOBAL"], categories: ["passport_nfc"], documents: ["passport", "id_card", "residence_permit", "selfie"], ratings: ["biometric"], engine: "didit", keywords: ["nfc", "paspoort", "passport", "chip", "mrz", "icao"] },
  { id: "w_identity", name: "W Identity", monogram: "W", regions: ["EU"], categories: ["zero_knowledge"], documents: ["zk_proof"], ratings: ["zk_enclave"], engine: "w_identity", keywords: ["pseudoniem", "pseudonym", "uniek mens", "unique human"] },
  { id: "itsme", name: "itsme®", monogram: "it", regions: ["BE", "LU", "NL"], categories: ["national_eid"], documents: ["eid_app", "id_card"], ratings: ["eidas_high"], engine: null, keywords: ["rijksregisternummer", "belgie", "belgium", "belgique"] },
  { id: "eid", name: "eID / eIDAS", monogram: "eID", regions: ["EU"], categories: ["national_eid"], documents: ["id_card", "eid_app"], ratings: ["eidas_high"], engine: null, keywords: ["eidas", "kaartlezer", "card reader", "nfc", "europe"] },
  { id: "digid", name: "DigiD", monogram: "Dg", regions: ["NL"], categories: ["national_eid"], documents: ["eid_app", "id_card", "passport"], ratings: ["eidas_high"], engine: null, keywords: ["bsn", "nederland", "netherlands", "digid hoog"] },
  { id: "france_identite", name: "France Identité", monogram: "FI", regions: ["FR"], categories: ["national_eid"], documents: ["eid_app", "id_card"], ratings: ["eidas_substantial"], engine: null, keywords: ["france", "frankrijk", "cni", "carte d'identite"] },
  { id: "mitid", name: "MitID", monogram: "Mi", regions: ["DK"], categories: ["national_eid"], documents: ["eid_app"], ratings: ["eidas_high"], engine: null, keywords: ["denmark", "danmark", "cpr"] },
  { id: "cie", name: "CIE", monogram: "CIE", regions: ["IT"], categories: ["national_eid"], documents: ["id_card", "eid_app"], ratings: ["eidas_high"], engine: null, keywords: ["italia", "italy", "carta d'identita elettronica", "codice fiscale"] },
  { id: "idnow", name: "IDnow", monogram: "ID", regions: ["DE", "FR", "EU"], categories: ["passport_nfc"], documents: ["passport", "id_card", "selfie"], ratings: ["biometric"], engine: null, keywords: ["videoident", "autoident", "germany"] },
  { id: "shufti_pro", name: "Shufti Pro", monogram: "SP", regions: ["GLOBAL"], categories: ["passport_nfc"], documents: ["passport", "id_card", "driving_licence", "selfie"], ratings: ["biometric"], engine: null, keywords: ["kyc", "aml"] },
  { id: "trulioo", name: "Trulioo", monogram: "Tr", regions: ["GLOBAL"], categories: ["passport_nfc"], documents: ["passport", "id_card", "driving_licence"], ratings: ["biometric"], engine: null, keywords: ["kyc", "global"] },
  { id: "world_id", name: "World ID", monogram: "WID", regions: ["GLOBAL"], categories: ["zero_knowledge"], documents: ["zk_proof"], ratings: ["zk_enclave", "biometric"], engine: null, keywords: ["orb", "proof of personhood", "zero knowledge"] },
];

export type ProviderFilter = "all" | ProviderCategory;

const EU = new Set(["AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR", "DE", "GR", "HU", "IE", "IT", "LV", "LT", "LU", "MT", "NL", "PL", "PT", "RO", "SK", "SI", "ES", "SE", "IS", "LI", "NO"]);

/** Region (ISO alpha-2) from a BCP 47 tag such as "nl-BE"; null when the tag names none. */
export function regionFromLocale(tag: string | null | undefined): string | null {
  const m = /^[a-z]{2,3}[-_]([A-Za-z]{2})\b/.exec(tag ?? "");
  return m ? m[1]!.toUpperCase() : null;
}

function fold(s: string): string {
  return s.normalize("NFKD").replace(/\p{M}+/gu, "").toLowerCase();
}

/** 0 = native to the region, 1 = EU-wide for an EU region, 2 = global, 3 = elsewhere. */
export function regionRank(p: IdentityProviderEntry, region: string | null): number {
  if (region && p.regions.includes(region)) return 0;
  if (region && EU.has(region) && p.regions.includes("EU")) return 1;
  if (p.regions.includes("GLOBAL")) return 2;
  return 3;
}

/**
 * Filtered and ordered list: active engines first, then by region relevance, then by name.
 * `docLabels` lets the search match translated document names.
 */
export function discoverProviders(opts: {
  query?: string;
  filter?: ProviderFilter;
  region?: string | null;
  active?: ReadonlySet<ProviderEngine>;
  docLabels?: Partial<Record<DocumentKind, string>>;
}): IdentityProviderEntry[] {
  const q = fold((opts.query ?? "").trim());
  const words = q ? q.split(/\s+/).slice(0, 6) : [];
  const filter = opts.filter ?? "all";
  const region = opts.region ?? null;
  const active = opts.active ?? new Set<ProviderEngine>();
  return IDENTITY_PROVIDERS.filter((p) => filter === "all" || p.categories.includes(filter))
    .filter((p) => {
      if (!words.length) return true;
      const hay = fold([p.name, p.id, ...p.regions, ...p.keywords, ...p.documents.map((d) => opts.docLabels?.[d] ?? d)].join(" "));
      return words.every((w) => hay.includes(w));
    })
    .sort((a, b) => {
      const aa = a.engine && active.has(a.engine) ? 0 : 1;
      const bb = b.engine && active.has(b.engine) ? 0 : 1;
      return aa - bb || regionRank(a, region) - regionRank(b, region) || a.name.localeCompare(b.name);
    });
}

/** Providers native to the member's region (or EU-wide for an EU member), for the recommended row. */
export function recommendedProviders(region: string | null, active: ReadonlySet<ProviderEngine>): IdentityProviderEntry[] {
  return discoverProviders({ region, active }).filter((p) => regionRank(p, region) <= 1 || (p.engine && active.has(p.engine))).slice(0, 6);
}
