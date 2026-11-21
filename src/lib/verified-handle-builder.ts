/**
 * Compound-name parsing en handle-opbouw voor GEVERIFIEERDE accounts.
 *
 * Ondersteunt Belgische/Nederlandse samengestelde achternamen ("De Smet",
 * "van der Graven") en meerdere voornamen ("Jona Zeno").
 *
 * REGEL VAN WETTELIJKE HERLEIDBAARHEID: minstens één primair naamdeel
 * (primaire voornaam OF primaire achternaam) staat altijd voluit in de handle.
 * Tussennamen en secundaire achternaamdelen zijn optioneel.
 *
 * Client-safe: geen server-imports.
 */

/** Tussenvoegsels die bij de achternaam horen. */
const SURNAME_PREFIXES = new Set([
  "de",
  "den",
  "der",
  "des",
  "het",
  "'t",
  "t",
  "ten",
  "ter",
  "te",
  "van",
  "vande",
  "vanden",
  "vander",
  "op",
  "in",
  "aan",
  "onder",
  "boven",
  "du",
  "le",
  "la",
  "les",
  "da",
  "di",
  "del",
  "della",
  "dos",
  "el",
  "al",
  "mac",
  "mc",
  "o",
  "st",
]);

export const HANDLE_SEPARATOR_OPTIONS = [
  { value: "", label: "geen" },
  { value: ".", label: "." },
  { value: "-", label: "-" },
  { value: "_", label: "_" },
  { value: ":", label: ":" },
  { value: "×", label: "×" },
  { value: ",", label: "," },
  { value: "~", label: "~" },
  { value: "•", label: "•" },
  { value: "|", label: "|" },
  { value: "/", label: "/" },
] as const;

export type HandleSeparator = (typeof HANDLE_SEPARATOR_OPTIONS)[number]["value"];

/** Scheidingstekens die de databank/URL echt aankan. */
export const STORAGE_SAFE_SEPARATORS = new Set([".", "-", "_", ""]);

export function fold(value: string): string {
  return value
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase()
    .replace(/[^a-z0-9]/g, "");
}

export interface ParsedLegalName {
  /** Primaire voornaam, voluit (gevouwen). */
  firstName: string;
  /** Tussennamen (tweede, derde voornaam …). */
  middleNames: string[];
  /** Alle achternaamdelen inclusief tussenvoegsels, in officiële volgorde. */
  surnameParts: string[];
}

/**
 * Splitst een volledige wettelijke naam in voornaam, tussennamen en een
 * samengestelde achternaam. Tussenvoegsels ("de", "van der") worden bij de
 * achternaam gehouden.
 */
export function parseLegalName(legalName: string | null | undefined): ParsedLegalName | null {
  const tokens = (legalName ?? "")
    .split(/\s+/)
    .map((token) => token.trim())
    .filter(Boolean);
  if (tokens.length < 2) return null;

  // Eerste tussenvoegsel (nooit op positie 0) markeert de start van de achternaam.
  let surnameStart = -1;
  for (let i = 1; i < tokens.length; i += 1) {
    if (SURNAME_PREFIXES.has(fold(tokens[i]!))) {
      surnameStart = i;
      break;
    }
  }
  if (surnameStart <= 0) surnameStart = tokens.length - 1;

  const firstNames = tokens.slice(0, surnameStart).map(fold).filter(Boolean);
  const surnameParts = tokens.slice(surnameStart).map(fold).filter(Boolean);
  if (firstNames.length === 0 || surnameParts.length === 0) return null;

  return {
    firstName: firstNames[0]!,
    middleNames: firstNames.slice(1),
    surnameParts,
  };
}

/** Achternaam voluit: alle delen aan elkaar ("desmet", "vandergraven"). */
export function surnameFull(parts: string[]): string {
  return parts.join("");
}

/** Achternaam als initialen van elk deel ("ds", "vdg"). */
export function surnameInitials(parts: string[]): string {
  return parts.map((part) => part[0] ?? "").join("");
}

/** Achternaam als één letter — de beginletter van het hoofddeel. */
export function surnameSingleInitial(parts: string[]): string {
  const main = parts[parts.length - 1] ?? "";
  return main[0] ?? "";
}

export type NameOrder = "first-first" | "surname-first";
export type MiddleMode = "full" | "initial" | "omit";
/** A = alles voluit · B = voornaam voluit + achternaam afgekort · C = voornaam afgekort + achternaam voluit */
export type FullnessMode = "all-full" | "surname-short" | "first-short";
export type SurnameShortStyle = "initials" | "single";

export interface HandleBuilderConfig {
  order: NameOrder;
  middle: MiddleMode;
  fullness: FullnessMode;
  surnameShortStyle: SurnameShortStyle;
  separator: HandleSeparator;
}

export const DEFAULT_BUILDER_CONFIG: HandleBuilderConfig = {
  order: "first-first",
  middle: "omit",
  fullness: "all-full",
  surnameShortStyle: "initials",
  separator: ".",
};

/**
 * Bouwt de handle op uit de geparste naam en de wizardkeuzes. Het resultaat is
 * altijd lowercase; enkel het gekozen scheidingsteken staat tussen de delen.
 */
export function buildHandle(name: ParsedLegalName, config: HandleBuilderConfig): string {
  const surnameShort =
    config.surnameShortStyle === "single"
      ? surnameSingleInitial(name.surnameParts)
      : surnameInitials(name.surnameParts);

  const firstPart = config.fullness === "first-short" ? (name.firstName[0] ?? "") : name.firstName;
  const surnamePart =
    config.fullness === "surname-short" ? surnameShort : surnameFull(name.surnameParts);

  const middlePieces: string[] = [];
  if (config.middle !== "omit" && name.middleNames.length > 0) {
    for (const middle of name.middleNames) {
      middlePieces.push(config.middle === "initial" ? (middle[0] ?? "") : middle);
    }
  }

  const segments =
    config.order === "first-first"
      ? [firstPart, ...middlePieces, surnamePart]
      : [surnamePart, ...middlePieces, firstPart];

  return segments.filter(Boolean).join(config.separator).toLowerCase();
}

/**
 * De handle blijft herleidbaar zolang minstens één primair naamdeel voluit in
 * de handle staat. De wizard garandeert dat al, maar dit is de expliciete check.
 */
export function isLegallyTraceable(name: ParsedLegalName, handle: string): boolean {
  const clean = fold(handle);
  return clean.includes(name.firstName) || clean.includes(surnameFull(name.surnameParts));
}

export const TRACEABILITY_MESSAGE =
  "Minstens je voornaam óf je achternaam moet voluit in je gebruikersnaam staan.";

/**
 * Opslagvorm: het gekozen sierteken (× • | / : ,) is niet URL-veilig en wordt
 * naar een punt vertaald zodra de handle echt opgeslagen wordt.
 */
export function toStorageHandle(handle: string): string {
  return handle
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, ".")
    .replace(/\.{2,}/g, ".")
    .replace(/^[._-]+|[._-]+$/g, "")
    .slice(0, 30);
}

/* ======================================================================== */
/* Prioriteit 3 — wettelijke handle-varianten uit de Didit-naam (Tier 1–4)  */
/* ======================================================================== */

/** Langste geverifieerde handle (gelijk aan toStorageHandle). */
export const VERIFIED_HANDLE_MAX = 30;
export const VERIFIED_HANDLE_MIN = 3;

/** Scheidingstekens voor Tier 1–3, in vaste volgorde (deterministisch). */
export const LEGAL_HANDLE_SEPARATORS = [".", "-", "_", ""] as const;

/** Tekens die NFKD niet ontbindt, of die taalkundig twee letters worden. */
const EXPANDED_TRANSLITERATION: Record<string, string> = {
  ä: "ae",
  ö: "oe",
  ü: "ue",
  ß: "ss",
  ø: "oe",
  æ: "ae",
  å: "aa",
  œ: "oe",
};
const SIMPLE_TRANSLITERATION: Record<string, string> = {
  ß: "ss",
  ø: "o",
  æ: "ae",
  œ: "oe",
  đ: "d",
  ð: "d",
  ł: "l",
  þ: "th",
  ı: "i",
};

export type FoldMode = "expanded" | "simple";

/**
 * Lowercase ASCII van één naamdeel. `expanded` volgt de taalregels
 * (ü→ue, ø→oe, å→aa), `simple` laat enkel het accent vallen (ü→u, å→a).
 */
export function foldNamePart(value: string, mode: FoldMode = "expanded"): string {
  let out = value.toLowerCase();
  if (mode === "expanded") out = out.replace(/[äöüßøæåœ]/g, (ch) => EXPANDED_TRANSLITERATION[ch] ?? ch);
  out = out.replace(/[ßøæœđðłþı]/g, (ch) => SIMPLE_TRANSLITERATION[ch] ?? ch);
  return out.normalize("NFKD").replace(/[\u0300-\u036f]/g, "").replace(/[^a-z0-9]/g, "");
}

export interface LegalNameParts {
  /** Voornamen zoals op het document (bv. "Jona Zeno"). */
  first: string;
  /** Familienaam zoals op het document (bv. "De Smet", "d'Haene"). */
  last: string;
}

export interface ParsedLegalNameV2 {
  firstName: string;
  middleNames: string[];
  /** Alle achternaamdelen, tussenvoegsels inbegrepen ("de", "smet"). */
  surnameParts: string[];
  /** Tussenvoegsels vooraan in de achternaam ("de", "van", "den", "d"). */
  prefixes: string[];
  /** Achternaamdelen zonder tussenvoegsels ("smet"). */
  mainParts: string[];
}

const APOSTROPHES = /['’‘`´ʼ]/g;
const isPrefix = (part: string) => SURNAME_PREFIXES.has(part) || part === "d" || part === "l";

function splitWords(raw: string, splitHyphen: boolean): string[] {
  const cleaned = raw.replace(APOSTROPHES, " ").trim();
  return cleaned.split(splitHyphen ? /[\s-]+/ : /\s+/).filter(Boolean);
}

function buildParsed(firstTokens: string[], lastTokens: string[], mode: FoldMode): ParsedLegalNameV2 | null {
  const firsts = firstTokens.map((t) => foldNamePart(t, mode)).filter(Boolean);
  const parts = lastTokens.map((t) => foldNamePart(t, mode)).filter(Boolean);
  if (firsts.length === 0 || parts.length === 0) return null;
  const prefixes: string[] = [];
  let i = 0;
  while (i < parts.length - 1 && isPrefix(parts[i]!)) prefixes.push(parts[i++]!);
  const mainParts = parts.slice(i);
  return { firstName: firsts[0]!, middleNames: firsts.slice(1), surnameParts: parts, prefixes, mainParts };
}

/**
 * Parseert de Didit-naam. Met aparte voor- en familienaam is de splitsing exact;
 * een losse string valt terug op de tussenvoegselregel van parseLegalName.
 */
export function parseLegalNameParts(input: LegalNameParts | string | null | undefined, mode: FoldMode = "expanded"): ParsedLegalNameV2 | null {
  if (!input) return null;
  if (typeof input === "string") {
    const tokens = splitWords(input, false);
    if (tokens.length < 2) return null;
    let surnameStart = -1;
    for (let i = 1; i < tokens.length; i += 1) {
      if (isPrefix(foldNamePart(tokens[i]!, mode))) {
        surnameStart = i;
        break;
      }
    }
    if (surnameStart <= 0) surnameStart = tokens.length - 1;
    return buildParsed(tokens.slice(0, surnameStart), tokens.slice(surnameStart).flatMap((t) => splitWords(t, true)), mode);
  }
  return buildParsed(splitWords(input.first ?? "", false), splitWords(input.last ?? "", true), mode);
}

export type HandleTier = 1 | 2 | 3 | 4;
export interface HandleCandidate {
  handle: string;
  tier: HandleTier;
}

const SAFE_SHAPE = /^[a-z0-9](?:[a-z0-9._-]*[a-z0-9])?$/;
/** Nooit: dubbele punt, of een punt naast een ander scheidingsteken, of gemengde - en _. */
const FORBIDDEN_ADJACENT = /\.\.|\.-|-\.|\._|_\.|-_|_-/;
/** Herhaalde - of _ zijn uitsluitend de Tier 4-terugvaloptie. */
const REPEATED_SEPARATOR = /--|__/;

/** Vormregel voor elke geverifieerde handle (Tier 4 mag `--`/`__`, nooit `..`). */
export function isSafeVerifiedHandleShape(handle: string, allowRepeated = false): boolean {
  if (handle.length < VERIFIED_HANDLE_MIN || handle.length > VERIFIED_HANDLE_MAX) return false;
  if (!SAFE_SHAPE.test(handle) || FORBIDDEN_ADJACENT.test(handle)) return false;
  if (!allowRepeated && REPEATED_SEPARATOR.test(handle)) return false;
  return true;
}

/**
 * Wettelijke herleidbaarheid: de handle bevat de primaire voornaam voluit, de
 * volledige familienaam, of het hoofddeel van de familienaam (zonder tussenvoegsels).
 */
export function isTraceableToLegalName(name: ParsedLegalNameV2, handle: string): boolean {
  const clean = handle.replace(/[._-]/g, "");
  const main = name.mainParts.join("");
  return (
    clean.includes(name.firstName) ||
    clean.includes(name.surnameParts.join("")) ||
    (main.length >= 3 && clean.includes(main))
  );
}

function pushUnique(out: string[], seen: Set<string>, handle: string, allowRepeated = false) {
  if (seen.has(handle)) return;
  if (!isSafeVerifiedHandleShape(handle, allowRepeated)) return;
  seen.add(handle);
  out.push(handle);
}

function tier1(n: ParsedLegalNameV2): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  const surname = n.surnameParts.join("");
  for (const sep of LEGAL_HANDLE_SEPARATORS) {
    pushUnique(out, seen, `${n.firstName}${sep}${surname}`);
    pushUnique(out, seen, `${surname}${sep}${n.firstName}`);
  }
  if (n.surnameParts.length > 1) {
    // Gesplitste tussenvoegsels: jona.de.smet, jona.de-smet, jona-de-smet, jona_de_smet …
    const combos: [string, string][] = [[".", "."], [".", "-"], ["-", "-"], ["_", "_"]];
    for (const [outer, inner] of combos) {
      const split = n.surnameParts.join(inner);
      pushUnique(out, seen, `${n.firstName}${outer}${split}`);
      pushUnique(out, seen, `${split}${outer}${n.firstName}`);
    }
  }
  return out;
}

function tier2(n: ParsedLegalNameV2): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  const surname = n.surnameParts.join("");
  const fi = n.firstName[0] ?? "";
  for (const sep of LEGAL_HANDLE_SEPARATORS) {
    pushUnique(out, seen, `${fi}${sep}${surname}`);
    pushUnique(out, seen, `${surname}${sep}${fi}`);
  }
  if (n.middleNames.length > 0) {
    const middleInitials = n.middleNames.map((m) => m[0] ?? "");
    for (const sep of LEGAL_HANDLE_SEPARATORS) {
      const mi = middleInitials.join(sep);
      const mf = n.middleNames.join(sep);
      pushUnique(out, seen, [n.firstName, mi, surname].join(sep));
      pushUnique(out, seen, [n.firstName, mf, surname].join(sep));
      pushUnique(out, seen, [fi, mi, surname].join(sep));
    }
  }
  return out;
}

function tier3(n: ParsedLegalNameV2, alt: ParsedLegalNameV2 | null): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  const surname = n.surnameParts.join("");
  const main = n.mainParts.join("");
  const fi = n.firstName[0] ?? "";
  if (n.prefixes.length > 0) {
    const pi = n.prefixes.map((p) => p[0] ?? "").join("");
    for (const sep of LEGAL_HANDLE_SEPARATORS) {
      pushUnique(out, seen, [fi, pi, main].join(sep)); // j.d.smet
      pushUnique(out, seen, [n.firstName, pi, main].join(sep)); // jona.d.smet
      pushUnique(out, seen, `${n.firstName}${sep}${main}`); // jona.smet (tussenvoegsel gestript)
      pushUnique(out, seen, `${main}${sep}${n.firstName}`);
    }
  }
  if (n.middleNames.length > 0) {
    const mi = n.middleNames.map((m) => m[0] ?? "").join("");
    for (const sep of LEGAL_HANDLE_SEPARATORS) pushUnique(out, seen, [surname, n.firstName, mi].join(sep)); // desmet.jona.z
  }
  if (alt) {
    // Transliteratie-varianten: dezelfde Tier 1/2-vormen met de eenvoudige vouwing (ü → u).
    for (const h of [...tier1(alt), ...tier2(alt)]) pushUnique(out, seen, h);
  }
  return out;
}

function tier4(n: ParsedLegalNameV2): string[] {
  const out: string[] = [];
  const seen = new Set<string>();
  const surname = n.surnameParts.join("");
  for (const count of [2, 3]) {
    for (const sep of ["-", "_"]) {
      const s = sep.repeat(count);
      pushUnique(out, seen, `${n.firstName}${s}${surname}`, true);
      pushUnique(out, seen, `${surname}${s}${n.firstName}`, true);
    }
  }
  return out;
}

export interface LegalHandleTiers {
  tier1: string[];
  tier2: string[];
  tier3: string[];
  tier4: string[];
}

/** Alle varianten per tier, zonder rekening te houden met bezetting. */
export function legalHandleTiers(input: LegalNameParts | string | null | undefined): LegalHandleTiers | null {
  const n = parseLegalNameParts(input, "expanded");
  if (!n) return null;
  const simple = parseLegalNameParts(input, "simple");
  const alt = simple && JSON.stringify(simple) !== JSON.stringify(n) ? simple : null;
  const used = new Set<string>();
  const keep = (list: string[]) =>
    list.filter((h) => {
      if (used.has(h) || (!isTraceableToLegalName(n, h) && !(alt && isTraceableToLegalName(alt, h)))) return false;
      used.add(h);
      return true;
    });
  const t1 = keep(tier1(n));
  const t2 = keep(tier2(n));
  const t3 = keep(tier3(n, alt));
  const t4 = keep(tier4(n));
  return { tier1: t1, tier2: t2, tier3: t3, tier4: t4 };
}

export type IsReserved = (handle: string) => boolean;

/**
 * De keuzelijst na Didit: alle vrije Tier 1–3-varianten. Pas als élke Tier 1–3-variant
 * bezet of gereserveerd is, verschijnen de Tier 4-varianten (`--`, `__`).
 */
export function verifiedHandleCandidates(
  input: LegalNameParts | string | null | undefined,
  opts: { isTaken?: (handle: string) => boolean; isReserved?: IsReserved } = {},
): HandleCandidate[] {
  const tiers = legalHandleTiers(input);
  if (!tiers) return [];
  const isTaken = opts.isTaken ?? (() => false);
  const isReserved = opts.isReserved ?? (() => false);
  const free = (h: string) => !isReserved(h) && !isTaken(h);
  const normal: HandleCandidate[] = [
    ...tiers.tier1.map((handle) => ({ handle, tier: 1 as const })),
    ...tiers.tier2.map((handle) => ({ handle, tier: 2 as const })),
    ...tiers.tier3.map((handle) => ({ handle, tier: 3 as const })),
  ];
  const available = normal.filter((c) => free(c.handle));
  if (available.length > 0) return available;
  return tiers.tier4.filter(free).map((handle) => ({ handle, tier: 4 as const }));
}

export type VerifiedHandleRejection =
  | "HANDLE_INVALID"
  | "HANDLE_RESERVED"
  | "HANDLE_NOT_LEGALLY_TRACEABLE"
  | "HANDLE_FALLBACK_NOT_ALLOWED"
  | "HANDLE_TAKEN";

export type VerifiedHandleValidation = { ok: true; tier: HandleTier } | { ok: false; code: VerifiedHandleRejection };

/**
 * Server-side hervalidatie van een gekozen handle: komt hij voor in de toegestane set van
 * déze geverifieerde naam, is hij niet gereserveerd, en is hij (nog) vrij? Een Tier 4-handle
 * wordt enkel aanvaard wanneer alle Tier 1–3-varianten op dat moment bezet zijn.
 */
export function validateChosenVerifiedHandle(
  input: LegalNameParts | string | null | undefined,
  rawHandle: string,
  opts: { isTaken: (handle: string) => boolean; isReserved: IsReserved },
): VerifiedHandleValidation {
  return validateChosenFromTiers(legalHandleTiers(input), rawHandle, opts);
}

/** Zelfde hervalidatie, met tiers die al uit de (verzegelde) naam zijn berekend. */
export function validateChosenFromTiers(
  tiers: LegalHandleTiers | null,
  rawHandle: string,
  opts: { isTaken: (handle: string) => boolean; isReserved: IsReserved },
): VerifiedHandleValidation {
  const handle = String(rawHandle ?? "").trim().replace(/^@/, "").toLowerCase();
  if (!isSafeVerifiedHandleShape(handle, true)) return { ok: false, code: "HANDLE_INVALID" };
  if (opts.isReserved(handle)) return { ok: false, code: "HANDLE_RESERVED" };
  if (!tiers) return { ok: false, code: "HANDLE_NOT_LEGALLY_TRACEABLE" };
  const tierOf = (): HandleTier | null => {
    if (tiers.tier1.includes(handle)) return 1;
    if (tiers.tier2.includes(handle)) return 2;
    if (tiers.tier3.includes(handle)) return 3;
    if (tiers.tier4.includes(handle)) return 4;
    return null;
  };
  const tier = tierOf();
  if (tier === null) return { ok: false, code: "HANDLE_NOT_LEGALLY_TRACEABLE" };
  if (opts.isTaken(handle)) return { ok: false, code: "HANDLE_TAKEN" };
  if (tier === 4) {
    const anyNormalFree = [...tiers.tier1, ...tiers.tier2, ...tiers.tier3].some((h) => !opts.isReserved(h) && !opts.isTaken(h));
    if (anyNormalFree) return { ok: false, code: "HANDLE_FALLBACK_NOT_ALLOWED" };
  }
  return { ok: true, tier };
}
