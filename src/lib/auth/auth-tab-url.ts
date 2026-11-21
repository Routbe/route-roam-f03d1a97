/** Auth card tabs: URL pairing (/login <-> /register) and W3C APG tablist keyboard handling. */
export type AuthTab = "signin" | "signup";

const PAIRED = new Set(["/login", "/register"]);

/** The address for `tab` when the card lives on /login or /register; null on every other route. */
export function authTabPath(pathname: string, tab: AuthTab): string | null {
  const clean = pathname.replace(/\/+$/, "") || "/";
  if (!PAIRED.has(clean)) return null;
  return tab === "signup" ? "/register" : "/login";
}

/**
 * Native History.prototype.replaceState with the current state kept. TanStack's browser history patches
 * window.history.replaceState and turns every call into a router navigation, which would remount the
 * card (and drop what was typed) when /login becomes /register; the prototype method only rewrites the
 * address. A later popstate or navigation reads the real URL again.
 */
export function nativeReplaceUrl(url: string) {
  History.prototype.replaceState.call(window.history, window.history.state, "", url);
}

/** Swaps /login and /register in place (query and hash kept), without remounting or adding a back-button step. */
export function syncAuthTabUrl(
  tab: AuthTab,
  loc: Pick<Location, "pathname" | "search" | "hash"> = window.location,
  replace: (url: string) => void = nativeReplaceUrl,
): boolean {
  const next = authTabPath(loc.pathname, tab);
  if (!next || next === loc.pathname) return false;
  replace(`${next}${loc.search}${loc.hash}`);
  return true;
}

/** Arrow keys wrap between the two tabs; Home/End jump to the first/last tab. */
export function authTabFromKey(key: string, current: AuthTab): AuthTab | null {
  switch (key) {
    case "ArrowLeft":
    case "ArrowRight":
    case "ArrowUp":
    case "ArrowDown":
      return current === "signin" ? "signup" : "signin";
    case "Home":
      return "signin";
    case "End":
      return "signup";
    default:
      return null;
  }
}
