/**
 * Touch devices cannot type into the "Extra voorzichtig typen" key-capture box: a div gets no
 * on-screen keyboard on iOS or Android. There the field falls back to a native password input
 * with autocomplete, autocorrect and spellcheck off, so the keyboard opens on the first tap.
 */
export type TouchProbe = { hasTouchEvent: boolean; maxTouchPoints: number };

export function isTouchDevice(p: TouchProbe): boolean {
  return p.hasTouchEvent || p.maxTouchPoints > 0;
}

/** Reads the probe from the browser; false during server rendering. */
export function detectTouch(): boolean {
  if (typeof window === "undefined" || typeof navigator === "undefined") return false;
  return isTouchDevice({ hasTouchEvent: "ontouchstart" in window, maxTouchPoints: navigator.maxTouchPoints ?? 0 });
}

/** The capture mode actually used: paranoid key capture only on non-touch devices. */
export function effectivePasswordMode<M extends "normal" | "paranoid">(requested: M, touch: boolean): "normal" | "paranoid" {
  return touch ? "normal" : requested;
}
