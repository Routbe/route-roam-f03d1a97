import { useCallback, useEffect, useState } from "react";
import {
  endSudo,
  readSudoStatus,
  requestSudo,
  subscribeSudo,
  sudoSnapshot,
  withSudo,
  type SudoState,
} from "@/lib/auth/sudo-client";

/**
 * Sudo Mode for components: whether a 300 s passkey window is open, a live countdown,
 * and helpers to ask for it (`request`), run a guarded action (`run`) or close it (`end`).
 */
export function useSudoMode() {
  const [state, setState] = useState<SudoState>(sudoSnapshot);
  const [now, setNow] = useState(() => Date.now());

  useEffect(() => subscribeSudo(setState), []);
  useEffect(() => {
    void readSudoStatus();
  }, []);
  useEffect(() => {
    if (!state.active) return;
    const id = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(id);
  }, [state.active]);

  const expiresMs = state.expiresAt ? Date.parse(state.expiresAt) : 0;
  const secondsLeft = state.active ? Math.max(0, Math.ceil((expiresMs - now) / 1000)) : 0;

  const run = useCallback(<T>(fn: () => Promise<T>) => withSudo(fn), []);
  return {
    active: secondsLeft > 0,
    secondsLeft,
    expiresAt: state.expiresAt,
    request: requestSudo,
    run,
    end: endSudo,
    refresh: readSudoStatus,
  };
}
