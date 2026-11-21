/**
 * Sign-in session lifetime (owner directive 2026-11-17): a session lives 90 days and slides,
 * i.e. every request on a session older than 24 hours pushes its end 90 days forward again.
 * Better Auth applies both values (session.expiresIn / session.updateAge).
 */
export const SESSION_MAX_AGE_SEC = 60 * 60 * 24 * 90;
export const SESSION_REFRESH_AFTER_SEC = 60 * 60 * 24;
