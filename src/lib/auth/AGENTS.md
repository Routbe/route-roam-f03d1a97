## Password pages
- Password sign-in, sign-up and set-up run only on /secure/password* documents (full page load, COOP/COEP/CSP from withSecureDocumentHeaders in src/server.ts) through opaque-client.ts and the crypto worker; every password option stays hidden until getAuthProviders reports OPAQUE live. Why: cross-origin isolation needs a hard document boundary, and no dead password button may appear while the deployed database lacks db/0270.

## Sudo Mode
- Sensitive mutations (merge, vault, key/secret rotation) use requireSudo(label): a signed __Host-sudo_session minted only from a general passkey step-up proof, bound to member and sign-in session, valid exactly 300 s from the passkey verification (src/lib/auth/sudo-rules.ts); database-clock passkey proofs stay in addition. Why: one passkey tap covers a short burst of actions without ever trusting a stretched or transplanted window.

## Social onboarding
- Providers keep disableSignUp; a Google/GitHub/GitLab callback refused with `signup_disabled` whose provider marks the e-mail verified becomes a signed `so.` ticket (state pending_passkey_setup, HttpOnly __Host- cookie, 10 min; social-onboarding.ts) and redirects to /auth/sign-up?onboard=social, where age then passkey run; the account is created and the provider linked only inside the verified passkey ceremony (finalizeEnrollment). Why: every account has a passkey and an abandoned OAuth hand-off leaves no row.

## Auth card tabs and Conditional UI
- The /login and /register tabs swap the address with History.prototype.replaceState (src/lib/auth/auth-tab-url.ts) and the conditional passkey request runs under one AbortController that is aborted before every explicit ceremony (src/lib/auth/conditional-passkey.ts). Why: TanStack patches window.history.replaceState into a navigation that remounts the card, and browsers allow only one WebAuthn request at a time.
