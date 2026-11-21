# EUDI wallet rules

- The OID4VCI token and credential endpoints accept only RFC 9449 DPoP (src/lib/eudi/dpop.ts): no Bearer fallback, the access token is stored as SHA-256(token "." jkt), server DPoP nonces use their own HMAC key, and jti replays are refused by a per-instance cache plus the shared ledger public.dpop_jti_replays (db/0295, rout_dpop_jti_claim on the database clock); any store failure refuses the proof. Why: an intercepted token or proof must be useless without the wallet's private key, on every server instance.
