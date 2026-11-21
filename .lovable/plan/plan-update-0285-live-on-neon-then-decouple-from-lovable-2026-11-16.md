# Plan: update 0285 live on Neon, then decouple from Lovable

## Phase 1 — Update 0285 on Neon

1. **Dry-run first, no writes**
   - Recheck that Neon's latest recorded update is still `0284_booking_ledger.sql` and that 0285 is not recorded yet.
   - Run the targeted tests: `workspace-group-0285`, `booking-ledger-0284`, `server-fn-auth-guard`, `migration-rollout`, `definer-execute-grants`.
   - If anything fails, stop and report. Nothing gets applied.
2. **Apply it exactly as written** (one transaction)
   - Build the rollout batch with `scripts/migration-rollout.ts db/0285_workspace_group_encryption.sql --after=0284_booking_ledger.sql`, sending the file's exact text.
   - Inside Neon, the transaction checks the SHA-256 against the file's checksum and checks that 0284 is the predecessor.
   - It then runs the file and records it in `public.schema_migrations`.
   - The search_path guard runs in the same transaction.
   - Before sending, I show the exact checksum. The approval card for the live write comes up after that.
3. **Sync the schema snapshot**
   - Run `bun scripts/schema-replay-snapshot.ts` and `scripts/schema-snapshot.ts`.
   - Then run `migration-history-check` (expected: 279 recorded, 0 differences, none pending) and `security-definer-check`.
4. **Check against live Neon (read only, plus test transactions that are always rolled back)**
   - Workspace public key (`workspace_keys`): one active epoch per workspace, publishable only by an owner or admin.
   - Member key envelopes (`workspace_member_keys`):
     - `rout_app` and PUBLIC have no table rights.
     - Every `rout_ws_*` function is SECURITY DEFINER with `search_path = pg_catalog, pg_temp`.
     - Calls as editor, developer and viewer are refused.
   - Losing admin rights: demote a test admin in a transaction that is rolled back, and confirm their envelopes are deleted by `workspace_members_role_revoke_ws_keys`.

**Correction to the brief:**
- 0285 has **no automatic `epoch = epoch + 1`**. On revocation, the trigger only deletes the envelopes.
- A new epoch comes only from an explicit `rout_ws_group_publish` by an owner or admin.
- I report what is actually there and don't change 0285. Automatic rotation would need a separate update 0286, which waits for your GO.

## Phase 2 — Decouple from Lovable

1. **Build setup** (`vite.config.ts`, `package.json`)
   - Replace `@lovable.dev/vite-tanstack-config` with a standard setup: `@tanstack/react-start/plugin/vite`, `@vitejs/plugin-react`, `@tailwindcss/vite`, `vite-tsconfig-paths` and `nitro`.
   - The output target is chosen with `NITRO_PRESET`, defaulting to `node-server`. Vercel and containers also work.
   - Keep the MDX plugin, the docs catalog, the `@` alias, and the `server` entry.
2. **Database connection only through `DATABASE_URL`** (`src/lib/neon.ts`, `src/lib/env.ts`)
   - Remove the gateway path that is triggered by `LOVABLE_API_KEY` and `NEON_API_KEY`.
   - Connect directly with the standard Postgres driver, with `sslmode=require` enforced.
   - The `set local role rout_app` and member context per transaction stay unchanged.
   - Update the matching tests: `neon`, `database-runtime`, `auth-database-transport`, `db-context-lazy-query`, `provider-error-privacy`.
3. **Admin scripts**
   - Switch these to a direct connection on `MIGRATION_URL`, falling back to `DATABASE_URL`: `migration-rollout`, `migrate-gateway` (renamed to a direct runner), `migration-history-check`, `security-definer-check`, `schema-snapshot`, `audit-rls`, `tenant-backfill`, `seed-test-user`, `owner-passkey-link`, `verify-live-merge`.
   - The checksum and predecessor checks and the definer guard stay byte-for-byte the same, now inside a normal BEGIN/COMMIT.
4. **Security and cleanup**
   - Lovable addresses (`app-url`, `app-mode`, `better-auth.server`, `security-headers`, `pwa`, `verification-requests`): only allowed when `NODE_ENV === 'development'`.
   - Remove `public/lovable-customization.js` and the Lovable error-reporter plugins.
   - Remove `LOVABLE_CRON_SECRET` from `cron-auth.ts` and its test. Cron then works only with your own `CRON_SECRET`.
   - Update `ENVIRONMENT.md` and `docs/HANDOVER.md`. In HANDOVER.md, changes go only in the appendix.
5. Run the full set of affected tests and report the results.

## Important consequences
- **The preview here stops working after Phase 2.1.** This environment can only run the app with the Lovable build package. After the switch, you build and run it on your own server. I can check the build locally, but you won't see a live preview here anymore.
- **Phase 1 writes to production Neon using the owner connection.** The approval card for that write is the final go-ahead.
- **I won't redeploy production.** You do that yourself on your own infrastructure, once Neon reports 0285.
