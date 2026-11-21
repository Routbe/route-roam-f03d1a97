-- 0287_profile_field_encryption.sql — A1 EXPAND (owner directive 2026-11-17 12:09 UTC).
-- Held in db-pending/ until the owner's "GO A1". Purely additive: nothing is revoked, no
-- existing column changes, so the code that runs at 0286 keeps working unchanged.
--
-- Application-level AEAD for private profile fields. For every private field f the profile row
-- gets f_sealed: an RPF1 envelope (src/lib/profile-private/field-seal.ts):
--   "RPF1" | key version u8 | nonce 24 | XChaCha20-Poly1305(padded plaintext) + tag 16
--   = 29 + 64k + 16 bytes (k >= 1, plaintext <= 4096 bytes), AAD = version | field | profile id,
-- and, where the app must find a row by value, f_bidx: HMAC-BLAKE3 (32 bytes) of the normalized
-- value under a per-field, per-version key. The forwarding token is index-only: never stored
-- readable once sealing is live.
--
-- The keys never reach the database in usable form. Each key version is a random 32-byte field
-- master key, stored in vault_enclave.profile_field_keys only wrapped with AES-256-GCM under a key
-- HKDF-derived from ROUT_VAULT_KEK (server environment). The database alone opens no field; the
-- environment alone holds no data. rout_app may read the wrapped keys (useless without the KEK)
-- and register the first one; rotation is an owner operation.
--
-- Deliberately NOT sealed (database-enforced logic, see field-seal.ts):
--   is_shadowbanned  drives public visibility in SQL (sitemap, discovery, Q&A rout_qa_submit);
--                    its effect is public by design, sealing it would only stop the enforcement.
--   referred_by      gets an owner-only definer here; the CONTRACT withholds the column.
--
-- Backfill (owner, after GO): scripts/a1-backfill.ts seals the legacy values of the fields whose
-- readers already use the sealed columns (BACKFILL_FIELDS in src/lib/profile-private/backfill-plan.ts:
-- VAT, Stripe account, payment method, moderation reason and moderator) and sets their plaintext to
-- NULL in batches. The other sealed columns stay empty until their readers move. The CONTRACT
-- (withhold the plaintext columns from rout_app, require NULL) is a later, separate migration.
-- Rollback: db-pending/0287_profile_field_encryption_rollback.sql (refuses once anything is sealed).

-- ---------------------------------------------------------------- key ring

create table vault_enclave.profile_field_keys (
  version smallint primary key,
  kid bytea not null,
  wrapped_key bytea not null,
  kek_id bytea not null,
  created_at timestamptz not null default pg_catalog.clock_timestamp(),
  retired_at timestamptz,
  constraint profile_field_keys_version_range check (version between 1 and 255),
  constraint profile_field_keys_kid_len check (octet_length(kid) = 16),
  constraint profile_field_keys_kid_unique unique (kid),
  -- "RFK1" magic(4) || kek id(16) || nonce(12) || AES-256-GCM(key 32) + tag(16)
  constraint profile_field_keys_wrap_len check (octet_length(wrapped_key) = 80),
  constraint profile_field_keys_wrap_magic check (substring(wrapped_key from 1 for 4) = '\x52464b31'::bytea),
  constraint profile_field_keys_wrap_kek check (substring(wrapped_key from 5 for 16) = kek_id),
  constraint profile_field_keys_kek_len check (octet_length(kek_id) = 16)
);
-- Exactly one version seals new values; retired versions stay readable for old ones.
create unique index profile_field_keys_one_active on vault_enclave.profile_field_keys ((true)) where retired_at is null;
revoke all on table vault_enclave.profile_field_keys from public, rout_app;
alter table vault_enclave.profile_field_keys enable row level security;

-- Key versions are never deleted and never change, except being retired once.
create function vault_enclave.profile_field_keys_guard() returns trigger
language plpgsql set search_path = pg_catalog, pg_temp as $$
begin
  if tg_op = 'DELETE' then raise exception 'vault_enclave.profile_field_keys is append-only'; end if;
  if old.retired_at is not null or new.retired_at is null
     or (new.version, new.kid, new.wrapped_key, new.kek_id, new.created_at)
        is distinct from (old.version, old.kid, old.wrapped_key, old.kek_id, old.created_at) then
    raise exception 'vault_enclave.profile_field_keys rows can only be retired once';
  end if;
  return new;
end $$;
create trigger profile_field_keys_guard before update or delete on vault_enclave.profile_field_keys
  for each row execute function vault_enclave.profile_field_keys_guard();
create trigger profile_field_keys_no_truncate before truncate on vault_enclave.profile_field_keys
  for each statement execute function vault_enclave.audit_logs_immutable();

alter table vault_enclave.audit_logs drop constraint audit_logs_action_check;
alter table vault_enclave.audit_logs add constraint audit_logs_action_check
  check (action in ('step_up_register', 'token_store', 'token_retrieve', 'server_key_register',
                    'sdm_card_register', 'sdm_recovery_retrieve', 'sdm_recovery_confirm',
                    'sdm_fleet_register', 'sdm_batch_register', 'sdm_batch_cards_register',
                    'sdm_tap_begin', 'sdm_tap_confirm', 'sdm_tap_consume',
                    'sdm_card_activate', 'sdm_batch_list', 'sdm_batch_export',
                    'sdm_station_register', 'sdm_station_list', 'sdm_station_retire',
                    'card_step_up_begin', 'card_step_up_complete', 'card_step_up_claim',
                    'sdm_card_revoke',
                    'pake_setup_register', 'pake_register', 'pake_signup_register',
                    'pake_unregister', 'pake_login',
                    'passkey_attestation_record',
                    'recovery_v4_begin', 'recovery_v4_confirm', 'recovery_v4_commit',
                    'recovery_v4_abort', 'recovery_v4_remove', 'recovery_v4_expire',
                    'recovery_v4_replay', 'recovery_v4_compromise', 'recovery_v4_server_share',
                    'anon_host_key_init', 'anon_host_key_advance', 'anon_host_key_retire',
                    'anon_host_state_read', 'anon_booking_record', 'anon_booking_check',
                    'anon_pseudonym_invalidate', 'anon_capacity_open', 'anon_ledger_read',
                    'anon_host_purge', 'anon_host_merge',
                    'anon_device_register', 'anon_device_revoke', 'anon_device_list',
                    'profile_field_key_register'));

-- Every version, retired or not: old values must stay openable after a rotation.
create function public.rout_profile_field_keys()
returns table (version integer, kid bytea, wrapped_key bytea, kek_id bytea, active boolean)
language sql stable security definer set search_path = pg_catalog, pg_temp as $$
  select k.version::integer, k.kid, k.wrapped_key, k.kek_id, k.retired_at is null
    from vault_enclave.profile_field_keys k order by k.version desc
$$;

-- Registers version 1 when the ring is empty; refuses everything else (rotation is owner-only).
-- A forged row is harmless: the server refuses any wrap that does not authenticate under the KEK.
create function public.rout_profile_field_key_register(p_kid bytea, p_wrapped_key bytea, p_kek_id bytea)
returns boolean language plpgsql security definer set search_path = pg_catalog, pg_temp as $$
declare
  v_caller uuid := vault_enclave.caller_user_id();
  v_rows int;
begin
  perform pg_catalog.pg_advisory_xact_lock(7421003287);
  if exists (select 1 from vault_enclave.profile_field_keys) then
    perform vault_enclave.append_audit(v_caller, 'profile_field_key_register', 'denied', 'ring_exists', null); return false;
  end if;
  begin
    insert into vault_enclave.profile_field_keys (version, kid, wrapped_key, kek_id)
    values (1, p_kid, p_wrapped_key, p_kek_id);
    get diagnostics v_rows = row_count;
  exception when check_violation or not_null_violation or unique_violation then
    perform vault_enclave.append_audit(v_caller, 'profile_field_key_register', 'denied', 'malformed', null); return false;
  end;
  perform vault_enclave.append_audit(v_caller, 'profile_field_key_register', 'granted', 'ok', null);
  return v_rows = 1;
end $$;

-- ---------------------------------------------------------------- sealed columns

alter table public.profiles
  add column business_vat_sealed bytea,
  add column stripe_account_id_sealed bytea,
  add column payment_method_sealed bytea,
  add column moderation_reason_sealed bytea,
  add column moderated_by_sealed bytea,
  add column email_sealed bytea,
  add column forwarding_email_sealed bytea,
  add column legal_first_name_sealed bytea,
  add column legal_last_name_sealed bytea,
  add column last_city_sealed bytea,
  add column last_country_sealed bytea,
  add column business_vat_bidx bytea,
  add column stripe_account_id_bidx bytea,
  add column email_bidx bytea,
  add column forwarding_email_bidx bytea,
  add column forwarding_email_token_bidx bytea;

-- Shape of an RPF1 envelope: magic, a key version, and 29 + 64k + 16 bytes with 1 <= k <= 65.
create function public.rout_rpf1_shape_ok(p bytea) returns boolean
language sql immutable set search_path = pg_catalog, pg_temp as $$
  select p is null or (
    pg_catalog.octet_length(p) between 109 and 4205
    and (pg_catalog.octet_length(p) - 45) % 64 = 0
    and substring(p from 1 for 4) = '\x52504631'::bytea
    and pg_catalog.get_byte(p, 4) >= 1)
$$;

alter table public.profiles
  add constraint profiles_business_vat_sealed_shape check (public.rout_rpf1_shape_ok(business_vat_sealed)),
  add constraint profiles_stripe_account_id_sealed_shape check (public.rout_rpf1_shape_ok(stripe_account_id_sealed)),
  add constraint profiles_payment_method_sealed_shape check (public.rout_rpf1_shape_ok(payment_method_sealed)),
  add constraint profiles_moderation_reason_sealed_shape check (public.rout_rpf1_shape_ok(moderation_reason_sealed)),
  add constraint profiles_moderated_by_sealed_shape check (public.rout_rpf1_shape_ok(moderated_by_sealed)),
  add constraint profiles_email_sealed_shape check (public.rout_rpf1_shape_ok(email_sealed)),
  add constraint profiles_forwarding_email_sealed_shape check (public.rout_rpf1_shape_ok(forwarding_email_sealed)),
  add constraint profiles_legal_first_name_sealed_shape check (public.rout_rpf1_shape_ok(legal_first_name_sealed)),
  add constraint profiles_legal_last_name_sealed_shape check (public.rout_rpf1_shape_ok(legal_last_name_sealed)),
  add constraint profiles_last_city_sealed_shape check (public.rout_rpf1_shape_ok(last_city_sealed)),
  add constraint profiles_last_country_sealed_shape check (public.rout_rpf1_shape_ok(last_country_sealed)),
  add constraint profiles_business_vat_bidx_len check (business_vat_bidx is null or octet_length(business_vat_bidx) = 32),
  add constraint profiles_stripe_account_id_bidx_len check (stripe_account_id_bidx is null or octet_length(stripe_account_id_bidx) = 32),
  add constraint profiles_email_bidx_len check (email_bidx is null or octet_length(email_bidx) = 32),
  add constraint profiles_forwarding_email_bidx_len check (forwarding_email_bidx is null or octet_length(forwarding_email_bidx) = 32),
  add constraint profiles_forwarding_email_token_bidx_len check (forwarding_email_token_bidx is null or octet_length(forwarding_email_token_bidx) = 32),
  -- An index never exists without its ciphertext (index-only token excepted).
  add constraint profiles_business_vat_bidx_pair check ((business_vat_bidx is null) = (business_vat_sealed is null)),
  add constraint profiles_stripe_account_id_bidx_pair check ((stripe_account_id_bidx is null) = (stripe_account_id_sealed is null)),
  add constraint profiles_email_bidx_pair check ((email_bidx is null) = (email_sealed is null)),
  add constraint profiles_forwarding_email_bidx_pair check ((forwarding_email_bidx is null) = (forwarding_email_sealed is null));

-- Same uniqueness as the plaintext columns had (one Stripe account per profile, one live token).
create unique index profiles_stripe_account_id_bidx_key on public.profiles (stripe_account_id_bidx) where stripe_account_id_bidx is not null;
create unique index profiles_forwarding_email_token_bidx_key on public.profiles (forwarding_email_token_bidx) where forwarding_email_token_bidx is not null;
create index profiles_business_vat_bidx_idx on public.profiles (business_vat_bidx) where business_vat_bidx is not null;
create index profiles_email_bidx_idx on public.profiles (email_bidx) where email_bidx is not null;
create index profiles_forwarding_email_bidx_idx on public.profiles (forwarding_email_bidx) where forwarding_email_bidx is not null;

-- rout_app reads ciphertext and blind indexes only (writes are covered by its table-level
-- INSERT/UPDATE on public.profiles). Decryption happens in the app process, never in SQL.
grant select (business_vat_sealed, stripe_account_id_sealed, payment_method_sealed, moderation_reason_sealed,
              moderated_by_sealed, email_sealed, forwarding_email_sealed, legal_first_name_sealed,
              legal_last_name_sealed, last_city_sealed, last_country_sealed, business_vat_bidx,
              stripe_account_id_bidx, email_bidx, forwarding_email_bidx, forwarding_email_token_bidx)
  on public.profiles to rout_app;

-- ---------------------------------------------------------------- referred_by (EXPAND)

-- Whether the calling member came in through an invite (the only app read of referred_by).
create function public.rout_profile_referred_mine()
returns boolean language sql stable security definer set search_path = pg_catalog, pg_temp as $$
  select coalesce((select p.referred_by is not null from public.profiles p
                    where p.id = public.rout_current_user_id()), false)
$$;

-- ---------------------------------------------------------------- function rights

revoke all on function vault_enclave.profile_field_keys_guard() from public, rout_app;
revoke all on function public.rout_rpf1_shape_ok(bytea) from public, rout_app;
revoke all on function public.rout_profile_field_keys() from public, rout_app;
revoke all on function public.rout_profile_field_key_register(bytea, bytea, bytea) from public, rout_app;
revoke all on function public.rout_profile_referred_mine() from public, rout_app;
-- Pure shape check used by CHECK constraints on rows rout_app writes.
grant execute on function public.rout_rpf1_shape_ok(bytea) to rout_app;
grant execute on function public.rout_profile_field_keys() to rout_app;
grant execute on function public.rout_profile_field_key_register(bytea, bytea, bytea) to rout_app;
grant execute on function public.rout_profile_referred_mine() to rout_app;
