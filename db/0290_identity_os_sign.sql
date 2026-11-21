-- 0290 (EXPAND, additive): Sovereign Identity OS claims, workspace IBAN via KYC, ROUT Sign requests.
--
-- Owner directives of 2026-11-17 ("Level-10 Sovereign Identity OS, ROUT Sign & Developer Platform")
-- and the owner's answers the same day (age gate 13-21 chosen by the app, Didit suffices for an IBAN,
-- DNSSEC for every domain, a qualified external signing service for ROUT Sign):
--   * verified_identity_nullifiers.age_floor: the member's age in whole years at attestation,
--     capped at 21, computed in the app from the document and never the date of birth itself.
--     An "over N" claim (N 13..21) is true only when age_floor >= N; an older attestation can only
--     under-state the age, so a stale value fails closed.
--   * rout_kyc_attest gains a 7-argument form with the age floor; the 6-argument form stays (it is
--     the 0288 schema marker) and forwards with no age.
--   * rout_my_identity_claims(): the caller's own claims for "Login met ROUT" (has_legal_identity,
--     is_real_human from zero-knowledge rows only, age_floor, and the primary universal nullifier
--     the server needs to derive a per-app nullifier). Member context only; nobody else's row.
--   * Workspace support (0283): a workspace whose owner holds a KYC legal-identity attestation may
--     link an IBAN without the holder-name match (Didit v3 keeps no name since 2026-11-17); a
--     workspace that is eligible only through its verified DNS domain keeps the name match.
--   * public.sign_requests: ROUT Sign. The PDF exists here only as ciphertext sealed in the browser
--     under a key that travels in the link fragment; rout_app has no table rights and works through
--     the definers below. A request is signed once, by a member with a KYC legal identity.
-- Held in db-pending/ until the owner's explicit GO for 0290; it runs after 0289.

alter table public.verified_identity_nullifiers
  add column if not exists age_floor smallint check (age_floor is null or age_floor between 0 and 21);

create function public.rout_kyc_attest(
  p_provider text, p_nullifiers text[], p_anchor_kinds text[],
  p_is_real_human boolean, p_has_legal_identity boolean, p_jurisdiction text, p_age_floor smallint)
 returns text
 language plpgsql
 security definer
 set search_path = pg_catalog, pg_temp
as $function$
declare
  v_user  uuid := public.rout_current_user_id();
  v_n     integer := coalesce(pg_catalog.array_length(p_nullifiers, 1), 0);
  v_other text;
  v_nf    text;
begin
  if v_user is null then
    return 'no_context';
  end if;
  if v_n = 0 or v_n > 4 or v_n <> coalesce(pg_catalog.array_length(p_anchor_kinds, 1), 0)
     or exists (select 1 from pg_catalog.unnest(p_nullifiers) x where x is null or x !~ '^[0-9a-f]{64}$')
     or exists (select 1 from pg_catalog.unnest(p_anchor_kinds) k where k is null or k not in ('personal_number', 'document', 'provider_subject'))
     or (p_jurisdiction is not null and p_jurisdiction !~ '^[A-Z]{3}$')
     or (p_age_floor is not null and p_age_floor not between 0 and 21)
     or p_provider is null or p_is_real_human is null or p_has_legal_identity is null
     -- World ID is a zero-knowledge proof, never a KYC document; it gets its own verifier.
     or p_provider = 'world_id' then
    return 'invalid_input';
  end if;
  for v_nf in select x from pg_catalog.unnest(p_nullifiers) x order by x loop
    perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended(v_nf, 288));
  end loop;
  select n.provider into v_other
    from public.verified_identity_nullifiers n
   where n.universal_nullifier = any (p_nullifiers) and n.user_id <> v_user
   order by n.attested_at
   limit 1;
  if v_other is not null then
    return case when v_other = p_provider then 'duplicate_human' else 'identity_already_attested_across_providers' end;
  end if;
  insert into public.verified_identity_nullifiers as t
      (universal_nullifier, user_id, provider, anchor_kind, is_real_human, has_legal_identity, jurisdiction, evidence, age_floor)
    select a.nf, v_user, p_provider, a.kind, p_is_real_human, p_has_legal_identity, p_jurisdiction, 'kyc_document', p_age_floor
      from rows from (pg_catalog.unnest(p_nullifiers), pg_catalog.unnest(p_anchor_kinds)) as a(nf, kind)
  -- A later attestation of the same member may only raise the recorded age floor.
  on conflict (universal_nullifier) do update
     set age_floor = greatest(t.age_floor, excluded.age_floor)
   where t.user_id = v_user and excluded.age_floor is not null;
  return 'ok';
end
$function$;
revoke all on function public.rout_kyc_attest(text, text[], text[], boolean, boolean, text, smallint) from public, rout_app;
grant execute on function public.rout_kyc_attest(text, text[], text[], boolean, boolean, text, smallint) to rout_app;

create or replace function public.rout_kyc_attest(
  p_provider text, p_nullifiers text[], p_anchor_kinds text[],
  p_is_real_human boolean, p_has_legal_identity boolean, p_jurisdiction text)
 returns text
 language sql
 security definer
 set search_path = pg_catalog, pg_temp
as $function$
  select public.rout_kyc_attest(p_provider, p_nullifiers, p_anchor_kinds, p_is_real_human, p_has_legal_identity,
    p_jurisdiction, null::smallint)
$function$;

-- The caller's own identity claims. No member context = no row.
create function public.rout_my_identity_claims()
 returns table(has_legal_identity boolean, is_real_human boolean, age_floor smallint, root_nullifier text)
 language sql
 stable
 security definer
 set search_path = pg_catalog, pg_temp
as $function$
  with me as (select public.rout_current_user_id() as id)
  select
    exists (select 1 from public.verified_identity_nullifiers n
             where n.user_id = me.id and n.evidence = 'kyc_document' and n.has_legal_identity)
      or exists (select 1 from public.identity_verifications iv
                  where iv.user_id = me.id and coalesce(iv.is_verified, false) and iv.verification_provider::text = 'didit')
      or exists (select 1 from public.verified_identities vi
                  where vi.user_id = me.id and coalesce(vi.tier_2_legal_identity, false) and vi.national_id_nullifier is not null),
    exists (select 1 from public.verified_identity_nullifiers n
             where n.user_id = me.id and n.evidence = 'zk_proof' and n.is_real_human),
    (select pg_catalog.max(n.age_floor) from public.verified_identity_nullifiers n
      where n.user_id = me.id and n.evidence = 'kyc_document'),
    (select n.universal_nullifier from public.verified_identity_nullifiers n
      where n.user_id = me.id and n.evidence = 'kyc_document'
      order by case n.anchor_kind when 'personal_number' then 0 when 'document' then 1 else 2 end, n.universal_nullifier
      limit 1)
  from me
  where me.id is not null
$function$;
revoke all on function public.rout_my_identity_claims() from public, rout_app;
grant execute on function public.rout_my_identity_claims() to rout_app;

-- Internal: the workspace owner holds a KYC legal identity (same rule as the blue mark, db/0288).
create function public.rout_ws_support_owner_kyc(p_ws uuid)
 returns boolean language sql stable security definer set search_path = pg_catalog, pg_temp
as $function$
  select exists (
    select 1 from public.workspace_members m
     where m.workspace_id = p_ws and m.role::text = 'owner'
       and (exists (select 1 from public.verified_identity_nullifiers n
                     where n.user_id = m.user_id and n.evidence = 'kyc_document' and n.has_legal_identity)
         or exists (select 1 from public.identity_verifications iv
                     where iv.user_id = m.user_id and coalesce(iv.is_verified, false) and iv.verification_provider::text = 'didit')
         or exists (select 1 from public.verified_identities vi
                     where vi.user_id = m.user_id and coalesce(vi.tier_2_legal_identity, false) and vi.national_id_nullifier is not null)))
$function$;
revoke all on function public.rout_ws_support_owner_kyc(uuid) from public, rout_app;

create or replace function public.rout_ws_support_get(p_ws uuid)
 returns table(enabled boolean, iban text, account_name text, presets_cents integer[], allow_custom boolean,
   min_cents integer, message text, psp_enabled boolean, owner_didit boolean, domain_verified boolean,
   providers jsonb)
 language plpgsql stable security definer set search_path = pg_catalog, pg_temp
as $function$
begin
  if not public.rout_ws_support_manager(p_ws) then return; end if;
  return query
  select coalesce(s.enabled, false), s.iban, s.account_name, coalesce(s.presets_cents, '{500,1000,2500}'::integer[]),
         coalesce(s.allow_custom, true), coalesce(s.min_cents, 100), s.message, coalesce(s.psp_enabled, false),
         public.rout_ws_support_owner_kyc(p_ws),
         w.domain_verified_at is not null,
         coalesce((select pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('provider', c.provider, 'last4', c.last4,
                     'mode', c.mode, 'verifiedAt', c.verified_at) order by c.provider)
                     from public.workspace_psp_credentials c where c.workspace_id = p_ws), '[]'::jsonb)
    from public.workspaces w
    left join public.workspace_tip_settings s on s.workspace_id = w.id
   where w.id = p_ws;
end $function$;

-- Managers: save settings. Answers ok | forbidden | not_eligible | name_mismatch | invalid.
create or replace function public.rout_ws_support_save(p_ws uuid, p_enabled boolean, p_iban text, p_account_name text,
  p_presets integer[], p_allow_custom boolean, p_min integer, p_message text, p_psp_enabled boolean)
 returns text language plpgsql volatile security definer set search_path = pg_catalog, pg_temp
as $function$
declare
  v_iban text := nullif(pg_catalog.upper(pg_catalog.regexp_replace(coalesce(p_iban, ''), '\s+', '', 'g')), '');
  v_name text := nullif(pg_catalog.btrim(coalesce(p_account_name, '')), '');
begin
  if not public.rout_ws_support_manager(p_ws) then return 'forbidden'; end if;
  if v_iban is not null and v_iban !~ '^[A-Z]{2}[0-9]{2}[A-Z0-9]{11,30}$' then return 'invalid'; end if;
  if p_min is null or p_min not between 100 and 500000 or pg_catalog.cardinality(coalesce(p_presets, '{}')) > 6
     or exists (select 1 from pg_catalog.unnest(coalesce(p_presets, '{}')) c where c < p_min or c > 500000)
     or (p_message is not null and pg_catalog.char_length(p_message) > 400)
     or (v_name is not null and pg_catalog.char_length(v_name) > 70) then
    return 'invalid';
  end if;
  if p_enabled or v_iban is not null then
    if v_iban is null or v_name is null then return 'invalid'; end if;
    -- A KYC-attested owner is eligible on its own; otherwise the verified domain plus a name match.
    if not public.rout_ws_support_owner_kyc(p_ws) then
      if not exists (select 1 from public.rout_ws_support_names(p_ws)) then return 'not_eligible'; end if;
      if not exists (select 1 from public.rout_ws_support_names(p_ws) n
                      where public.rout_ws_support_norm(n) = public.rout_ws_support_norm(v_name)) then
        return 'name_mismatch';
      end if;
    end if;
  end if;
  insert into public.workspace_tip_settings as s (workspace_id, enabled, iban, account_name, presets_cents, allow_custom,
      min_cents, message, psp_enabled, updated_by, updated_at)
  values (p_ws, p_enabled, v_iban, v_name, coalesce(p_presets, '{}'), p_allow_custom, p_min,
      nullif(pg_catalog.btrim(coalesce(p_message, '')), ''), p_psp_enabled, public.rout_current_user_id(), pg_catalog.now())
  on conflict (workspace_id) do update set enabled = excluded.enabled, iban = excluded.iban,
      account_name = excluded.account_name, presets_cents = excluded.presets_cents, allow_custom = excluded.allow_custom,
      min_cents = excluded.min_cents, message = excluded.message, psp_enabled = excluded.psp_enabled,
      updated_by = excluded.updated_by, updated_at = pg_catalog.now();
  return 'ok';
end $function$;

create or replace function public.rout_ws_psp_save(p_ws uuid, p_provider text, p_ciphertext text, p_iv text,
  p_last4 text, p_mode text, p_publishable_key text)
 returns text language plpgsql volatile security definer set search_path = pg_catalog, pg_temp
as $function$
begin
  if not public.rout_ws_support_manager(p_ws) then return 'forbidden'; end if;
  if not public.rout_ws_support_owner_kyc(p_ws) and not exists (select 1 from public.rout_ws_support_names(p_ws)) then
    return 'not_eligible';
  end if;
  if p_provider not in ('stripe', 'mollie') or p_mode not in ('live', 'test') then return 'invalid'; end if;
  insert into public.workspace_psp_credentials (workspace_id, provider, ciphertext, iv, last4, mode, publishable_key, saved_by, verified_at)
  values (p_ws, p_provider, p_ciphertext, p_iv, pg_catalog.right(coalesce(p_last4, ''), 4), p_mode, p_publishable_key,
          public.rout_current_user_id(), pg_catalog.now())
  on conflict (workspace_id, provider) do update set ciphertext = excluded.ciphertext, iv = excluded.iv,
    last4 = excluded.last4, mode = excluded.mode, publishable_key = excluded.publishable_key,
    saved_by = excluded.saved_by, verified_at = pg_catalog.now();
  return 'ok';
end $function$;

-- Public: eligibility is re-checked at every read (a lost attestation or domain closes the page).
create or replace function public.rout_public_ws_support(p_slug text)
 returns table(workspace_id uuid, name text, slug text, avatar_url text, account_name text, iban text,
   presets_cents integer[], allow_custom boolean, min_cents integer, message text, providers text[])
 language sql stable security definer set search_path = pg_catalog, pg_temp
as $function$
  select w.id, w.name, w.slug, w.avatar_url, s.account_name, s.iban, s.presets_cents, s.allow_custom, s.min_cents, s.message,
         case when s.psp_enabled then coalesce((select pg_catalog.array_agg(c.provider order by c.provider)
           from public.workspace_psp_credentials c where c.workspace_id = w.id), '{}'::text[]) else '{}'::text[] end
    from public.workspaces w
    join public.workspace_tip_settings s on s.workspace_id = w.id
   where w.slug = pg_catalog.lower(p_slug) and s.enabled and s.iban is not null and s.account_name is not null
     and (public.rout_ws_support_owner_kyc(w.id)
       or exists (select 1 from public.rout_ws_support_names(w.id) n
                   where public.rout_ws_support_norm(n) = public.rout_ws_support_norm(s.account_name)))
   limit 1
$function$;

-- ROUT Sign ---------------------------------------------------------------------------------------
create table public.sign_requests (
  id                uuid primary key default pg_catalog.gen_random_uuid(),
  owner_id          uuid not null references public.users(id) on delete cascade,
  ciphertext        bytea not null check (pg_catalog.octet_length(ciphertext) between 64 and 12000000),
  ciphertext_sha256 text not null check (ciphertext_sha256 ~ '^[0-9a-f]{64}$'),
  min_read_seconds  integer not null check (min_read_seconds between 10 and 600),
  status            text not null default 'open' check (status in ('open', 'signed', 'revoked')),
  created_at        timestamptz not null default pg_catalog.now(),
  expires_at        timestamptz not null,
  signer_id         uuid references public.users(id) on delete set null,
  signer_binding    text check (signer_binding is null or signer_binding ~ '^[0-9a-f]{64}$'),
  signed_digest     text check (signed_digest is null or signed_digest ~ '^[0-9a-f]{64}$'),
  signed_ciphertext bytea check (signed_ciphertext is null or pg_catalog.octet_length(signed_ciphertext) between 64 and 16000000),
  signed_at         timestamptz,
  constraint sign_requests_signed_shape check (
    (status = 'signed') = (signed_at is not null and signer_binding is not null and signed_digest is not null and signed_ciphertext is not null))
);
create index sign_requests_owner_id_fkx on public.sign_requests (owner_id, created_at desc);
create index sign_requests_signer_id_fkx on public.sign_requests (signer_id);
revoke all on table public.sign_requests from public, rout_app;
alter table public.sign_requests enable row level security;

-- Owner: store a sealed PDF. Answers the new id, or null for invalid input / no context / too many open.
create function public.rout_sign_request_create(p_ciphertext bytea, p_days integer, p_min_read integer)
 returns uuid language plpgsql volatile security definer set search_path = pg_catalog, pg_temp
as $function$
declare
  v_user uuid := public.rout_current_user_id();
  v_id   uuid;
begin
  if v_user is null or p_ciphertext is null or pg_catalog.octet_length(p_ciphertext) not between 64 and 12000000
     or p_days is null or p_days not between 1 and 30 or p_min_read is null or p_min_read not between 10 and 600 then
    return null;
  end if;
  if (select pg_catalog.count(*) from public.sign_requests r
       where r.owner_id = v_user and r.status = 'open' and r.expires_at > pg_catalog.now()) >= 20 then
    return null;
  end if;
  insert into public.sign_requests (owner_id, ciphertext, ciphertext_sha256, min_read_seconds, expires_at)
  values (v_user, p_ciphertext, pg_catalog.encode(pg_catalog.sha256(p_ciphertext), 'hex'), p_min_read,
          pg_catalog.now() + pg_catalog.make_interval(days => p_days))
  returning id into v_id;
  return v_id;
end $function$;

-- Any signed-in member holding the link: the sealed PDF (useless without the fragment key).
create function public.rout_sign_request_open(p_id uuid)
 returns table(ciphertext bytea, ciphertext_sha256 text, status text, expires_at timestamptz, min_read_seconds integer,
   is_owner boolean, is_signer boolean, signed_ciphertext bytea, signed_at timestamptz)
 language sql stable security definer set search_path = pg_catalog, pg_temp
as $function$
  select r.ciphertext, r.ciphertext_sha256,
         case when r.status = 'open' and r.expires_at <= pg_catalog.now() then 'expired' else r.status end,
         r.expires_at, r.min_read_seconds,
         r.owner_id = public.rout_current_user_id(), r.signer_id = public.rout_current_user_id(),
         case when r.owner_id = public.rout_current_user_id() or r.signer_id = public.rout_current_user_id()
              then r.signed_ciphertext end,
         r.signed_at
    from public.sign_requests r
   where r.id = p_id and r.status <> 'revoked' and public.rout_current_user_id() is not null
$function$;

-- Server, after the signing service returned: records the signature once, and only for exactly the
-- sealed PDF that was decrypted and signed (p_source_sha256 = the stored ciphertext's SHA-256).
-- Answers ok | no_context | not_found | expired | not_open | no_legal_identity | invalid_input | source_changed.
create function public.rout_sign_request_mark_signed(p_id uuid, p_source_sha256 text, p_binding text, p_digest text, p_signed bytea)
 returns text language plpgsql volatile security definer set search_path = pg_catalog, pg_temp
as $function$
declare
  v_user uuid := public.rout_current_user_id();
  r      public.sign_requests%rowtype;
begin
  if v_user is null then return 'no_context'; end if;
  if p_source_sha256 is null or p_source_sha256 !~ '^[0-9a-f]{64}$'
     or p_binding is null or p_binding !~ '^[0-9a-f]{64}$' or p_digest is null or p_digest !~ '^[0-9a-f]{64}$'
     or p_signed is null or pg_catalog.octet_length(p_signed) not between 64 and 16000000 then
    return 'invalid_input';
  end if;
  select * into r from public.sign_requests where id = p_id for update;
  if not found or r.status = 'revoked' then return 'not_found'; end if;
  if r.status <> 'open' then return 'not_open'; end if;
  if r.expires_at <= pg_catalog.now() then return 'expired'; end if;
  if r.ciphertext_sha256 <> p_source_sha256 then return 'source_changed'; end if;
  if not exists (select 1 from public.verified_identity_nullifiers n
                  where n.user_id = v_user and n.evidence = 'kyc_document' and n.has_legal_identity) then
    return 'no_legal_identity';
  end if;
  update public.sign_requests
     set status = 'signed', signer_id = v_user, signer_binding = p_binding, signed_digest = p_digest,
         signed_ciphertext = p_signed, signed_at = pg_catalog.now()
   where id = p_id;
  return 'ok';
end $function$;

create function public.rout_sign_request_revoke(p_id uuid)
 returns text language plpgsql volatile security definer set search_path = pg_catalog, pg_temp
as $function$
begin
  update public.sign_requests set status = 'revoked', ciphertext = pg_catalog.decode(pg_catalog.repeat('00', 64), 'hex')
   where id = p_id and owner_id = public.rout_current_user_id() and status = 'open';
  return case when found then 'ok' else 'not_found' end;
end $function$;

create function public.rout_sign_requests_mine()
 returns table(id uuid, status text, created_at timestamptz, expires_at timestamptz, signed_at timestamptz, size_bytes integer)
 language sql stable security definer set search_path = pg_catalog, pg_temp
as $function$
  select r.id, case when r.status = 'open' and r.expires_at <= pg_catalog.now() then 'expired' else r.status end,
         r.created_at, r.expires_at, r.signed_at, pg_catalog.octet_length(r.ciphertext)
    from public.sign_requests r
   where r.owner_id = public.rout_current_user_id() and r.status <> 'revoked'
   order by r.created_at desc
   limit 50
$function$;

revoke all on function public.rout_sign_request_create(bytea, integer, integer) from public, rout_app;
revoke all on function public.rout_sign_request_open(uuid) from public, rout_app;
revoke all on function public.rout_sign_request_mark_signed(uuid, text, text, text, bytea) from public, rout_app;
revoke all on function public.rout_sign_request_revoke(uuid) from public, rout_app;
revoke all on function public.rout_sign_requests_mine() from public, rout_app;
grant execute on function public.rout_sign_request_create(bytea, integer, integer) to rout_app;
grant execute on function public.rout_sign_request_open(uuid) to rout_app;
grant execute on function public.rout_sign_request_mark_signed(uuid, text, text, text, bytea) to rout_app;
grant execute on function public.rout_sign_request_revoke(uuid) to rout_app;
grant execute on function public.rout_sign_requests_mine() to rout_app;
