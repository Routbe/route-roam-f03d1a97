-- Rollback of 0290 (identity OS claims, workspace IBAN via KYC, ROUT Sign requests).
-- Refuses while a sign request or a recorded age floor exists; otherwise restores 0288/0283 exactly.
do $$
begin
  if exists (select 1 from public.sign_requests) then
    raise exception 'rollback_0290_refused: sign_requests is not empty';
  end if;
  if exists (select 1 from public.verified_identity_nullifiers where age_floor is not null) then
    raise exception 'rollback_0290_refused: age floors recorded';
  end if;
end $$;

drop function if exists public.rout_sign_requests_mine();
drop function if exists public.rout_sign_request_revoke(uuid);
drop function if exists public.rout_sign_request_mark_signed(uuid, text, text, text, bytea);
drop function if exists public.rout_sign_request_open(uuid);
drop function if exists public.rout_sign_request_create(bytea, integer, integer);
drop table if exists public.sign_requests;

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
         exists (select 1 from public.workspace_members m
                   left join public.identity_verifications iv on iv.user_id = m.user_id
                   left join public.verified_identities vi on vi.user_id = m.user_id
                  where m.workspace_id = p_ws and m.role::text = 'owner'
                    and ((coalesce(iv.is_verified, false) and iv.verification_provider::text = 'didit')
                      or (coalesce(vi.tier_2_legal_identity, false) and vi.national_id_nullifier is not null))),
         w.domain_verified_at is not null,
         coalesce((select pg_catalog.jsonb_agg(pg_catalog.jsonb_build_object('provider', c.provider, 'last4', c.last4,
                     'mode', c.mode, 'verifiedAt', c.verified_at) order by c.provider)
                     from public.workspace_psp_credentials c where c.workspace_id = p_ws), '[]'::jsonb)
    from public.workspaces w
    left join public.workspace_tip_settings s on s.workspace_id = w.id
   where w.id = p_ws;
end $function$;

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
    if not exists (select 1 from public.rout_ws_support_names(p_ws)) then return 'not_eligible'; end if;
    if not exists (select 1 from public.rout_ws_support_names(p_ws) n
                    where public.rout_ws_support_norm(n) = public.rout_ws_support_norm(v_name)) then
      return 'name_mismatch';
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
  if not exists (select 1 from public.rout_ws_support_names(p_ws)) then return 'not_eligible'; end if;
  if p_provider not in ('stripe', 'mollie') or p_mode not in ('live', 'test') then return 'invalid'; end if;
  insert into public.workspace_psp_credentials (workspace_id, provider, ciphertext, iv, last4, mode, publishable_key, saved_by, verified_at)
  values (p_ws, p_provider, p_ciphertext, p_iv, pg_catalog.right(coalesce(p_last4, ''), 4), p_mode, p_publishable_key,
          public.rout_current_user_id(), pg_catalog.now())
  on conflict (workspace_id, provider) do update set ciphertext = excluded.ciphertext, iv = excluded.iv,
    last4 = excluded.last4, mode = excluded.mode, publishable_key = excluded.publishable_key,
    saved_by = excluded.saved_by, verified_at = pg_catalog.now();
  return 'ok';
end $function$;

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
     and exists (select 1 from public.rout_ws_support_names(w.id) n
                  where public.rout_ws_support_norm(n) = public.rout_ws_support_norm(s.account_name))
   limit 1
$function$;

drop function if exists public.rout_ws_support_owner_kyc(uuid);
drop function if exists public.rout_my_identity_claims();

create or replace function public.rout_kyc_attest(
  p_provider text, p_nullifiers text[], p_anchor_kinds text[],
  p_is_real_human boolean, p_has_legal_identity boolean, p_jurisdiction text)
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
     or p_provider is null or p_is_real_human is null or p_has_legal_identity is null
     -- World ID is a zero-knowledge proof, never a KYC document; it gets its own verifier.
     or p_provider = 'world_id' then
    return 'invalid_input';
  end if;
  -- Serialise attempts on the same anchors (sorted, so two attempts never wait on each other in a cycle).
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
  insert into public.verified_identity_nullifiers
      (universal_nullifier, user_id, provider, anchor_kind, is_real_human, has_legal_identity, jurisdiction, evidence)
    select a.nf, v_user, p_provider, a.kind, p_is_real_human, p_has_legal_identity, p_jurisdiction, 'kyc_document'
      from rows from (pg_catalog.unnest(p_nullifiers), pg_catalog.unnest(p_anchor_kinds)) as a(nf, kind)
  on conflict (universal_nullifier) do nothing;
  return 'ok';
end
$function$;
drop function if exists public.rout_kyc_attest(text, text[], text[], boolean, boolean, text, smallint);
alter table public.verified_identity_nullifiers drop column if exists age_floor;
