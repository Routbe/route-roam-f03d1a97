-- 0294: EUDI wallet interop (EXPAND, additive).
--
--   oid4vci_offers      OpenID4VCI pre-authorized offers. Only SHA-256 hashes of the pre-authorized
--                       code, the transaction code and the access token are stored. The claims are
--                       taken here from rout_my_identity_claims(), never from the caller.
--   wallet_credentials  one row per issued wallet credential; status_idx is its index in the
--                       Token Status List (draft-ietf-oauth-status-list). An index without an active
--                       row (revoked, expired or deleted) is published as revoked.
--   oid4vp_requests     OpenID4VP verification requests started in the Developer Console; the
--                       verified result is readable only by the member who started the request.
-- rout_app gets no table rights; everything goes through the definers below.

create table if not exists public.oid4vci_offers (
  id           uuid primary key default gen_random_uuid(),
  user_id      uuid not null references public.users(id) on delete cascade,
  config       text not null check (config in ('rout_verified_human')),
  claims       jsonb not null check (jsonb_typeof(claims) = 'object' and octet_length(claims::text) <= 2000),
  code_hash    text not null unique check (code_hash ~ '^[0-9a-f]{64}$'),
  tx_hash      text not null check (tx_hash ~ '^[0-9a-f]{64}$'),
  token_hash   text unique check (token_hash is null or token_hash ~ '^[0-9a-f]{64}$'),
  attempts     smallint not null default 0 check (attempts between 0 and 5),
  created_at   timestamptz not null default now(),
  expires_at   timestamptz not null,
  redeemed_at  timestamptz,
  issued_at    timestamptz
);
create index if not exists oid4vci_offers_user_id_idx on public.oid4vci_offers (user_id, created_at);

create table if not exists public.wallet_credentials (
  status_idx  bigint generated always as identity (minvalue 0 start with 0) primary key check (status_idx between 0 and 131071),
  user_id     uuid not null references public.users(id) on delete cascade,
  config      text not null check (config in ('rout_verified_human')),
  jti_hash    text not null unique check (jti_hash ~ '^[0-9a-f]{64}$'),
  issued_at   timestamptz not null default now(),
  expires_at  timestamptz not null,
  revoked_at  timestamptz
);
create index if not exists wallet_credentials_user_id_idx on public.wallet_credentials (user_id);

create table if not exists public.oid4vp_requests (
  id            uuid primary key default gen_random_uuid(),
  user_id       uuid not null references public.users(id) on delete cascade,
  label         text not null check (char_length(label) between 1 and 80),
  nonce         text not null check (nonce ~ '^[A-Za-z0-9_-]{22,64}$'),
  state         text not null unique check (state ~ '^[A-Za-z0-9_-]{22,64}$'),
  dcql          jsonb not null check (jsonb_typeof(dcql) = 'object' and octet_length(dcql::text) <= 4000),
  status        text not null default 'pending' check (status in ('pending', 'verified', 'rejected')),
  result        jsonb check (result is null or octet_length(result::text) <= 8000),
  created_at    timestamptz not null default now(),
  expires_at    timestamptz not null,
  completed_at  timestamptz
);
create index if not exists oid4vp_requests_user_id_idx on public.oid4vp_requests (user_id, created_at);

revoke all on public.oid4vci_offers, public.wallet_credentials, public.oid4vp_requests from public, rout_app;
revoke all on sequence public.wallet_credentials_status_idx_seq from public, rout_app;
alter table public.oid4vci_offers enable row level security;
alter table public.wallet_credentials enable row level security;
alter table public.oid4vp_requests enable row level security;

-- New offer for the signed-in member. Only verified humans get one; at most 5 per 10 minutes.
create or replace function public.rout_vci_offer_create(p_config text, p_code_hash text, p_tx_hash text)
 returns uuid
 language plpgsql volatile security definer set search_path = pg_catalog, pg_temp
as $function$
declare
  v_user uuid := public.rout_current_user_id();
  v_human boolean;
  v_age smallint;
  v_id uuid;
begin
  if v_user is null or p_config <> 'rout_verified_human' or p_code_hash !~ '^[0-9a-f]{64}$' or p_tx_hash !~ '^[0-9a-f]{64}$' then
    return null;
  end if;
  select coalesce(c.has_legal_identity, false) or coalesce(c.is_real_human, false), c.age_floor
    into v_human, v_age
    from public.rout_my_identity_claims() c;
  if not coalesce(v_human, false) then return null; end if;
  delete from public.oid4vci_offers o where o.user_id = v_user and o.expires_at < now() - interval '1 day';
  if (select pg_catalog.count(*) from public.oid4vci_offers o where o.user_id = v_user and o.created_at > now() - interval '10 minutes') >= 5 then
    return null;
  end if;
  insert into public.oid4vci_offers (user_id, config, claims, code_hash, tx_hash, expires_at)
  values (v_user, p_config, pg_catalog.jsonb_build_object('verified_human', true, 'age_floor', v_age), p_code_hash, p_tx_hash, now() + interval '10 minutes')
  returning oid4vci_offers.id into v_id;
  return v_id;
end $function$;

-- Token endpoint: redeem a pre-authorized code with its transaction code. Answers ok | invalid |
-- invalid_tx | used | expired | locked; five wrong transaction codes lock the offer.
create or replace function public.rout_vci_redeem(p_code_hash text, p_tx_hash text, p_token_hash text)
 returns text
 language plpgsql volatile security definer set search_path = pg_catalog, pg_temp
as $function$
declare
  v public.oid4vci_offers%rowtype;
begin
  if p_code_hash !~ '^[0-9a-f]{64}$' or p_tx_hash !~ '^[0-9a-f]{64}$' or p_token_hash !~ '^[0-9a-f]{64}$' then
    return 'invalid';
  end if;
  select * into v from public.oid4vci_offers o where o.code_hash = p_code_hash for update;
  if not found then return 'invalid'; end if;
  if v.redeemed_at is not null then return 'used'; end if;
  if v.expires_at <= now() then return 'expired'; end if;
  if v.attempts >= 5 then return 'locked'; end if;
  if v.tx_hash <> p_tx_hash then
    update public.oid4vci_offers o set attempts = o.attempts + 1 where o.id = v.id;
    return 'invalid_tx';
  end if;
  update public.oid4vci_offers o set redeemed_at = now(), token_hash = p_token_hash where o.id = v.id;
  return 'ok';
end $function$;

-- Credential endpoint: one credential per redeemed offer, within 5 minutes of redemption.
create or replace function public.rout_vci_issue(p_token_hash text, p_jti_hash text, p_days integer)
 returns table(status_idx bigint, config text, claims jsonb, expires_at timestamptz)
 language plpgsql volatile security definer set search_path = pg_catalog, pg_temp
as $function$
declare
  v public.oid4vci_offers%rowtype;
  v_idx bigint;
  v_exp timestamptz;
begin
  if p_token_hash !~ '^[0-9a-f]{64}$' or p_jti_hash !~ '^[0-9a-f]{64}$' then return; end if;
  select * into v from public.oid4vci_offers o where o.token_hash = p_token_hash for update;
  if not found or v.issued_at is not null or v.redeemed_at is null or v.redeemed_at < now() - interval '5 minutes' then
    return;
  end if;
  update public.oid4vci_offers o set issued_at = now() where o.id = v.id;
  insert into public.wallet_credentials (user_id, config, jti_hash, expires_at)
  values (v.user_id, v.config, p_jti_hash, now() + pg_catalog.make_interval(days => least(greatest(coalesce(p_days, 1), 1), 365)))
  returning wallet_credentials.status_idx, wallet_credentials.expires_at into v_idx, v_exp;
  return query select v_idx, v.config, v.claims, v_exp;
end $function$;

-- The caller's own wallet credentials.
create or replace function public.rout_vci_mine()
 returns table(status_idx bigint, config text, issued_at timestamptz, expires_at timestamptz, revoked_at timestamptz)
 language sql stable security definer set search_path = pg_catalog, pg_temp
as $function$
  select w.status_idx, w.config, w.issued_at, w.expires_at, w.revoked_at
    from public.wallet_credentials w
   where w.user_id = public.rout_current_user_id()
   order by w.status_idx desc
   limit 100
$function$;

-- Revoke one of the caller's own wallet credentials.
create or replace function public.rout_vci_revoke(p_idx bigint)
 returns boolean
 language plpgsql volatile security definer set search_path = pg_catalog, pg_temp
as $function$
begin
  update public.wallet_credentials w set revoked_at = now()
   where w.status_idx = p_idx and w.user_id = public.rout_current_user_id() and w.revoked_at is null;
  return found;
end $function$;

-- Public Token Status List input: the indices that are currently valid. Everything else is revoked.
create or replace function public.rout_public_status_active()
 returns table(status_idx bigint)
 language sql stable security definer set search_path = pg_catalog, pg_temp
as $function$
  select w.status_idx from public.wallet_credentials w
   where w.revoked_at is null and w.expires_at > now()
   order by w.status_idx
$function$;

-- Developer Console: start an OpenID4VP request (at most 20 per 10 minutes, valid 10 minutes).
create or replace function public.rout_vp_request_create(p_label text, p_nonce text, p_state text, p_dcql jsonb)
 returns uuid
 language plpgsql volatile security definer set search_path = pg_catalog, pg_temp
as $function$
declare
  v_user uuid := public.rout_current_user_id();
  v_id uuid;
begin
  if v_user is null then return null; end if;
  delete from public.oid4vp_requests r where r.user_id = v_user and r.expires_at < now() - interval '1 day';
  if (select pg_catalog.count(*) from public.oid4vp_requests r where r.user_id = v_user and r.created_at > now() - interval '10 minutes') >= 20 then
    return null;
  end if;
  insert into public.oid4vp_requests (user_id, label, nonce, state, dcql, expires_at)
  values (v_user, p_label, p_nonce, p_state, p_dcql, now() + interval '10 minutes')
  returning oid4vp_requests.id into v_id;
  return v_id;
end $function$;

-- Response endpoint: what the wallet's answer is checked against (no owner, no result).
create or replace function public.rout_vp_request_for_wallet(p_id uuid)
 returns table(nonce text, state text, dcql jsonb, status text, expires_at timestamptz)
 language sql stable security definer set search_path = pg_catalog, pg_temp
as $function$
  select r.nonce, r.state, r.dcql, r.status, r.expires_at from public.oid4vp_requests r where r.id = p_id
$function$;

-- Response endpoint: store the outcome once, only for a pending, unexpired request with the right state.
create or replace function public.rout_vp_request_complete(p_id uuid, p_state text, p_status text, p_result jsonb)
 returns boolean
 language plpgsql volatile security definer set search_path = pg_catalog, pg_temp
as $function$
begin
  if p_status not in ('verified', 'rejected') then return false; end if;
  update public.oid4vp_requests r set status = p_status, result = p_result, completed_at = now()
   where r.id = p_id and r.state = p_state and r.status = 'pending' and r.expires_at > now();
  return found;
end $function$;

-- Developer Console: the caller's own request and its result.
create or replace function public.rout_vp_request_mine(p_id uuid)
 returns table(label text, status text, result jsonb, created_at timestamptz, expires_at timestamptz, completed_at timestamptz)
 language sql stable security definer set search_path = pg_catalog, pg_temp
as $function$
  select r.label, r.status, r.result, r.created_at, r.expires_at, r.completed_at
    from public.oid4vp_requests r
   where r.id = p_id and r.user_id = public.rout_current_user_id()
$function$;

revoke all on function public.rout_vci_offer_create(text, text, text) from public, rout_app;
revoke all on function public.rout_vci_redeem(text, text, text) from public, rout_app;
revoke all on function public.rout_vci_issue(text, text, integer) from public, rout_app;
revoke all on function public.rout_vci_mine() from public, rout_app;
revoke all on function public.rout_vci_revoke(bigint) from public, rout_app;
revoke all on function public.rout_public_status_active() from public, rout_app;
revoke all on function public.rout_vp_request_create(text, text, text, jsonb) from public, rout_app;
revoke all on function public.rout_vp_request_for_wallet(uuid) from public, rout_app;
revoke all on function public.rout_vp_request_complete(uuid, text, text, jsonb) from public, rout_app;
revoke all on function public.rout_vp_request_mine(uuid) from public, rout_app;
grant execute on function public.rout_vci_offer_create(text, text, text) to rout_app;
grant execute on function public.rout_vci_redeem(text, text, text) to rout_app;
grant execute on function public.rout_vci_issue(text, text, integer) to rout_app;
grant execute on function public.rout_vci_mine() to rout_app;
grant execute on function public.rout_vci_revoke(bigint) to rout_app;
grant execute on function public.rout_public_status_active() to rout_app;
grant execute on function public.rout_vp_request_create(text, text, text, jsonb) to rout_app;
grant execute on function public.rout_vp_request_for_wallet(uuid) to rout_app;
grant execute on function public.rout_vp_request_complete(uuid, text, text, jsonb) to rout_app;
grant execute on function public.rout_vp_request_mine(uuid) to rout_app;
