-- 0293: ROUT support treasury (/support/donations, /support/partners) (EXPAND, additive).
--
-- Donations to ROUT itself, with three privacy levels:
--   1 public       linked to the member (rout.current_user_id) and shown with their @handle;
--   2 pseudonymous no member id is stored; the donor proves the gift with a Merkle inclusion proof;
--   3 anonymous    no member id, no proof material kept.
-- Payer name, payer IBAN and e-mail are never stored. Provider references (Stripe session id,
-- the structured communication) live only while a donation is pending and are cleared on payment.
-- Every paid donation appends one Poseidon leaf to an append-only tree of depth 32
-- (treasury_merkle_nodes); each new root is stored with its hybrid Ed25519 + ML-DSA-65 signature
-- (treasury_roots). Credentials are stored only as AES-GCM ciphertext sealed by the server.
-- rout_app gets no table rights; everything goes through the definers below.

create table if not exists public.supporter_donations (
  id             uuid primary key default gen_random_uuid(),
  privacy_level  smallint not null check (privacy_level in (1, 2, 3)),
  rail           text not null check (rail in ('sepa', 'stripe')),
  user_id        uuid references public.users(id) on delete set null,
  attested       boolean not null default false,
  amount_cents   integer not null check (amount_cents between 100 and 500000),
  currency       text not null default 'EUR' check (currency = 'EUR'),
  ogm            text unique check (ogm is null or ogm ~ '^[0-9]{12}$'),
  provider_ref   text unique check (provider_ref is null or char_length(provider_ref) between 1 and 255),
  access_hash    text not null check (access_hash ~ '^[0-9a-f]{64}$'),
  status         text not null default 'pending' check (status in ('pending', 'paid', 'failed', 'expired')),
  confirmed_via  text check (confirmed_via is null or confirmed_via in ('bunq', 'stripe', 'manual')),
  merkle_index   bigint unique check (merkle_index is null or merkle_index between 0 and 4294967295),
  leaf           text check (leaf is null or leaf ~ '^[0-9a-f]{64}$'),
  tx_hash        text check (tx_hash is null or tx_hash ~ '^[0-9a-f]{64}$'),
  receipt        jsonb,
  created_at     timestamptz not null default now(),
  paid_at        timestamptz,
  check (privacy_level = 1 or user_id is null),
  check ((rail = 'sepa') = (ogm is not null) or status <> 'pending'),
  check (status <> 'paid' or (merkle_index is not null and leaf is not null and paid_at is not null))
);
create index if not exists supporter_donations_user_id_idx on public.supporter_donations (user_id) where user_id is not null;
create index if not exists supporter_donations_paid_at_idx on public.supporter_donations (paid_at) where status = 'paid';

create table if not exists public.treasury_merkle_nodes (
  level  smallint not null check (level between 0 and 32),
  idx    bigint not null check (idx between 0 and 4294967295),
  hash   text not null check (hash ~ '^[0-9a-f]{64}$'),
  primary key (level, idx)
);

create table if not exists public.treasury_roots (
  size        bigint primary key check (size between 1 and 4294967296),
  root        text not null check (root ~ '^[0-9a-f]{64}$'),
  kid         text not null check (kid ~ '^[0-9a-f]{16}$'),
  sig_ed25519 text not null check (char_length(sig_ed25519) between 80 and 100),
  sig_mldsa65 text check (sig_mldsa65 is null or char_length(sig_mldsa65) between 4000 and 4500),
  signed_at   timestamptz not null default now()
);

create table if not exists public.supporter_credentials (
  id            uuid primary key default gen_random_uuid(),
  donation_id   uuid not null unique references public.supporter_donations(id) on delete cascade,
  user_id       uuid references public.users(id) on delete cascade,
  jti_hash      text not null unique check (jti_hash ~ '^[0-9a-f]{64}$'),
  ciphertext    text not null check (char_length(ciphertext) <= 24000),
  iv            text not null check (char_length(iv) <= 64),
  presentation  text check (presentation is null or char_length(presentation) <= 4000),
  issued_at     timestamptz not null default now(),
  expires_at    timestamptz not null,
  revoked_at    timestamptz
);
create index if not exists supporter_credentials_user_id_idx on public.supporter_credentials (user_id) where user_id is not null;

create table if not exists public.partner_attestations (
  domain      text primary key check (domain ~ '^[a-z0-9.-]{3,253}$'),
  dnssec      boolean not null,
  did_web     boolean not null,
  payload     text not null check (char_length(payload) <= 1000),
  kid         text not null check (kid ~ '^[0-9a-f]{16}$'),
  sig_ed25519 text not null check (char_length(sig_ed25519) between 80 and 100),
  sig_mldsa65 text check (sig_mldsa65 is null or char_length(sig_mldsa65) between 4000 and 4500),
  checked_at  timestamptz not null
);

revoke all on public.supporter_donations, public.treasury_merkle_nodes, public.treasury_roots,
  public.supporter_credentials, public.partner_attestations from public, rout_app;
alter table public.supporter_donations enable row level security;
alter table public.treasury_merkle_nodes enable row level security;
alter table public.treasury_roots enable row level security;
alter table public.supporter_credentials enable row level security;
alter table public.partner_attestations enable row level security;

-- Start a donation. Level 1 needs a signed-in member; levels 2 and 3 never store one, even when
-- the caller is signed in. `attested` = the caller holds a Didit result (kept as a flag only).
create or replace function public.rout_support_create(p_level smallint, p_rail text, p_amount integer, p_ogm text, p_access_hash text)
 returns table(id uuid, attested boolean)
 language plpgsql volatile security definer set search_path = pg_catalog, pg_temp
as $function$
declare
  v_user uuid := public.rout_current_user_id();
  v_attested boolean := false;
  v_id uuid;
begin
  if p_level not in (1, 2, 3) or p_rail not in ('sepa', 'stripe') or p_amount not between 100 and 500000
     or p_access_hash !~ '^[0-9a-f]{64}$' or ((p_rail = 'sepa') <> (p_ogm is not null))
     or (p_ogm is not null and p_ogm !~ '^[0-9]{12}$') then
    return;
  end if;
  if p_level = 1 and v_user is null then return; end if;
  if p_level in (1, 2) and v_user is not null then
    select coalesce(b.didit_legal_identity, false) into v_attested
      from public.rout_public_identity_badges(array[v_user]) b limit 1;
  end if;
  insert into public.supporter_donations (privacy_level, rail, user_id, attested, amount_cents, ogm, access_hash)
  values (p_level, p_rail, case when p_level = 1 then v_user end, coalesce(v_attested, false), p_amount, p_ogm, p_access_hash)
  returning supporter_donations.id into v_id;
  return query select v_id, coalesce(v_attested, false);
end $function$;

-- Attach the Stripe Checkout session to a pending Stripe donation (caller proves the access token).
create or replace function public.rout_support_set_provider_ref(p_id uuid, p_access_hash text, p_ref text)
 returns boolean language plpgsql volatile security definer set search_path = pg_catalog, pg_temp
as $function$
begin
  update public.supporter_donations d set provider_ref = p_ref
   where d.id = p_id and d.access_hash = p_access_hash and d.rail = 'stripe' and d.status = 'pending' and d.provider_ref is null;
  return found;
end $function$;

-- Webhooks: the pending donation behind a structured communication or a Stripe session.
create or replace function public.rout_support_pending(p_ogm text, p_ref text)
 returns table(id uuid, privacy_level smallint, rail text, amount_cents integer, attested boolean, handle text)
 language sql stable security definer set search_path = pg_catalog, pg_temp
as $function$
  select d.id, d.privacy_level, d.rail, d.amount_cents, d.attested, p.username
    from public.supporter_donations d
    left join public.profiles p on p.id = d.user_id
   where d.status = 'pending'
     and ((p_ogm is not null and d.ogm = p_ogm) or (p_ref is not null and d.provider_ref = p_ref))
   limit 1
$function$;

-- Public tree data: the stored siblings on the path of p_index (missing = empty subtree).
create or replace function public.rout_public_treasury_siblings(p_index bigint)
 returns table(level smallint, hash text)
 language sql stable security definer set search_path = pg_catalog, pg_temp
as $function$
  select n.level, n.hash
    from pg_catalog.generate_series(0, 31) l
    join public.treasury_merkle_nodes n on n.level = l and n.idx = ((p_index >> l) # 1)
   where p_index between 0 and 4294967295
$function$;

-- Mark paid + append the leaf in one transaction. Answers ok | retry | unknown | already_paid |
-- not_pending | amount_mismatch | invalid. `retry` = another payment took this index first.
create or replace function public.rout_support_mark_paid(p_id uuid, p_amount integer, p_confirmed_via text, p_tx_hash text,
  p_index bigint, p_leaf text, p_nodes jsonb, p_root text, p_kid text, p_sig_ed text, p_sig_pq text, p_receipt jsonb)
 returns text language plpgsql volatile security definer set search_path = pg_catalog, pg_temp
as $function$
declare
  v_row public.supporter_donations%rowtype;
  v_size bigint;
  v_node jsonb;
  v_count integer := 0;
begin
  perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtext('rout.treasury.append'));
  select * into v_row from public.supporter_donations d where d.id = p_id for update;
  if not found then return 'unknown'; end if;
  if v_row.status = 'paid' then return 'already_paid'; end if;
  if v_row.status <> 'pending' then return 'not_pending'; end if;
  if v_row.amount_cents <> p_amount then return 'amount_mismatch'; end if;
  if p_confirmed_via not in ('bunq', 'stripe', 'manual') or p_tx_hash !~ '^[0-9a-f]{64}$' or p_leaf !~ '^[0-9a-f]{64}$'
     or p_root !~ '^[0-9a-f]{64}$' or pg_catalog.jsonb_typeof(p_nodes) <> 'array' or pg_catalog.jsonb_array_length(p_nodes) <> 33
     or p_receipt is null then
    return 'invalid';
  end if;
  select coalesce(pg_catalog.max(r.size), 0) into v_size from public.treasury_roots r;
  if p_index <> v_size then return 'retry'; end if;
  for v_node in select * from pg_catalog.jsonb_array_elements(p_nodes) loop
    if (v_node->>'level')::int <> v_count or (v_node->>'idx')::bigint <> (p_index >> v_count)
       or (v_node->>'hash') !~ '^[0-9a-f]{64}$' then
      return 'invalid';
    end if;
    if v_count = 0 and (v_node->>'hash') <> p_leaf then return 'invalid'; end if;
    if v_count = 32 and (v_node->>'hash') <> p_root then return 'invalid'; end if;
    v_count := v_count + 1;
  end loop;
  insert into public.treasury_merkle_nodes (level, idx, hash)
  select (n->>'level')::smallint, (n->>'idx')::bigint, n->>'hash' from pg_catalog.jsonb_array_elements(p_nodes) n
  on conflict (level, idx) do update set hash = excluded.hash;
  insert into public.treasury_roots (size, root, kid, sig_ed25519, sig_mldsa65) values (v_size + 1, p_root, p_kid, p_sig_ed, p_sig_pq);
  update public.supporter_donations d
     set status = 'paid', paid_at = now(), confirmed_via = p_confirmed_via, tx_hash = p_tx_hash,
         merkle_index = p_index, leaf = p_leaf, receipt = p_receipt, ogm = null, provider_ref = null
   where d.id = p_id;
  return 'ok';
end $function$;

-- Store the sealed credential (+ the public presentation for level 1 only).
create or replace function public.rout_support_store_credential(p_donation uuid, p_jti_hash text, p_ct text, p_iv text,
  p_presentation text, p_expires timestamptz)
 returns boolean language plpgsql volatile security definer set search_path = pg_catalog, pg_temp
as $function$
declare
  v_level smallint;
  v_user uuid;
begin
  select d.privacy_level, d.user_id into v_level, v_user from public.supporter_donations d
   where d.id = p_donation and d.status = 'paid';
  if not found or v_level = 3 then return false; end if;
  insert into public.supporter_credentials (donation_id, user_id, jti_hash, ciphertext, iv, presentation, expires_at)
  values (p_donation, case when v_level = 1 then v_user end, p_jti_hash, p_ct, p_iv,
          case when v_level = 1 then p_presentation end, p_expires)
  on conflict (donation_id) do nothing;
  return found;
end $function$;

-- Status page (thank-you link): only with the access token from the link fragment.
create or replace function public.rout_support_by_access(p_id uuid, p_access_hash text)
 returns table(status text, privacy_level smallint, rail text, amount_cents integer, ogm text, receipt jsonb,
   merkle_index bigint, cred_ciphertext text, cred_iv text, created_at timestamptz)
 language sql stable security definer set search_path = pg_catalog, pg_temp
as $function$
  select d.status, d.privacy_level, d.rail, d.amount_cents, d.ogm, d.receipt, d.merkle_index, c.ciphertext, c.iv, d.created_at
    from public.supporter_donations d
    left join public.supporter_credentials c on c.donation_id = d.id and c.revoked_at is null
   where d.id = p_id and d.access_hash = p_access_hash
$function$;

-- The caller's own public (level 1) donations.
create or replace function public.rout_support_mine()
 returns table(id uuid, amount_cents integer, status text, rail text, created_at timestamptz, paid_at timestamptz,
   receipt jsonb, merkle_index bigint, cred_ciphertext text, cred_iv text)
 language sql stable security definer set search_path = pg_catalog, pg_temp
as $function$
  select d.id, d.amount_cents, d.status, d.rail, d.created_at, d.paid_at, d.receipt, d.merkle_index, c.ciphertext, c.iv
    from public.supporter_donations d
    left join public.supporter_credentials c on c.donation_id = d.id and c.revoked_at is null
   where d.user_id = public.rout_current_user_id() and d.privacy_level = 1
   order by d.created_at desc
   limit 100
$function$;

-- Public ledger: paid donations, newest first. Level 1 shows the handle, level 2 its index,
-- level 3 neither.
create or replace function public.rout_public_treasury_ledger(p_limit integer)
 returns table(merkle_index bigint, privacy_level smallint, handle text, attested boolean, amount_cents integer, paid_month text)
 language sql stable security definer set search_path = pg_catalog, pg_temp
as $function$
  select case when d.privacy_level = 3 then null else d.merkle_index end,
         d.privacy_level,
         case when d.privacy_level = 1 and not coalesce(p.is_banned, false) then p.username end,
         case when d.privacy_level = 3 then false else d.attested end,
         d.amount_cents,
         pg_catalog.to_char(d.paid_at at time zone 'Europe/Brussels', 'YYYY-MM')
    from public.supporter_donations d
    left join public.profiles p on p.id = d.user_id
   where d.status = 'paid'
   order by d.merkle_index desc
   limit least(greatest(coalesce(p_limit, 50), 1), 200)
$function$;

-- Public totals for the current month (Europe/Brussels) and the latest signed root.
create or replace function public.rout_public_treasury_summary()
 returns table(month_cents bigint, month_count integer, total_cents bigint, size bigint, root text, kid text, sig_ed25519 text, sig_mldsa65 text)
 language sql stable security definer set search_path = pg_catalog, pg_temp
as $function$
  with m as (
    select coalesce(pg_catalog.sum(d.amount_cents) filter (where pg_catalog.date_trunc('month', d.paid_at at time zone 'Europe/Brussels')
                                                       = pg_catalog.date_trunc('month', now() at time zone 'Europe/Brussels')), 0)::bigint as month_cents,
           (pg_catalog.count(*) filter (where pg_catalog.date_trunc('month', d.paid_at at time zone 'Europe/Brussels')
                                          = pg_catalog.date_trunc('month', now() at time zone 'Europe/Brussels')))::integer as month_count,
           coalesce(pg_catalog.sum(d.amount_cents), 0)::bigint as total_cents
      from public.supporter_donations d where d.status = 'paid'
  ), r as (select * from public.treasury_roots order by size desc limit 1)
  select m.month_cents, m.month_count, m.total_cents, r.size, r.root, r.kid, r.sig_ed25519, r.sig_mldsa65
    from m left join r on true
$function$;

-- Public profile crown: the newest valid level-1 presentation of a handle.
create or replace function public.rout_public_supporter_presentation(p_handle text)
 returns text language sql stable security definer set search_path = pg_catalog, pg_temp
as $function$
  select c.presentation
    from public.profiles p
    join public.supporter_credentials c on c.user_id = p.id
   where p.username = pg_catalog.lower(p_handle) and not coalesce(p.is_banned, false)
     and c.presentation is not null and c.revoked_at is null and c.expires_at > now()
   order by c.issued_at desc
   limit 1
$function$;

-- No writer for partner_attestations yet: one arrives with the first real partner agreement,
-- behind an admin check. Until then the table stays empty and the page lists suppliers only.

create or replace function public.rout_public_partner_attestations()
 returns table(domain text, payload text, kid text, sig_ed25519 text, sig_mldsa65 text, checked_at timestamptz)
 language sql stable security definer set search_path = pg_catalog, pg_temp
as $function$
  select a.domain, a.payload, a.kid, a.sig_ed25519, a.sig_mldsa65, a.checked_at from public.partner_attestations a order by a.domain
$function$;

revoke all on function public.rout_support_create(smallint, text, integer, text, text) from public;
revoke all on function public.rout_support_set_provider_ref(uuid, text, text) from public;
revoke all on function public.rout_support_pending(text, text) from public;
revoke all on function public.rout_public_treasury_siblings(bigint) from public;
revoke all on function public.rout_support_mark_paid(uuid, integer, text, text, bigint, text, jsonb, text, text, text, text, jsonb) from public;
revoke all on function public.rout_support_store_credential(uuid, text, text, text, text, timestamptz) from public;
revoke all on function public.rout_support_by_access(uuid, text) from public;
revoke all on function public.rout_support_mine() from public;
revoke all on function public.rout_public_treasury_ledger(integer) from public;
revoke all on function public.rout_public_treasury_summary() from public;
revoke all on function public.rout_public_supporter_presentation(text) from public;
revoke all on function public.rout_public_partner_attestations() from public;
grant execute on function public.rout_support_create(smallint, text, integer, text, text) to rout_app;
grant execute on function public.rout_support_set_provider_ref(uuid, text, text) to rout_app;
grant execute on function public.rout_support_pending(text, text) to rout_app;
grant execute on function public.rout_public_treasury_siblings(bigint) to rout_app;
grant execute on function public.rout_support_mark_paid(uuid, integer, text, text, bigint, text, jsonb, text, text, text, text, jsonb) to rout_app;
grant execute on function public.rout_support_store_credential(uuid, text, text, text, text, timestamptz) to rout_app;
grant execute on function public.rout_support_by_access(uuid, text) to rout_app;
grant execute on function public.rout_support_mine() to rout_app;
grant execute on function public.rout_public_treasury_ledger(integer) to rout_app;
grant execute on function public.rout_public_treasury_summary() to rout_app;
grant execute on function public.rout_public_supporter_presentation(text) to rout_app;
grant execute on function public.rout_public_partner_attestations() to rout_app;

-- Account merge: donations and supporter credentials are money/credential records (strategy "skip"
-- in account-merge-rules.ts). execute_account_merge refuses a secondary account that owns one,
-- instead of nulling the donor or cascading the credential away (same pattern as 0215/0289).
do $own$ begin execute format('grant rout_merge_executor to %I with inherit true, set true', current_user); end $own$;
grant create on schema public to rout_merge_executor;

do $m$
declare
  v_def text;
  v_new text;
  v_guard text := '';
  t text;
begin
  foreach t in array array['supporter_donations', 'supporter_credentials'] loop
    execute format('grant select (user_id) on public.%I to rout_merge_executor', t);
    execute format('drop policy if exists atomic_merge_guard on public.%I', t);
    execute format('create policy atomic_merge_guard on public.%I for select to rout_merge_executor using (true)', t);
  end loop;
  select pg_get_functiondef('public.execute_account_merge(text,text,text,text)'::regprocedure) into v_def;
  foreach t in array array['supporter_donations', 'supporter_credentials'] loop
    continue when position('merge_blocked:' || t || '''' in v_def) > 0;
    v_guard := v_guard || format(E' perform public.rout_merge_assert((not exists (select 1 from public.%I where "user_id" = v_secondary)), %L);\n', t, 'merge_blocked:' || t);
  end loop;
  if v_guard = '' then return; end if;
  v_new := regexp_replace(v_def, E'([^\\n]*''merge_blocked:verified_identities''[^\\n]*\\n)', E'\\1' || replace(v_guard, '\', '\\'));
  if v_new = v_def then
    raise exception 'execute_account_merge: guard anchor merge_blocked:verified_identities not found';
  end if;
  execute v_new;
end $m$;

revoke create on schema public from rout_merge_executor;
do $own$ begin execute format('revoke rout_merge_executor from %I', current_user); end $own$;
