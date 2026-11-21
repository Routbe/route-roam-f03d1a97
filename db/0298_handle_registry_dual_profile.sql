-- 0298 (EXPAND, additive): handle registry for the dual-profile model (Prioriteit 3).
--
-- A member keeps at most two strictly separate public profiles:
--   * a free pseudonymous alias  -> rout.be/u/<alias>     (public.alias_profiles)
--   * a verified identity profile -> rout.be/<legal-handle> (public.profiles.username)
-- public.handle_registry records every claimed handle per namespace with its status
-- (ACTIVE, RESERVED_HOLD, TOMBSTONED, REVOKED). It is maintained only by triggers on
-- profiles and alias_profiles, so every existing write path keeps it exact; no app code
-- writes it. The hard limits live here as partial unique indexes:
--   * one ACTIVE /u/ alias per member      (uq_user_single_unverified_alias)
--   * one ACTIVE root handle per member    (uq_user_single_root_verified)
--   * one live owner per (namespace, handle), tombstones included (uq_handle_per_namespace)
-- A renamed or released handle becomes TOMBSTONED for 14 days, so an old /u/ name is
-- never handed to someone else straight away.
--
-- Zero public correlation: every profile gets its own public_profile_id (profiles and
-- alias_profiles), and registry rows point at that id, never at the other profile.
-- rout_app reads only its own registry rows (RLS); availability is answered by
-- rout_handle_available / rout_handles_taken, which return booleans/handles only.
--
-- rout_claim_verified_root_handle is the only claim path for a Didit-verified member:
-- it takes advisory locks on the handle and the caller, re-checks Didit attestation,
-- shape, the system_reserved list, the shared namespace (profiles, aliases, verified
-- domains, workspace root aliases), the 14-day tombstones and the caller's own alias
-- (a root handle never equals the member's alias), then sets profiles.username and
-- verified in one transaction. The server has already verified that the handle is in
-- the allowed set derived from the sealed Didit name (src/lib/verified-root-handle.server.ts).
--
-- Root handles of accounts that may not yet hold one (no verification, grant, workspace
-- or Didit attestation) are registered as RESERVED_HOLD. Converting them to /u/ aliases
-- (Option A) and the hard enforcement (root eligibility, reserved names, 30-day alias
-- rename cooldown) are the CONTRACT step db-pending/0299_handle_namespace_contract.sql,
-- applied only once production runs the code that uses this migration.
--
-- Every definer runs on pg_catalog, pg_temp with schema-qualified objects; internal
-- helpers carry no EXECUTE for PUBLIC or rout_app. Rollback:
-- db-pending/0298_handle_registry_dual_profile_rollback.sql.

do $types$
begin
  if pg_catalog.to_regtype('public.handle_namespace') is null then
    create type public.handle_namespace as enum ('root_verified', 'user_unverified', 'system_reserved');
  end if;
  if pg_catalog.to_regtype('public.handle_status') is null then
    create type public.handle_status as enum ('RESERVED_HOLD', 'ACTIVE', 'TOMBSTONED', 'REVOKED');
  end if;
end
$types$;

-- Own public identifier per profile (never the shared account id).
alter table public.profiles add column if not exists public_profile_id uuid not null default pg_catalog.gen_random_uuid();
create unique index if not exists profiles_public_profile_id_key on public.profiles (public_profile_id);
alter table public.alias_profiles add column if not exists public_profile_id uuid not null default pg_catalog.gen_random_uuid();
create unique index if not exists alias_profiles_public_profile_id_key on public.alias_profiles (public_profile_id);

create table if not exists public.handle_registry (
  id uuid primary key default pg_catalog.gen_random_uuid(),
  namespace public.handle_namespace not null,
  handle_normalized text not null,
  status public.handle_status not null default 'ACTIVE',
  user_id uuid references public.profiles (id) on delete cascade,
  profile_id uuid not null,
  claimed_at timestamptz not null default now(),
  last_renamed_at timestamptz,
  tombstoned_until timestamptz,
  constraint handle_registry_handle_lower check (handle_normalized = lower(handle_normalized)),
  constraint handle_registry_handle_shape check (
    namespace = 'system_reserved'
    or (handle_normalized ~ '^[a-z0-9][a-z0-9._-]{1,62}[a-z0-9]$'
        and handle_normalized !~ '(\.\.|\.-|\._|-\.|_\.)')
  ),
  constraint handle_registry_owner check ((namespace = 'system_reserved') = (user_id is null)),
  constraint handle_registry_tombstone check ((status = 'TOMBSTONED') = (tombstoned_until is not null))
);

create unique index if not exists uq_user_single_unverified_alias on public.handle_registry (user_id)
  where (namespace = 'user_unverified' and status = 'ACTIVE');
create unique index if not exists uq_user_single_root_verified on public.handle_registry (user_id)
  where (namespace = 'root_verified' and status = 'ACTIVE');
create unique index if not exists uq_handle_per_namespace on public.handle_registry (namespace, handle_normalized)
  where (status in ('ACTIVE', 'RESERVED_HOLD', 'TOMBSTONED'));
create index if not exists handle_registry_user_id_idx on public.handle_registry (user_id);
create index if not exists handle_registry_profile_id_idx on public.handle_registry (profile_id);

alter table public.handle_registry enable row level security;
revoke all on public.handle_registry from public, rout_app;
grant select on public.handle_registry to rout_app;
drop policy if exists rout_owner_read on public.handle_registry;
create policy rout_owner_read on public.handle_registry for select to rout_app
  using (user_id = public.rout_current_user_id());

-- Shape rule shared by the triggers and the claim (system_reserved is exempt).
create or replace function public.rout_handle_shape_ok(p_handle text) returns boolean
  language sql immutable security definer set search_path = pg_catalog, pg_temp
as $$
  select p_handle operator(pg_catalog.~) '^[a-z0-9][a-z0-9._-]{1,62}[a-z0-9]$'
     and p_handle operator(pg_catalog.!~) '(\.\.|\.-|\._|-\.|_\.)'
$$;
revoke all on function public.rout_handle_shape_ok(text) from public, rout_app;

-- Didit KYC attestation (same rule as src/lib/kyc/root-handle-gate.ts).
create or replace function public.rout_didit_attested(p_user uuid) returns boolean
  language sql stable security definer set search_path = pg_catalog, pg_temp
as $$
  select exists (
      select 1 from public.verified_identity_nullifiers v
       where v.user_id = p_user and v.provider = 'didit' and v.evidence = 'kyc_document' and v.has_legal_identity
    ) or exists (
      select 1 from public.identity_verifications iv
       where iv.user_id = p_user and iv.is_verified and iv.verification_provider::text = 'didit'
    )
$$;
revoke all on function public.rout_didit_attested(uuid) from public, rout_app;

-- May this account hold a root handle? Verified profile, admin/team grant, workspace
-- profile or Didit attestation.
create or replace function public.rout_root_handle_eligible(p_user uuid) returns boolean
  language sql stable security definer set search_path = pg_catalog, pg_temp
as $$
  select coalesce((
      select p.verified or p.handle_grant is not null or p.workspace_id is not null
        from public.profiles p where p.id = p_user
    ), false) or public.rout_didit_attested(p_user)
$$;
revoke all on function public.rout_root_handle_eligible(uuid) from public, rout_app;

-- Moves the current registry row of (user, namespace) to p_new. The previous handle is
-- tombstoned for 14 days; an expired tombstone of p_new is revoked first; the member's
-- own tombstone of p_new is reclaimed. Handles that fail the shape rule are not registered.
create or replace function public.rout_handle_registry_move(
  p_user uuid, p_namespace public.handle_namespace, p_profile uuid, p_new text, p_status public.handle_status
) returns void
  language plpgsql security definer set search_path = pg_catalog, pg_temp
as $$
declare
  v_new text := nullif(pg_catalog.lower(pg_catalog.btrim(coalesce(p_new, ''))), '');
  v_current public.handle_registry%rowtype;
  v_had_previous boolean := false;
begin
  select * into v_current from public.handle_registry r
   where r.user_id = p_user and r.namespace = p_namespace and r.status in ('ACTIVE', 'RESERVED_HOLD')
   order by r.claimed_at desc limit 1;

  if found and v_current.handle_normalized = v_new then
    if v_current.status <> p_status or v_current.profile_id <> p_profile then
      update public.handle_registry set status = p_status, profile_id = p_profile where id = v_current.id;
    end if;
    return;
  end if;

  if found then
    v_had_previous := true;
    update public.handle_registry
       set status = 'TOMBSTONED', tombstoned_until = now() + interval '14 days'
     where id = v_current.id;
  end if;

  if v_new is null or not public.rout_handle_shape_ok(v_new) then
    return;
  end if;

  update public.handle_registry
     set status = 'REVOKED', tombstoned_until = null
   where namespace = p_namespace and handle_normalized = v_new
     and status = 'TOMBSTONED' and tombstoned_until <= now();

  update public.handle_registry
     set status = p_status, tombstoned_until = null, profile_id = p_profile,
         last_renamed_at = case when v_had_previous then now() else last_renamed_at end
   where namespace = p_namespace and handle_normalized = v_new
     and status = 'TOMBSTONED' and user_id = p_user;
  if found then
    return;
  end if;

  if exists (
    select 1 from public.handle_registry r
     where r.namespace = p_namespace and r.handle_normalized = v_new
       and r.status = 'TOMBSTONED' and r.user_id is distinct from p_user
  ) then
    raise exception 'handle_cooling_down: % is recently released', v_new using errcode = 'unique_violation';
  end if;

  insert into public.handle_registry (namespace, handle_normalized, status, user_id, profile_id, claimed_at, last_renamed_at)
  values (p_namespace, v_new, p_status, p_user, p_profile, now(), case when v_had_previous then now() else null end);
end
$$;
revoke all on function public.rout_handle_registry_move(uuid, public.handle_namespace, uuid, text, public.handle_status) from public, rout_app;

create or replace function public.handle_registry_sync_profiles() returns trigger
  language plpgsql security definer set search_path = pg_catalog, pg_temp
as $$
begin
  if tg_op = 'UPDATE'
     and pg_catalog.lower(coalesce(old.username, '')) = pg_catalog.lower(coalesce(new.username, ''))
     and old.verified is not distinct from new.verified
     and old.handle_grant is not distinct from new.handle_grant
     and old.workspace_id is not distinct from new.workspace_id then
    return null;
  end if;
  if tg_op = 'INSERT' and new.username is null then
    return null;
  end if;
  perform public.rout_handle_registry_move(
    new.id, 'root_verified', new.public_profile_id, new.username,
    case when public.rout_root_handle_eligible(new.id) then 'ACTIVE'::public.handle_status
         else 'RESERVED_HOLD'::public.handle_status end
  );
  return null;
end
$$;
revoke all on function public.handle_registry_sync_profiles() from public, rout_app;

create or replace function public.handle_registry_sync_aliases() returns trigger
  language plpgsql security definer set search_path = pg_catalog, pg_temp
as $$
begin
  if tg_op = 'DELETE' then
    perform public.rout_handle_registry_move(old.user_id, 'user_unverified', old.public_profile_id, null, 'ACTIVE');
    return null;
  end if;
  if tg_op = 'UPDATE' and old.user_id is distinct from new.user_id then
    -- Account merge moves the alias row: its registry rows follow it.
    update public.handle_registry
       set user_id = new.user_id
     where user_id = old.user_id and namespace = 'user_unverified' and profile_id = new.public_profile_id;
  end if;
  if tg_op = 'UPDATE' and pg_catalog.lower(old.handle) = pg_catalog.lower(new.handle)
     and old.user_id is not distinct from new.user_id then
    return null;
  end if;
  perform public.rout_handle_registry_move(new.user_id, 'user_unverified', new.public_profile_id, new.handle, 'ACTIVE');
  return null;
end
$$;
revoke all on function public.handle_registry_sync_aliases() from public, rout_app;

drop trigger if exists profiles_handle_registry_sync on public.profiles;
create trigger profiles_handle_registry_sync
  after insert or update of username, verified, handle_grant, workspace_id on public.profiles
  for each row execute function public.handle_registry_sync_profiles();

drop trigger if exists alias_profiles_handle_registry_sync on public.alias_profiles;
create trigger alias_profiles_handle_registry_sync
  after insert or update of handle, user_id or delete on public.alias_profiles
  for each row execute function public.handle_registry_sync_aliases();

-- Is p_handle free in p_namespace for the calling member? Booleans only, never an owner.
create or replace function public.rout_handle_available(p_namespace public.handle_namespace, p_handle text) returns boolean
  language plpgsql stable security definer set search_path = pg_catalog, pg_temp
as $$
declare
  v_uid uuid := public.rout_current_user_id();
  v_h text := pg_catalog.lower(pg_catalog.btrim(coalesce(p_handle, '')));
begin
  if v_h = '' or p_namespace = 'system_reserved' then
    return false;
  end if;
  if p_namespace = 'root_verified' and exists (
    select 1 from public.handle_registry r where r.namespace = 'system_reserved' and r.handle_normalized = v_h
  ) then
    return false;
  end if;
  if exists (
    select 1 from public.handle_registry r
     where r.namespace = p_namespace and r.handle_normalized = v_h
       and r.user_id is distinct from v_uid
       and (r.status in ('ACTIVE', 'RESERVED_HOLD') or (r.status = 'TOMBSTONED' and r.tombstoned_until > now()))
  ) then
    return false;
  end if;
  if exists (
    select 1 from public.profiles p
     where (pg_catalog.lower(p.username) = v_h or pg_catalog.lower(coalesce(p.subdomain_alias, '')) = v_h)
       and p.id is distinct from v_uid
  ) or exists (
    select 1 from public.alias_profiles a where pg_catalog.lower(a.handle) = v_h and a.user_id is distinct from v_uid
  ) or exists (
    select 1 from public.domain_claims d
     where d.handle = v_h and d.status in ('verified', 'grace') and d.user_id is distinct from v_uid
  ) or exists (
    select 1 from public.workspace_root_aliases w where w.handle = v_h
  ) then
    return false;
  end if;
  return true;
end
$$;
revoke all on function public.rout_handle_available(public.handle_namespace, text) from public, rout_app;
grant execute on function public.rout_handle_available(public.handle_namespace, text) to rout_app;

-- Which of these handles are NOT available to the caller (one round trip for a candidate list).
create or replace function public.rout_handles_taken(p_namespace public.handle_namespace, p_handles text[]) returns setof text
  language sql stable security definer set search_path = pg_catalog, pg_temp
as $$
  select h from pg_catalog.unnest(coalesce(p_handles, '{}'::text[])) as h
   where pg_catalog.array_length(p_handles, 1) <= 200
     and not public.rout_handle_available(p_namespace, h)
$$;
revoke all on function public.rout_handles_taken(public.handle_namespace, text[]) from public, rout_app;
grant execute on function public.rout_handles_taken(public.handle_namespace, text[]) to rout_app;

-- The one claim path after Didit (see header). Returns the claimed handle.
create or replace function public.rout_claim_verified_root_handle(p_handle text, p_copy_links boolean, p_hide_alias boolean)
  returns text
  language plpgsql security definer set search_path = pg_catalog, pg_temp
as $$
declare
  v_uid uuid := public.rout_current_user_id();
  v_h text := pg_catalog.lower(pg_catalog.btrim(coalesce(p_handle, '')));
  v_root public.handle_registry%rowtype;
  v_fresh boolean;
  v_alias_blocks jsonb;
begin
  if v_uid is null then
    raise exception 'not_authenticated' using errcode = '42501';
  end if;
  perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('rout.root_claim.user:' || v_uid::text, 0));
  perform pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended('rout.handle:' || v_h, 0));

  if not public.rout_didit_attested(v_uid) then
    raise exception 'root_handle_identity_required' using errcode = '42501';
  end if;
  if not public.rout_handle_shape_ok(v_h) then
    raise exception 'handle_invalid' using errcode = '22023';
  end if;
  if exists (select 1 from public.handle_registry r where r.namespace = 'system_reserved' and r.handle_normalized = v_h) then
    raise exception 'handle_reserved' using errcode = '22023';
  end if;
  if exists (select 1 from public.alias_profiles a where a.user_id = v_uid and pg_catalog.lower(a.handle) = v_h) then
    raise exception 'handle_matches_own_alias' using errcode = '22023';
  end if;
  if not public.rout_handle_available('root_verified', v_h) then
    raise exception 'handle_taken' using errcode = 'unique_violation';
  end if;

  select * into v_root from public.handle_registry r
   where r.user_id = v_uid and r.namespace = 'root_verified' and r.status = 'ACTIVE' limit 1;
  v_fresh := not found;
  if not v_fresh then
    if v_root.handle_normalized = v_h then
      return v_h;
    end if;
    if v_root.last_renamed_at is not null and v_root.last_renamed_at > now() - interval '30 days' then
      raise exception 'root_handle_cooldown' using errcode = '22023';
    end if;
  end if;

  if v_fresh then
    -- Start of a new verified profile: blank (default) or a one-time copy of the alias links.
    v_alias_blocks := (select a.blocks from public.alias_profiles a where a.user_id = v_uid);
    update public.profiles
       set display_name = null, tagline = null, bio = null, avatar_url = null, favicon_url = null,
           profile_descriptions = '{}'::jsonb,
           blocks = case when coalesce(p_copy_links, false) then coalesce(v_alias_blocks, '[]'::jsonb) else '[]'::jsonb end
     where id = v_uid;
    delete from public.profile_drafts where user_id = v_uid and space = 'verified';
  end if;

  if coalesce(p_hide_alias, false) then
    update public.alias_profiles
       set display_prefs = coalesce(display_prefs, '{}'::jsonb) || pg_catalog.jsonb_build_object('publicProfile', false),
           updated_at = now()
     where user_id = v_uid;
  end if;

  update public.profiles
     set username = v_h, verified = true, verified_at = coalesce(verified_at, now()), updated_at = now()
   where id = v_uid;
  if not found then
    raise exception 'profile_not_found' using errcode = 'P0002';
  end if;
  return v_h;
end
$$;
revoke all on function public.rout_claim_verified_root_handle(text, boolean, boolean) from public, rout_app;
grant execute on function public.rout_claim_verified_root_handle(text, boolean, boolean) to rout_app;

-- System routes and protected public terms (mirror of src/lib/reserved-slugs.ts
-- SYSTEM_ROUTE_SLUGS + PROTECTED_PUBLIC_SLUGS).
insert into public.handle_registry (namespace, handle_normalized, status, user_id, profile_id)
select 'system_reserved', h, 'RESERVED_HOLD', null, pg_catalog.gen_random_uuid()
  from pg_catalog.unnest(array[
    'u', 'api', 'auth', 'login', 'register', 'admin', 'dashboard', 'settings', 'about', 'verify',
    'badge', 'badges', 'workspace', 'workspaces', 'org', 'support', 'privacy', 'terms', 'legal',
    'security', 'status', 'rout', 'delplanche', 'postmaster', 'abuse', 'well-known', 'robots.txt',
    'sitemap.xml',
    'monarchie', 'koninklijkpaleis', 'palaisroyal', 'belgie', 'belgique', 'belgien', 'belgium',
    'brussels', 'bruxelles', 'brussel', 'vlaanderen', 'wallonie', 'vrt', 'rtbf', 'federaal',
    'overheid', 'gouvernement', 'politie', 'police'
  ]::text[]) as h
on conflict do nothing;

-- Backfill from the current state (idempotent).
insert into public.handle_registry (namespace, handle_normalized, status, user_id, profile_id, claimed_at)
select 'root_verified', pg_catalog.lower(p.username),
       case when public.rout_root_handle_eligible(p.id) then 'ACTIVE'::public.handle_status
            else 'RESERVED_HOLD'::public.handle_status end,
       p.id, p.public_profile_id, coalesce(p.verified_at, p.created_at, now())
  from public.profiles p
 where p.username is not null
   and public.rout_handle_shape_ok(pg_catalog.lower(p.username))
   and not exists (
     select 1 from public.handle_registry r
      where r.user_id = p.id and r.namespace = 'root_verified' and r.status in ('ACTIVE', 'RESERVED_HOLD')
   )
on conflict do nothing;

insert into public.handle_registry (namespace, handle_normalized, status, user_id, profile_id, claimed_at)
select 'user_unverified', pg_catalog.lower(a.handle), 'ACTIVE', a.user_id, a.public_profile_id, a.created_at
  from public.alias_profiles a
 where public.rout_handle_shape_ok(pg_catalog.lower(a.handle))
   and not exists (
     select 1 from public.handle_registry r
      where r.user_id = a.user_id and r.namespace = 'user_unverified' and r.status = 'ACTIVE'
   )
on conflict do nothing;
