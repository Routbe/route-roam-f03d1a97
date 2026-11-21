-- 0299 (CONTRACT, held back): the root namespace rout.be/<handle> becomes exclusive to
-- accounts that may hold it (Didit attestation, verified profile, admin/team grant or
-- workspace profile), system-reserved names can no longer be taken by a personal
-- account, and a /u/ alias can be renamed at most once per 30 days.
--
-- Apply only after production runs the code that uses db/0298 (the public health probe
-- reports schema 0298 or higher), then move this file into db/ and raise
-- CODE_SCHEMA_LEVEL. Needs db/0298.
--
-- Option A (idempotent): every account that may not hold a root handle but still has
-- profiles.username keeps that name as its free /u/ alias. When the account has no alias
-- yet, the alias row is created with that name and a copy of the profile content (the
-- name was never public at the root: public reads require profiles.verified). When it
-- already has an alias, the alias stays. Then profiles.username becomes NULL; the 0298
-- trigger tombstones the released root name for 14 days. Running it again finds nothing.
--
-- Rollback: db-pending/0299_handle_namespace_contract_rollback.sql removes the guards;
-- converted aliases stay (no data is deleted).

insert into public.alias_profiles (
  user_id, handle, display_name, tagline, bio, avatar_url, favicon_url, theme, card_style,
  blocks, display_prefs, profile_descriptions, created_at, updated_at
)
select p.id, pg_catalog.lower(p.username), p.display_name, p.tagline, p.bio, p.avatar_url, p.favicon_url,
       coalesce(p.theme, 'noir'), coalesce(p.card_style, 'bordered'), coalesce(p.blocks, '[]'::jsonb),
       coalesce(p.display_prefs, '{}'::jsonb), coalesce(p.profile_descriptions, '{}'::jsonb), now(), now()
  from public.profiles p
 where p.username is not null
   and not public.rout_root_handle_eligible(p.id)
   and not exists (select 1 from public.alias_profiles a where a.user_id = p.id)
   and not exists (
     select 1 from public.alias_profiles a2 where pg_catalog.lower(a2.handle) = pg_catalog.lower(p.username)
   )
on conflict do nothing;

update public.profiles p
   set username = null, updated_at = now()
 where p.username is not null
   and not public.rout_root_handle_eligible(p.id);

-- Hard root rule (runs with the NEW row, so a claim that sets username and verified in
-- one statement passes).
create or replace function public.rout_enforce_root_handle_policy() returns trigger
  language plpgsql security definer set search_path = pg_catalog, pg_temp
as $$
declare
  v_h text := pg_catalog.lower(pg_catalog.btrim(coalesce(new.username, '')));
begin
  if v_h = '' then
    return new;
  end if;
  if tg_op = 'UPDATE' and pg_catalog.lower(coalesce(old.username, '')) = v_h then
    return new;
  end if;
  if exists (select 1 from public.handle_registry r where r.namespace = 'system_reserved' and r.handle_normalized = v_h) then
    raise exception 'handle_reserved: % is reserved', v_h using errcode = '22023';
  end if;
  if not (new.verified or new.handle_grant is not null or new.workspace_id is not null
          or public.rout_didit_attested(new.id)) then
    raise exception 'root_handle_identity_required' using errcode = '42501';
  end if;
  return new;
end
$$;
revoke all on function public.rout_enforce_root_handle_policy() from public, rout_app;

drop trigger if exists profiles_root_handle_policy on public.profiles;
create trigger profiles_root_handle_policy
  before insert or update of username on public.profiles
  for each row execute function public.rout_enforce_root_handle_policy();

-- 30-day cooldown on renaming a /u/ alias, measured from the last rename.
create or replace function public.rout_enforce_alias_rename_cooldown() returns trigger
  language plpgsql security definer set search_path = pg_catalog, pg_temp
as $$
declare
  v_last timestamptz;
begin
  if pg_catalog.lower(old.handle) = pg_catalog.lower(new.handle) or old.user_id is distinct from new.user_id then
    return new;
  end if;
  select r.last_renamed_at into v_last from public.handle_registry r
   where r.user_id = new.user_id and r.namespace = 'user_unverified' and r.status = 'ACTIVE'
   limit 1;
  if v_last is not null and v_last > now() - interval '30 days' then
    raise exception 'alias_rename_cooldown: next rename after %', v_last + interval '30 days' using errcode = '22023';
  end if;
  return new;
end
$$;
revoke all on function public.rout_enforce_alias_rename_cooldown() from public, rout_app;

drop trigger if exists alias_profiles_rename_cooldown on public.alias_profiles;
create trigger alias_profiles_rename_cooldown
  before update of handle on public.alias_profiles
  for each row execute function public.rout_enforce_alias_rename_cooldown();
