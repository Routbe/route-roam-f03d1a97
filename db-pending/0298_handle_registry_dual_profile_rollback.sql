-- Rollback of db/0298_handle_registry_dual_profile.sql. Refuses while the CONTRACT
-- (db-pending/0299_handle_namespace_contract.sql) is still installed, because that
-- step depends on the registry. Removes the registry, its triggers and functions and
-- the two enums. The public_profile_id columns stay (additive, harmless) so public
-- identifiers already handed out keep working if 0298 is re-applied.
do $guard$
begin
  if pg_catalog.to_regprocedure('public.rout_enforce_root_handle_policy()') is not null then
    raise exception '0298 rollback: roll back 0299 first';
  end if;
end
$guard$;

drop trigger if exists profiles_handle_registry_sync on public.profiles;
drop trigger if exists alias_profiles_handle_registry_sync on public.alias_profiles;
drop function if exists public.rout_claim_verified_root_handle(text, boolean, boolean);
drop function if exists public.rout_handles_taken(public.handle_namespace, text[]);
drop function if exists public.rout_handle_available(public.handle_namespace, text);
drop function if exists public.handle_registry_sync_aliases();
drop function if exists public.handle_registry_sync_profiles();
drop function if exists public.rout_handle_registry_move(uuid, public.handle_namespace, uuid, text, public.handle_status);
drop function if exists public.rout_root_handle_eligible(uuid);
drop function if exists public.rout_didit_attested(uuid);
drop function if exists public.rout_handle_shape_ok(text);
drop table if exists public.handle_registry;
drop type if exists public.handle_status;
drop type if exists public.handle_namespace;
