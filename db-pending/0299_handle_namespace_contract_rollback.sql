-- Rollback of db-pending/0299_handle_namespace_contract.sql: removes the root policy and
-- alias cooldown guards. Converted aliases (Option A) stay; no data is deleted.
drop trigger if exists profiles_root_handle_policy on public.profiles;
drop trigger if exists alias_profiles_rename_cooldown on public.alias_profiles;
drop function if exists public.rout_enforce_root_handle_policy();
drop function if exists public.rout_enforce_alias_rename_cooldown();
