-- Rollback of db/0297: the 0122 trigger body (hex suffix, invoker rights) and the
-- EXECUTE rights Neon held before 0297 (PUBLIC and rout_app, read back on
-- 2026-11-21: {=X/neondb_owner,neondb_owner=X/neondb_owner,rout_app=X/neondb_owner}).
create or replace function public.enforce_workspace_slug_suffix() returns trigger
  language plpgsql security invoker set search_path = public
  as $$
  begin
    new.slug := lower(new.slug);
    if new.slug !~ '-[a-z0-9]{4}$' and not public.workspace_may_drop_suffix(new.plan, new.id) then
      new.slug := left(new.slug, 35) || '-' || substr(md5(gen_random_uuid()::text), 1, 4);
    end if;
    return new;
  end
  $$;
grant execute on function public.enforce_workspace_slug_suffix() to public, rout_app;
