-- 0297 (EXPAND, function body only): the 4-character suffix of free workspaces
-- (/w/<name>-<suffix>, db/0122) becomes Crockford base32 with a collision check.
--
-- Before: substr(md5(gen_random_uuid()::text), 1, 4) — 16 hex characters, so
-- 65 536 suffixes per name, and a collision surfaced to the member as a unique
-- violation on workspaces_slug_key. After: 20 bits from gen_random_uuid() mapped
-- onto 0123456789abcdefghjkmnpqrstvwxyz (no i, l, o, u; 1 048 576 suffixes per
-- name), and up to 8 fresh draws until the slug is free. The alphabet equals
-- CROCKFORD_SUFFIX_ALPHABET in src/lib/workspace-slug-suffix.ts
-- (src/test/migration-0297.test.ts). Existing slugs are untouched: a slug that
-- already ends in -[a-z0-9]{4} keeps it, exactly as before.
--
-- The trigger becomes SECURITY DEFINER so the free-slug check sees every
-- workspace instead of only those RLS shows the inserting member; search_path is
-- pinned to pg_catalog, pg_temp and every object is schema-qualified. Like the
-- trigger-only definers in 0286, it carries no EXECUTE for PUBLIC or rout_app:
-- PostgreSQL never checks EXECUTE when a trigger fires.
--
-- No table, column, policy or trigger definition changes. Rollback:
-- db-pending/0297_workspace_slug_crockford_suffix_rollback.sql.

create or replace function public.enforce_workspace_slug_suffix() returns trigger
  language plpgsql security definer set search_path = pg_catalog, pg_temp
as $$
declare
  v_alphabet constant text := '0123456789abcdefghjkmnpqrstvwxyz';
  v_base text;
  v_candidate text;
  v_bytes bytea;
  v_attempt integer := 0;
begin
  new.slug := pg_catalog.lower(new.slug);
  if new.slug operator(pg_catalog.~) '-[a-z0-9]{4}$' or public.workspace_may_drop_suffix(new.plan, new.id) then
    return new;
  end if;
  v_base := pg_catalog.rtrim(pg_catalog.left(new.slug, 35), '-');
  loop
    v_attempt := v_attempt + 1;
    v_bytes := pg_catalog.uuid_send(pg_catalog.gen_random_uuid());
    v_candidate := v_base || '-'
      || pg_catalog.substr(v_alphabet, (pg_catalog.get_byte(v_bytes, 0) & 31) + 1, 1)
      || pg_catalog.substr(v_alphabet, (pg_catalog.get_byte(v_bytes, 1) & 31) + 1, 1)
      || pg_catalog.substr(v_alphabet, (pg_catalog.get_byte(v_bytes, 2) & 31) + 1, 1)
      || pg_catalog.substr(v_alphabet, (pg_catalog.get_byte(v_bytes, 3) & 31) + 1, 1);
    exit when v_attempt >= 8 or not exists (
      select 1 from public.workspaces w where w.slug = v_candidate and w.id is distinct from new.id
    );
  end loop;
  new.slug := v_candidate;
  return new;
end
$$;
revoke all on function public.enforce_workspace_slug_suffix() from public, rout_app;
