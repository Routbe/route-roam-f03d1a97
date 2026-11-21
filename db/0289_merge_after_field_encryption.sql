-- 0289: account merge after 0287/0288 (EXPAND, additive; nothing is revoked). Held in db-pending/ until the owner's "GO 0289".
--
-- Found after 0287 and 0288 went live (2026-11-17): execute_account_merge (db/0152) runs as
-- rout_merge_executor, which updates public.profiles but had no EXECUTE on
-- public.rout_rpf1_shape_ok(bytea). 0287's eleven *_sealed CHECK constraints call it, so every
-- merge stopped with "permission denied for function rout_rpf1_shape_ok" and rolled back.
-- 0288 added public.verified_identity_nullifiers (FK on delete cascade) without a merge guard,
-- so deleting a secondary account would have cascaded its nullifier rows away.
--
--   1. rout_merge_executor may execute the pure shape check (no data access, immutable).
--   2. execute_account_merge refuses a secondary account that owns a nullifier row, exactly like
--      identity_verifications and verified_identities (merge_blocked:verified_identity_nullifiers).

grant execute on function public.rout_rpf1_shape_ok(bytea) to rout_merge_executor;

do $own$ begin execute format('grant rout_merge_executor to %I with inherit true, set true', current_user); end $own$;
grant create on schema public to rout_merge_executor;

do $m$
declare
  v_def text;
  v_new text;
begin
  select pg_get_functiondef('public.execute_account_merge(text,text,text,text)'::regprocedure) into v_def;
  if position('merge_blocked:verified_identity_nullifiers''' in v_def) > 0 then return; end if;
  v_new := regexp_replace(v_def, E'([^\\n]*''merge_blocked:verified_identities''[^\\n]*\\n)',
    E'\\1 perform public.rout_merge_assert((not exists (select 1 from public."verified_identity_nullifiers" where "user_id" = v_secondary)), ''merge_blocked:verified_identity_nullifiers'');\n');
  if v_new = v_def then
    raise exception 'execute_account_merge: guard anchor merge_blocked:verified_identities not found';
  end if;
  execute v_new;
end $m$;

revoke create on schema public from rout_merge_executor;
do $own$ begin execute format('revoke rout_merge_executor from %I', current_user); end $own$;
