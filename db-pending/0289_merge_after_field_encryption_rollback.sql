-- Rollback of db/0289. Removes the nullifier merge guard and the executor's EXECUTE on the shape
-- check again. Warning: afterwards every account merge fails again while 0287 is in place.
do $own$ begin execute format('grant rout_merge_executor to %I with inherit true, set true', current_user); end $own$;
grant create on schema public to rout_merge_executor;
do $m$
declare
  v_def text;
  v_new text;
begin
  select pg_get_functiondef('public.execute_account_merge(text,text,text,text)'::regprocedure) into v_def;
  v_new := regexp_replace(v_def, E'[^\\n]*''merge_blocked:verified_identity_nullifiers''[^\\n]*\\n', '', 'g');
  if v_new <> v_def then execute v_new; end if;
end $m$;
revoke create on schema public from rout_merge_executor;
do $own$ begin execute format('revoke rout_merge_executor from %I', current_user); end $own$;
revoke execute on function public.rout_rpf1_shape_ok(bytea) from rout_merge_executor;
