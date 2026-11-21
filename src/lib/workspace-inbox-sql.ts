/**
 * Statements of the workspace manager inbox (db/0285). Kept free of server imports so the
 * offline replay test runs the exact text the app sends.
 *
 * KEY_INIT is one atomic batch: publish the next epoch, store the caller's own wsk envelope,
 * then fail the whole transaction (division by zero) unless the caller can now read that
 * envelope back. A refused publish or store therefore never leaves a live key nobody holds,
 * which would make every new question unreadable.
 */
export const KEY_INIT: readonly string[] = [
  "select public.rout_ws_group_publish($1::uuid, $2::int, $3, $4) as r",
  "select public.rout_ws_group_member_store($1::uuid, $2::int, $3::uuid, $4::uuid, $5, $6) as r",
  "select 1 / ((public.rout_ws_group_member_key($1::uuid, $2::int) ->> 'ok')::boolean::int) as held",
];

export const ROLE = "select public.rout_workspace_role($1::uuid)::text as r";
/** The public ask key answers only while the page is switched on and a live key exists. */
export const ASK_KEY = "select public.rout_public_ws_ask_key($1) as r";
export const STATE = "select public.rout_ws_group_state($1::uuid) as r";
export const MEMBER_KEY = "select public.rout_ws_group_member_key($1::uuid, $2::int) as r";
export const QUESTIONS = "select * from public.rout_ws_question_list($1::uuid)";
export const ASK_SAVE = "select public.rout_ws_ask_save($1::uuid, $2::boolean) as r";
export const REPLY = "select public.rout_ws_question_reply($1::uuid, $2, decode($3, 'hex')) as r";
export const PUBLISH = "select public.rout_ws_question_publish($1::uuid, $2, $3) as r";
export const DECLINE = "select public.rout_ws_question_decline($1::uuid) as r";
