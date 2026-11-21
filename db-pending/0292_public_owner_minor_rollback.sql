-- Rollback of 0292: removes the under-18 check; the card falls back to rout_user_is_minor (under 16).
drop function if exists public.rout_public_owner_is_minor(uuid);
