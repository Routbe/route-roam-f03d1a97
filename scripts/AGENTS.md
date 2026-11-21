
## Function region
- Vercel functions are pinned to the Neon database's region (VERCEL_FUNCTION_REGION in nitro-target.ts). Why: each app query is a multi-round-trip transaction, so a function on another continent pushed Studio loads past the browser timeout.
