import { DEFAULT_PUBLIC_ORIGIN, releaseEnvironmentWarnings, validateReleaseEnvironment, withReleaseDefaults } from "./release-config";

// PUBLIC_ORIGIN falls back to the canonical https://rout.be, so a missing or
// malformed value neither stops the build nor prints a warning.
const env = withReleaseDefaults(process.env);
if (env.PUBLIC_ORIGIN !== process.env["PUBLIC_ORIGIN"]) console.log(`PUBLIC_ORIGIN not set to a valid HTTPS URL; using ${DEFAULT_PUBLIC_ORIGIN}.`);
const issues = validateReleaseEnvironment(env);
for (const warning of releaseEnvironmentWarnings(env)) console.warn(`Warning: ${warning}`);
if (issues.length) {
  console.error("Release configuration is incomplete:");
  for (const issue of issues) console.error(`- ${issue.key}: ${issue.reason}`);
  process.exitCode = 1;
} else {
  console.log("Required release settings are configured. Provider access, database permissions and authentication still require end-to-end verification.");
}
