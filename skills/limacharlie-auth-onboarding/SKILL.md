---
name: limacharlie-auth-onboarding
description: Set up or troubleshoot LimaCharlie MCP authentication with secure local credential storage, org API keys, JWT refresh, UID confusion, onboarding smoke tests, and reauth. Use when users need to configure LimaCharlie MCP auth, verify credentials, rotate keys, diagnose missing_credentials or permission errors, or avoid pasting API keys/JWTs into env files.
---

# LimaCharlie Auth Onboarding

## Workflow

Use the default configure helper as the normal credential setup path. Do not
ask users to bring a credential-store instance, paste production LimaCharlie
API keys into `.env` files, or put keys in chat. If a local test must use
direct environment variables, label it as temporary and prefer the default
configure helper for real use.

1. Identify the intended org and key type:
   - Prefer an organization API key for MCP runtime access.
   - Use a user API key only when the requested workflow truly needs user-wide
     access across organizations.
   - Do not ask for an `LC_UID` unless using user API key JWT exchange.
2. Store or reference the key:
   - Use `limacharlie-mcp-configure --oid <org-id>` for the default path.
   - Only ask for external credential-store details when the user explicitly
     wants an advanced operator deployment.
   - Use only `LC_MCP_CONFIG` when the runtime config file is not in the
     default location.
   - Keep `LC_API_KEY` as local test fallback only.
3. Verify without exposing secrets:
   - Call `lc_auth_status` first.
   - Call `lc_auth_whoami` with `oid` and a concrete `check_perm` when diagnosing permissions.
   - Call `lc_auth_refresh` after rotation or suspected stale JWT cache.
4. Run a smoke test:
   - Use `lc_list_orgs` if the key can discover orgs.
   - Use `lc_tool_catalog` to confirm the intended profile is active.
   - Use one safe read such as `lc_review_org_posture` or `lc_list_sensors`.

## Permission Guidance

For read-only review onboarding, start with the smallest permissions needed for
org, sensor, detection, case, content, output, user, and API key metadata reads.
For response workflows, add only the specific permissions required by the
previewed mutation surfaces. Never request broad destructive permissions just to
make onboarding easier.

## Failure Handling

If auth fails, report the concrete failure class and next check. Do not print
API keys, credential-store tokens, JWTs, or authorization headers. If an org
API key works in the LimaCharlie UI but the MCP fails, rerun
`limacharlie-mcp-configure --oid <org-id>`, then verify the MCP client is
using the expected profile and config path. Do not ask for `uid` unless user
API key mode is intentional.
