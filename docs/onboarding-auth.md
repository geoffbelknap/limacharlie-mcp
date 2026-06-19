# Onboarding And Auth

This MCP should make LimaCharlie authentication feel like a normal local
credential setup. Users should not manually create, paste, rotate, or re-paste
JWTs.

## Choose The Right Auth Mode

Most deployments should use organization API key mode. User API key mode exists
for multi-org workflows, but it is easier to misconfigure.

| Need | Key source | Required MCP values | Notes |
| --- | --- | --- | --- |
| Work in one LimaCharlie org | Org page -> Access Management -> REST API | `LC_API_KEY` or `LC_API_KEY_REF`, plus explicit `oid` tool inputs | Recommended default. The org REST API page may say "User-Generated API Keys"; those are still org-scoped keys. |
| Discover/list orgs across the user's account | Account Settings -> API Keys | `LC_AUTH_MODE=user_api_key`, `LC_UID`, and `LC_USER_API_KEY` or `LC_USER_API_KEY_REF` | Use only when multi-org access is needed. Keep separate from the org key. |

Do not overwrite a working organization API key with a user API key. Keep both
values separate:

```bash
LC_API_KEY=your-organization-api-key
LC_USER_API_KEY=your-user-api-key
LC_UID=your-user-id
LC_ORG_ID=your-organization-id
```

When both keys are present, the runtime stays in organization API key mode
unless `LC_AUTH_MODE=user_api_key` is set.

## Recommended Setup

Use an Organization API key for the org you want the MCP to access, stored in
Vault. Vault is the default credential provider for deployment. Raw environment
API keys are a local-development fallback, not the recommended runtime model.

1. In LimaCharlie, open the organization.
2. Go to Access Management -> REST API.
3. Create an API key with the minimum permissions needed for the workflows.
4. Run `limacharlie-mcp-vault-bootstrap` with a Vault token file. The helper
   reads the LimaCharlie key through a hidden prompt, writes it to Vault KV v2,
   and prints a nonsecret MCP env block.
5. Put only that nonsecret env block in the MCP client config.
6. Start the MCP server.
7. Call `lc_auth_status`.
8. Call `lc_list_orgs` or an org-scoped read such as `lc_list_sensors`.

```bash
limacharlie-mcp-vault-bootstrap \
  --vault-addr "https://vault.example.com" \
  --token-file "/run/secrets/limacharlie-mcp-bootstrap-token" \
  --runtime-token-file "/run/secrets/limacharlie-mcp-vault-token"
```

For unattended setup, pipe the key from an approved secret manager:

```bash
approved-secret-manager read limacharlie/mcp/api-key \
  | limacharlie-mcp-vault-bootstrap \
      --vault-addr "https://vault.example.com" \
      --token-file "/run/secrets/limacharlie-mcp-bootstrap-token" \
      --runtime-token-file "/run/secrets/limacharlie-mcp-vault-token" \
      --api-key-stdin
```

Example stdio config:

```json
{
  "mcpServers": {
    "limacharlie-local": {
      "command": "/path/to/limacharlie-mcp/.venv/bin/limacharlie-mcp",
      "env": {
        "LC_SECRET_PROVIDER": "vault",
        "LC_VAULT_ADDR": "https://vault.example.com",
        "LC_VAULT_TOKEN_FILE": "/run/secrets/limacharlie-mcp-vault-token",
        "LC_API_KEY_REF": "vault://secret/data/limacharlie/mcp#api_key"
      }
    }
  }
}
```

For a local-only test environment:

```bash
export LC_SECRET_PROVIDER=env
export LC_API_KEY=your-organization-api-key
```

Do not use `.env` files for production LimaCharlie API keys.

See [Deployment](deployment.md) for Vault policies, Vault Agent token-file
setup, and MCP client config templates.

## Preflight With Auth Doctor

Use `limacharlie-mcp-auth-doctor` before adding the MCP to an agent client. It
prints configuration shape, selected auth mode, bounded live-check status, and
secret leak checks without printing API keys, UID values, Vault tokens, or JWTs.

For local development:

```bash
limacharlie-mcp-auth-doctor --env-file /path/to/local-env
```

For user-key mode with both org and user keys present:

```bash
limacharlie-mcp-auth-doctor --env-file /path/to/local-env --mode user_api_key
```

For production Vault-backed runtime, pass the same nonsecret env values your MCP
client will pass and run:

```bash
limacharlie-mcp-auth-doctor
```

If you only want to inspect which variables are present, without calling
LimaCharlie:

```bash
limacharlie-mcp-auth-doctor --no-live
```

## What Happens Internally

LimaCharlie REST authentication uses short-lived JWTs. This MCP hides that from
the user:

- Vault stores the stable LimaCharlie API key.
- `limacharlie-mcp-vault-bootstrap` writes the key to Vault without echoing or
  returning it.
- The server reads the API key from the configured Vault reference only when it
  needs a new LimaCharlie JWT.
- The server exchanges that API key for a LimaCharlie JWT.
- JWTs are cached in memory only.
- JWT values are never returned by tools.
- JWT values are not written to the audit log.
- The server refreshes expired or near-expired JWTs automatically.

## Reauth

Most users should not need to do anything. If the API key is valid, a later
tool call refreshes the JWT automatically.

Use `lc_auth_refresh` when:

- a user just rotated the API key in Vault,
- a token is suspected to be stale,
- a user wants to verify auth before a workflow,
- a user changed from user API key mode to org API key mode.

Use `lc_auth_status` when:

- onboarding a new client,
- checking whether credentials are configured,
- checking whether a JWT is cached and when it expires,
- diagnosing whether the MCP is in org API key or user API key mode.

`lc_auth_status` and `lc_auth_refresh` do not expose API keys or JWTs.

## User API Key Mode

Only use this mode when the MCP needs account-level multi-org discovery such as
`lc_list_orgs`.

Create the key in LimaCharlie under Account Settings -> API Keys, not under the
organization REST API page. The key table shows the key name later, but the
secret value is shown only once at creation time. If the secret was not copied
then, delete that user key and create a new one.

The `LC_UID` value must be the user id accepted by `https://jwt.limacharlie.io`.
On the account API key page, use the copy control associated with the text that
describes "your User ID"; do not use the email copy control or the API key row
name. If LimaCharlie shows more than one user-shaped identifier, validate the
pair by attempting a JWT exchange before wiring it into the MCP. In practice
the JWT-accepted UID may look like a Firebase-style non-UUID string rather than
the UUID-shaped account id shown in some UI places.

User API keys are supported by setting both:

```bash
LC_SECRET_PROVIDER=vault
LC_AUTH_MODE=user_api_key
LC_UID=your-user-id
LC_USER_API_KEY_REF=vault://secret/data/limacharlie/mcp-user#api_key
```

Bootstrap a user API key with:

```bash
limacharlie-mcp-vault-bootstrap \
  --vault-addr "https://vault.example.com" \
  --token-file "/run/secrets/limacharlie-mcp-bootstrap-token" \
  --runtime-token-file "/run/secrets/limacharlie-mcp-vault-token" \
  --path "limacharlie/mcp-user" \
  --user-api-key
```

User API key mode can list orgs and then mint org-scoped JWTs for individual
org operations. It is more powerful than an organization API key because it
inherits the user's permissions across organizations. Prefer organization API
keys for routine local MCP use unless multi-org access is required.

Keep user API key material separate from the organization API key. `LC_API_KEY`
remains the org-scoped local-development key; `LC_USER_API_KEY` is the
local-development fallback for user-scoped mode.

For local development only, user API key mode can also use
`LC_SECRET_PROVIDER=env` with `LC_USER_API_KEY`. If both `LC_API_KEY` and
`LC_USER_API_KEY` are present in the same environment, set
`LC_AUTH_MODE=user_api_key` to select the user key. Without that selector, the
runtime stays in org API key mode.

## Other KMS Or HSM Providers

The runtime currently supports Vault and direct env-key fallback. If an
environment standardizes on a different KMS or HSM, prefer one of these paths:

- Use Vault Agent or an approved broker to expose the key through the same Vault
  HTTP shape.
- Add a new credential provider with the same non-leakage behavior:
  `lc_auth_status` reports readiness booleans only, and JWT refresh resolves the
  key just-in-time without returning or auditing it.

Do not add a raw provider that returns stable LimaCharlie API keys to agents.

## Permission Profiles

For the smallest onboarding smoke test, an organization API key only needs:

- `org.get`
- `sensor.list`
- `sensor.get`

That is enough for `limacharlie-mcp-auth-doctor`, `lc_auth_whoami`,
`lc_get_org_info`, and `lc_list_sensors` to prove the MCP can authenticate and
reach the target org.

For broader read-only investigation, add only the permissions for the data
families you expect the MCP to inspect:

- `sensor.list`
- `sensor.get`
- `insight.evt.get`
- `insight.det.get`
- `insight.stat`
- `dr.list`
- `fp.ctrl`
- `yara.get`
- `lookup.get`
- `audit.get`

Some LimaCharlie read/list endpoints are guarded by broader permission names.
For example, user inventory may require `user.ctrl`, API key inventory may
require `apikey.ctrl`, AI session and usage inventory may require
`ai_agent.get`, and Hive-backed secret or lookup inventory may require
`secret.get.mtd` or `lookup.get.mtd`. Treat those as elevated permissions:
grant them only to a dedicated MCP key when the matching tool family is needed.

For administration inventory, add only the needed read/list permissions for API
keys, installation keys, outputs, extensions, and org config. Validate each
added permission with `lc_auth_whoami` and the specific read tool before adding
more.

Do not grant write permissions such as `sensor.task`, `sensor.tag`, `dr.set`,
`dr.del`, `output.set`, or key-management permissions until the matching MCP
mutation tool has a preview/confirm implementation.

## Troubleshooting

If `lc_auth_status` returns `missing_credentials`, the MCP process did not
receive a complete Vault configuration. Check `LC_VAULT_ADDR`,
`LC_VAULT_TOKEN_FILE`, and `LC_API_KEY_REF` or `LC_USER_API_KEY_REF` in the MCP
client config `env` block. For local development fallback, check
`LC_SECRET_PROVIDER=env` with `LC_API_KEY` for org mode or `LC_USER_API_KEY`
for user mode.

If org-scoped tools fail with `error.class: auth` or `error.class: policy`,
call `lc_auth_whoami` with the target `oid` and optional `check_perm`.

Common auth mistakes:

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| `lc_list_orgs` fails in org-key mode | Organization API keys cannot do unscoped account org discovery | Use org-scoped tools with explicit `oid`, or switch to user API key mode. |
| JWT exchange returns `unknown api key` in user mode | `LC_USER_API_KEY` is missing, wrong, or actually an org API key | Create a fresh user API key under Account Settings -> API Keys and copy the secret shown once. |
| JWT exchange returns `user not found` in user mode | `LC_UID` is not the JWT-accepted user id | Re-copy the user id from the account user API key guidance, or validate with the direct JWT exchange before using the MCP. |
| `LC_UID` is set and org tools unexpectedly fail | Older configs may accidentally pair `LC_UID` with an org key | Current runtime defaults to org mode unless `LC_AUTH_MODE=user_api_key` is set; remove stale `LC_AUTH_MODE` if needed. |

If a user API key produces large JWT issues, pass explicit `oid` values to
org-scoped tools. This causes the server to request org-scoped JWTs instead of
using a broad multi-org token.
