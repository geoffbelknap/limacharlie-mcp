# Onboarding And Auth

This MCP should make LimaCharlie authentication feel like a normal local
credential setup. Users should not manually create, paste, rotate, or re-paste
JWTs.

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
  --token-file "/run/secrets/vault-token"
```

For unattended setup, pipe the key from an approved secret manager:

```bash
approved-secret-manager read limacharlie/mcp/api-key \
  | limacharlie-mcp-vault-bootstrap \
      --vault-addr "https://vault.example.com" \
      --token-file "/run/secrets/vault-token" \
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
        "LC_VAULT_TOKEN_FILE": "/run/secrets/vault-token",
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

User API keys are supported by setting both:

```bash
LC_SECRET_PROVIDER=vault
LC_UID=your-user-id
LC_API_KEY_REF=vault://secret/data/limacharlie/mcp-user#api_key
```

User API key mode can list orgs and then mint org-scoped JWTs for individual
org operations. It is more powerful than an organization API key because it
inherits the user's permissions across organizations. Prefer organization API
keys for routine local MCP use unless multi-org access is required.

For local development only, user API key mode can also use
`LC_SECRET_PROVIDER=env` with `LC_API_KEY`.

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

For read-only investigation, start with:

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

For administration inventory, add only the needed read/list permissions for
API keys, installation keys, outputs, extensions, and org config.

Do not grant write permissions such as `sensor.task`, `sensor.tag`, `dr.set`,
`dr.del`, `output.set`, or key-management permissions until the matching MCP
mutation tool has a preview/confirm implementation.

## Troubleshooting

If `lc_auth_status` returns `missing_credentials`, the MCP process did not
receive a complete Vault configuration. Check `LC_VAULT_ADDR`,
`LC_VAULT_TOKEN_FILE`, and `LC_API_KEY_REF` in the MCP client config `env`
block. For local development fallback, check `LC_SECRET_PROVIDER=env` and
`LC_API_KEY`.

If org-scoped tools fail with `error.class: auth` or `error.class: policy`,
call `lc_auth_whoami` with the target `oid` and optional `check_perm`.

If a user API key produces large JWT issues, pass explicit `oid` values to
org-scoped tools. This causes the server to request org-scoped JWTs instead of
using a broad multi-org token.
