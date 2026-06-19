# Onboarding And Auth

This MCP should make LimaCharlie authentication feel like a normal local
credential setup. Users should not manually create, paste, rotate, or re-paste
JWTs.

## Recommended Setup

Use an Organization API key for the org you want the MCP to access.

1. In LimaCharlie, open the organization.
2. Go to Access Management -> REST API.
3. Create an API key with the minimum permissions needed for the workflows.
4. Put the key in the MCP client's environment as `LC_API_KEY`.
5. Start the MCP server.
6. Call `lc_auth_status`.
7. Call `lc_list_orgs` or an org-scoped read such as `lc_list_sensors`.

Example stdio config:

```json
{
  "mcpServers": {
    "limacharlie-local": {
      "command": "/path/to/limacharlie-mcp/.venv/bin/limacharlie-mcp",
      "env": {
        "LC_API_KEY": "your-organization-api-key"
      }
    }
  }
}
```

## What Happens Internally

LimaCharlie REST authentication uses short-lived JWTs. This MCP hides that from
the user:

- `LC_API_KEY` is the stable credential.
- The server exchanges that API key for a LimaCharlie JWT.
- JWTs are cached in memory only.
- JWT values are never returned by tools.
- JWT values are not written to the audit log.
- The server refreshes expired or near-expired JWTs automatically.

## Reauth

Most users should not need to do anything. If the API key is valid, a later
tool call refreshes the JWT automatically.

Use `lc_auth_refresh` when:

- a user just rotated the API key in their MCP client configuration,
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
LC_UID=your-user-id
LC_API_KEY=your-user-api-key
```

User API key mode can list orgs and then mint org-scoped JWTs for individual
org operations. It is more powerful than an organization API key because it
inherits the user's permissions across organizations. Prefer organization API
keys for routine local MCP use unless multi-org access is required.

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
receive `LC_API_KEY`. Put it in the MCP client config `env` block rather than
only in an interactive shell.

If org-scoped tools fail with `error.class: auth` or `error.class: policy`,
call `lc_auth_whoami` with the target `oid` and optional `check_perm`.

If a user API key produces large JWT issues, pass explicit `oid` values to
org-scoped tools. This causes the server to request org-scoped JWTs instead of
using a broad multi-org token.
