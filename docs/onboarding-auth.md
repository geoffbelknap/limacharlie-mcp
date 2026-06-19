# Onboarding And Auth

This MCP should make LimaCharlie authentication feel like a normal local
credential setup. Users should not manually create, paste, rotate, or re-paste
JWTs.

The default setup uses a managed local Vault. That is a good thing for users:
it protects the stable LimaCharlie API key on the local machine, keeps it out
of chat history, `.env` files, MCP client configuration, and audit logs, and
lets the MCP use short-lived LimaCharlie JWTs for API calls.

## Choose The Right Auth Mode

Most deployments should use organization API key mode. User API key mode exists
for multi-org workflows, but it is easier to misconfigure.

| Need | Key source | Required values | Notes |
| --- | --- | --- | --- |
| Work in one LimaCharlie org | Org page -> Access Management -> REST API | Organization ID and organization API key | Recommended default. The org REST API page may say "User-Generated API Keys"; those are still org-scoped keys. |
| Discover/list orgs across the user's account | Account Settings -> API Keys | User ID and user API key | Use only when multi-org access is needed. Keep separate from the org key. |

Do not overwrite a working organization API key with a user API key. Keep both
values separate. When in doubt, use the organization API key.

## Where To Find Each Value

Use these LimaCharlie locations before running setup:

| Value | Where to find it | What to copy |
| --- | --- | --- |
| Organization ID, or `oid` | Open the organization in LimaCharlie. The browser URL looks like `https://app.limacharlie.io/orgs/<oid>/...`. You can also go to Organization Settings -> Access Management -> REST API and use the `OID` line. | Copy the UUID-shaped org ID, for example `263c19e9-bd4a-475a-8cd3-5403af446cb9`. |
| Organization API key | In the target org, go to Organization Settings -> Access Management -> REST API. Under User-Generated API Keys, click Create API Key. | Copy the secret value shown at creation time. It is shown once. This is the recommended key for normal MCP use. |
| User API key | Click your account/avatar, open Account Settings, then API Keys. Use Create User API Key. | Copy the secret value shown at creation time. Use this only for multi-org discovery. |
| User ID, or `uid` | On Account Settings -> API Keys, use the copy control associated with the text that describes your User ID. | Copy the JWT-accepted user id. It may not be the email address and may not be the UUID-shaped account id. |

Screenshot checklist for user-facing docs:

- `lc-org-rest-api.png`: Organization Settings -> Access Management -> REST API, showing the API Root, `OID`, and Create API Key area.
- `lc-account-api-keys.png`: Account Settings -> API Keys, showing the User API Keys page and the user-id copy control.

Do not include screenshots that show real API keys, JWTs, or personal account
details.

## Recommended Setup

Use an Organization API key for the org you want the MCP to access. The setup
stores the key in managed local Vault and keeps JWT refresh hidden from the
user. Raw environment API keys are a local-development fallback, not the
recommended runtime model.

1. In LimaCharlie, open the organization.
2. Go to Access Management -> REST API.
3. Create an API key with the minimum permissions needed for the workflows.
4. Run `limacharlie-mcp-configure` with the org ID. The helper reads the
   LimaCharlie key through a hidden prompt and stores it in local Vault.
5. Start a new Codex or Claude chat with the LimaCharlie MCP plugin enabled.
6. Ask the agent to check LimaCharlie MCP auth status. It should confirm that
   credentials are configured without showing secrets.
7. Ask the agent to review your LimaCharlie org posture. For a smaller smoke
   test, ask it to list LimaCharlie sensors.

```bash
limacharlie-mcp-configure \
  --oid "263c19e9-bd4a-475a-8cd3-5403af446cb9"
```

Expected success output is a short checklist: the key was stored in managed
local Vault, local MCP config was written, JWT refresh was verified, and org
access was verified. If the output says live verification failed, the key was
stored locally but LimaCharlie rejected it or the live check could not complete.
Do not start review or response workflows until JWT refresh verifies
successfully. Use `--json` only when a script needs the full structured
configuration result.

For unattended setup, provide all values and pipe the key from an approved
secret manager:

```bash
approved-secret-manager read limacharlie/mcp/api-key \
  | limacharlie-mcp-configure \
      --oid "263c19e9-bd4a-475a-8cd3-5403af446cb9" \
      --yes \
      --api-key-stdin
```

Example stdio config with the default config path:

```json
{
  "mcpServers": {
    "limacharlie-local": {
      "command": "/path/to/limacharlie-mcp/.venv/bin/limacharlie-mcp-review"
    }
  }
}
```

If the config file is not in the default location, pass only `LC_MCP_CONFIG`:

```json
{
  "mcpServers": {
    "limacharlie-local": {
      "command": "/path/to/limacharlie-mcp/.venv/bin/limacharlie-mcp-review",
      "env": {
        "LC_MCP_CONFIG": "/path/to/limacharlie-mcp-config.json"
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

See [Deployment](deployment.md) for advanced operator deployment and MCP client
config templates.

## Preflight With Auth Doctor

Use `limacharlie-mcp-auth-doctor` before adding the MCP to an agent client. It
prints configuration shape, selected auth mode, bounded live-check status, and
secret leak checks without printing API keys, UID values, credential-store
tokens, or JWTs.

For local development:

```bash
limacharlie-mcp-auth-doctor --env-file /path/to/local-env
```

For user-key mode with both org and user keys present:

```bash
limacharlie-mcp-auth-doctor --env-file /path/to/local-env --mode user_api_key
```

For the normal configured runtime, run:

```bash
limacharlie-mcp-auth-doctor
```

If the config file is not in the default location:

```bash
limacharlie-mcp-auth-doctor --config /path/to/limacharlie-mcp-config.json
```

If you only want to inspect which variables are present, without calling
LimaCharlie:

```bash
limacharlie-mcp-auth-doctor --no-live
```

## How Auth Behaves

LimaCharlie REST authentication uses short-lived JWTs. This MCP handles that
refresh work for the user:

- `limacharlie-mcp-configure` asks for the LimaCharlie API key through a hidden
  prompt and stores it in managed local Vault.
- MCP tools never return API keys or JWTs.
- API keys and JWTs are not written to the audit log.
- Expired or near-expired JWTs refresh automatically during later tool calls.

## Reauth

Most users should not need to do anything. If the API key is valid, a later
tool call refreshes the JWT automatically.

Use `lc_auth_refresh` when:

- a user just rotated the API key,
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

The `uid` value must be the user id accepted by `https://jwt.limacharlie.io`.
On the account API key page, use the copy control associated with the text that
describes "your User ID"; do not use the email copy control or the API key row
name. If LimaCharlie shows more than one user-shaped identifier, validate the
pair by attempting a JWT exchange before wiring it into the MCP. In practice
the JWT-accepted UID may look like a Firebase-style non-UUID string rather than
the UUID-shaped account id shown in some UI places.

Bootstrap a user API key with:

```bash
limacharlie-mcp-configure \
  --user-api-key \
  --uid "your-user-id" \
  --oid "263c19e9-bd4a-475a-8cd3-5403af446cb9"
```

This stores the user API key separately from the organization API key.

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

## Permission Profiles

For the smallest onboarding smoke test, an organization API key only needs:

- `org.get`
- `sensor.list`
- `sensor.get`

That is enough for `limacharlie-mcp-auth-doctor`, `lc_auth_whoami`,
`lc_get_org_info`, and `lc_list_sensors` to prove the MCP can authenticate and
reach the target org.

For first run plus read-only posture review, use a dedicated organization API
key with:

- `org.get`
- `sensor.list`
- `sensor.get`
- `insight.list`
- `insight.evt.get`
- `insight.det.get`
- `insight.stat`
- `audit.get`
- `output.list`
- `dr.list`
- `dr.list.managed`
- `fp.ctrl`
- `yara.get`
- `lookup.get`
- `ikey.list`
- `ingestkey.ctrl`
- `user.ctrl`
- `apikey.ctrl`
- `job.get`
- `replicant.get`
- `replicant.task`

`replicant.task` is needed for complete service-backed content review, such as
listing rules managed through LimaCharlie services. The permission name is
broader than the read path sounds, so grant it only to a dedicated MCP key.

Some LimaCharlie read/list endpoints are guarded by broader permission names.
For example, user inventory may require `user.ctrl`, API key inventory may
require `apikey.ctrl`, AI session and usage inventory may require
`ai_agent.get`, and Hive-backed secret or lookup inventory may require
`secret.get.mtd` or `lookup.get.mtd`. Treat those as elevated permissions:
grant them only to a dedicated MCP key when the matching tool family is needed.

For broader investigation beyond posture review, add only the permissions for
the data families you expect the MCP to inspect.

For administration inventory, add only the needed read/list permissions for API
keys, installation keys, outputs, extensions, and org config. Validate each
added permission with `lc_auth_whoami` and the specific read tool before adding
more.

Do not grant write permissions such as `sensor.task`, `sensor.tag`, `dr.set`,
`dr.del`, `output.set`, or key-management permissions until the matching MCP
mutation tool has a preview/confirm implementation.

## Troubleshooting

If `lc_auth_status` returns `missing_credentials`, the MCP process did not
receive complete credential configuration. Rerun `limacharlie-mcp-configure`
with the correct org ID, then start a new MCP client session. If the config
file is not in the default location, make sure the MCP client sets
`LC_MCP_CONFIG` to the correct path. For local development fallback, check
`LC_SECRET_PROVIDER=env` with `LC_API_KEY` for org mode or `LC_USER_API_KEY`
for user mode.

If org-scoped tools fail with `error.class: auth` or `error.class: policy`,
call `lc_auth_whoami` with the target `oid` and optional `check_perm`.

Common auth mistakes:

| Symptom | Likely cause | Fix |
| --- | --- | --- |
| `lc_list_orgs` fails in org-key mode | Organization API keys cannot do unscoped account org discovery | Use org-scoped tools with explicit `oid`, or switch to user API key mode. |
| JWT exchange returns `unknown api key` in org mode | The pasted key is wrong, expired/deleted, or not the org API key secret for this organization | Create a fresh key under Organization Settings -> Access Management -> REST API for the target org, rerun configure, and paste the new secret shown once. |
| JWT exchange returns `unknown api key` in user mode | `LC_USER_API_KEY` is missing, wrong, or actually an org API key | Create a fresh user API key under Account Settings -> API Keys and copy the secret shown once. |
| JWT exchange returns `user not found` in user mode | `LC_UID` is not the JWT-accepted user id | Re-copy the user id from the account user API key guidance, or validate with the direct JWT exchange before using the MCP. |
| `LC_UID` is set and org tools unexpectedly fail | Older configs may accidentally pair `LC_UID` with an org key | Current runtime defaults to org mode unless `LC_AUTH_MODE=user_api_key` is set; remove stale `LC_AUTH_MODE` if needed. |

If a user API key produces large JWT issues, pass explicit `oid` values to
org-scoped tools. This causes the server to request org-scoped JWTs instead of
using a broad multi-org token.
