# Deployment

This project deploys as a local stdio MCP server. It intentionally does not
ship Docker artifacts. Install it as a Python package, run it from an MCP
client, and use Vault as the default credential provider.

## Model

- The MCP process runs `limacharlie-mcp` from a Python virtual environment.
- Vault stores the stable LimaCharlie API key.
- Vault Agent, platform secret mounting, or `vault login` provides a local
  Vault token file.
- The MCP client passes nonsecret environment values to the process.
- The MCP exchanges the LimaCharlie API key for short-lived JWTs in memory.

Do not put production LimaCharlie API keys in `.env` files or MCP client
configuration.

## Install

Choose an install path owned by the operator or service account that will run
the MCP process.

```bash
python -m venv /opt/limacharlie-mcp/.venv
/opt/limacharlie-mcp/.venv/bin/pip install /path/to/limacharlie-mcp
```

For local development from the repo checkout:

```bash
python -m venv .venv
. .venv/bin/activate
pip install -e ".[dev]"
```

## Vault Policies

The repo includes example Vault KV v2 policies:

- `deploy/vault/policies/limacharlie-mcp-bootstrap.hcl`
- `deploy/vault/policies/limacharlie-mcp-runtime.hcl`

Use the bootstrap policy only for initial setup or API-key rotation. Use the
runtime policy for the MCP process.

```bash
vault policy write limacharlie-mcp-bootstrap deploy/vault/policies/limacharlie-mcp-bootstrap.hcl
vault policy write limacharlie-mcp-runtime deploy/vault/policies/limacharlie-mcp-runtime.hcl
```

If your KV mount or secret path differs from `secret/data/limacharlie/mcp`,
update the policies and `LC_API_KEY_REF` together.

For user API key mode, store the key at a separate path and use
`LC_USER_API_KEY_REF` instead of `LC_API_KEY_REF`.

## Vault Agent Token File

The MCP runtime should usually read a Vault token from a file:

```bash
LC_VAULT_TOKEN_FILE=/run/secrets/limacharlie-mcp-vault-token
```

`deploy/vault/agent-example.hcl` shows a Vault Agent AppRole setup that writes
that token file. It is an example only; adapt the auth method and paths to your
environment.

The token file should be readable only by the account running the MCP server.

## Bootstrap Or Rotate The LimaCharlie Key

Run the bootstrap helper with a token that has the bootstrap policy:

```bash
limacharlie-mcp-vault-bootstrap \
  --vault-addr "https://vault.example.com" \
  --token-file "/run/secrets/limacharlie-mcp-bootstrap-token" \
  --runtime-token-file "/run/secrets/limacharlie-mcp-vault-token"
```

The helper prompts for the LimaCharlie API key without echoing it, writes it to
Vault, and prints a nonsecret MCP env block. The bootstrap token should have
write access only for setup or rotation; the runtime token file printed in the
env block should use the narrower runtime policy.

For user-scoped API key mode, keep the secret separate from the org key:

```bash
limacharlie-mcp-vault-bootstrap \
  --vault-addr "https://vault.example.com" \
  --token-file "/run/secrets/limacharlie-mcp-bootstrap-token" \
  --runtime-token-file "/run/secrets/limacharlie-mcp-vault-token" \
  --path "limacharlie/mcp-user" \
  --user-api-key
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

After rotation, call `lc_auth_refresh` or let the next LimaCharlie API request
refresh the in-memory JWT automatically.

## MCP Client Config

Start from one of these templates:

- `deploy/mcp-client/stdio-vault.json`
- `deploy/mcp-client/stdio-vault-user-key.json`

Production config should contain only nonsecret values:

```json
{
  "mcpServers": {
    "limacharlie-local": {
      "command": "/opt/limacharlie-mcp/.venv/bin/limacharlie-mcp",
      "env": {
        "LC_SECRET_PROVIDER": "vault",
        "LC_VAULT_ADDR": "https://vault.example.com",
        "LC_VAULT_TOKEN_FILE": "/run/secrets/limacharlie-mcp-vault-token",
        "LC_API_KEY_REF": "vault://secret/data/limacharlie/mcp#api_key",
        "LC_MCP_AUDIT_LOG": "/var/log/limacharlie-mcp/audit.jsonl"
      }
    }
  }
}
```

Make sure the audit-log directory is writable by the MCP process.

## Smoke Test

After configuring the MCP client, run these tools:

1. `lc_auth_status`
2. `lc_auth_refresh`
3. `lc_list_orgs`
4. One org-scoped read, such as `lc_get_org_info` or `lc_list_sensors`

Expected behavior:

- `lc_auth_status` reports `credential_provider: vault`.
- No tool returns a Vault token, LimaCharlie API key, or JWT.
- The audit log is written locally without authorization headers.

## No Docker

Do not add Dockerfiles, Compose files, or container deployment instructions to
this repo. If isolated local execution is needed during development, run it in
the workspace's preferred lightweight runtime outside this user-facing
deployment path.
