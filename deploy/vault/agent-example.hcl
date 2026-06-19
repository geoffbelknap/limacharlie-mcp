# Example Vault Agent config for limacharlie-mcp.
#
# This example uses AppRole auto-auth and writes a renewable Vault token to a
# local file. Point LC_VAULT_TOKEN_FILE at the sink path in the MCP client
# config. Replace all example paths and role details before use.

pid_file = "/var/run/limacharlie-mcp/vault-agent.pid"

vault {
  address = "https://vault.example.com"
}

auto_auth {
  method "approle" {
    mount_path = "auth/approle"

    config = {
      role_id_file_path                   = "/etc/limacharlie-mcp/vault-role-id"
      secret_id_file_path                 = "/etc/limacharlie-mcp/vault-secret-id"
      remove_secret_id_file_after_reading = false
    }
  }

  sink "file" {
    config = {
      path = "/run/secrets/limacharlie-mcp-vault-token"
      mode = 0600
    }
  }
}

cache {
  use_auto_auth_token = true
}
