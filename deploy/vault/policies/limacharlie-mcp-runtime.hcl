# Runtime policy for limacharlie-mcp.
#
# Assumptions:
# - Vault KV v2 is mounted at "secret".
# - The LimaCharlie API key is stored at secret/data/limacharlie/mcp.
# - The optional LimaCharlie user API key is stored at secret/data/limacharlie/mcp-user.
# - The key field name is "api_key".
#
# If you use a different mount or path, update both this policy and api_key_ref
# or user_api_key_ref in the LimaCharlie MCP config file.

path "secret/data/limacharlie/mcp" {
  capabilities = ["read"]
}

path "secret/metadata/limacharlie/mcp" {
  capabilities = ["read"]
}

path "secret/data/limacharlie/mcp-user" {
  capabilities = ["read"]
}

path "secret/metadata/limacharlie/mcp-user" {
  capabilities = ["read"]
}
