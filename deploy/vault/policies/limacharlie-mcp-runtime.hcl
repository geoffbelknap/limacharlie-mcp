# Runtime policy for limacharlie-mcp.
#
# Assumptions:
# - Vault KV v2 is mounted at "secret".
# - The LimaCharlie API key is stored at secret/data/limacharlie/mcp.
# - The key field name is "api_key".
#
# If you use a different mount or path, update both this policy and
# LC_API_KEY_REF in the MCP client config.

path "secret/data/limacharlie/mcp" {
  capabilities = ["read"]
}

path "secret/metadata/limacharlie/mcp" {
  capabilities = ["read"]
}
