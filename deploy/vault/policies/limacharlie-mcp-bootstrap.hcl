# Bootstrap policy for limacharlie-mcp-vault-bootstrap.
#
# Use this policy only for initial setup or API-key rotation. The MCP runtime
# should use the narrower limacharlie-mcp-runtime policy.

path "secret/data/limacharlie/mcp" {
  capabilities = ["create", "update", "read"]
}

path "secret/metadata/limacharlie/mcp" {
  capabilities = ["read", "list"]
}
