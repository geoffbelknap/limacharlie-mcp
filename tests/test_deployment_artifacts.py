from __future__ import annotations

import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_no_docker_deployment_artifacts() -> None:
    ignored = {".git", ".venv", "__pycache__", ".pytest_cache"}
    dockerish: list[Path] = []
    for path in ROOT.rglob("*"):
        if any(part in ignored for part in path.parts):
            continue
        lowered = path.name.lower()
        if lowered == "dockerfile" or lowered.startswith("docker-compose") or lowered in {"compose.yml", "compose.yaml"}:
            dockerish.append(path.relative_to(ROOT))

    assert dockerish == []


def test_mcp_client_templates_use_vault_refs_without_raw_api_keys() -> None:
    templates = sorted((ROOT / "deploy" / "mcp-client").glob("*.json"))
    assert templates

    for template in templates:
        config = json.loads(template.read_text(encoding="utf-8"))
        servers = config["mcpServers"]
        for server in servers.values():
            env = server["env"]
            assert env["LC_SECRET_PROVIDER"] == "vault"
            assert "LC_API_KEY" not in env
            assert env["LC_API_KEY_REF"].startswith("vault://")
            assert "LC_VAULT_TOKEN" not in env
            assert "LC_VAULT_TOKEN_FILE" in env


def test_vault_policies_split_bootstrap_and_runtime_access() -> None:
    policy_dir = ROOT / "deploy" / "vault" / "policies"
    runtime = (policy_dir / "limacharlie-mcp-runtime.hcl").read_text(encoding="utf-8")
    bootstrap = (policy_dir / "limacharlie-mcp-bootstrap.hcl").read_text(encoding="utf-8")

    assert 'capabilities = ["read"]' in runtime
    assert '"update"' not in runtime
    assert '"create"' not in runtime
    assert '"create", "update", "read"' in bootstrap
