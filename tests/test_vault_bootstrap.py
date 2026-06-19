from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from limacharlie_mcp import vault_bootstrap


class FakeKVVersion:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def create_or_update_secret(self, *, mount_point: str, path: str, secret: dict[str, str]) -> None:
        self.calls.append({"mount_point": mount_point, "path": path, "secret": secret})


class FakeKV:
    def __init__(self) -> None:
        self.v1 = FakeKVVersion()
        self.v2 = FakeKVVersion()


class FakeSecrets:
    def __init__(self) -> None:
        self.kv = FakeKV()


class FakeVaultClient:
    instances: list["FakeVaultClient"] = []
    authenticated = True

    def __init__(self, *, url: str, token: str, namespace: str | None = None) -> None:
        self.url = url
        self.token = token
        self.namespace = namespace
        self.secrets = FakeSecrets()
        self.instances.append(self)

    def is_authenticated(self) -> bool:
        return self.authenticated


def test_vault_bootstrap_writes_lc_key_without_returning_it(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    FakeVaultClient.instances = []
    monkeypatch.setattr(vault_bootstrap.hvac, "Client", FakeVaultClient)
    token_file = tmp_path / "token-file"
    token_file.write_text("vault-token-secret", encoding="utf-8")
    config = vault_bootstrap.VaultBootstrapConfig(
        vault_addr="http://vault.local",
        token_file=token_file,
        namespace="team-a",
        mount="secret",
        path="limacharlie/mcp",
        field="api_key",
        kv_version=2,
    )

    result = vault_bootstrap.write_limacharlie_key(config, "lc-api-key")
    payload = vault_bootstrap.result_payload(result)
    serialized = json.dumps(payload)

    assert result.api_key_ref == "vault://secret/data/limacharlie/mcp#api_key"
    assert result.env == {
        "LC_SECRET_PROVIDER": "vault",
        "LC_VAULT_ADDR": "http://vault.local",
        "LC_VAULT_TOKEN_FILE": str(token_file),
        "LC_API_KEY_REF": "vault://secret/data/limacharlie/mcp#api_key",
        "LC_VAULT_NAMESPACE": "team-a",
    }
    client = FakeVaultClient.instances[0]
    assert client.url == "http://vault.local"
    assert client.token == "vault-token-secret"
    assert client.namespace == "team-a"
    assert client.secrets.kv.v2.calls == [
        {"mount_point": "secret", "path": "limacharlie/mcp", "secret": {"api_key": "lc-api-key"}}
    ]
    assert "lc-api-key" not in serialized
    assert "vault-token-secret" not in serialized


def test_vault_bootstrap_supports_kv1_refs(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    FakeVaultClient.instances = []
    monkeypatch.setattr(vault_bootstrap.hvac, "Client", FakeVaultClient)
    token_file = tmp_path / "vault-token"
    token_file.write_text("vault-token", encoding="utf-8")
    config = vault_bootstrap.VaultBootstrapConfig(
        vault_addr="http://vault.local",
        token_file=token_file,
        namespace=None,
        mount="kv",
        path="limacharlie/mcp",
        field="api_key",
        kv_version=1,
    )

    result = vault_bootstrap.write_limacharlie_key(config, "lc-api-key")

    assert result.api_key_ref == "vault://kv/limacharlie/mcp#api_key"
    assert "LC_VAULT_NAMESPACE" not in result.env
    client = FakeVaultClient.instances[0]
    assert client.secrets.kv.v1.calls == [
        {"mount_point": "kv", "path": "limacharlie/mcp", "secret": {"api_key": "lc-api-key"}}
    ]


def test_vault_bootstrap_rejects_missing_token_file(tmp_path: Path) -> None:
    config = vault_bootstrap.VaultBootstrapConfig(
        vault_addr="http://vault.local",
        token_file=tmp_path / "missing-token",
        namespace=None,
        mount="secret",
        path="limacharlie/mcp",
        field="api_key",
        kv_version=2,
    )

    with pytest.raises(ValueError, match="not readable"):
        vault_bootstrap.write_limacharlie_key(config, "lc-api-key")
