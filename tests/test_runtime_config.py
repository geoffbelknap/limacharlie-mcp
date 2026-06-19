from __future__ import annotations

import json
from pathlib import Path

import pytest

from limacharlie_mcp.api import LimaCharlieAPI
from limacharlie_mcp.auth_doctor import run_doctor
from limacharlie_mcp.configure import run_configure
from limacharlie_mcp.runtime_config import load_runtime_config


OID = "263c19e9-bd4a-475a-8cd3-5403af446cb9"


def clear_lc_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in (
        "LC_API_KEY",
        "LC_USER_API_KEY",
        "LC_UID",
        "LC_ORG_ID",
        "LC_OID",
        "LC_AUTH_MODE",
        "LC_SECRET_PROVIDER",
        "LC_CREDENTIAL_PROVIDER",
        "LC_API_KEY_REF",
        "LC_API_KEY_SECRET_REF",
        "LC_USER_API_KEY_REF",
        "LC_USER_API_KEY_SECRET_REF",
        "LC_VAULT_ADDR",
        "VAULT_ADDR",
        "LC_VAULT_TOKEN",
        "VAULT_TOKEN",
        "LC_VAULT_TOKEN_FILE",
        "VAULT_TOKEN_FILE",
        "LC_MCP_CONFIG",
        "LC_MCP_AUDIT_LOG",
    ):
        monkeypatch.delenv(key, raising=False)


def write_config(path: Path, token_file: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "credential_provider": "vault",
                "auth_mode": "org_api_key",
                "oid": OID,
                "vault_addr": "http://vault.local",
                "vault_token_file": str(token_file),
                "api_key_ref": "vault://secret/data/limacharlie/mcp#api_key",
            }
        ),
        encoding="utf-8",
    )


def test_runtime_config_rejects_secret_fields(tmp_path: Path) -> None:
    config = tmp_path / "config.json"
    config.write_text(json.dumps({"api_key": "lc-secret"}), encoding="utf-8")

    with pytest.raises(ValueError, match="must not contain secret values"):
        load_runtime_config(config)


def test_api_uses_config_file_and_env_overrides(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    clear_lc_env(monkeypatch)
    token_file = tmp_path / "vault-token"
    token_file.write_text("vault-token", encoding="utf-8")
    config = tmp_path / "config.json"
    write_config(config, token_file)

    client = LimaCharlieAPI(config_path=config, audit_path=tmp_path / "audit.jsonl")
    assert client.default_oid == OID
    assert client.credential_provider == "vault"
    assert client.vault_addr == "http://vault.local"
    assert client.api_key_ref == "vault://secret/data/limacharlie/mcp#api_key"

    monkeypatch.setenv("LC_ORG_ID", "00000000-0000-4000-8000-000000000000")
    overridden = LimaCharlieAPI(config_path=config, audit_path=tmp_path / "audit.jsonl")
    assert overridden.default_oid == "00000000-0000-4000-8000-000000000000"


def test_auth_doctor_reports_config_file_shape(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    clear_lc_env(monkeypatch)
    token_file = tmp_path / "vault-token"
    token_file.write_text("vault-token", encoding="utf-8")
    config = tmp_path / "config.json"
    write_config(config, token_file)

    result = run_doctor(config_file=config, live=False)

    assert result["ok"] is True
    assert result["config"]["credential_provider"] == "vault"
    assert result["config"]["oid_present"] is True
    assert result["config"]["org_api_key_ref_present"] is True
    assert result["config"]["vault_token_file_present"] is True


def test_configure_writes_nonsecret_config_for_existing_vault_ref(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clear_lc_env(monkeypatch)
    token_file = tmp_path / "vault-token"
    token_file.write_text("vault-token", encoding="utf-8")
    config = tmp_path / "config.json"

    result = run_configure(
        [
            "--config",
            str(config),
            "--oid",
            OID,
            "--vault-addr",
            "http://vault.local",
            "--token-file",
            str(token_file),
            "--api-key-ref",
            "vault://secret/data/limacharlie/mcp#api_key",
            "--skip-vault-write",
            "--skip-doctor",
            "--yes",
        ]
    )

    saved = json.loads(config.read_text(encoding="utf-8"))
    assert result["ok"] is True
    assert saved == {
        "api_key_ref": "vault://secret/data/limacharlie/mcp#api_key",
        "auth_mode": "org_api_key",
        "credential_provider": "vault",
        "oid": OID,
        "vault_addr": "http://vault.local",
        "vault_token_file": str(token_file),
    }
    assert "api_key" not in saved
    assert "vault_token" not in saved
