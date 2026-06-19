from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import pytest

from limacharlie_mcp.api import LimaCharlieAPI
from limacharlie_mcp.auth_doctor import run_doctor
from limacharlie_mcp import api as api_module
from limacharlie_mcp.configure import run_configure
from limacharlie_mcp import configure as configure_module
from limacharlie_mcp.runtime_config import load_runtime_config
from limacharlie_mcp.vault_bootstrap import VaultBootstrapResult


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


def test_configure_defaults_to_managed_local_vault(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clear_lc_env(monkeypatch)
    config = tmp_path / "config.json"
    root_token_file = tmp_path / "vault" / "root-token"
    runtime_token_file = tmp_path / "vault" / "runtime-token"
    root_token_file.parent.mkdir()
    root_token_file.write_text("root-token", encoding="utf-8")
    runtime_token_file.write_text("runtime-token", encoding="utf-8")

    monkeypatch.setattr(
        configure_module,
        "ensure_managed_vault",
        lambda mapping=None: SimpleNamespace(
            addr="http://127.0.0.1:8220",
            root_token_file=root_token_file,
            runtime_token_file=runtime_token_file,
            started=True,
            initialized=True,
            sealed=False,
        ),
    )

    result = run_configure(
        [
            "--config",
            str(config),
            "--oid",
            OID,
            "--api-key-ref",
            "vault://secret/data/limacharlie/mcp#api_key",
            "--skip-vault-write",
            "--skip-doctor",
            "--yes",
        ]
    )

    saved = json.loads(config.read_text(encoding="utf-8"))
    assert result["ok"] is True
    assert result["managed_vault"] is True
    assert saved["managed_vault"] == {
        "enabled": True,
        "addr": "http://127.0.0.1:8220",
        "state_dir": str(Path.home() / ".local" / "share" / "limacharlie-mcp" / "vault"),
    }
    assert saved["vault_addr"] == "http://127.0.0.1:8220"
    assert saved["vault_token_file"] == str(runtime_token_file)
    assert saved["api_key_ref"] == "vault://secret/data/limacharlie/mcp#api_key"


def test_configure_managed_vault_writes_lc_key_with_root_token(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clear_lc_env(monkeypatch)
    config = tmp_path / "config.json"
    root_token_file = tmp_path / "vault" / "root-token"
    runtime_token_file = tmp_path / "vault" / "runtime-token"
    root_token_file.parent.mkdir()
    root_token_file.write_text("root-token", encoding="utf-8")
    runtime_token_file.write_text("runtime-token", encoding="utf-8")
    captured = {}

    monkeypatch.setattr(
        configure_module,
        "ensure_managed_vault",
        lambda mapping=None: SimpleNamespace(
            addr="http://127.0.0.1:8220",
            root_token_file=root_token_file,
            runtime_token_file=runtime_token_file,
            started=True,
            initialized=True,
            sealed=False,
        ),
    )
    monkeypatch.setattr(configure_module, "read_api_key", lambda *, api_key_stdin: "lc-secret")

    def fake_write(config, api_key):
        captured["token_file"] = config.token_file
        captured["runtime_token_file"] = config.runtime_token_file
        captured["api_key"] = api_key
        return VaultBootstrapResult(
            api_key_ref="vault://secret/data/limacharlie/mcp#api_key",
            env={},
        )

    monkeypatch.setattr(configure_module, "write_limacharlie_key", fake_write)

    result = run_configure(
        [
            "--config",
            str(config),
            "--oid",
            OID,
            "--skip-doctor",
            "--yes",
        ]
    )

    saved = json.loads(config.read_text(encoding="utf-8"))
    assert result["ok"] is True
    assert captured == {
        "token_file": root_token_file,
        "runtime_token_file": runtime_token_file,
        "api_key": "lc-secret",
    }
    assert saved["vault_token_file"] == str(runtime_token_file)
    assert "lc-secret" not in json.dumps(saved)


def test_api_auto_starts_managed_vault_from_config(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    clear_lc_env(monkeypatch)
    runtime_token_file = tmp_path / "runtime-token"
    runtime_token_file.write_text("runtime-token", encoding="utf-8")
    config = tmp_path / "config.json"
    config.write_text(
        json.dumps(
            {
                "credential_provider": "vault",
                "auth_mode": "org_api_key",
                "oid": OID,
                "api_key_ref": "vault://secret/data/limacharlie/mcp#api_key",
                "managed_vault": {"enabled": True, "addr": "http://127.0.0.1:8220"},
            }
        ),
        encoding="utf-8",
    )

    calls = []
    monkeypatch.setattr(
        api_module,
        "ensure_managed_vault",
        lambda mapping=None: calls.append(mapping)
        or SimpleNamespace(
            addr="http://127.0.0.1:8220",
            root_token_file=tmp_path / "root-token",
            runtime_token_file=runtime_token_file,
            started=False,
            initialized=True,
            sealed=False,
        ),
    )

    client = LimaCharlieAPI(config_path=config, audit_path=tmp_path / "audit.jsonl")

    assert calls == [{"enabled": True, "addr": "http://127.0.0.1:8220"}]
    assert client.vault_addr == "http://127.0.0.1:8220"
    assert client.vault_token_file == str(runtime_token_file)
