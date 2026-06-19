from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from limacharlie_mcp.api import LimaCharlieAPI
from limacharlie_mcp.auth_doctor import run_doctor
from limacharlie_mcp import api as api_module
from limacharlie_mcp.configure import run_configure
from limacharlie_mcp import configure as configure_module
from limacharlie_mcp.configure import ProvisionedRuntimeKey
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


def test_configure_cli_prints_human_success_by_default(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
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
    monkeypatch.setattr(
        configure_module,
        "run_doctor",
        lambda *, config_file, live: {
            "ok": True,
            "config": {"oid_present": True},
            "checks": [
                {"step": "auth_status", "ok": True},
                {"step": "auth_refresh_org_scoped", "ok": True},
                {"step": "get_org_info", "ok": True},
            ],
            "leak_checks": {},
        },
    )

    configure_module.main(
        [
            "--config",
            str(config),
            "--oid",
            OID,
            "--api-key-ref",
            "vault://secret/data/limacharlie/mcp#api_key",
            "--skip-vault-write",
            "--yes",
        ]
    )

    output = capsys.readouterr().out
    assert output.startswith("Configured and verified LimaCharlie MCP auth.")
    assert "[OK] Stored the LimaCharlie organization API key in managed local Vault" in output
    assert "[OK] Wrote local MCP config" in output
    assert "[OK] Verified JWT refresh" in output
    assert f"[OK] Verified access to org {OID}" in output
    assert 'Ask: "Check my LimaCharlie MCP auth status."' in output
    assert "The agent should confirm credentials are configured without showing secrets." in output
    assert 'Ask: "Review my LimaCharlie org posture."' in output
    assert 'For a smaller smoke test, ask: "List my LimaCharlie sensors."' in output
    assert "Run lc_auth_status" not in output
    assert "api_key_ref" not in output
    assert "vault_token_file" not in output
    assert "secret/data" not in output


def test_configure_cli_warns_when_live_verification_fails(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
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
    monkeypatch.setattr(
        configure_module,
        "run_doctor",
        lambda *, config_file, live: {
            "ok": False,
            "config": {"oid_present": True},
            "checks": [
                {"step": "auth_status", "ok": True},
                {
                    "step": "auth_refresh_org_scoped",
                    "ok": False,
                    "error_class": "internal",
                    "error_code": "request_failed",
                    "error_message": 'JWT exchange failed with status 401: {"error":"unknown api key"}',
                },
            ],
            "leak_checks": {},
        },
    )

    with pytest.raises(SystemExit) as exc:
        configure_module.main(
            [
                "--config",
                str(config),
                "--oid",
                OID,
                "--api-key-ref",
                "vault://secret/data/limacharlie/mcp#api_key",
                "--skip-vault-write",
                "--yes",
            ]
        )

    assert exc.value.code == 2
    output = capsys.readouterr().out
    assert output.startswith("Configured local LimaCharlie MCP auth, but live verification failed.")
    assert "[OK] Stored the LimaCharlie organization API key in managed local Vault" in output
    assert "[FAILED] JWT refresh check did not complete" in output
    assert "unknown api key" in output
    assert "Create or copy a fresh organization API key" in output
    assert "Do not start review or response workflows" in output
    assert 'Ask: "Review my LimaCharlie org posture."' not in output


def test_configure_cli_json_preserves_structured_output(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
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
    monkeypatch.setattr(
        configure_module,
        "run_doctor",
        lambda *, config_file, live: {
            "ok": True,
            "config": {"oid_present": True},
            "checks": [{"step": "auth_status", "ok": True}],
            "leak_checks": {},
        },
    )

    configure_module.main(
        [
            "--config",
            str(config),
            "--oid",
            OID,
            "--api-key-ref",
            "vault://secret/data/limacharlie/mcp#api_key",
            "--skip-vault-write",
            "--yes",
            "--json",
        ]
    )

    payload = json.loads(capsys.readouterr().out)
    assert payload["ok"] is True
    assert payload["api_key_ref"] == "vault://secret/data/limacharlie/mcp#api_key"
    assert payload["managed_vault"] is True


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


def test_configure_can_provision_runtime_key_from_bootstrap_key(
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
    monkeypatch.setattr(configure_module, "read_api_key", lambda *, api_key_stdin: "bootstrap-secret")

    def fake_provision(**kwargs):
        captured["provision"] = kwargs
        return ProvisionedRuntimeKey(
            api_key="runtime-secret",
            name=kwargs["name"],
            permissions=kwargs["permissions"],
            key_hash="runtime-hash",
        )

    def fake_write(config, api_key):
        captured["written_api_key"] = api_key
        return VaultBootstrapResult(
            api_key_ref="vault://secret/data/limacharlie/mcp#api_key",
            env={},
        )

    monkeypatch.setattr(configure_module, "_provision_runtime_api_key", fake_provision)
    monkeypatch.setattr(configure_module, "write_limacharlie_key", fake_write)

    result = run_configure(
        [
            "--config",
            str(config),
            "--oid",
            OID,
            "--provision-runtime-key",
            "--bootstrap-key-name",
            "limacharlie-mcp-bootstrap",
            "--skip-doctor",
            "--yes",
        ]
    )

    saved = json.loads(config.read_text(encoding="utf-8"))
    assert result["ok"] is True
    assert result["provisioned_runtime_key"]["name"] == "limacharlie-mcp-runtime"
    assert result["provisioned_runtime_key"]["key_hash_present"] is True
    assert "bootstrap-secret" not in json.dumps(result)
    assert "runtime-secret" not in json.dumps(result)
    assert captured["provision"]["bootstrap_api_key"] == "bootstrap-secret"
    assert "org.get" in captured["provision"]["permissions"]
    assert captured["written_api_key"] == "runtime-secret"
    assert saved["api_key_ref"] == "vault://secret/data/limacharlie/mcp#api_key"
    assert "bootstrap-secret" not in json.dumps(saved)
    assert "runtime-secret" not in json.dumps(saved)
    assert result["bootstrap_key"] == {
        "name": "limacharlie-mcp-bootstrap",
        "delete_manually": True,
    }


def test_configure_generates_bootstrap_key_name_when_not_provided() -> None:
    args = configure_module.parse_args(["--oid", OID, "--provision-runtime-key", "--skip-doctor", "--yes"])

    name = configure_module._ensure_bootstrap_key_name(args)

    assert name.startswith("limacharlie-mcp-bootstrap-")
    assert args.bootstrap_key_name == name
    assert len(name) == len("limacharlie-mcp-bootstrap-") + 8


def test_provision_runtime_api_key_exchanges_bootstrap_key_without_leaking_secret() -> None:
    class FakeProvisionHTTP:
        def __init__(self) -> None:
            self.calls = []
            self.closed = False

        def request(self, method, url, **kwargs):
            self.calls.append({"method": method, "url": url, **kwargs})
            if url == "https://jwt.test":
                return httpx.Response(200, json={"jwt": "jwt-token"})
            if url == f"https://api.test/v1/orgs/{OID}/keys":
                return httpx.Response(200, json={"api_key": "runtime-secret", "key_hash": "hash-1"})
            return httpx.Response(404, json={"error": "not found"})

        def close(self) -> None:
            self.closed = True

    fake = FakeProvisionHTTP()

    result = configure_module._provision_runtime_api_key(
        oid=OID,
        bootstrap_api_key="bootstrap-secret",
        name="runtime",
        permissions=["org.get", "sensor.list"],
        api_root="https://api.test",
        jwt_root="https://jwt.test",
        timeout_seconds=5,
        http_client=fake,
    )

    assert result.api_key == "runtime-secret"
    assert result.key_hash == "hash-1"
    assert result.permissions == ["org.get", "sensor.list"]
    assert fake.calls[0]["data"] == {"oid": OID, "secret": "bootstrap-secret"}
    assert fake.calls[1]["headers"]["Authorization"] == "Bearer jwt-token"
    assert fake.calls[1]["params"] == {"key_name": "runtime", "perms": "org.get,sensor.list"}
    assert fake.closed is False


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
