from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import httpx

from limacharlie_mcp.auth_doctor import run_doctor


OID = "263c19e9-bd4a-475a-8cd3-5403af446cb9"


class FakeHTTP:
    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []
        self.routes: list[tuple[str, str, httpx.Response]] = []

    def add(self, method: str, url: str, payload: Any, status_code: int = 200) -> None:
        self.routes.append(
            (
                method,
                url,
                httpx.Response(status_code, json=payload, headers={"content-type": "application/json"}),
            )
        )

    def request(self, method, url, *, headers=None, params=None, data=None, json=None, timeout=None):
        self.calls.append(
            {
                "method": method,
                "url": url,
                "headers": headers or {},
                "params": params or {},
                "data": data,
                "json": json,
                "timeout": timeout,
            }
        )
        for route_method, route_url, response in self.routes:
            if route_method == method and route_url == url:
                return response
        raise AssertionError(f"unexpected request: {method} {url}")


def write_env_file(path: Path, *, auth_mode: str | None = None) -> None:
    lines = [
        "LC_API_KEY=org-secret",
        "LC_USER_API_KEY=user-secret",
        "LC_UID=firebase-user-id-1234567890",
        f"LC_ORG_ID={OID}",
        f"LC_MCP_AUDIT_LOG={path.parent / 'audit.jsonl'}",
    ]
    if auth_mode:
        lines.append(f"LC_AUTH_MODE={auth_mode}")
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def test_auth_doctor_defaults_to_org_mode_when_both_keys_exist(tmp_path: Path) -> None:
    env_file = tmp_path / "env"
    write_env_file(env_file)
    fake = FakeHTTP()
    fake.add("POST", "https://jwt.limacharlie.io", {"jwt": "test-token", "expires_in": 3000})
    fake.add("GET", f"https://api.limacharlie.io/v1/orgs/{OID}", {"oid": OID, "name": "Test"})

    result = run_doctor(env_file=env_file, http_client=fake)

    assert result["ok"] is True
    assert result["config"]["effective_mode"] == "org_api_key"
    assert fake.calls[0]["data"]["secret"] == "org-secret"
    assert "uid" not in fake.calls[0]["data"]
    serialized = json.dumps(result)
    assert "org-secret" not in serialized
    assert "user-secret" not in serialized
    assert "firebase-user-id-1234567890" not in serialized


def test_auth_doctor_user_mode_uses_user_key_and_lists_orgs(tmp_path: Path) -> None:
    env_file = tmp_path / "env"
    write_env_file(env_file, auth_mode="user_api_key")
    fake = FakeHTTP()
    fake.add("POST", "https://jwt.limacharlie.io", {"jwt": "test-token", "expires_in": 3000})
    fake.add("GET", f"https://api.limacharlie.io/v1/orgs/{OID}", {"oid": OID, "name": "Test"})
    fake.add("GET", "https://api.limacharlie.io/v1/user/orgs", {"orgs": [{"oid": OID, "name": "Test"}]})

    result = run_doctor(env_file=env_file, http_client=fake)

    assert result["ok"] is True
    assert result["config"]["effective_mode"] == "user_api_key"
    assert any(check["step"] == "list_orgs_user_scoped" and check["org_count"] == 1 for check in result["checks"])
    assert fake.calls[0]["data"]["secret"] == "user-secret"
    assert fake.calls[0]["data"]["uid"] == "firebase-user-id-1234567890"


def test_auth_doctor_no_live_reports_config_shape(tmp_path: Path) -> None:
    env_file = tmp_path / "env"
    write_env_file(env_file)

    result = run_doctor(env_file=env_file, live=False)

    assert result["ok"] is True
    assert result["config"]["org_api_key_present"] is True
    assert result["config"]["user_api_key_present"] is True
    assert result["config"]["uid_present"] is True
    assert [check["step"] for check in result["checks"]] == ["auth_status"]
