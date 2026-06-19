from __future__ import annotations

import argparse
import json
import os
import shlex
import sys
from pathlib import Path
from typing import Any

from .api import HttpClient, LimaCharlieAPI
from .runtime_config import load_runtime_config


CONFIG_ENV_MAP = {
    "oid": "LC_ORG_ID",
    "uid": "LC_UID",
    "auth_mode": "LC_AUTH_MODE",
    "credential_provider": "LC_SECRET_PROVIDER",
    "api_key_ref": "LC_API_KEY_REF",
    "user_api_key_ref": "LC_USER_API_KEY_REF",
    "vault_addr": "LC_VAULT_ADDR",
    "vault_token_file": "LC_VAULT_TOKEN_FILE",
    "vault_namespace": "LC_VAULT_NAMESPACE",
    "api_root": "LC_API_ROOT",
    "jwt_root": "LC_JWT_ROOT",
    "cases_root": "LC_CASES_API_ROOT",
    "ai_root": "LC_AI_SESSIONS_ROOT",
    "timeout_seconds": "LC_MCP_TIMEOUT_SECONDS",
    "audit_log": "LC_MCP_AUDIT_LOG",
}


def _parse_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip().removeprefix("export ").strip()
        value = value.strip()
        try:
            parsed = shlex.split(value, posix=True)
            value = parsed[0] if parsed else ""
        except ValueError:
            value = value.strip("\"'")
        if key:
            values[key] = value
    return values


def _config_as_env(config: dict[str, Any]) -> dict[str, str]:
    values: dict[str, str] = {}
    for config_key, env_key in CONFIG_ENV_MAP.items():
        value = config.get(config_key)
        if value is not None and value != "":
            values[env_key] = str(value)
    return values


def _load_values(env_file: Path | None, config_file: Path | None) -> dict[str, str]:
    config = load_runtime_config(config_file)
    values = _config_as_env(config)
    values.update({key: value for key, value in os.environ.items() if value})
    if env_file:
        values.update(_parse_env_file(env_file))
    return values


def _presence(values: dict[str, str], key: str) -> bool:
    return bool(values.get(key))


def _summarize_response(step: str, result: dict[str, Any]) -> dict[str, Any]:
    error = result.get("error") if isinstance(result, dict) else None
    data = result.get("data") if isinstance(result, dict) else None
    summary: dict[str, Any] = {
        "step": step,
        "operation": result.get("operation") if isinstance(result, dict) else None,
        "ok": bool(result.get("ok")) if isinstance(result, dict) else False,
        "credential_mode": data.get("credential_mode") if isinstance(data, dict) else None,
        "api_key_source": data.get("api_key_source") if isinstance(data, dict) else None,
        "error_code": error.get("code") if isinstance(error, dict) else None,
        "error_class": error.get("class") if isinstance(error, dict) else None,
        "error_message": error.get("message") if isinstance(error, dict) else None,
    }
    if isinstance(data, dict) and isinstance(data.get("orgs"), list):
        summary["org_count"] = len(data["orgs"])
    return summary


def _secret_leak_checks(result: dict[str, Any], values: dict[str, str]) -> dict[str, bool]:
    serialized = json.dumps(result, sort_keys=True, default=str)
    checks: dict[str, bool] = {}
    for key in ("LC_API_KEY", "LC_USER_API_KEY", "LC_UID", "LC_VAULT_TOKEN", "VAULT_TOKEN"):
        value = values.get(key)
        if value:
            checks[f"{key.lower()}_absent"] = value not in serialized
    return checks


def run_doctor(
    *,
    env_file: Path | None = None,
    config_file: Path | None = None,
    mode: str | None = None,
    oid: str | None = None,
    live: bool = True,
    http_client: HttpClient | None = None,
) -> dict[str, Any]:
    values = _load_values(env_file, config_file)
    requested_mode = mode or values.get("LC_AUTH_MODE") or "auto"
    if requested_mode == "auto":
        auth_mode = None
    else:
        auth_mode = requested_mode
    scoped_oid = oid or values.get("LC_ORG_ID") or values.get("LC_OID")

    client = LimaCharlieAPI(
        api_key=values.get("LC_API_KEY"),
        user_api_key=values.get("LC_USER_API_KEY"),
        uid=values.get("LC_UID") or None,
        auth_mode=auth_mode,
        credential_provider=values.get("LC_SECRET_PROVIDER") or values.get("LC_CREDENTIAL_PROVIDER"),
        api_key_ref=values.get("LC_API_KEY_REF") or values.get("LC_API_KEY_SECRET_REF"),
        user_api_key_ref=values.get("LC_USER_API_KEY_REF") or values.get("LC_USER_API_KEY_SECRET_REF"),
        vault_addr=values.get("LC_VAULT_ADDR") or values.get("VAULT_ADDR"),
        vault_token=values.get("LC_VAULT_TOKEN") or values.get("VAULT_TOKEN"),
        vault_token_file=values.get("LC_VAULT_TOKEN_FILE") or values.get("VAULT_TOKEN_FILE"),
        vault_namespace=values.get("LC_VAULT_NAMESPACE") or values.get("VAULT_NAMESPACE"),
        api_root=values.get("LC_API_ROOT"),
        jwt_root=values.get("LC_JWT_ROOT"),
        cases_root=values.get("LC_CASES_API_ROOT"),
        ai_root=values.get("LC_AI_SESSIONS_ROOT"),
        default_oid=scoped_oid,
        audit_path=Path(values["LC_MCP_AUDIT_LOG"]) if values.get("LC_MCP_AUDIT_LOG") else None,
        http_client=http_client,
    )

    checks: list[dict[str, Any]] = []
    status = client.auth_status(scoped_oid)
    checks.append(_summarize_response("auth_status", status))

    if live:
        credential_mode = status.get("data", {}).get("credential_mode") if isinstance(status.get("data"), dict) else None
        if scoped_oid:
            refresh = client.auth_refresh(scoped_oid)
            checks.append(_summarize_response("auth_refresh_org_scoped", refresh))
            if refresh.get("ok"):
                checks.append(_summarize_response("get_org_info", client.get_org_info(scoped_oid)))
        else:
            checks.append(
                {
                    "step": "auth_refresh_org_scoped",
                    "ok": False,
                    "skipped": True,
                    "reason": "LC_ORG_ID or --oid is required for org-scoped validation.",
                }
            )
        if credential_mode == "user_api_key":
            checks.append(_summarize_response("list_orgs_user_scoped", client.list_orgs()))

    result = {
        "ok": all(check.get("ok") or check.get("skipped") for check in checks),
        "config": {
            "requested_mode": requested_mode,
            "effective_mode": status.get("data", {}).get("credential_mode") if isinstance(status.get("data"), dict) else None,
            "credential_provider": status.get("data", {}).get("credential_provider") if isinstance(status.get("data"), dict) else None,
            "oid_present": bool(scoped_oid),
            "uid_present": _presence(values, "LC_UID"),
            "org_api_key_present": _presence(values, "LC_API_KEY"),
            "user_api_key_present": _presence(values, "LC_USER_API_KEY"),
            "org_api_key_ref_present": _presence(values, "LC_API_KEY_REF") or _presence(values, "LC_API_KEY_SECRET_REF"),
            "user_api_key_ref_present": _presence(values, "LC_USER_API_KEY_REF")
            or _presence(values, "LC_USER_API_KEY_SECRET_REF"),
            "vault_addr_present": _presence(values, "LC_VAULT_ADDR") or _presence(values, "VAULT_ADDR"),
            "vault_token_file_present": _presence(values, "LC_VAULT_TOKEN_FILE") or _presence(values, "VAULT_TOKEN_FILE"),
        },
        "checks": checks,
    }
    result["leak_checks"] = _secret_leak_checks(result, values)
    result["ok"] = bool(result["ok"] and all(result["leak_checks"].values()))
    return result


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Validate LimaCharlie MCP auth configuration without printing secrets.")
    parser.add_argument(
        "--config",
        type=Path,
        help="Optional LimaCharlie MCP config file. Defaults to LC_MCP_CONFIG or ~/.config/limacharlie-mcp/config.json.",
    )
    parser.add_argument("--env-file", type=Path, help="Optional dotenv-style file to read for local validation.")
    parser.add_argument("--oid", help="Organization ID to use for org-scoped validation.")
    parser.add_argument(
        "--mode",
        choices=["auto", "org_api_key", "user_api_key"],
        default=None,
        help="Auth mode to validate. Defaults to LC_AUTH_MODE or auto.",
    )
    parser.add_argument("--no-live", action="store_true", help="Only report configuration shape; do not call LimaCharlie.")
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    result = run_doctor(
        env_file=args.env_file,
        config_file=args.config,
        mode=args.mode,
        oid=args.oid,
        live=not args.no_live,
    )
    print(json.dumps(result, indent=2, sort_keys=True))
    if not result["ok"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main(sys.argv[1:])
