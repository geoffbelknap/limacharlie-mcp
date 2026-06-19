from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from pathlib import Path
from typing import Any

from .auth_doctor import run_doctor
from .local_vault import config_from_mapping, config_to_mapping, ensure_managed_vault
from .runtime_config import load_runtime_config, resolve_config_path, write_runtime_config
from .vault_bootstrap import (
    DEFAULT_FIELD,
    DEFAULT_MOUNT,
    DEFAULT_PATH,
    VaultBootstrapConfig,
    build_api_key_ref,
    default_token_file,
    read_api_key,
    write_limacharlie_key,
)


def _prompt(label: str, default: str | None = None, *, secret: bool = False) -> str:
    prompt = f"{label}"
    if default:
        prompt += f" [{default}]"
    prompt += ": "
    if secret:
        value = getpass.getpass(prompt).strip()
    else:
        value = input(prompt).strip()
    return value or default or ""


def _value(
    *,
    arg_value: str | Path | None,
    env_name: str | None,
    config: dict[str, Any],
    config_key: str,
    prompt_label: str,
    assume_yes: bool,
    required: bool = True,
) -> str:
    current = str(arg_value) if arg_value is not None else ""
    if not current and env_name:
        current = os.environ.get(env_name, "")
    if not current:
        raw_config = config.get(config_key)
        current = str(raw_config) if raw_config is not None else ""
    if not current and not assume_yes and sys.stdin.isatty():
        current = _prompt(prompt_label)
    if required and not current:
        raise ValueError(f"{prompt_label} is required")
    return current


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Configure LimaCharlie MCP auth with Vault-backed secrets and a nonsecret config file."
    )
    parser.add_argument(
        "--config",
        type=Path,
        help="Config file to write. Defaults to ~/.config/limacharlie-mcp/config.json.",
    )
    parser.add_argument("--oid", help="LimaCharlie organization ID.")
    parser.add_argument(
        "--external-vault",
        action="store_true",
        help="Use an existing Vault instance instead of the managed local Vault default.",
    )
    parser.add_argument("--vault-addr", help="Existing Vault server URL, for example https://vault.example.com.")
    parser.add_argument(
        "--token-file",
        type=Path,
        help="Existing Vault bootstrap token file. Defaults to VAULT_TOKEN_FILE or ~/.vault-token in external Vault mode.",
    )
    parser.add_argument(
        "--runtime-token-file",
        type=Path,
        help="Vault token file the MCP runtime should use. Defaults to --token-file for local setup.",
    )
    parser.add_argument("--namespace", help="Optional Vault Enterprise namespace.")
    parser.add_argument("--mount", default=DEFAULT_MOUNT, help="Vault KV mount name.")
    parser.add_argument("--path", default=DEFAULT_PATH, help="Vault KV secret path.")
    parser.add_argument("--field", default=DEFAULT_FIELD, help="Vault KV field name.")
    parser.add_argument("--kv-version", type=int, choices=[1, 2], default=2)
    parser.add_argument("--uid", help="LimaCharlie user ID for user API key mode.")
    parser.add_argument(
        "--user-api-key",
        action="store_true",
        help="Configure user API key mode instead of the recommended organization API key mode.",
    )
    parser.add_argument(
        "--auth-mode",
        choices=["org_api_key", "user_api_key", "auto"],
        help="Auth mode to write. Defaults to org_api_key, or user_api_key with --user-api-key.",
    )
    parser.add_argument(
        "--api-key-ref",
        help="Existing Vault API key ref to use instead of writing a new secret.",
    )
    parser.add_argument("--skip-vault-write", action="store_true", help="Only write config for an existing Vault ref.")
    parser.add_argument("--api-key-stdin", action="store_true", help="Read the LimaCharlie API key from stdin.")
    parser.add_argument("--yes", action="store_true", help="Fail on missing values instead of prompting.")
    parser.add_argument("--no-live", action="store_true", help="Do not call LimaCharlie after writing config.")
    parser.add_argument("--skip-doctor", action="store_true", help="Skip the post-config auth doctor run.")
    parser.add_argument("--json", action="store_true", help="Print the full structured configuration result as JSON.")
    parser.add_argument("--verbose", action="store_true", help="Include nonsecret config details in human-readable output.")
    return parser.parse_args(argv)


def _bootstrap_config(args: argparse.Namespace, *, vault_addr: str, token_file: Path) -> VaultBootstrapConfig:
    runtime_token_file = args.runtime_token_file.expanduser() if args.runtime_token_file else token_file
    return VaultBootstrapConfig(
        vault_addr=vault_addr.rstrip("/"),
        token_file=token_file,
        runtime_token_file=runtime_token_file,
        namespace=args.namespace,
        mount=args.mount.strip("/"),
        path=args.path.strip("/"),
        field=args.field.strip(),
        kv_version=args.kv_version,
        credential_kind="user" if args.user_api_key else "org",
    )


def build_config_values(
    args: argparse.Namespace,
    *,
    existing_config: dict[str, Any],
    api_key_ref: str,
    vault_addr: str,
    token_file: Path,
    oid: str,
    uid: str | None,
    managed_vault: dict[str, Any] | None,
) -> dict[str, Any]:
    auth_mode = args.auth_mode or ("user_api_key" if args.user_api_key else "org_api_key")
    runtime_token_file = args.runtime_token_file.expanduser() if args.runtime_token_file else token_file
    values: dict[str, Any] = dict(existing_config)
    values.update(
        {
            "credential_provider": "vault",
            "auth_mode": auth_mode,
            "oid": oid,
            "vault_addr": vault_addr.rstrip("/"),
            "vault_token_file": str(runtime_token_file),
            "vault_namespace": args.namespace or existing_config.get("vault_namespace"),
            "managed_vault": managed_vault,
        }
    )
    if args.user_api_key:
        values["uid"] = uid
        values["user_api_key_ref"] = api_key_ref
        values.pop("api_key_ref", None)
    else:
        values["api_key_ref"] = api_key_ref
        values.pop("user_api_key_ref", None)
        values.pop("uid", None)
    return values


def run_configure(argv: list[str] | argparse.Namespace | None = None) -> dict[str, Any]:
    args = argv if isinstance(argv, argparse.Namespace) else parse_args(argv)
    config_path, _ = resolve_config_path(args.config)
    existing_config = load_runtime_config(config_path) if config_path.exists() else {}
    default_token = args.token_file or default_token_file()

    oid = _value(
        arg_value=args.oid,
        env_name="LC_ORG_ID",
        config=existing_config,
        config_key="oid",
        prompt_label="LimaCharlie organization ID",
        assume_yes=args.yes,
    )
    existing_managed = existing_config.get("managed_vault")
    existing_uses_managed = isinstance(existing_managed, dict) and bool(existing_managed.get("enabled"))
    existing_uses_external = bool(existing_config.get("vault_addr")) and not existing_uses_managed
    use_external_vault = bool(args.external_vault or args.vault_addr or args.token_file or existing_uses_external)
    managed_vault_config = None
    if use_external_vault:
        vault_addr = _value(
            arg_value=args.vault_addr,
            env_name="VAULT_ADDR",
            config=existing_config,
            config_key="vault_addr",
            prompt_label="Vault address",
            assume_yes=args.yes,
        )
        token_file_text = _value(
            arg_value=default_token,
            env_name="VAULT_TOKEN_FILE",
            config=existing_config,
            config_key="vault_token_file",
            prompt_label="Vault token file",
            assume_yes=args.yes,
        )
        token_file = Path(token_file_text).expanduser()
    else:
        local_config = config_from_mapping(existing_managed if isinstance(existing_managed, dict) else None)
        status = ensure_managed_vault(config_to_mapping(local_config))
        vault_addr = status.addr
        token_file = status.root_token_file
        if not args.runtime_token_file:
            args.runtime_token_file = status.runtime_token_file
        managed_vault_config = config_to_mapping(local_config)
    uid = None
    if args.user_api_key:
        uid = _value(
            arg_value=args.uid,
            env_name="LC_UID",
            config=existing_config,
            config_key="uid",
            prompt_label="LimaCharlie user ID",
            assume_yes=args.yes,
        )

    bootstrap_config = _bootstrap_config(args, vault_addr=vault_addr, token_file=token_file)
    if args.skip_vault_write:
        config_ref_key = "user_api_key_ref" if args.user_api_key else "api_key_ref"
        api_key_ref = args.api_key_ref or existing_config.get(config_ref_key)
        if not api_key_ref:
            api_key_ref = build_api_key_ref(bootstrap_config)
    else:
        api_key = read_api_key(api_key_stdin=args.api_key_stdin)
        api_key_ref = write_limacharlie_key(bootstrap_config, api_key).api_key_ref

    config_values = build_config_values(
        args,
        existing_config=existing_config,
        api_key_ref=api_key_ref,
        vault_addr=vault_addr,
        token_file=token_file,
        oid=oid,
        uid=uid,
        managed_vault=managed_vault_config,
    )
    write_runtime_config(config_path, config_values)

    doctor = None
    if not args.skip_doctor:
        doctor = run_doctor(config_file=config_path, live=not args.no_live)

    result = {
        "ok": bool(doctor.get("ok", True) if isinstance(doctor, dict) else True),
        "config_path": str(config_path),
        "credential_provider": "vault",
        "auth_mode": config_values["auth_mode"],
        "api_key_ref": api_key_ref,
        "managed_vault": bool(managed_vault_config),
        "doctor": doctor,
    }
    return result


def _check_ok(doctor: dict[str, Any] | None, step: str) -> bool:
    if not isinstance(doctor, dict):
        return False
    checks = doctor.get("checks")
    if not isinstance(checks, list):
        return False
    return any(isinstance(check, dict) and check.get("step") == step and check.get("ok") for check in checks)


def _format_human_result(result: dict[str, Any], args: argparse.Namespace) -> str:
    auth_mode = str(result.get("auth_mode") or "")
    key_label = "user API key" if auth_mode == "user_api_key" else "organization API key"
    doctor = result.get("doctor") if isinstance(result.get("doctor"), dict) else None
    oid = None
    if isinstance(doctor, dict):
        config = doctor.get("config")
        if isinstance(config, dict) and config.get("oid_present"):
            oid = args.oid

    lines = ["Configured LimaCharlie MCP auth.", ""]
    if result.get("managed_vault"):
        lines.append(f"[OK] Stored the LimaCharlie {key_label} in managed local Vault")
    else:
        lines.append(f"[OK] Stored the LimaCharlie {key_label} in the configured Vault")
    lines.append("[OK] Wrote local MCP config")

    if doctor is None:
        lines.append("- Skipped auth verification")
    else:
        if _check_ok(doctor, "auth_refresh_org_scoped"):
            lines.append("[OK] Verified JWT refresh")
        elif args.no_live:
            lines.append("- Skipped live JWT refresh check")
        else:
            lines.append("- JWT refresh check did not complete")

        if _check_ok(doctor, "get_org_info"):
            suffix = f" {oid}" if oid else ""
            lines.append(f"[OK] Verified access to org{suffix}")
        elif args.no_live:
            lines.append("- Skipped live org access check")

    if args.verbose:
        lines.extend(
            [
                "",
                f"Config: {result.get('config_path')}",
                f"Auth mode: {result.get('auth_mode')}",
                f"Credential store: {'managed local Vault' if result.get('managed_vault') else 'external Vault'}",
            ]
        )

    lines.extend(
        [
            "",
            "Next:",
            "1. Open a new Codex or Claude chat with the LimaCharlie MCP plugin enabled.",
            "2. Ask: \"Check my LimaCharlie MCP auth status.\"",
            "   The agent should confirm credentials are configured without showing secrets.",
            "3. Ask: \"Review my LimaCharlie org posture.\"",
            "   For a smaller smoke test, ask: \"List my LimaCharlie sensors.\"",
        ]
    )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    try:
        result = run_configure(args)
    except ValueError as exc:
        if args.json:
            print(json.dumps({"ok": False, "error": str(exc)}, indent=2), file=sys.stderr)
        else:
            print(f"Configuration failed: {exc}", file=sys.stderr)
        raise SystemExit(1) from exc
    except Exception as exc:
        if args.json:
            print(
                json.dumps(
                    {
                        "ok": False,
                        "error": "LimaCharlie MCP configuration failed.",
                        "error_type": type(exc).__name__,
                    },
                    indent=2,
                ),
                file=sys.stderr,
            )
        else:
            detail = f" ({type(exc).__name__})" if args.verbose else ""
            print(f"Configuration failed: LimaCharlie MCP configuration failed.{detail}", file=sys.stderr)
        raise SystemExit(1) from exc
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(_format_human_result(result, args))
    if not result["ok"]:
        raise SystemExit(2)


if __name__ == "__main__":
    main(sys.argv[1:])
