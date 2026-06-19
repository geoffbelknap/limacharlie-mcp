from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import hvac


DEFAULT_MOUNT = "secret"
DEFAULT_PATH = "limacharlie/mcp"
DEFAULT_FIELD = "api_key"


@dataclass(frozen=True)
class VaultBootstrapConfig:
    vault_addr: str
    token_file: Path
    runtime_token_file: Path | None
    namespace: str | None
    mount: str
    path: str
    field: str
    kv_version: int
    credential_kind: str = "org"


@dataclass(frozen=True)
class VaultBootstrapResult:
    api_key_ref: str
    env: dict[str, str]


def default_token_file() -> Path | None:
    configured = os.environ.get("LC_VAULT_TOKEN_FILE") or os.environ.get("VAULT_TOKEN_FILE")
    if configured:
        return Path(configured).expanduser()
    home_token = Path.home() / ".vault-token"
    if home_token.exists():
        return home_token
    return None


def build_api_key_ref(config: VaultBootstrapConfig) -> str:
    clean_mount = config.mount.strip("/")
    clean_path = config.path.strip("/")
    clean_field = config.field.strip()
    if config.kv_version == 2:
        return f"vault://{clean_mount}/data/{clean_path}#{clean_field}"
    return f"vault://{clean_mount}/{clean_path}#{clean_field}"


def build_mcp_env(config: VaultBootstrapConfig, api_key_ref: str) -> dict[str, str]:
    ref_env_var = "LC_USER_API_KEY_REF" if config.credential_kind == "user" else "LC_API_KEY_REF"
    env = {
        "LC_SECRET_PROVIDER": "vault",
        "LC_VAULT_ADDR": config.vault_addr,
        "LC_VAULT_TOKEN_FILE": str(config.runtime_token_file or "<path-to-runtime-vault-token-file>"),
        ref_env_var: api_key_ref,
    }
    if config.namespace:
        env["LC_VAULT_NAMESPACE"] = config.namespace
    return env


def read_api_key(*, api_key_stdin: bool) -> str:
    if api_key_stdin:
        api_key = sys.stdin.read().strip()
    else:
        api_key = getpass.getpass("LimaCharlie API key secret (input hidden): ").strip()
    if not api_key:
        raise ValueError("LimaCharlie API key was empty")
    return api_key


def read_vault_token(token_file: Path) -> str:
    try:
        token = token_file.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise ValueError("Vault token file is not readable") from exc
    if not token:
        raise ValueError("Vault token file is empty")
    return token


def write_limacharlie_key(config: VaultBootstrapConfig, api_key: str) -> VaultBootstrapResult:
    token = read_vault_token(config.token_file)
    client = hvac.Client(url=config.vault_addr, token=token, namespace=config.namespace)
    if not client.is_authenticated():
        raise ValueError("Vault token was rejected")

    secret = {config.field: api_key}
    if config.kv_version == 2:
        client.secrets.kv.v2.create_or_update_secret(
            mount_point=config.mount,
            path=config.path,
            secret=secret,
        )
    else:
        client.secrets.kv.v1.create_or_update_secret(
            mount_point=config.mount,
            path=config.path,
            secret=secret,
        )

    api_key_ref = build_api_key_ref(config)
    return VaultBootstrapResult(api_key_ref=api_key_ref, env=build_mcp_env(config, api_key_ref))


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Store a LimaCharlie API key in Vault and print a nonsecret MCP env block."
    )
    parser.add_argument("--vault-addr", default=os.environ.get("LC_VAULT_ADDR") or os.environ.get("VAULT_ADDR"))
    parser.add_argument("--token-file", type=Path, default=default_token_file())
    parser.add_argument(
        "--runtime-token-file",
        type=Path,
        default=os.environ.get("LC_RUNTIME_VAULT_TOKEN_FILE"),
        help="Runtime Vault token file to print in the MCP env block. Do not reuse the bootstrap token for runtime.",
    )
    parser.add_argument("--namespace", default=os.environ.get("LC_VAULT_NAMESPACE") or os.environ.get("VAULT_NAMESPACE"))
    parser.add_argument("--mount", default=DEFAULT_MOUNT)
    parser.add_argument("--path", default=DEFAULT_PATH)
    parser.add_argument("--field", default=DEFAULT_FIELD)
    parser.add_argument("--kv-version", type=int, choices=[1, 2], default=2)
    parser.add_argument(
        "--user-api-key",
        action="store_true",
        help="Print LC_USER_API_KEY_REF instead of LC_API_KEY_REF for user-scoped API key mode.",
    )
    parser.add_argument(
        "--api-key-stdin",
        action="store_true",
        help="Read the LimaCharlie API key from stdin instead of an interactive hidden prompt.",
    )
    return parser.parse_args(argv)


def config_from_args(args: argparse.Namespace) -> VaultBootstrapConfig:
    if not args.vault_addr:
        raise ValueError("Vault address is required; pass --vault-addr or set VAULT_ADDR")
    if not args.token_file:
        raise ValueError("Vault token file is required; pass --token-file or run vault login first")
    mount = args.mount.strip("/")
    path = args.path.strip("/")
    field = args.field.strip()
    if not mount:
        raise ValueError("Vault mount must not be empty")
    if not path:
        raise ValueError("Vault path must not be empty")
    if not field:
        raise ValueError("Vault field must not be empty")
    return VaultBootstrapConfig(
        vault_addr=args.vault_addr.rstrip("/"),
        token_file=args.token_file.expanduser(),
        runtime_token_file=args.runtime_token_file.expanduser() if args.runtime_token_file else None,
        namespace=args.namespace,
        mount=mount,
        path=path,
        field=field,
        kv_version=args.kv_version,
        credential_kind="user" if args.user_api_key else "org",
    )


def result_payload(result: VaultBootstrapResult) -> dict[str, Any]:
    return {
        "ok": True,
        "api_key_ref": result.api_key_ref,
        "ref_env_var": "LC_USER_API_KEY_REF" if "LC_USER_API_KEY_REF" in result.env else "LC_API_KEY_REF",
        "mcp_env": result.env,
    }


def main(argv: list[str] | None = None) -> None:
    try:
        args = parse_args(argv)
        config = config_from_args(args)
        api_key = read_api_key(api_key_stdin=args.api_key_stdin)
        result = write_limacharlie_key(config, api_key)
    except ValueError as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, indent=2), file=sys.stderr)
        raise SystemExit(1) from exc
    except Exception as exc:
        print(
            json.dumps(
                {
                    "ok": False,
                    "error": "Vault bootstrap failed; verify the Vault address, token policy, mount, and path.",
                    "error_type": type(exc).__name__,
                },
                indent=2,
            ),
            file=sys.stderr,
        )
        raise SystemExit(1) from exc

    print(json.dumps(result_payload(result), indent=2))


if __name__ == "__main__":
    main()
