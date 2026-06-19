from __future__ import annotations

import json
import os
import shutil
import socket
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import httpx


DEFAULT_ADDR = "http://127.0.0.1:8220"
DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8220
RUNTIME_POLICY = "limacharlie-mcp-runtime"


@dataclass(frozen=True)
class ManagedVaultConfig:
    addr: str
    state_dir: Path
    data_dir: Path
    config_file: Path
    pid_file: Path
    log_file: Path
    root_token_file: Path
    runtime_token_file: Path
    init_file: Path


@dataclass(frozen=True)
class ManagedVaultStatus:
    addr: str
    root_token_file: Path
    runtime_token_file: Path
    started: bool
    initialized: bool
    sealed: bool


def default_state_dir() -> Path:
    return Path.home() / ".local" / "share" / "limacharlie-mcp" / "vault"


def config_from_mapping(mapping: dict[str, Any] | None = None) -> ManagedVaultConfig:
    values = mapping or {}
    addr = str(values.get("addr") or DEFAULT_ADDR).rstrip("/")
    state_dir = Path(values.get("state_dir") or default_state_dir()).expanduser()
    return ManagedVaultConfig(
        addr=addr,
        state_dir=state_dir,
        data_dir=state_dir / "data",
        config_file=state_dir / "vault.hcl",
        pid_file=state_dir / "vault.pid",
        log_file=state_dir / "vault.log",
        root_token_file=state_dir / "root-token",
        runtime_token_file=state_dir / "runtime-token",
        init_file=state_dir / "init.json",
    )


def config_to_mapping(config: ManagedVaultConfig) -> dict[str, Any]:
    return {
        "enabled": True,
        "addr": config.addr,
        "state_dir": str(config.state_dir),
    }


def _write_private(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    os.chmod(path, 0o600)


def _vault_binary() -> str:
    binary = shutil.which("vault")
    if not binary:
        raise ValueError(
            "Managed local Vault requires the `vault` binary on PATH. "
            "Install HashiCorp Vault, then rerun limacharlie-mcp-configure."
        )
    return binary


def _write_server_config(config: ManagedVaultConfig) -> None:
    config.state_dir.mkdir(parents=True, exist_ok=True)
    config.data_dir.mkdir(parents=True, exist_ok=True)
    rendered = f"""
storage "file" {{
  path = "{config.data_dir}"
}}

listener "tcp" {{
  address = "{DEFAULT_HOST}:{_port(config.addr)}"
  tls_disable = 1
}}

api_addr = "{config.addr}"
disable_mlock = true
ui = false
""".strip()
    _write_private(config.config_file, rendered + "\n")


def _port(addr: str) -> int:
    return int(addr.rsplit(":", 1)[1])


def _pid_running(pid_file: Path) -> bool:
    try:
        pid = int(pid_file.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return False
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def _port_open(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.2)
        return sock.connect_ex((host, port)) == 0


def _request(config: ManagedVaultConfig, method: str, path: str, *, token: str | None = None, json_body: Any = None) -> httpx.Response:
    headers = {"X-Vault-Token": token} if token else None
    return httpx.request(
        method,
        f"{config.addr}/v1/{path.lstrip('/')}",
        headers=headers,
        json=json_body,
        timeout=5,
    )


def _health(config: ManagedVaultConfig) -> dict[str, Any] | None:
    try:
        response = _request(config, "GET", "sys/health")
    except httpx.HTTPError:
        return None
    try:
        payload = response.json()
    except ValueError:
        return None
    return payload if isinstance(payload, dict) else None


def _wait_for_health(config: ManagedVaultConfig, *, timeout_seconds: float = 10) -> dict[str, Any]:
    deadline = time.time() + timeout_seconds
    while time.time() < deadline:
        health = _health(config)
        if health is not None:
            return health
        time.sleep(0.2)
    raise RuntimeError("Managed local Vault did not start in time")


def _start_server(config: ManagedVaultConfig) -> bool:
    if _health(config) is not None:
        return False
    if _port_open(DEFAULT_HOST, _port(config.addr)) and not _pid_running(config.pid_file):
        raise RuntimeError(f"Port {_port(config.addr)} is already in use and is not responding like Vault")

    binary = _vault_binary()
    _write_server_config(config)
    config.log_file.parent.mkdir(parents=True, exist_ok=True)
    log = config.log_file.open("ab")
    process = subprocess.Popen(
        [binary, "server", "-config", str(config.config_file)],
        stdout=log,
        stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
        start_new_session=True,
    )
    _write_private(config.pid_file, f"{process.pid}\n")
    return True


def _root_token(config: ManagedVaultConfig) -> str | None:
    try:
        token = config.root_token_file.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return token or None


def _runtime_token(config: ManagedVaultConfig) -> str | None:
    try:
        token = config.runtime_token_file.read_text(encoding="utf-8").strip()
    except OSError:
        return None
    return token or None


def _init(config: ManagedVaultConfig) -> tuple[str, str]:
    response = _request(
        config,
        "POST",
        "sys/init",
        json_body={"secret_shares": 1, "secret_threshold": 1},
    )
    response.raise_for_status()
    payload = response.json()
    root_token = payload["root_token"]
    unseal_key = payload["keys_base64"][0]
    _write_private(config.root_token_file, root_token + "\n")
    _write_private(config.init_file, json.dumps({"unseal_key": unseal_key}, indent=2) + "\n")
    return root_token, unseal_key


def _unseal(config: ManagedVaultConfig, unseal_key: str | None = None) -> None:
    if not unseal_key:
        try:
            raw = json.loads(config.init_file.read_text(encoding="utf-8"))
            unseal_key = raw["unseal_key"]
        except (OSError, KeyError, ValueError) as exc:
            raise RuntimeError("Managed local Vault is sealed and the local unseal key is missing") from exc
    response = _request(config, "POST", "sys/unseal", json_body={"key": unseal_key})
    response.raise_for_status()


def _ensure_kv2(config: ManagedVaultConfig, root_token: str) -> None:
    response = _request(config, "GET", "sys/mounts", token=root_token)
    response.raise_for_status()
    mounts = response.json()
    secret_mount = mounts.get("secret/") if isinstance(mounts, dict) else None
    if isinstance(secret_mount, dict) and secret_mount.get("type") == "kv":
        options = secret_mount.get("options") if isinstance(secret_mount.get("options"), dict) else {}
        if options.get("version") == "2":
            return
    if secret_mount:
        raise RuntimeError("Managed local Vault secret/ mount exists but is not KV v2")
    response = _request(
        config,
        "POST",
        "sys/mounts/secret",
        token=root_token,
        json_body={"type": "kv", "options": {"version": "2"}},
    )
    if response.status_code not in {200, 204}:
        response.raise_for_status()


def _ensure_runtime_token(config: ManagedVaultConfig, root_token: str) -> None:
    policy = """
path "secret/data/limacharlie/mcp" {
  capabilities = ["read"]
}

path "secret/data/limacharlie/mcp-user" {
  capabilities = ["read"]
}

path "secret/metadata/limacharlie/mcp" {
  capabilities = ["read"]
}

path "secret/metadata/limacharlie/mcp-user" {
  capabilities = ["read"]
}
""".strip()
    response = _request(
        config,
        "PUT",
        f"sys/policies/acl/{RUNTIME_POLICY}",
        token=root_token,
        json_body={"policy": policy},
    )
    response.raise_for_status()

    if _runtime_token(config):
        return
    response = _request(
        config,
        "POST",
        "auth/token/create",
        token=root_token,
        json_body={"policies": [RUNTIME_POLICY], "renewable": True, "no_default_policy": True},
    )
    response.raise_for_status()
    payload = response.json()
    token = payload["auth"]["client_token"]
    _write_private(config.runtime_token_file, token + "\n")


def ensure_managed_vault(mapping: dict[str, Any] | None = None) -> ManagedVaultStatus:
    config = config_from_mapping(mapping)
    started = _start_server(config)
    health = _wait_for_health(config)

    initialized = bool(health.get("initialized"))
    sealed = bool(health.get("sealed"))
    root_token = _root_token(config)

    if not initialized:
        root_token, unseal_key = _init(config)
        _unseal(config, unseal_key)
        initialized = True
        sealed = False
    elif sealed:
        _unseal(config)
        sealed = False

    root_token = root_token or _root_token(config)
    if not root_token:
        raise RuntimeError("Managed local Vault root token is missing")
    _ensure_kv2(config, root_token)
    _ensure_runtime_token(config, root_token)

    return ManagedVaultStatus(
        addr=config.addr,
        root_token_file=config.root_token_file,
        runtime_token_file=config.runtime_token_file,
        started=started,
        initialized=initialized,
        sealed=sealed,
    )
