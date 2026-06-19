from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Mapping


DEFAULT_CONFIG_PATH = Path.home() / ".config" / "limacharlie-mcp" / "config.json"

SECRET_CONFIG_KEYS = {
    "api_key",
    "user_api_key",
    "vault_token",
    "jwt",
    "token",
}


def resolve_config_path(
    config_path: str | Path | None = None,
    *,
    environ: Mapping[str, str] | None = None,
) -> tuple[Path, bool]:
    env = environ if environ is not None else os.environ
    if config_path is not None:
        return Path(config_path).expanduser(), True
    configured = env.get("LC_MCP_CONFIG")
    if configured:
        return Path(configured).expanduser(), True
    return DEFAULT_CONFIG_PATH, False


def load_runtime_config(
    config_path: str | Path | None = None,
    *,
    environ: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    path, explicit = resolve_config_path(config_path, environ=environ)
    if not path.exists():
        if explicit:
            raise ValueError(f"LimaCharlie MCP config file does not exist: {path}")
        return {}

    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ValueError(f"LimaCharlie MCP config file is not valid JSON: {path}") from exc

    if not isinstance(raw, dict):
        raise ValueError("LimaCharlie MCP config file must contain a JSON object")

    forbidden = sorted(key for key in raw if key in SECRET_CONFIG_KEYS)
    if forbidden:
        joined = ", ".join(forbidden)
        raise ValueError(
            "LimaCharlie MCP config file must not contain secret values. "
            f"Move these fields to Vault or environment-only local development: {joined}"
        )

    return dict(raw)


def env_first(
    config: Mapping[str, Any],
    environ: Mapping[str, str],
    config_key: str,
    *env_names: str,
    explicit: Any = None,
) -> Any:
    if explicit is not None:
        return explicit
    for name in env_names:
        value = environ.get(name)
        if value:
            return value
    value = config.get(config_key)
    return value if value != "" else None


def write_runtime_config(path: Path, values: Mapping[str, Any]) -> None:
    forbidden = sorted(key for key in values if key in SECRET_CONFIG_KEYS and values.get(key))
    if forbidden:
        joined = ", ".join(forbidden)
        raise ValueError(f"Refusing to write secret fields to config: {joined}")

    clean = {key: value for key, value in values.items() if value is not None and value != ""}
    path = path.expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(clean, indent=2, sort_keys=True) + "\n", encoding="utf-8")
