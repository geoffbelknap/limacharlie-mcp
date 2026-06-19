from __future__ import annotations

import os
from pathlib import Path

from limacharlie_mcp.local_vault import config_from_mapping, config_to_mapping


def test_managed_vault_config_round_trips_state_dir(tmp_path: Path) -> None:
    config = config_from_mapping({"addr": "http://127.0.0.1:8221", "state_dir": str(tmp_path)})

    assert config.addr == "http://127.0.0.1:8221"
    assert config.state_dir == tmp_path
    assert config.data_dir == tmp_path / "data"
    assert config.root_token_file == tmp_path / "root-token"
    assert config.runtime_token_file == tmp_path / "runtime-token"
    assert config_to_mapping(config) == {
        "enabled": True,
        "addr": "http://127.0.0.1:8221",
        "state_dir": str(tmp_path),
    }


def test_managed_vault_private_file_writer_uses_owner_only_permissions(tmp_path: Path) -> None:
    from limacharlie_mcp import local_vault

    path = tmp_path / "secret"
    local_vault._write_private(path, "secret\n")

    assert path.read_text(encoding="utf-8") == "secret\n"
    assert oct(os.stat(path).st_mode & 0o777) == "0o600"
