"""RAM-backed workspace: layout, permissions, locking, link naming."""

from __future__ import annotations

import stat
from pathlib import Path

import pytest

from nord_up.errors import BusyError, ConfigError
from nord_up.runtime import (
    RuntimeWorkspace,
    discover_interfaces,
    interface_name,
    write_private,
)


def test_workspace_layout_is_private_and_cleaned_up(tmp_path: Path) -> None:
    root = tmp_path / "run"
    with RuntimeWorkspace("nordlynx_zz", root=root) as workspace:
        assert stat.S_IMODE(workspace.directory.stat().st_mode) == 0o700
        assert workspace.config_path == root / "nordlynx_zz.conf"
        assert workspace.state_path == root / "nordlynx_zz.state.json"
        write_private(workspace.config_path, "test-key")

    assert not root.exists()  # config, state, lock and directory are gone

    # The lock is released, so a fresh instance takes over immediately.
    with RuntimeWorkspace("nordlynx_zz", root=root) as workspace:
        assert not workspace.config_path.exists()


def test_only_one_instance_owns_a_link(tmp_path: Path) -> None:
    root = tmp_path / "run"
    with RuntimeWorkspace("nordlynx_zz", root=root), pytest.raises(BusyError):
        RuntimeWorkspace("nordlynx_zz", root=root).open()

    # Different links do not block each other.
    with RuntimeWorkspace("nordlynx_qq", root=root):
        pass


def test_interface_names_carry_the_country_code(tmp_path: Path) -> None:
    assert interface_name("ZZ") == "nordlynx_zz"
    assert interface_name(None) == "nordlynx"
    assert interface_name("zz", override="my-vpn") == "my-vpn"

    for bad in ("bad name", "x" * 16):
        with pytest.raises(ConfigError):
            RuntimeWorkspace(bad, root=tmp_path)


def test_discover_interfaces_lists_only_nord_up_configs(tmp_path: Path) -> None:
    root = tmp_path / "run"
    root.mkdir()
    (root / "nordlynx_zz.conf").write_text("[Interface]\n")
    (root / "nordlynx_qq.conf").write_text("[Interface]\n")
    (root / "nordlynx_qq.state.json").write_text("{}")
    (root / "notes.txt").write_text("ignore me")

    assert discover_interfaces(root) == ["nordlynx_qq", "nordlynx_zz"]
    assert discover_interfaces(tmp_path / "missing") == []


def test_write_private_forces_owner_only_mode(tmp_path: Path) -> None:
    path = tmp_path / "x.conf"
    path.write_text("old")
    path.chmod(0o666)

    write_private(path, "test-key")

    assert path.read_text() == "test-key"
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
