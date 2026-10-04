"""wg-quick/ip wrapper: argument vectors, exit codes, tool paths (no root)."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from nord_up.errors import WireGuardError
from nord_up.wireguard import WireGuardTool


def _script(tmp_path: Path, body: str, name: str = "tool") -> Path:
    path = tmp_path / name
    path.write_text("#!/bin/sh\n" + body)
    path.chmod(0o755)
    return path


def test_up_and_down_pass_the_config_path_as_an_argument(tmp_path: Path) -> None:
    log = tmp_path / "args"
    tool_bin = _script(tmp_path, f'printf "%s\\n" "$@" >> "{log}"\n')
    config = tmp_path / "nordlynx_zz.conf"
    config.write_text("[Interface]\n")
    tool = WireGuardTool(binary=str(tool_bin), ip_binary="/bin/true")

    tool.up(config)
    tool.down(config)

    assert log.read_text().splitlines() == ["up", str(config), "down", str(config)]


def test_failures_surface_stderr_and_exit_code(tmp_path: Path) -> None:
    tool_bin = _script(tmp_path, 'echo "wg: something broke" >&2\nexit 1\n')

    with pytest.raises(WireGuardError) as info:
        WireGuardTool(binary=str(tool_bin), ip_binary="/bin/true").up(tmp_path / "x.conf")

    assert "something broke" in str(info.value)
    assert "exit 1" in str(info.value)


def test_is_up_and_delete_link_use_ip_argv(tmp_path: Path) -> None:
    up = _script(tmp_path, "exit 0\n", name="ip-up")
    down = _script(tmp_path, "exit 1\n", name="ip-down")
    log = tmp_path / "args"
    recording = _script(tmp_path, f'printf "%s\\n" "$@" > "{log}"\n', name="ip-record")

    assert WireGuardTool(binary="/bin/true", ip_binary=str(up)).is_up("nordlynx_zz") is True
    assert WireGuardTool(binary="/bin/true", ip_binary=str(down)).is_up("nordlynx_zz") is False

    WireGuardTool(binary="/bin/true", ip_binary=str(recording)).delete_link("nordlynx_zz")
    assert log.read_text().splitlines() == ["link", "delete", "dev", "nordlynx_zz"]


def test_env_overrides_tool_paths_and_missing_tools_are_reported(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("NORD_UP_WG_QUICK", "/opt/wg-quick")
    monkeypatch.setenv("NORD_UP_IP", "/opt/ip")
    tool = WireGuardTool()
    assert (tool.wg_quick, tool.ip) == ("/opt/wg-quick", "/opt/ip")

    monkeypatch.delenv("NORD_UP_WG_QUICK")
    assert WireGuardTool().wg_quick == shutil.which("wg-quick")

    with pytest.raises(WireGuardError, match="wg-quick"):
        WireGuardTool(binary="", ip_binary="/bin/true").require_available()
    with pytest.raises(WireGuardError, match="iproute2"):
        WireGuardTool(binary="/bin/true", ip_binary="").require_available()
