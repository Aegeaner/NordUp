"""The connection record: round-trip, privacy, corrupt input."""

from __future__ import annotations

import json
import stat
from pathlib import Path
from typing import Any

import pytest

from nord_up.state import ConnectionState, read_state, remove_state, write_state


def _state(**overrides: Any) -> ConnectionState:
    values: dict[str, Any] = {
        "interface": "nordlynx_zz",
        "server": "node7.example.net",
        "endpoint": "203.0.113.7:51820",
        "address": "10.5.0.2/32",
        "config_path": "/run/nordlynx_zz.conf",
        "started_at": 1_700_000_000.0,
        "dns": "127.0.0.1",
    }
    values.update(overrides)
    return ConnectionState(**values)


def test_round_trip_is_private_and_carries_no_key_material(tmp_path: Path) -> None:
    path = tmp_path / "nordlynx_zz.state.json"
    write_state(path, _state())

    assert read_state(path) == _state()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert "PrivateKey" not in path.read_text()


def test_dns_may_be_absent_or_null(tmp_path: Path) -> None:
    path = tmp_path / "state.json"
    write_state(path, _state())
    payload = json.loads(path.read_text())

    payload.pop("dns")
    path.write_text(json.dumps(payload))
    assert read_state(path) == _state(dns=None)

    payload["dns"] = None
    path.write_text(json.dumps(payload))
    assert read_state(path) == _state(dns=None)


@pytest.mark.parametrize(
    "text",
    [
        "{not json",
        "[]",
        "null",
        '{"interface": "", "started_at": 1}',
        '{"interface": "x", "server": 1, "endpoint": "y", "address": "z",'
        ' "config_path": "c", "started_at": "yesterday"}',
    ],
)
def test_missing_file_and_unusable_payloads_read_as_none(tmp_path: Path, text: str) -> None:
    path = tmp_path / "state.json"
    assert read_state(path) is None

    path.write_text(text)
    assert read_state(path) is None

    remove_state(path)
    remove_state(path)  # idempotent
    assert not path.exists()
