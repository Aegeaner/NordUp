"""Record of the tunnel a workspace currently owns.

The config file alone cannot say whether an interface is *live* or was left
behind by a killed run — and in the default (async) mode the process that brought
it up exits immediately, so nothing else remembers.  ``state.json`` next to the
config resolves that, and carries the details the CLI prints after connecting.
It never contains key material.
"""

from __future__ import annotations

import contextlib
import json
import time
from dataclasses import asdict, dataclass, fields
from pathlib import Path
from typing import Any

from .runtime import write_private

__all__ = ["ConnectionState", "read_state", "remove_state", "write_state"]


@dataclass(frozen=True, slots=True)
class ConnectionState:
    """Everything needed to report on, or tear down, a live connection."""

    interface: str
    server: str
    endpoint: str
    address: str
    config_path: str
    started_at: float
    dns: str | None = None

    @property
    def started_display(self) -> str:
        return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.started_at))

    @property
    def age_seconds(self) -> int:
        return max(0, int(time.time() - self.started_at))


def write_state(path: Path, state: ConnectionState) -> None:
    write_private(path, json.dumps(asdict(state), sort_keys=True) + "\n")


def read_state(path: Path) -> ConnectionState | None:
    """Parse a state file, or ``None`` when it is missing or unusable."""
    try:
        payload: Any = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    if not isinstance(payload, dict):
        return None

    values: dict[str, Any] = {}
    for field in fields(ConnectionState):
        value = payload.get(field.name)
        if field.name == "dns":
            if value is not None and not isinstance(value, str):
                return None
        elif field.name == "started_at":
            if not isinstance(value, (int, float)) or isinstance(value, bool):
                return None
        elif not isinstance(value, str) or not value:
            return None
        values[field.name] = value
    return ConnectionState(**values)


def remove_state(path: Path) -> None:
    with contextlib.suppress(OSError):
        path.unlink()
