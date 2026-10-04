"""Subprocess wrapper around ``wg-quick`` and ``ip``.

Every call is an argument vector — no shell, so nothing from the API or the
command line can be interpreted.  ``wg-quick`` re-executes itself through
``sudo`` when not run as root; its prompt goes to ``/dev/tty``, so capturing
stdout/stderr still leaves elevation interactive.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from pathlib import Path

from .errors import PrivilegeError, WireGuardError

__all__ = ["ENV_IP", "ENV_WG_QUICK", "WireGuardTool", "require_privileges"]

LOGGER = logging.getLogger("nord_up.wireguard")

WG_QUICK = "wg-quick"
IP = "ip"

#: Point at non-standard tool locations (custom installs, wireguard-go, tests).
ENV_WG_QUICK = "NORD_UP_WG_QUICK"
ENV_IP = "NORD_UP_IP"

_UP_TIMEOUT = 90.0
_DOWN_TIMEOUT = 60.0
_LINK_TIMEOUT = 20.0


def require_privileges() -> None:
    """Fail early when the interface cannot be managed at all.

    Either the process is root, or ``sudo`` is available for ``wg-quick`` to
    checking up front avoids a failed API round trip before
    the user learns they cannot use the tunnel.
    """
    if os.geteuid() == 0:
        return
    if shutil.which("sudo") is None:
        raise PrivilegeError(
            "managing a WireGuard interface needs root: run as root or install sudo"
        )


class WireGuardTool:
    """Minimal, testable facade over the WireGuard userspace tools."""

    def __init__(self, binary: str | None = None, ip_binary: str | None = None) -> None:
        if binary is not None:
            self.wg_quick = binary
        else:
            self.wg_quick = os.environ.get(ENV_WG_QUICK) or shutil.which(WG_QUICK)
        if ip_binary is not None:
            self.ip = ip_binary
        else:
            self.ip = os.environ.get(ENV_IP) or shutil.which(IP)

    def require_available(self) -> None:
        if not self.wg_quick:
            raise WireGuardError(f"{WG_QUICK} not found in PATH; install wireguard-tools")
        if not self.ip:
            raise WireGuardError(f"{IP} not found in PATH; install iproute2")

    def is_up(self, interface: str) -> bool:
        """True when the kernel already has the interface."""
        if not self.ip:
            return False
        result = self._run([self.ip, "link", "show", "dev", interface], _LINK_TIMEOUT)
        return result.returncode == 0

    def up(self, config_path: Path) -> None:
        self._wg_quick("up", config_path, _UP_TIMEOUT)

    def down(self, config_path: Path) -> None:
        self._wg_quick("down", config_path, _DOWN_TIMEOUT)

    def delete_link(self, interface: str) -> None:
        """Last-resort teardown when no config file is available."""
        if not self.ip:
            raise WireGuardError(f"{IP} not found in PATH")
        self._check(
            self._run([self.ip, "link", "delete", "dev", interface], _LINK_TIMEOUT),
            f"ip link delete {interface}",
        )

    # -- internals ---------------------------------------------------------

    def _wg_quick(self, action: str, config_path: Path, timeout: float) -> None:
        if not self.wg_quick:
            raise WireGuardError(f"{WG_QUICK} not found in PATH; install wireguard-tools")
        result = self._run([self.wg_quick, action, str(config_path)], timeout)
        if result.stdout:
            LOGGER.debug("%s %s stdout:\n%s", WG_QUICK, action, result.stdout.strip())
        self._check(result, f"{WG_QUICK} {action} {config_path}")

    def _run(self, argv: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
        try:
            return subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise WireGuardError(f"{argv[0]} timed out after {timeout:.0f}s") from exc
        except OSError as exc:
            raise WireGuardError(f"cannot execute {argv[0]}: {exc}") from exc

    @staticmethod
    def _check(result: subprocess.CompletedProcess[str], description: str) -> None:
        if result.returncode == 0:
            return
        detail = (result.stderr or result.stdout or "").strip()
        raise WireGuardError(
            f"{description} failed (exit {result.returncode})" + (f": {detail}" if detail else "")
        )
