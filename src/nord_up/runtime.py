"""RAM-backed, single-instance configuration workspace.

Configs live on tmpfs (``/dev/shm``, else ``$TMPDIR``) in a ``0700`` directory
as ``0600`` files, guarded by an advisory ``flock``: a second invocation exits
with :class:`BusyError`.  ``wg-quick`` derives the interface name from the
config *filename*, so the path is deterministic (``<root>/<iface>.conf``) and a
leftover file proves a previous run died before cleanup.
"""

from __future__ import annotations

import contextlib
import fcntl
import os
import re
import tempfile
from pathlib import Path

from .errors import BusyError, ConfigError, NordUpError

__all__ = [
    "DEFAULT_INTERFACE",
    "ENV_RUNTIME_ROOT",
    "INTERFACE_PATTERN",
    "STATE_SUFFIX",
    "RuntimeWorkspace",
    "default_runtime_root",
    "discover_interfaces",
    "interface_name",
    "write_private",
]

#: Interface name handed to ``wg-quick`` (Linux IFNAMSIZ is 15 chars).
DEFAULT_INTERFACE = "nordlynx"

#: Override the workspace root (used by tests and unusual layouts).
ENV_RUNTIME_ROOT = "NORD_UP_RUNTIME_DIR"

#: Same grammar wg-quick enforces for ``<interface>.conf``.
INTERFACE_PATTERN = re.compile(r"^[A-Za-z0-9_=+.-]{1,15}$")

#: Per-interface record describing the tunnel this workspace currently owns.
STATE_SUFFIX = ".state.json"

_DIRECTORY_MODE = 0o700
_FILE_MODE = 0o600
_LOCK_SUFFIX = ".lock"


def _validate_interface(interface: str) -> str:
    if not INTERFACE_PATTERN.fullmatch(interface):
        raise ConfigError(
            f"invalid interface name {interface!r}: must match {INTERFACE_PATTERN.pattern}"
        )
    return interface


def interface_name(country_code: str | None = None, override: str | None = None) -> str:
    """The link name for a connection, e.g. ``nordlynx_zz``.

    ``--interface`` wins outright; otherwise the lowercased country code is
    appended so ``ip link``/``wg show`` say which country a tunnel belongs to
    and several countries can run side by side.
    """
    if override:
        # Validate here so the CLI fails before any privileged work happens.
        return _validate_interface(override)
    if not country_code:
        return DEFAULT_INTERFACE
    name = f"{DEFAULT_INTERFACE}_{country_code.lower()}"
    if not INTERFACE_PATTERN.fullmatch(name):
        raise ConfigError(f"cannot build an interface name from country code {country_code!r}")
    return name


def discover_interfaces(root: Path | None = None) -> list[str]:
    """Every nord-up link in a workspace root, sorted by name."""
    directory = default_runtime_root() if root is None else Path(root)
    try:
        entries = list(directory.glob("*.conf"))
    except OSError:
        return []
    return sorted(entry.stem for entry in entries if INTERFACE_PATTERN.fullmatch(entry.stem))


def default_runtime_root() -> Path:
    """Return the per-user workspace root, preferring a memory filesystem."""
    override = os.environ.get(ENV_RUNTIME_ROOT)
    if override:
        return Path(override)
    uid = os.getuid()
    memory = Path("/dev/shm")
    if os.path.ismount(memory) and os.access(memory, os.W_OK):
        return memory / f"nord-up-{uid}"
    return Path(tempfile.gettempdir()) / f"nord-up-{uid}"


class RuntimeWorkspace:
    """Context manager owning the config directory and the interface lock."""

    def __init__(self, interface: str = DEFAULT_INTERFACE, *, root: Path | None = None) -> None:
        self.interface = _validate_interface(interface)
        self._root = Path(root) if root is not None else default_runtime_root()
        self._directory: Path | None = None
        self._lock_fd: int | None = None

    # -- paths -------------------------------------------------------------

    @property
    def directory(self) -> Path:
        if self._directory is None:
            raise NordUpError("workspace is not open")
        return self._directory

    @property
    def config_path(self) -> Path:
        return self.directory / f"{self.interface}.conf"

    @property
    def lock_path(self) -> Path:
        return self._root / f".{self.interface}{_LOCK_SUFFIX}"

    @property
    def state_path(self) -> Path:
        """Root-based, so a read-only command can look without opening a lock."""
        return self._root / f"{self.interface}{STATE_SUFFIX}"

    # -- lifecycle ---------------------------------------------------------

    def __enter__(self) -> RuntimeWorkspace:
        self.open()
        return self

    def __exit__(self, *exc_info: object) -> bool:
        self.cleanup()
        return False

    def open(self) -> None:
        self._prepare_directory()
        self._acquire_lock()

    def release(self) -> None:
        """Drop the lock but keep the workspace: the tunnel stays up."""
        if self._lock_fd is not None:
            with contextlib.suppress(OSError):
                os.close(self._lock_fd)
            self._lock_fd = None

    def cleanup(self) -> None:
        """Idempotent removal of every artifact and (if empty) the root."""
        if self._directory is None:
            return
        for path in (self.config_path, self.state_path, self.lock_path):
            with contextlib.suppress(OSError):
                path.unlink()
        self.release()
        with contextlib.suppress(OSError):
            os.rmdir(self._root)  # only succeeds when nothing else lives here
        self._directory = None

    # -- internals ---------------------------------------------------------

    def _prepare_directory(self) -> None:
        try:
            self._root.mkdir(mode=_DIRECTORY_MODE, parents=True, exist_ok=True)
            os.chmod(self._root, _DIRECTORY_MODE)
        except OSError as exc:
            raise ConfigError(f"cannot prepare {self._root}: {exc}") from exc
        self._directory = self._root

    def _acquire_lock(self) -> None:
        """Take an exclusive advisory lock, defeating the unlink/write race."""
        for _ in range(16):
            try:
                fd = os.open(self.lock_path, os.O_CREAT | os.O_RDWR, _FILE_MODE)
            except OSError as exc:
                raise ConfigError(f"cannot create lock {self.lock_path}: {exc}") from exc
            try:
                fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except OSError:
                os.close(fd)
                raise BusyError(
                    f"another nord-up instance already holds interface {self.interface!r}"
                ) from None
            if _same_inode(fd, self.lock_path):
                self._lock_fd = fd
                return
            # The lock file was replaced between open() and flock(); retry.
            os.close(fd)
        raise BusyError(f"could not acquire lock for interface {self.interface!r}")


def write_private(path: Path, text: str, mode: int = _FILE_MODE) -> None:
    """Write ``text`` with restrictive permissions, syncing to stable storage."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(path, mode)
    except BaseException:
        with contextlib.suppress(OSError):
            path.unlink()
        raise


def _same_inode(fd: int, path: Path) -> bool:
    try:
        return os.fstat(fd).st_ino == os.stat(path).st_ino
    except OSError:
        return False
