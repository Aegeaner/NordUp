"""WireGuard configuration rendering and DNS normalization.

Every managed ``*.conf`` pins ``DNS`` to the local resolver before ``wg-quick
up``, so the tunnel cannot fall back to the public resolvers NordVPN hands out.
When ``/etc/resolv.conf`` already resolves *only* through that address (a local
DNSCrypt-proxy on ``127.0.0.1`` by default), the rewrite is skipped: it would
change nothing, and it would drag in wg-quick's ``resolvconf`` plumbing.
"""

from __future__ import annotations

import contextlib
import os
import tempfile
from collections.abc import Iterable, Sequence
from pathlib import Path

from .errors import ConfigError
from .models import Server

__all__ = [
    "DEFAULT_ADDRESS",
    "DEFAULT_ALLOWED_IPS",
    "DEFAULT_KEEPALIVE",
    "DEFAULT_RESOLV_CONF",
    "ENV_RESOLV_CONF",
    "PRIVATE_FILE_MODE",
    "PROXY_DNS",
    "enforce_dns",
    "enforce_dns_directory",
    "enforce_dns_file",
    "render_config",
    "resolv_conf_path",
    "resolver_already_in_use",
    "resolver_nameservers",
]

#: Local resolver address pinned into every generated/normalized config.  This
#: is where a local DNSCrypt-proxy (or equivalent stub) listens by default, so
#: the tunnel never falls back to the public resolvers NordVPN hands out.
PROXY_DNS = "127.0.0.1"

#: Point at a non-standard resolver configuration (containers, chroots, tests).
ENV_RESOLV_CONF = "NORD_UP_RESOLV_CONF"
DEFAULT_RESOLV_CONF = Path("/etc/resolv.conf")

DEFAULT_ADDRESS = "10.5.0.2/32"
DEFAULT_KEEPALIVE = 25
DEFAULT_ALLOWED_IPS: tuple[str, ...] = ("0.0.0.0/0", "::/0")

#: Configs carry a private key: owner read/write only.
PRIVATE_FILE_MODE = 0o600


def render_config(
    *,
    private_key: str,
    server: Server,
    address: str = DEFAULT_ADDRESS,
    dns: str | None = PROXY_DNS,
    keepalive: int = DEFAULT_KEEPALIVE,
    allowed_ips: Sequence[str] = DEFAULT_ALLOWED_IPS,
) -> str:
    """Render a full-tunnel NordLynx WireGuard configuration.

    ``dns`` becomes the ``DNS`` directive; pass ``None`` to omit it and leave
    the system resolver — typically the local DNSCrypt-proxy — untouched.
    """
    if not allowed_ips:
        raise ConfigError("allowed_ips must not be empty")
    dns_line = "" if dns is None else f"DNS = {_single_line(dns, 'DNS')}\n"
    return (
        "[Interface]\n"
        f"PrivateKey = {_single_line(private_key, 'PrivateKey')}\n"
        f"Address = {_single_line(address, 'Address')}\n"
        f"{dns_line}"
        "[Peer]\n"
        f"PublicKey = {_single_line(server.public_key, 'PublicKey')}\n"
        f"Endpoint = {_single_line(server.endpoint, 'Endpoint')}\n"
        f"AllowedIPs = {_single_line(', '.join(allowed_ips), 'AllowedIPs')}\n"
        f"PersistentKeepalive = {int(keepalive)}\n"
    )


def resolv_conf_path() -> Path:
    """The resolver configuration to inspect; ``NORD_UP_RESOLV_CONF`` overrides."""
    override = os.environ.get(ENV_RESOLV_CONF, "").strip()
    return Path(override) if override else DEFAULT_RESOLV_CONF


def resolver_nameservers(path: Path | None = None) -> list[str]:
    """Every ``nameserver`` address in a resolv.conf-style file (never raises)."""
    target = resolv_conf_path() if path is None else path
    try:
        text = target.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    nameservers: list[str] = []
    for line in text.splitlines():
        fields = line.split("#", 1)[0].split()
        if len(fields) >= 2 and fields[0] == "nameserver":
            nameservers.append(fields[1])
    return nameservers


def resolver_already_in_use(address: str, path: Path | None = None) -> bool:
    """True when ``address`` is the only resolver the system would consult.

    When it is, asking ``wg-quick`` to rewrite ``/etc/resolv.conf`` is a no-op:
    the tunnel keeps using the local stub (DNSCrypt-proxy by default) either
    way.  Skipping the rewrite also avoids wg-quick's ``resolvconf`` plumbing,
    which needs a working ``systemd-resolved``/openresolv backend.
    """
    nameservers = resolver_nameservers(path)
    return bool(nameservers) and all(nameserver == address for nameserver in nameservers)


def enforce_dns(text: str, dns: str = PROXY_DNS) -> str:
    """Force ``DNS = <dns>`` in every ``[Interface]`` section.

    Existing ``DNS`` entries are replaced (duplicates collapsed); a missing one
    is added to the section.  Sections other than ``[Interface]`` are preserved
    byte for byte.
    """
    dns = _single_line(dns, "DNS")
    lines = text.splitlines()
    out: list[str] = []
    in_interface = False
    dns_written = False
    interface_seen = False

    for line in lines:
        header = _section_header(line)
        if header is not None:
            if in_interface and not dns_written:
                out.append(f"DNS = {dns}")
            in_interface = header == "interface"
            dns_written = False
            if in_interface:
                interface_seen = True
            out.append(line)
            continue

        if in_interface and _key(line) == "dns":
            if not dns_written:
                out.append(f"DNS = {dns}")
                dns_written = True
            continue  # drop duplicate DNS entries

        out.append(line)

    if in_interface and not dns_written:
        out.append(f"DNS = {dns}")

    if not interface_seen:
        raise ConfigError("configuration has no [Interface] section")

    return "\n".join(out) + "\n"


def enforce_dns_file(path: Path, dns: str = PROXY_DNS) -> bool:
    """Normalize one config in place; return ``True`` when bytes changed.

    The replacement is atomic (temp file + :func:`os.replace`) and the file is
    forced to mode ``0600`` because it contains a private key.  Unreadable or
    undecodable files raise :class:`ConfigError`.
    """
    try:
        original = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"cannot read {path}: {exc}") from exc

    normalized = enforce_dns(original, dns)
    changed = normalized != original
    if changed:
        _write_atomic(path, normalized)
    else:
        _force_private_mode(path)
    return changed


def enforce_dns_directory(
    directory: Path, dns: str = PROXY_DNS, pattern: str = "*.conf"
) -> list[Path]:
    """Normalize every matching config under ``directory``.

    Returns the paths whose contents changed.  Run before every
    ``wg-quick up`` so no code path can hand a stale resolver to WireGuard.
    """
    changed: list[Path] = []
    for path in sorted(_conf_files(directory, pattern)):
        if enforce_dns_file(path, dns):
            changed.append(path)
    return changed


def _conf_files(directory: Path, pattern: str) -> Iterable[Path]:
    if not directory.is_dir():
        return ()
    return (entry for entry in directory.glob(pattern) if entry.is_file())


def _write_atomic(path: Path, text: str, mode: int = PRIVATE_FILE_MODE) -> None:
    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=f".{path.name}.", suffix=".tmp")
    tmp_path = Path(tmp_name)
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_path, path)
        _sync_directory(path.parent)
    except BaseException:
        with contextlib.suppress(OSError):
            tmp_path.unlink()
        raise


def _force_private_mode(path: Path) -> None:
    with contextlib.suppress(OSError):
        if os.stat(path).st_mode & 0o077:
            os.chmod(path, PRIVATE_FILE_MODE)


def _sync_directory(directory: Path) -> None:
    with contextlib.suppress(OSError):
        fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)


def _section_header(line: str) -> str | None:
    stripped = line.strip()
    if len(stripped) >= 2 and stripped.startswith("[") and stripped.endswith("]"):
        return stripped[1:-1].strip().lower()
    return None


def _key(line: str) -> str | None:
    stripped = line.lstrip()
    if not stripped or stripped.startswith("#"):
        return None
    head, separator, _ = line.partition("=")
    if not separator:
        return None
    return head.strip().lower()


def _single_line(value: str, field: str) -> str:
    """Reject values that could inject new directives or sections."""
    if not isinstance(value, str) or any(ch in value for ch in "\r\n"):
        raise ConfigError(f"{field} contains an invalid value")
    value = value.strip()
    if not value:
        raise ConfigError(f"{field} must not be empty")
    return value
