"""Typed error hierarchy.

Every failure mode the CLI can surface has a dedicated class so the entry
point can map it to a stable process exit code without string matching.
"""

from __future__ import annotations

__all__ = [
    "ApiError",
    "AuthError",
    "BusyError",
    "ConfigError",
    "NoServerError",
    "NordUpError",
    "PrivilegeError",
    "UsageError",
    "WireGuardError",
]


class NordUpError(Exception):
    """Base class for every expected nord-up failure."""


class UsageError(NordUpError):
    """Bad invocation: missing token, malformed country code, bad interface."""


class AuthError(NordUpError):
    """The NordVPN API rejected the access token."""


class ApiError(NordUpError):
    """The NordVPN API was unreachable, throttled or returned an unusable body."""


class NoServerError(NordUpError):
    """No usable NordLynx server matched the requested filters."""


class ConfigError(NordUpError):
    """A WireGuard configuration could not be rendered or normalized safely."""


class PrivilegeError(NordUpError):
    """Root privileges (or a way to obtain them) are required."""


class BusyError(NordUpError):
    """Another nord-up instance already owns the interface."""


class WireGuardError(NordUpError):
    """``wg-quick`` or ``ip`` failed to bring the interface up or down."""
