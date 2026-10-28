"""Command line entry point."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import logging
import os
import re
import sys
from pathlib import Path

from . import __version__
from .api import DEFAULT_BASE_URL, DEFAULT_RETRIES, DEFAULT_TIMEOUT, NordVpnApi
from .errors import (
    ApiError,
    AuthError,
    BusyError,
    ConfigError,
    NordUpError,
    NoServerError,
    PrivilegeError,
    UsageError,
    WireGuardError,
)
from .service import ConnectOptions, ConnectResult, NordUpService
from .state import ConnectionState
from .wgconfig import DEFAULT_ADDRESS, DEFAULT_KEEPALIVE, DEFAULT_MTU

__all__ = ["build_parser", "exit_code_for", "main"]

LOGGER = logging.getLogger("nord_up.cli")

EXIT_OK = 0
EXIT_ERROR = 1
EXIT_USAGE = 2
EXIT_AUTH = 3
EXIT_NO_SERVER = 4
EXIT_WIREGUARD = 5
EXIT_PRIVILEGE = 6
EXIT_BUSY = 7
EXIT_INTERRUPTED = 130

_EXIT_CODES: tuple[tuple[type[NordUpError], int], ...] = (
    (UsageError, EXIT_USAGE),
    (ConfigError, EXIT_USAGE),
    (AuthError, EXIT_AUTH),
    (NoServerError, EXIT_NO_SERVER),
    (BusyError, EXIT_BUSY),
    (PrivilegeError, EXIT_PRIVILEGE),
    (WireGuardError, EXIT_WIREGUARD),
    (ApiError, EXIT_ERROR),
    (NordUpError, EXIT_ERROR),
)

#: Country may be an ISO code or a name.
_COUNTRY_QUERY_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._'-]*$")

_EPILOG = """\
environment:
  NORD_TOKEN            NordVPN access token; used automatically when --token is
                        omitted (run `sudo -E` so sudo preserves the variable)
  NORD_UP_RUNTIME_DIR   override the config workspace (default: /dev/shm)
  NORD_UP_WG_QUICK      path to wg-quick (default: $PATH)
  NORD_UP_IP            path to ip (default: $PATH)

examples:
  sudo -E nord-up -c <country>      connect, print the link and return
  sudo -E nord-up -c <country> -f   stay attached; Ctrl+C disconnects
  nord-up -s                        show the live connection
  nord-up -d                        disconnect and clean up
  nord-up -l                        list countries
  nord-up -c <country> --dry-run    print the config, touch nothing
  sudo -E nord-up -c <country> --dns 127.0.0.1
                                    pin a resolver (e.g. a local stub)
  sudo -E nord-up -c <country> --mtu 1420
                                    raise the link MTU on a full-MTU path
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="nord-up",
        description="Connect to the live fastest NordVPN NordLynx server and leave no residue.",
        epilog=_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--token", "-t", help="NordVPN access token (default: $NORD_TOKEN)")
    parser.add_argument(
        "--country",
        "-c",
        metavar="COUNTRY",
        help="ISO country code or country name",
    )
    parser.add_argument(
        "-l",
        "--list-countries",
        action="store_true",
        help="print the countries NordVPN offers (code, id, name) and exit",
    )
    parser.add_argument(
        "-d",
        "--disconnect",
        action="store_true",
        help="bring the interface down and delete every artifact",
    )
    parser.add_argument(
        "-s",
        "--status",
        action="store_true",
        help="print the live connection, if any (exit 1 when disconnected)",
    )
    parser.add_argument(
        "--interface",
        "-i",
        default=None,
        metavar="NAME",
        help="link name (default: nordlynx_<country>, e.g. nordlynx_zz)",
    )
    parser.add_argument(
        "--dns",
        default=None,
        metavar="ADDR",
        help=(
            "pin this resolver into every config instead of leaving the system "
            "resolver alone; skipped when the system already resolves through it"
        ),
    )
    parser.add_argument(
        "--mtu",
        type=int,
        default=DEFAULT_MTU,
        metavar="N",
        help=(
            f"WireGuard link MTU (default: {DEFAULT_MTU}, which fits PPPoE/DS-Lite "
            "paths); raise to 1420 on a full-MTU path, lower to 1280 if needed"
        ),
    )
    parser.add_argument("--address", default=DEFAULT_ADDRESS, help="tunnel client address")
    parser.add_argument(
        "--keepalive", type=int, default=DEFAULT_KEEPALIVE, help="PersistentKeepalive seconds"
    )
    parser.add_argument(
        "--servers",
        type=int,
        default=5,
        metavar="N",
        help="candidate servers fetched in one request for failover (default: 5)",
    )
    parser.add_argument(
        "--timeout", type=float, default=DEFAULT_TIMEOUT, help="per-request HTTP timeout"
    )
    parser.add_argument("--retries", type=int, default=DEFAULT_RETRIES, help="API retry budget")
    parser.add_argument("--api-base", default=DEFAULT_BASE_URL, help="override the API base URL")
    parser.add_argument(
        "--runtime-dir", type=Path, default=None, help="override the config workspace directory"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="select a server and print the pinned config without touching WireGuard",
    )
    parser.add_argument(
        "-f",
        "--foreground",
        action="store_true",
        help="stay attached and disconnect on Ctrl+C instead of returning at once",
    )
    parser.add_argument("-v", "--verbose", action="count", default=0, help="-v info, -vv debug")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def exit_code_for(exc: BaseException) -> int:
    for error_type, code in _EXIT_CODES:
        if isinstance(exc, error_type):
            return code
    return EXIT_ERROR


def resolve_token(args: argparse.Namespace) -> str:
    token = _optional_token(args)
    if not token:
        raise UsageError(
            "no access token found: set NORD_TOKEN in the environment "
            "(export NORD_TOKEN=...) or pass --token/-t; "
            "under sudo use `sudo -E` so the variable is preserved"
        )
    return token


def options_from_args(args: argparse.Namespace) -> ConnectOptions:
    country = args.country.strip() if args.country else None
    if country is not None and not _COUNTRY_QUERY_PATTERN.fullmatch(country):
        raise UsageError(f"invalid country {args.country!r}: expected a country code or name")
    if args.servers < 1:
        raise UsageError("--servers must be at least 1")
    if args.dns is not None and not args.dns.strip():
        raise UsageError("--dns must not be empty")
    return ConnectOptions(
        token=resolve_token(args),
        country=country,
        interface=args.interface,  # None -> derived from the resolved country
        dns=args.dns,
        mtu=args.mtu,
        address=args.address,
        keepalive=args.keepalive,
        server_limit=args.servers,
        timeout=args.timeout,
        retries=args.retries,
        api_base=args.api_base,
        dry_run=args.dry_run,
        runtime_root=args.runtime_dir,
    )


def _configure_logging(verbosity: int) -> None:
    level = logging.WARNING
    if verbosity == 1:
        level = logging.INFO
    elif verbosity >= 2:
        level = logging.DEBUG
    logging.basicConfig(
        level=level, format="%(levelname)s: %(message)s", stream=sys.stderr, force=True
    )


def _redact(config_text: str) -> str:
    return re.sub(r"(?m)^(PrivateKey\s*=\s*).*$", r"\1<redacted>", config_text)


def _optional_token(args: argparse.Namespace) -> str:
    return (args.token or os.environ.get("NORD_TOKEN") or "").strip()


async def _list_countries(args: argparse.Namespace) -> int:
    # The countries endpoint is public; a token is optional, not required.
    async with NordVpnApi(
        _optional_token(args),
        base_url=args.api_base,
        timeout=args.timeout,
        retries=args.retries,
    ) as api:
        countries = await api.countries()
    width = max((len(country.code) for country in countries), default=2)
    for country in countries:
        sys.stdout.write(f"{country.code:<{width}}  {country.id:>4}  {country.name}\n")
    return EXIT_OK


def _discard_stdout() -> None:
    """Point stdout at /dev/null so the interpreter's exit flush cannot re-raise."""
    with contextlib.suppress(OSError, ValueError, AttributeError):
        devnull = os.open(os.devnull, os.O_WRONLY)
        try:
            os.dup2(devnull, sys.stdout.fileno())
        finally:
            os.close(devnull)


def _local_service(args: argparse.Namespace) -> NordUpService:
    """A service for disconnect/status: needs the workspace, not the API."""
    options = ConnectOptions(token="", interface=args.interface, runtime_root=args.runtime_dir)
    return NordUpService(options)


def _print_connection(state: ConnectionState) -> None:
    dns = state.dns if state.dns is not None else "system (not managed)"
    rows = (
        ("interface", f"{state.interface} (up)"),
        ("server", f"{state.server} ({state.endpoint})"),
        ("address", state.address),
        ("dns", dns),
        ("config", state.config_path),
        ("since", f"{state.started_display} ({state.age_seconds}s ago)"),
    )
    width = max(len(key) for key, _ in rows)
    for key, value in rows:
        sys.stdout.write(f"{key:<{width}}  {value}\n")
    sys.stdout.write(f"{'disconnect':<{width}}  nord-up -d\n")


def _disconnect(args: argparse.Namespace) -> int:
    removed = _local_service(args).down()
    if not removed:
        sys.stdout.write("no nord-up link to disconnect\n")
        return EXIT_OK
    for interface in removed:
        sys.stdout.write(f"{interface} disconnected\n")
    return EXIT_OK


def _status(args: argparse.Namespace) -> int:
    reports = _local_service(args).status()
    states = [report.state for report in reports if report.state is not None]
    for index, state in enumerate(states):
        if index:
            sys.stdout.write("\n")
        _print_connection(state)
    if states:
        return EXIT_OK

    for report in reports:
        if report.up:
            LOGGER.error(
                "%s is up, but no nord-up state was found; `nord-up -d` removes it",
                report.interface,
            )
        else:
            sys.stdout.write(f"{report.interface} is not connected\n")
    if not reports:
        sys.stdout.write("nord-up is not connected\n")
    return EXIT_ERROR


async def _connect(service: NordUpService, *, foreground: bool) -> ConnectResult:
    """Connect; only a foreground run stays around to disconnect again."""
    result = await service.up()
    if not foreground or result.state is None:
        return result
    try:
        await service.wait()
    finally:
        try:
            service.down()
        except NordUpError as exc:  # a teardown error must not mask the interrupt
            LOGGER.error("failed to disconnect cleanly: %s", exc)
    return result


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    _configure_logging(args.verbose)
    try:
        if args.list_countries:
            return asyncio.run(_list_countries(args))
        if args.disconnect:
            return _disconnect(args)
        if args.status:
            return _status(args)
        options = options_from_args(args)
        result = asyncio.run(_connect(NordUpService(options), foreground=args.foreground))
    except KeyboardInterrupt:
        LOGGER.warning("interrupted")
        return EXIT_INTERRUPTED
    except BrokenPipeError:
        # Downstream closed the pipe (e.g. `nord-up --list-countries | head`).
        _discard_stdout()
        return EXIT_OK
    except NordUpError as exc:
        LOGGER.error("%s", exc)
        return exit_code_for(exc)

    if result.config_text is not None:
        sys.stdout.write(_redact(result.config_text))
    elif result.state is not None:
        _print_connection(result.state)
    else:
        LOGGER.info("connected to %s as %s", result.server, result.interface)
    return EXIT_OK
