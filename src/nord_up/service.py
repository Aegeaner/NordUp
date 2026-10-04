"""Connection lifecycle orchestration.

``NordUpService`` splits the lifecycle into four steps so the CLI can choose how
long it stays around:

* :meth:`NordUpService.up` - preflight, resolve the country, open the workspace,
  recover, then ``wg-quick up``.  The interface is named after the country
  (``nordlynx_zz``), and the config, the state record and the live link are left
  in place with the lock released, so the process may exit while the tunnel keeps
  running.
* :meth:`NordUpService.wait` - block until SIGINT/SIGTERM/SIGHUP.
* :meth:`NordUpService.down` - ``wg-quick down`` and delete every artifact, for
  one link or for every link in the workspace.
* :meth:`NordUpService.status` - read-only report of the live links.

A failed ``down`` raises *before* deleting anything, so the disconnect can just
be retried.
"""

from __future__ import annotations

import asyncio
import logging
import signal
import time
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

from .api import DEFAULT_BASE_URL, DEFAULT_RETRIES, DEFAULT_TIMEOUT, NordVpnApi
from .errors import BusyError, NordUpError, WireGuardError
from .models import Country, Credentials, Server
from .runtime import (
    RuntimeWorkspace,
    discover_interfaces,
    interface_name,
    write_private,
)
from .state import ConnectionState, read_state, remove_state, write_state
from .wgconfig import (
    DEFAULT_ADDRESS,
    DEFAULT_KEEPALIVE,
    PROXY_DNS,
    enforce_dns_directory,
    render_config,
    resolver_already_in_use,
)
from .wireguard import WireGuardTool, require_privileges

__all__ = ["ConnectOptions", "ConnectResult", "ConnectionStatus", "NordUpService"]

LOGGER = logging.getLogger("nord_up.service")

_SIGNALS = ("SIGINT", "SIGTERM", "SIGHUP")


class Api(Protocol):
    """The slice of :class:`NordVpnApi` the service depends on."""

    async def credentials(self) -> Credentials: ...

    async def country(self, query: str) -> Country: ...

    async def recommend_servers(
        self, *, country_id: int | None = None, limit: int = 5
    ) -> list[Server]: ...


class Tool(Protocol):
    """The slice of :class:`WireGuardTool` the service depends on."""

    def require_available(self) -> None: ...

    def is_up(self, interface: str) -> bool: ...

    def up(self, config_path: Path) -> None: ...

    def down(self, config_path: Path) -> None: ...

    def delete_link(self, interface: str) -> None: ...


@dataclass(frozen=True, slots=True)
class ConnectOptions:
    """Everything that shapes one connection attempt."""

    token: str
    country: str | None = None
    #: ``None`` derives the link name from the resolved country code.
    interface: str | None = None
    dns: str | None = PROXY_DNS
    address: str = DEFAULT_ADDRESS
    keepalive: int = DEFAULT_KEEPALIVE
    server_limit: int = 5
    timeout: float = DEFAULT_TIMEOUT
    retries: int = DEFAULT_RETRIES
    api_base: str = DEFAULT_BASE_URL
    dry_run: bool = False
    runtime_root: Path | None = None


@dataclass(frozen=True, slots=True)
class ConnectResult:
    """Outcome of a successful (or dry-run) connection."""

    interface: str
    server: Server
    config_path: Path | None = None
    config_text: str | None = None
    state: ConnectionState | None = None


@dataclass(frozen=True, slots=True)
class ConnectionStatus:
    """What :meth:`NordUpService.status` found on disk and in the kernel."""

    interface: str
    up: bool
    state: ConnectionState | None = None


class NordUpService:
    """Owns the connect/disconnect lifecycle."""

    def __init__(
        self,
        options: ConnectOptions,
        *,
        api_factory: Callable[..., Api] | None = None,
        wg: Tool | None = None,
        workspace_factory: Callable[..., RuntimeWorkspace] = RuntimeWorkspace,
        stop_event: asyncio.Event | None = None,
    ) -> None:
        self.options = options
        self._api_factory: Callable[..., Api] = api_factory or NordVpnApi
        self._wg = wg
        self._workspace_factory = workspace_factory
        self._stop_event = stop_event

    # -- connect / stay / disconnect ---------------------------------------

    async def up(self) -> ConnectResult:
        """Bring the tunnel up and leave it running.

        On success the workspace (config + state) stays on disk, the link is up
        and the lock is released, so the caller can return while the tunnel keeps
        running.  A dry run renders the config, touches nothing and removes the
        workspace.
        """
        options = self.options
        wg = self._tool()
        if not options.dry_run:
            wg.require_available()
            require_privileges()

        async with self._api_factory(
            options.token,
            base_url=options.api_base,
            timeout=options.timeout,
            retries=options.retries,
        ) as api:
            # The country is resolved first: it names the interface.
            country = await api.country(options.country) if options.country else None
            interface = interface_name(
                country.code if country is not None else None, options.interface
            )
            LOGGER.info("link %s", interface)

            workspace = self._workspace_factory(interface, root=options.runtime_root)
            workspace.open()

            # Refusing comes first and cleans up nothing: those artifacts belong
            # to the live connection and must survive an attempt to replace it.
            if not options.dry_run:
                try:
                    self._refuse_if_connected(workspace, wg)
                except BaseException:
                    workspace.release()
                    raise

            keep = False
            try:
                if not options.dry_run:
                    self._recover_stale(workspace, wg, interface)
                credentials, servers = await asyncio.gather(
                    api.credentials(),
                    api.recommend_servers(
                        country_id=country.id if country is not None else None,
                        limit=options.server_limit,
                    ),
                )
                LOGGER.info("%d NordLynx candidate(s) for %s", len(servers), interface)
                result = self._activate(workspace, wg, credentials, servers, interface)
                if result.state is None:
                    return result  # dry run
                write_state(workspace.state_path, result.state)
                keep = True
                return result
            finally:
                if keep:
                    workspace.release()
                else:
                    workspace.cleanup()

    async def wait(self) -> None:
        """Block until SIGINT/SIGTERM/SIGHUP (or the injected stop event)."""
        if self._stop_event is not None:
            LOGGER.info("connected; waiting for shutdown")
            await self._stop_event.wait()
            return

        stop = asyncio.Event()
        loop = asyncio.get_running_loop()
        installed: list[signal.Signals] = []
        for name in _SIGNALS:
            sig = getattr(signal, name, None)
            if sig is None:
                continue
            try:
                loop.add_signal_handler(sig, stop.set)
            except (NotImplementedError, RuntimeError, ValueError):
                continue
            installed.append(sig)
        try:
            LOGGER.info("connected; press Ctrl+C to disconnect and clean up")
            await stop.wait()
        finally:
            for sig in installed:
                with suppress(Exception):
                    loop.remove_signal_handler(sig)

    def down(self) -> list[str]:
        """Disconnect every targeted link and delete its artifacts.

        Targets are ``--interface`` when given, otherwise every nord-up link in
        the workspace.  Returns the links that were removed.  A ``wg-quick down``
        failure propagates *before* anything is deleted, so it can be retried.
        """
        removed: list[str] = []
        for interface in self._targets():
            if self._down_one(interface):
                removed.append(interface)
        return removed

    def status(self) -> list[ConnectionStatus]:
        """Report every targeted link.  Read-only: takes no lock."""
        wg = self._tool()
        reports: list[ConnectionStatus] = []
        for interface in self._targets():
            workspace = self._workspace_factory(interface, root=self.options.runtime_root)
            state = read_state(workspace.state_path)
            up = self._probe(wg, interface)
            reports.append(
                ConnectionStatus(interface=interface, up=up, state=state if up else None)
            )
        return reports

    # -- core flow ---------------------------------------------------------

    def _tool(self) -> Tool:
        return self._wg if self._wg is not None else WireGuardTool()

    def _targets(self) -> list[str]:
        """One explicit ``--interface``, else whatever the workspace holds."""
        override = self.options.interface
        if override:
            return [override]
        return discover_interfaces(self.options.runtime_root)

    def _effective_dns(self) -> str | None:
        """The resolver to pin, or ``None`` to leave ``/etc/resolv.conf`` alone.

        A ``DNS`` directive makes wg-quick rewrite the system resolver; when the
        system already resolves *only* through that address the rewrite is a
        no-op and is skipped, avoiding wg-quick's `resolvconf` plumbing.
        """
        dns = self.options.dns
        if dns is None:
            return None
        if resolver_already_in_use(dns):
            LOGGER.info("system resolver already uses %s; not asking wg-quick to rewrite it", dns)
            return None
        return dns

    def _activate(
        self,
        workspace: RuntimeWorkspace,
        wg: Tool,
        credentials: Credentials,
        servers: list[Server],
        interface: str,
    ) -> ConnectResult:
        options = self.options
        failures: list[str] = []
        dns = self._effective_dns()

        for server in servers:
            config = render_config(
                private_key=credentials.private_key,
                server=server,
                address=options.address,
                dns=dns,
                keepalive=options.keepalive,
            )
            write_private(workspace.config_path, config)
            if dns is None:
                LOGGER.debug("no DNS directive: wg-quick leaves /etc/resolv.conf alone")
            else:
                changed = enforce_dns_directory(workspace.directory, dns)
                LOGGER.debug("DNS pinned to %s; %d config file(s) rewritten", dns, len(changed))

            if options.dry_run:
                return ConnectResult(
                    interface=interface,
                    server=server,
                    config_path=workspace.config_path,
                    config_text=config,
                )

            LOGGER.info("bringing up %s on %s via %s", server, interface, workspace.config_path)
            try:
                wg.up(workspace.config_path)
            except WireGuardError as exc:
                failures.append(f"{server}: {exc}")
                LOGGER.warning("server %s failed: %s", server, exc)
                self._force_down(wg, interface)
                continue
            return ConnectResult(
                interface=interface,
                server=server,
                config_path=workspace.config_path,
                state=ConnectionState(
                    interface=interface,
                    server=server.hostname,
                    endpoint=server.endpoint,
                    address=options.address,
                    config_path=str(workspace.config_path),
                    started_at=time.time(),
                    dns=dns,
                ),
            )

        raise WireGuardError(
            "no candidate server could be brought up"
            + ("".join(f"\n  - {failure}" for failure in failures))
        )

    # -- recovery and teardown ---------------------------------------------

    def _probe(self, wg: Tool, interface: str) -> bool:
        """Is the link up?  A broken probe counts as up: do not stomp blindly."""
        try:
            return wg.is_up(interface)
        except NordUpError as exc:
            LOGGER.warning("cannot probe %s (%s); assuming it is up", interface, exc)
            return True

    def _refuse_if_connected(self, workspace: RuntimeWorkspace, wg: Tool) -> None:
        """Two live tunnels on one link cannot coexist; say so plainly."""
        state = read_state(workspace.state_path)
        if state is None:
            return
        if self._probe(wg, state.interface):
            raise BusyError(
                f"already connected to {state.server} on {state.interface}; "
                "run `nord-up --disconnect` first"
            )
        LOGGER.warning("state for %s is stale (link is down); removing it", state.interface)
        remove_state(workspace.state_path)

    def _recover_stale(self, workspace: RuntimeWorkspace, wg: Tool, interface: str) -> None:
        """Deal with an interface/config a killed previous run left behind."""
        # Not connected (checked above), so any record for this link is stale.
        remove_state(workspace.state_path)
        config = workspace.config_path
        if not config.exists():
            return
        LOGGER.warning("found config left by a previous run: %s", config)
        if self._probe(wg, interface):
            LOGGER.warning("link %s is still up; taking it down", interface)
            with suppress(NordUpError):
                wg.down(config)
        with suppress(OSError):
            config.unlink()

    def _down_one(self, interface: str) -> bool:
        wg = self._tool()
        workspace = self._workspace_factory(interface, root=self.options.runtime_root)
        workspace.open()
        try:
            removed = self._disconnect(workspace, wg, interface)
        except BaseException:
            workspace.release()  # keep config + state so a retry can work
            raise
        workspace.cleanup()
        return removed

    def _disconnect(self, workspace: RuntimeWorkspace, wg: Tool, interface: str) -> bool:
        leftovers = read_state(workspace.state_path) is not None or workspace.config_path.exists()
        if self._probe(wg, interface):
            LOGGER.info("disconnecting %s", interface)
            if workspace.config_path.exists():
                wg.down(workspace.config_path)
            else:
                wg.delete_link(interface)
            return True
        if leftovers:
            LOGGER.debug("link %s is already down; removing leftovers", interface)
        return leftovers

    def _force_down(self, wg: Tool, interface: str) -> None:
        """Remove a half-configured interface before trying the next server.

        Best effort by design: a failing probe or teardown must never mask the
        original ``up`` failure that sent us here.
        """
        with suppress(Exception):
            if wg.is_up(interface):
                wg.delete_link(interface)
