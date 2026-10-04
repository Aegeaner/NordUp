"""Connect/disconnect lifecycle with injected fakes (no network, no root).

Fixtures are reserved values: example.net hostnames, RFC 5737 addresses, fake
keys and a fictional country.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest

from nord_up.errors import BusyError, WireGuardError
from nord_up.models import Country, Credentials, Server
from nord_up.runtime import RuntimeWorkspace
from nord_up.service import ConnectOptions, NordUpService
from nord_up.state import read_state

LINK = "nordlynx_zz"  # link name is derived from the country code
CONFIG = f"{LINK}.conf"
STATE = f"{LINK}.state.json"
PRIVATE_KEY = "test-private-key"
ZETLAND = Country(id=1, code="ZZ", name="Zetland")
SERVERS = [
    Server(id=7, hostname="node7.example.net", station="203.0.113.7", public_key="test-pub-a"),
    Server(id=8, hostname="node8.example.net", station="203.0.113.8", public_key="test-pub-b"),
]


@pytest.fixture(autouse=True)
def _resolv_conf(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Keep the DNS policy deterministic: a resolver that is not the pinned one."""
    resolv = tmp_path / "resolv.conf"
    resolv.write_text("nameserver 203.0.113.53\n")
    monkeypatch.setenv("NORD_UP_RESOLV_CONF", str(resolv))
    monkeypatch.setattr("nord_up.service.require_privileges", lambda: None)
    return resolv


class FakeApi:
    """Minimal stand-in for ``NordVpnApi``; records what the service asked for."""

    def __init__(self, token: str, **kwargs: Any) -> None:
        self.token = token
        self.kwargs = kwargs
        self.country_query: str | None = None
        self.country_id: int | None = None
        self.limit: int | None = None

    async def __aenter__(self) -> FakeApi:
        return self

    async def __aexit__(self, *exc_info: object) -> bool:
        return False

    async def credentials(self) -> Credentials:
        return Credentials(private_key=PRIVATE_KEY)

    async def country(self, query: str) -> Country:
        self.country_query = query
        return ZETLAND

    async def recommend_servers(
        self, *, country_id: int | None = None, limit: int = 5
    ) -> list[Server]:
        self.country_id = country_id
        self.limit = limit
        return list(SERVERS)


class FakeWG:
    """Records wg-quick calls; ``fail_ups``/``fail_downs`` fail the first N."""

    def __init__(self, fail_ups: int = 0, fail_downs: int = 0, already_up: bool = False) -> None:
        self.ups: list[Path] = []
        self.contents: list[str] = []
        self.downs: list[Path] = []
        self.fail_ups = fail_ups
        self.fail_downs = fail_downs
        self._up = already_up

    def require_available(self) -> None:
        return None

    def is_up(self, _interface: str) -> bool:
        return self._up

    def up(self, config_path: Path) -> None:
        self.ups.append(Path(config_path))
        if len(self.ups) <= self.fail_ups:
            raise WireGuardError("refused to bring up")
        self.contents.append(self.ups[-1].read_text())
        self._up = True

    def down(self, config_path: Path) -> None:
        self.downs.append(Path(config_path))
        if self.fail_downs > 0:
            self.fail_downs -= 1
            raise WireGuardError("refused to bring down")
        self._up = False

    def delete_link(self, _interface: str) -> None:
        self._up = False


def _service(tmp_path: Path, wg: FakeWG, stop: asyncio.Event | None = None, **overrides: Any):
    """A service wired to the fakes; ``country="zz"`` unless overridden."""
    values: dict[str, Any] = {
        "token": "tok",
        "country": "zz",
        "runtime_root": tmp_path / "run",
        **overrides,
    }
    return NordUpService(ConnectOptions(**values), api_factory=FakeApi, wg=wg, stop_event=stop)


def _up(tmp_path: Path, wg: FakeWG, **overrides: Any) -> Any:
    return asyncio.run(_service(tmp_path, wg, **overrides).up())


def test_dry_run_renders_the_config_and_leaves_nothing(tmp_path: Path) -> None:
    wg = FakeWG()

    result = _up(tmp_path, wg, dry_run=True)

    assert result.state is None
    assert result.interface == LINK
    assert "DNS = 127.0.0.1" in result.config_text
    assert "Endpoint = 203.0.113.7:51820" in result.config_text
    assert wg.ups == []
    assert not (tmp_path / "run").exists()


@pytest.mark.parametrize(("resolver", "pinned"), [("203.0.113.53", True), ("127.0.0.1", False)])
def test_dns_is_pinned_unless_the_stub_already_is_the_resolver(
    tmp_path: Path, _resolv_conf: Path, resolver: str, pinned: bool
) -> None:
    _resolv_conf.write_text(f"nameserver {resolver}\n")

    result = _up(tmp_path, FakeWG(), dry_run=True)

    assert ("DNS = 127.0.0.1" in result.config_text) is pinned


def test_up_leaves_the_tunnel_running_and_records_it(tmp_path: Path) -> None:
    wg = FakeWG()

    result = _up(tmp_path, wg)

    assert wg.ups == [result.config_path] and wg.downs == []
    assert result.config_path is not None and result.config_path.exists()

    state = read_state(tmp_path / "run" / STATE)
    assert state is not None
    assert (state.interface, state.server, state.endpoint) == (
        LINK,
        "node7.example.net",
        "203.0.113.7:51820",
    )
    assert (state.address, state.dns) == ("10.5.0.2/32", "127.0.0.1")

    with RuntimeWorkspace(LINK, root=tmp_path / "run"):
        pass  # the lock was released: the CLI process may exit


def test_up_refuses_an_existing_link_without_touching_it(tmp_path: Path) -> None:
    wg = FakeWG()
    service = _service(tmp_path, wg)

    async def go() -> None:
        await service.up()
        await service.up()

    with pytest.raises(BusyError, match="already connected"):
        asyncio.run(go())

    assert wg.downs == []
    assert (tmp_path / "run" / CONFIG).exists()
    assert read_state(tmp_path / "run" / STATE) is not None


def test_stale_state_and_config_from_a_killed_run_are_recovered(tmp_path: Path) -> None:
    root = tmp_path / "run"
    root.mkdir(parents=True)
    (root / CONFIG).write_text("[Interface]\nPrivateKey = stale-key\n")
    (root / STATE).write_text('{"interface": "broken"\n')
    wg = FakeWG(already_up=True)

    result = _up(tmp_path, wg)

    assert wg.downs == [root / CONFIG]  # stale link taken down before reconnecting
    assert result.config_path == root / CONFIG
    assert "stale-key" not in wg.contents[0] and PRIVATE_KEY in wg.contents[0]


def test_disconnect_is_idempotent_and_retryable(tmp_path: Path) -> None:
    wg = FakeWG(fail_downs=1)
    service = _service(tmp_path, wg)
    asyncio.run(service.up())

    with pytest.raises(WireGuardError):
        service.down()  # nothing deleted: wait for the retry
    assert (tmp_path / "run" / CONFIG).exists()
    assert read_state(tmp_path / "run" / STATE) is not None

    assert service.down() == [LINK]
    assert wg.downs == [tmp_path / "run" / CONFIG, tmp_path / "run" / CONFIG]
    assert not (tmp_path / "run").exists()
    assert service.down() == []


def test_status_reports_the_live_link(tmp_path: Path) -> None:
    wg = FakeWG()
    service = _service(tmp_path, wg)
    assert service.status() == []

    asyncio.run(service.up())

    (report,) = service.status()
    assert (report.interface, report.up) == (LINK, True)
    assert report.state is not None and report.state.server == "node7.example.net"


def test_foreground_lifecycle_waits_then_tears_down(tmp_path: Path) -> None:
    stop = asyncio.Event()
    wg = FakeWG()
    service = _service(tmp_path, wg, stop=stop)

    async def go() -> Any:
        result = await service.up()
        stop.set()
        await service.wait()
        return result, service.down()

    result, removed = asyncio.run(go())

    assert removed == [LINK]
    assert wg.downs == [result.config_path]
    assert not (tmp_path / "run").exists()


def test_failover_then_all_candidates_failing(tmp_path: Path) -> None:
    result = _up(tmp_path, FakeWG(fail_ups=1))
    assert result.server is SERVERS[1]

    wg = FakeWG(fail_ups=len(SERVERS))
    with pytest.raises(WireGuardError, match="no candidate"):
        _up(tmp_path, wg)
    assert not (tmp_path / "run").exists()  # nothing half-configured is left
