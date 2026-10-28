"""CLI surface: arguments, output, exit codes (service stubbed out)."""

from __future__ import annotations

import time
from typing import Any

import pytest

from nord_up.cli import (
    EXIT_AUTH,
    EXIT_BUSY,
    EXIT_ERROR,
    EXIT_NO_SERVER,
    EXIT_OK,
    EXIT_PRIVILEGE,
    EXIT_USAGE,
    EXIT_WIREGUARD,
    build_parser,
    exit_code_for,
    main,
    options_from_args,
    resolve_token,
)
from nord_up.errors import (
    AuthError,
    BusyError,
    ConfigError,
    NoServerError,
    PrivilegeError,
    UsageError,
    WireGuardError,
)
from nord_up.models import Country, Server
from nord_up.service import ConnectionStatus, ConnectResult
from nord_up.state import ConnectionState
from nord_up.wgconfig import DEFAULT_MTU

SERVER = Server(id=7, hostname="node7.example.net", station="203.0.113.7", public_key="test-pub-a")


def _state(**overrides: Any) -> ConnectionState:
    values: dict[str, Any] = {
        "interface": "nordlynx_zz",
        "server": "node7.example.net",
        "endpoint": "203.0.113.7:51820",
        "address": "10.5.0.2/32",
        "config_path": "/run/nordlynx_zz.conf",
        "started_at": time.time(),
        "dns": "127.0.0.1",
    }
    values.update(overrides)
    return ConnectionState(**values)


def _stub_service(monkeypatch: pytest.MonkeyPatch, **handlers: Any) -> None:
    """Replace the service with a stand-in exposing only the given handlers."""

    def __init__(_self: Any, _options: Any) -> None:
        return None

    handlers.setdefault("__init__", __init__)
    monkeypatch.setattr("nord_up.cli.NordUpService", type("StubService", (), handlers))
    monkeypatch.setenv("NORD_TOKEN", "tok")


def test_parser_defaults_and_token_precedence(monkeypatch: pytest.MonkeyPatch) -> None:
    args = build_parser().parse_args([])
    assert (args.interface, args.dns, args.mtu, args.foreground) == (
        None,
        None,
        DEFAULT_MTU,
        False,
    )

    monkeypatch.setenv("NORD_TOKEN", "env-token")
    assert resolve_token(build_parser().parse_args([])) == "env-token"
    assert resolve_token(build_parser().parse_args(["-t", "flag-token"])) == "flag-token"

    monkeypatch.delenv("NORD_TOKEN", raising=False)
    with pytest.raises(UsageError):
        resolve_token(build_parser().parse_args([]))


def test_short_flags_alias_the_long_ones() -> None:
    for short, attribute in (
        ("-l", "list_countries"),
        ("-s", "status"),
        ("-d", "disconnect"),
        ("-f", "foreground"),
    ):
        assert getattr(build_parser().parse_args([short]), attribute) is True


def test_options_validate_country_dns_and_server_count(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("NORD_TOKEN", "tok")
    parse = build_parser().parse_args

    assert options_from_args(parse(["-c", "Zetland"])).country == "Zetland"
    assert options_from_args(parse([])).dns is None
    assert options_from_args(parse([])).mtu == DEFAULT_MTU
    assert options_from_args(parse(["--dns", "10.0.0.1"])).dns == "10.0.0.1"
    assert options_from_args(parse(["--mtu", "1400"])).mtu == 1400

    for argv in (["-c", "bad!"], ["--dns", "  "], ["--servers", "0"]):
        with pytest.raises(UsageError):
            options_from_args(parse(argv))

    with pytest.raises(SystemExit):  # removed in 2.0; DNS is opt-in now
        parse(["--no-dns"])


def test_exit_codes_are_stable() -> None:
    assert exit_code_for(UsageError("x")) == EXIT_USAGE
    assert exit_code_for(ConfigError("x")) == EXIT_USAGE
    assert exit_code_for(AuthError("x")) == EXIT_AUTH
    assert exit_code_for(NoServerError("x")) == EXIT_NO_SERVER
    assert exit_code_for(BusyError("x")) == EXIT_BUSY
    assert exit_code_for(PrivilegeError("x")) == EXIT_PRIVILEGE
    assert exit_code_for(WireGuardError("x")) == EXIT_WIREGUARD
    assert exit_code_for(ValueError("x")) == EXIT_ERROR


def test_list_countries_prints_a_table_without_a_token(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    class FakeApi:
        def __init__(self, _token: str, **_kwargs: Any) -> None:
            pass

        async def __aenter__(self) -> FakeApi:
            return self

        async def __aexit__(self, *_exc: object) -> bool:
            return False

        async def countries(self) -> list[Country]:
            return [Country(id=1, code="ZZ", name="Zetland")]

    monkeypatch.setattr("nord_up.cli.NordVpnApi", FakeApi)
    monkeypatch.delenv("NORD_TOKEN", raising=False)

    assert main(["--list-countries"]) == EXIT_OK
    assert capsys.readouterr().out.strip() == "ZZ     1  Zetland"


def test_dry_run_prints_the_redacted_config(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    async def up(_self: Any) -> ConnectResult:
        return ConnectResult(
            interface="nordlynx_zz",
            server=SERVER,
            config_text="[Interface]\nPrivateKey = test-secret\n",
        )

    _stub_service(monkeypatch, up=up)

    assert main(["--dry-run"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "test-secret" not in out
    assert "PrivateKey = <redacted>" in out


def test_connect_prints_the_connection_and_foreground_tears_down(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    calls: list[str] = []

    async def up(_self: Any) -> ConnectResult:
        calls.append("up")
        return ConnectResult(interface="nordlynx_zz", server=SERVER, state=_state())

    async def wait(_self: Any) -> None:
        calls.append("wait")

    def down(_self: Any) -> list[str]:
        calls.append("down")
        return ["nordlynx_zz"]

    _stub_service(monkeypatch, up=up, wait=wait, down=down)

    assert main([]) == EXIT_OK  # async: returns after printing the connection
    out = capsys.readouterr().out
    assert "nordlynx_zz (up)" in out
    assert "node7.example.net (203.0.113.7:51820)" in out
    assert "nord-up -d" in out
    assert calls == ["up"]

    assert main(["--foreground"]) == EXIT_OK
    assert calls == ["up", "up", "wait", "down"]


def test_disconnect_and_status_dispatch(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def down(_self: Any) -> list[str]:
        return ["nordlynx_zz"]

    def status(_self: Any) -> list[ConnectionStatus]:
        return [
            ConnectionStatus(interface="nordlynx_zz", up=True, state=_state()),
            ConnectionStatus(interface="nordlynx_qq", up=False),
        ]

    _stub_service(monkeypatch, down=down, status=status)

    assert main(["-d"]) == EXIT_OK
    assert "nordlynx_zz disconnected" in capsys.readouterr().out

    assert main(["--status"]) == EXIT_OK
    out = capsys.readouterr().out
    assert "nordlynx_zz (up)" in out
    assert "node7.example.net (203.0.113.7:51820)" in out


def test_status_exits_nonzero_with_nothing_connected(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def status(_self: Any) -> list[ConnectionStatus]:
        return [ConnectionStatus(interface="nordlynx_zz", up=False)]

    _stub_service(monkeypatch, status=status)

    assert main(["--status"]) == EXIT_ERROR
    assert "not connected" in capsys.readouterr().out


def test_service_errors_map_to_exit_codes(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    async def up(_self: Any) -> ConnectResult:
        raise AuthError("token rejected")

    _stub_service(monkeypatch, up=up)

    assert main([]) == EXIT_AUTH
    assert "token rejected" in capsys.readouterr().err
