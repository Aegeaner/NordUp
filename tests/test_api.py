"""NordVPN API client. Fixtures use reserved values: example.net, RFC 5737 IPs."""

from __future__ import annotations

import asyncio
import base64
from typing import Any

import httpx
import pytest

from nord_up.api import NordVpnApi
from nord_up.errors import ApiError, AuthError, NoServerError

PRIVATE_KEY = "test-private-key"
CREDENTIALS = {"nordlynx_private_key": PRIVATE_KEY, "username": "test-user"}
COUNTRIES = [
    {"id": 1, "code": "ZZ", "name": "Zetland"},
    {"id": 2, "code": "QQ", "name": "Quoland"},
    {"id": 3, "code": "VV", "name": "Verdania"},
    {"id": 4, "code": "ZM", "name": "Zetland Minor"},
]
RECOMMENDATIONS = [
    {
        "id": 7,
        "hostname": "node7.example.net",
        "station": "203.0.113.7",
        "technologies": [
            {
                "identifier": "wireguard_udp",
                "metadata": [{"name": "public_key", "value": "test-pub-a"}],
            }
        ],
    },
    {
        "id": 8,
        "hostname": "node8.example.net",
        "station": "203.0.113.8",
        "technologies": [
            {
                "identifier": "wireguard_udp",
                "metadata": [{"key": "public_key", "value": "test-pub-b"}],
            }
        ],
    },
    {"id": 9, "hostname": "node9.example.net", "station": "", "technologies": []},
]


def _client(handler: Any, token: str = "tok", **kwargs: Any) -> NordVpnApi:
    kwargs.setdefault("sleeper", lambda _delay: asyncio.sleep(0))
    return NordVpnApi(
        token, base_url="https://api.test", transport=httpx.MockTransport(handler), **kwargs
    )


def _run(coro: Any) -> Any:
    return asyncio.run(coro)


def test_credentials_use_basic_auth_and_parse_the_key() -> None:
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["auth"] = request.headers["authorization"]
        return httpx.Response(200, json=CREDENTIALS)

    async def go() -> Any:
        async with _client(handler) as api:
            return await api.credentials()

    credentials = _run(go())
    assert credentials.private_key == PRIVATE_KEY
    assert PRIVATE_KEY not in repr(credentials)  # never leak key material
    assert seen["auth"] == "Basic " + base64.b64encode(b"token:tok").decode()


@pytest.mark.parametrize(("status", "code"), [(401, 101301), (400, 100106)])
def test_a_rejected_token_is_terminal(status: int, code: int) -> None:
    calls: list[int] = []

    def handler(_request: httpx.Request) -> httpx.Response:
        calls.append(1)
        return httpx.Response(status, json={"errors": {"message": "nope", "code": code}})

    async def go() -> None:
        async with _client(handler) as api:
            await api.credentials()

    with pytest.raises(AuthError, match=f"HTTP {status}"):
        _run(go())
    assert len(calls) == 1  # one auth scheme only


def test_countries_are_sorted_cached_and_fetched_without_a_token() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json=COUNTRIES)

    async def go() -> list[str]:
        async with _client(handler, token="") as api:
            await api.countries()
            return [country.name for country in await api.countries()]

    assert _run(go()) == ["Quoland", "Verdania", "Zetland", "Zetland Minor"]
    assert len(requests) == 1  # cached in memory
    assert "authorization" not in requests[0].headers


def test_country_resolution_covers_codes_names_punctuation_and_ambiguity() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=COUNTRIES)

    async def go() -> tuple[str, str, str]:
        async with _client(handler) as api:
            return (
                (await api.country("ZZ")).name,
                (await api.country("z.e.t.l.a.n.d")).name,
                (await api.country("verd")).name,
            )

    assert _run(go()) == ("Zetland", "Zetland", "Verdania")

    async def ambiguous() -> None:
        async with _client(handler) as api:
            await api.country("zet")

    with pytest.raises(NoServerError, match="ambiguous"):
        _run(ambiguous())


def test_recommendations_parse_both_key_spellings_and_send_filters() -> None:
    seen: dict[str, str] = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen.update(dict(request.url.params))
        return httpx.Response(200, json=RECOMMENDATIONS)

    async def go() -> list[Any]:
        async with _client(handler) as api:
            return await api.recommend_servers(country_id=1, limit=3)

    servers = _run(go())
    assert [server.endpoint for server in servers] == [
        "203.0.113.7:51820",
        "203.0.113.8:51820",
    ]
    assert servers[1].public_key == "test-pub-b"  # `key` metadata spelling
    assert seen["filters[country_id]"] == "1"
    assert seen["filters[servers_technologies][identifier]"] == "wireguard_udp"


def test_recommendations_without_usable_rows_fail() -> None:
    def handler(_request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=[RECOMMENDATIONS[2]])

    async def go() -> None:
        async with _client(handler) as api:
            await api.recommend_servers(limit=1)

    with pytest.raises(NoServerError):
        _run(go())


def test_transient_errors_are_retried_and_retry_after_is_honoured() -> None:
    delays: list[float] = []
    attempts: list[int] = []

    async def sleeper(delay: float) -> None:
        delays.append(delay)

    def handler(_request: httpx.Request) -> httpx.Response:
        attempts.append(1)
        if len(attempts) == 1:
            return httpx.Response(503, headers={"Retry-After": "2.5"})
        return httpx.Response(200, json=CREDENTIALS)

    async def go() -> str:
        async with _client(handler, retries=1, sleeper=sleeper) as api:
            return (await api.credentials()).private_key

    assert _run(go()) == PRIVATE_KEY
    assert attempts == [1, 1] and delays == [2.5]


@pytest.mark.parametrize("mode", ["transport", "malformed", "exhausted"])
def test_unusable_responses_are_api_errors(mode: str) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if mode == "transport":
            raise httpx.ConnectError("no route to host", request=request)
        if mode == "malformed":
            return httpx.Response(200, text="<html>not json</html>")
        return httpx.Response(500, text="boom")

    async def go() -> None:
        async with _client(handler, retries=1, backoff_base=0.0) as api:
            await api.credentials()

    with pytest.raises(ApiError):
        _run(go())
