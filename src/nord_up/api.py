"""Async NordVPN API client.

One pooled :class:`httpx.AsyncClient` serves every call; credentials and server
selection run concurrently, several failover candidates come back in a single
recommendation request, and the country table is cached in memory. Nothing is
cached on disk — the process leaves no residue.
"""

from __future__ import annotations

import asyncio
import base64
import logging
import random
from collections.abc import Awaitable, Callable, Mapping
from typing import Any

import httpx

from . import __version__
from .errors import ApiError, AuthError, NoServerError
from .models import NORDLYNX_TECHNOLOGY, Country, Credentials, Server, resolve_country

__all__ = [
    "DEFAULT_BASE_URL",
    "DEFAULT_RETRIES",
    "DEFAULT_TIMEOUT",
    "NordVpnApi",
]

LOGGER = logging.getLogger("nord_up.api")

DEFAULT_BASE_URL = "https://api.nordvpn.com"
DEFAULT_TIMEOUT = 10.0
DEFAULT_RETRIES = 3

CREDENTIALS_PATH = "/v1/users/services/credentials"
COUNTRIES_PATH = "/v1/servers/countries"
RECOMMENDATIONS_PATH = "/v1/servers/recommendations"

_USER_AGENT = f"nord-up/{__version__}"

#: Transient statuses worth another attempt.
_RETRY_STATUS = frozenset({408, 425, 429, 500, 502, 503, 504})

#: NordVPN returns HTTP 400 with this code for a bad/missing token.
_AUTH_ERROR_CODE = 100106

Sleeper = Callable[[float], Awaitable[None]]


class NordVpnApi:
    """Thin, retrying, connection-pooled client for the public NordVPN API."""

    def __init__(
        self,
        token: str,
        *,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = DEFAULT_TIMEOUT,
        retries: int = DEFAULT_RETRIES,
        backoff_base: float = 0.25,
        backoff_max: float = 4.0,
        max_connections: int = 16,
        transport: httpx.AsyncBaseTransport | None = None,
        sleeper: Sleeper | None = None,
    ) -> None:
        self._token = token
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout
        self._retries = max(0, retries)
        self._backoff_base = backoff_base
        self._backoff_max = backoff_max
        self._max_connections = max_connections
        self._transport = transport
        self._sleeper: Sleeper = sleeper or asyncio.sleep
        self._client: httpx.AsyncClient | None = None
        self._countries: list[Country] | None = None

    # -- lifecycle ---------------------------------------------------------

    async def __aenter__(self) -> NordVpnApi:
        headers = {
            "Accept": "application/json",
            "User-Agent": _USER_AGENT,
        }
        # Token as HTTP Basic (`curl -u "token:$TOKEN"`), set as a plain header:
        # httpx's `auth=` would rewrite the default headers on every request.
        if self._token:
            headers["Authorization"] = _basic_auth_header(self._token)
        self._client = httpx.AsyncClient(
            base_url=self._base_url,
            headers=headers,
            timeout=httpx.Timeout(self._timeout),
            limits=httpx.Limits(
                max_connections=self._max_connections,
                max_keepalive_connections=self._max_connections,
            ),
            follow_redirects=True,
            transport=self._transport,
        )
        return self

    async def __aexit__(self, *exc_info: object) -> None:
        await self.aclose()

    async def aclose(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    # -- public API --------------------------------------------------------

    async def credentials(self) -> Credentials:
        """Fetch the NordLynx private key bound to the access token.

        Sends the token as HTTP Basic (``curl -u "token:$TOKEN"``).  A 401 is
        terminal: a rejected token is never retried under another scheme.
        """
        payload = await self._get_json(CREDENTIALS_PATH)
        if not isinstance(payload, Mapping):
            raise ApiError("credentials response is not a JSON object")
        private_key = payload.get("nordlynx_private_key")
        if not isinstance(private_key, str) or not private_key:
            raise ApiError("credentials response has no nordlynx_private_key")
        return Credentials(private_key=private_key)

    async def countries(self) -> list[Country]:
        """All countries NordVPN serves, sorted by name (cached in memory)."""
        return list(await self._country_list())

    async def country(self, query: str) -> Country:
        """Resolve a country code or name to a country."""
        country = resolve_country(await self._country_list(), query)
        LOGGER.debug("country %r resolved to %s", query, country)
        return country

    async def recommend_servers(
        self, *, country_id: int | None = None, limit: int = 5
    ) -> list[Server]:
        """Return up to ``limit`` NordLynx servers, best first."""
        params: dict[str, str] = {
            "filters[servers_technologies][identifier]": NORDLYNX_TECHNOLOGY,
            "limit": str(max(1, min(limit, 100))),
        }
        if country_id is not None:
            params["filters[country_id]"] = str(country_id)

        payload = await self._get_json(RECOMMENDATIONS_PATH, params=params)
        if not isinstance(payload, list):
            raise ApiError("recommendations response is not a JSON array")

        servers: list[Server] = []
        for record in payload:
            if not isinstance(record, Mapping):
                continue
            server = Server.from_api(record)
            if server is not None:
                servers.append(server)

        if not servers:
            scope = "for the requested country" if country_id is not None else "in the region"
            raise NoServerError(f"no usable NordLynx server {scope}")
        return servers

    # -- internals ---------------------------------------------------------

    async def _country_list(self) -> list[Country]:
        if self._countries is None:
            payload = await self._get_json(COUNTRIES_PATH)
            if not isinstance(payload, list):
                raise ApiError("countries response is not a JSON array")
            countries: list[Country] = []
            for record in payload:
                if not isinstance(record, Mapping):
                    continue
                country = Country.from_api(record)
                if country is not None:
                    countries.append(country)
            countries.sort(key=lambda country: country.name)
            self._countries = countries
        return self._countries

    async def _get_json(
        self,
        path: str,
        params: Mapping[str, str] | None = None,
    ) -> Any:
        if self._client is None:  # pragma: no cover - misuse guard
            raise RuntimeError("NordVpnApi must be used as an async context manager")

        attempt = 0
        while True:
            try:
                response = await self._client.get(path, params=params)
            except httpx.HTTPError as exc:
                if attempt >= self._retries:
                    raise ApiError(f"GET {path} failed: {exc}") from exc
                await self._backoff(attempt, None, path)
                attempt += 1
                continue

            status = response.status_code
            if status >= 400:
                if status in _RETRY_STATUS and attempt < self._retries:
                    await self._backoff(attempt, _retry_after(response), path)
                    attempt += 1
                    continue
                payload = _json_or_none(response)
                code = _error_field(payload, "code")
                if status in (401, 403) or code == _AUTH_ERROR_CODE:
                    detail = _error_field(payload, "message")
                    note = f": {detail}" if isinstance(detail, str) and detail else ""
                    raise AuthError(
                        f"NordVPN rejected the access token (HTTP {status}{note}); check NORD_TOKEN"
                    )
                raise ApiError(f"GET {path} returned HTTP {status}: {_snippet(response)}")

            try:
                return response.json()
            except ValueError as exc:
                raise ApiError(f"GET {path} returned malformed JSON") from exc

    async def _backoff(self, attempt: int, retry_after: float | None, path: str) -> None:
        if retry_after is not None:
            delay = retry_after
        else:
            ceiling = min(self._backoff_max, self._backoff_base * (2**attempt))
            delay = random.uniform(0, ceiling)  # full jitter
        LOGGER.debug(
            "retrying %s in %.2fs (attempt %d/%d)", path, delay, attempt + 1, self._retries
        )
        await self._sleeper(delay)


def _basic_auth_header(token: str) -> str:
    """The ``Authorization`` value equivalent to ``curl -u "token:<token>"``."""
    return "Basic " + base64.b64encode(f"token:{token}".encode()).decode()


def _retry_after(response: httpx.Response) -> float | None:
    raw = response.headers.get("Retry-After")
    if raw is None:
        return None
    try:
        return max(0.0, float(raw))
    except ValueError:
        return None


def _json_or_none(response: httpx.Response) -> Any:
    try:
        return response.json()
    except ValueError:
        return None


def _error_field(payload: Any, key: str) -> Any:
    """Read ``errors[key]`` from an API error body, tolerating both shapes."""
    if not isinstance(payload, Mapping):
        return None
    errors = payload.get("errors")
    if isinstance(errors, Mapping):
        return errors.get(key)
    if isinstance(errors, list):
        for item in errors:
            if isinstance(item, Mapping) and key in item:
                return item[key]
    return None


def _snippet(response: httpx.Response) -> str:
    text = response.text.strip().replace("\n", " ")
    return text[:200] if text else "<empty body>"
