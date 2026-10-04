"""Domain models shared across the package."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any

from .errors import NoServerError

__all__ = [
    "NORDLYNX_PORT",
    "NORDLYNX_TECHNOLOGY",
    "Country",
    "Credentials",
    "Server",
    "normalize_country_query",
    "resolve_country",
]

#: NordLynx is NordVPN's WireGuard deployment; UDP/51820 on every station.
NORDLYNX_PORT = 51820

#: Technology identifier used by the public API for NordLynx.
NORDLYNX_TECHNOLOGY = "wireguard_udp"


@dataclass(frozen=True, slots=True)
class Credentials:
    """NordLynx credentials minted by the API for the current token."""

    #: Kept out of repr(): a dataclass repr would otherwise leak the key.
    private_key: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class Server:
    """One NordLynx-capable server from the recommendations endpoint."""

    id: int
    hostname: str
    station: str
    public_key: str

    @property
    def endpoint(self) -> str:
        """``host:port`` suitable for the ``Endpoint`` directive."""
        return f"{self.station}:{NORDLYNX_PORT}"

    @classmethod
    def from_api(cls, payload: Mapping[str, Any]) -> Server | None:
        """Parse one API record, or ``None`` when it cannot make a tunnel.

        The public key is nested in ``technologies[].metadata[]``; records
        without a station IP or key are discarded rather than raising.
        """
        station = payload.get("station")
        public_key = _technology_metadata(
            payload.get("technologies"), NORDLYNX_TECHNOLOGY, "public_key"
        )
        if not isinstance(station, str) or not station or not public_key:
            return None
        server_id = payload.get("id")
        hostname = payload.get("hostname")
        return cls(
            id=server_id if isinstance(server_id, int) else 0,
            hostname=hostname if isinstance(hostname, str) and hostname else station,
            station=station,
            public_key=public_key,
        )

    def __str__(self) -> str:
        return f"{self.hostname} ({self.station})"


@dataclass(frozen=True, slots=True)
class Country:
    """A country offered by NordVPN, as listed by ``/v1/servers/countries``."""

    id: int
    code: str
    name: str

    @classmethod
    def from_api(cls, payload: Mapping[str, Any]) -> Country | None:
        code = payload.get("code")
        name = payload.get("name")
        identifier = payload.get("id")
        if not isinstance(code, str) or not code or not isinstance(name, str) or not name:
            return None
        return cls(id=identifier if isinstance(identifier, int) else 0, code=code, name=name)


#: Colloquial names mapped onto the official country name.  Explicit and small:
#: guessing silently connects users to the wrong country.
_COUNTRY_ALIASES: dict[str, str] = {
    "usa": "unitedstates",
    "usofa": "unitedstates",
    "america": "unitedstates",
    "uk": "unitedkingdom",
    "britain": "unitedkingdom",
    "greatbritain": "unitedkingdom",
    "uae": "unitedarabemirates",
    "korea": "southkorea",
    "skorea": "southkorea",
    "czechia": "czechrepublic",
}

_NON_ALPHANUMERIC = re.compile(r"[^a-z0-9]+")


def normalize_country_query(value: str) -> str:
    """Canonicalize a code or name: case and punctuation are ignored."""
    return _NON_ALPHANUMERIC.sub("", value.lower())


def resolve_country(countries: Iterable[Country], query: str) -> Country:
    """Resolve a country code or name to a single :class:`Country`.

    Matching order: exact code, exact name, known alias, then a unique
    substring of the name.  Ambiguous and unknown queries raise
    :class:`NoServerError` so the caller gets an actionable message instead of
    an arbitrary server on another continent.
    """
    normalized = normalize_country_query(query)
    if not normalized:
        raise NoServerError("empty country query")

    table = list(countries)
    normalized_alias = _COUNTRY_ALIASES.get(normalized, normalized)

    for country in table:
        if normalize_country_query(country.code) == normalized:
            return country
    for country in table:
        if normalize_country_query(country.name) == normalized_alias:
            return country

    partial = [c for c in table if normalized_alias in normalize_country_query(c.name)]
    if len(partial) == 1:
        return partial[0]
    if partial:
        names = ", ".join(sorted(c.name for c in partial))
        raise NoServerError(f"country {query!r} is ambiguous: matches {names}; use a country code")
    raise NoServerError(f"unknown country {query!r}; list valid options with --list-countries")


def _technology_metadata(technologies: Any, identifier: str, key: str) -> str | None:
    """Extract ``key`` from a technology's metadata list.

    Entries are labelled ``name`` by the live API and ``key`` by some payloads;
    both spellings are accepted.
    """
    if not isinstance(technologies, (list, tuple)):
        return None
    for technology in technologies:
        if not isinstance(technology, Mapping):
            continue
        if technology.get("identifier") != identifier:
            continue
        metadata = technology.get("metadata")
        if not isinstance(metadata, Sequence) or isinstance(metadata, (str, bytes)):
            continue
        for item in metadata:
            if not isinstance(item, Mapping):
                continue
            label = item.get("name")
            if label is None:
                label = item.get("key")
            if label != key:
                continue
            value = item.get("value")
            if isinstance(value, str) and value:
                return value
    return None
