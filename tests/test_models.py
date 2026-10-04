"""Country resolution: codes, names, aliases, ambiguity (pure, no network)."""

from __future__ import annotations

import pytest

from nord_up.errors import NoServerError
from nord_up.models import Country, normalize_country_query, resolve_country

ZETLAND = Country(id=1, code="ZZ", name="Zetland")
ZETLAND_MINOR = Country(id=4, code="ZM", name="Zetland Minor")
QUOLAND = Country(id=2, code="QQ", name="Quoland")
WORLD = [ZETLAND, QUOLAND, ZETLAND_MINOR]


def test_code_and_name_resolve_case_insensitively_and_ignore_punctuation() -> None:
    for query in ("zz", "ZZ", "zZ", "Zetland", "zetland", "z.e.t.l.a.n.d", " zetland "):
        assert resolve_country(WORLD, query) is ZETLAND


def test_unique_substring_resolves() -> None:
    assert resolve_country(WORLD, "quo") is QUOLAND


def test_ambiguous_query_names_every_candidate() -> None:
    with pytest.raises(NoServerError) as info:
        resolve_country(WORLD, "zet")

    message = str(info.value)
    assert "Zetland" in message
    assert "Zetland Minor" in message


def test_unknown_and_empty_queries_are_refused() -> None:
    with pytest.raises(NoServerError, match="--list-countries"):
        resolve_country(WORLD, "nowhere")
    with pytest.raises(NoServerError):
        resolve_country(WORLD, "  ---  ")


def test_normalization_collapses_punctuation_and_case() -> None:
    assert normalize_country_query("Z.Z.") == "zz"
    assert normalize_country_query(" Zetland  Minor ") == "zetlandminor"


@pytest.mark.parametrize(("query", "expected"), [("uk", "GB"), ("usa", "US"), ("korea", "KR")])
def test_colloquial_aliases_map_onto_the_official_names(query: str, expected: str) -> None:
    """The alias table is shipped data, so it is tested with the names it maps."""
    world = [
        Country(id=900, code="GB", name="United Kingdom"),
        Country(id=901, code="US", name="United States"),
        Country(id=902, code="KR", name="South Korea"),
    ]
    assert resolve_country(world, query).code == expected


def test_country_from_api_discards_incomplete_records() -> None:
    assert Country.from_api({"id": 1, "code": "ZZ", "name": "Zetland"}) == ZETLAND
    assert Country.from_api({"id": 1, "code": "", "name": "Zetland"}) is None
    assert Country.from_api({"id": 1, "code": "ZZ"}) is None
