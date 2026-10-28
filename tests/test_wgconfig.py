"""Config rendering, DNS enforcement and resolver probing."""

from __future__ import annotations

import stat
from pathlib import Path

import pytest

from nord_up.errors import ConfigError
from nord_up.models import Server
from nord_up.wgconfig import (
    DEFAULT_RESOLV_CONF,
    enforce_dns,
    enforce_dns_directory,
    enforce_dns_file,
    render_config,
    resolv_conf_path,
    resolver_already_in_use,
    resolver_nameservers,
)

SERVER = Server(id=7, hostname="node7.example.net", station="203.0.113.7", public_key="test-pub-a")
CONFIG = "[Interface]\nPrivateKey = test-key\nDNS = 1.1.1.1\n[Peer]\nPublicKey = test-pub-a\n"
PINNED = "10.0.0.1"


def test_render_config_writes_every_directive() -> None:
    text = render_config(private_key="test-key", server=SERVER, dns=PINNED, mtu=1400)

    assert text.startswith("[Interface]\n")
    assert "Address = 10.5.0.2/32" in text
    assert "MTU = 1400" in text
    assert f"DNS = {PINNED}" in text
    assert "Endpoint = 203.0.113.7:51820" in text
    assert "AllowedIPs = 0.0.0.0/0, ::/0" in text
    assert text.endswith("PersistentKeepalive = 25\n")


def test_render_config_omits_dns_and_mtu_by_default_and_rejects_injection() -> None:
    text = render_config(private_key="test-key", server=SERVER)
    assert "DNS" not in text
    assert "MTU" not in text

    with pytest.raises(ConfigError):
        render_config(private_key="key\nDNS = 9.9.9.9", server=SERVER)
    with pytest.raises(ConfigError):
        render_config(private_key="test-key", server=SERVER, mtu=1200)


def test_enforce_dns_replaces_inserts_and_is_idempotent() -> None:
    replaced = enforce_dns(CONFIG, PINNED)
    assert "DNS = 1.1.1.1" not in replaced
    assert f"DNS = {PINNED}" in replaced
    assert enforce_dns(replaced, PINNED) == replaced  # idempotent

    inserted = enforce_dns("[Interface]\nPrivateKey = k\n[Peer]\nPublicKey = p\n", PINNED)
    lines = inserted.splitlines()
    assert lines.index(f"DNS = {PINNED}") < lines.index("[Peer]")

    with pytest.raises(ConfigError):
        enforce_dns("[Peer]\nPublicKey = p\n", PINNED)  # no [Interface] section


def test_enforce_dns_file_and_directory_fix_mode_and_leave_others_alone(tmp_path: Path) -> None:
    config = tmp_path / "nordlynx_zz.conf"
    config.write_text(CONFIG)
    config.chmod(0o666)
    note = tmp_path / "note.txt"
    note.write_text("DNS = 9.9.9.9\n")

    assert enforce_dns_directory(tmp_path, PINNED) == [config]
    assert f"DNS = {PINNED}" in config.read_text()
    assert stat.S_IMODE(config.stat().st_mode) == 0o600
    assert note.read_text() == "DNS = 9.9.9.9\n"

    assert enforce_dns_file(config, PINNED) is False  # already normalized, mode kept
    with pytest.raises(ConfigError):
        enforce_dns_file(tmp_path / "missing.conf", PINNED)


def test_resolver_probe_reads_nameservers_and_ignores_noise(tmp_path: Path) -> None:
    resolv = tmp_path / "resolv.conf"
    resolv.write_text(
        "# managed\nnameserver\t127.0.0.1\nsearch lan\nnameserver 10.0.0.1 # trailing\n"
    )

    assert resolver_nameservers(resolv) == ["127.0.0.1", "10.0.0.1"]
    assert resolver_nameservers(tmp_path / "missing.conf") == []

    resolv.write_text("nameserver 127.0.0.1\n")
    assert resolver_already_in_use("127.0.0.1", resolv) is True

    resolv.write_text("nameserver 127.0.0.1\nnameserver 10.0.0.1\n")
    assert resolver_already_in_use("127.0.0.1", resolv) is False


def test_resolv_conf_path_honours_the_env_override(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert resolv_conf_path() == DEFAULT_RESOLV_CONF

    custom = tmp_path / "custom.conf"
    monkeypatch.setenv("NORD_UP_RESOLV_CONF", str(custom))
    assert resolv_conf_path() == custom

    monkeypatch.setenv("NORD_UP_RESOLV_CONF", "   ")
    assert resolv_conf_path() == DEFAULT_RESOLV_CONF
