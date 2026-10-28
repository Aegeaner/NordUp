# nord-up

Stateless NordVPN **NordLynx** (WireGuard) connector for Linux.

A run asks the live API for the fastest servers, renders a config into a RAM
workspace, optionally pins a resolver, brings the link up with `wg-quick` as
`nordlynx_<cc>`, prints it and returns. `nord-up -d` disconnects and deletes
every artifact.

Needs `httpx`, `wireguard-tools` (`wg-quick`) and `iproute2` (`ip`).

## Install

```bash
ln -s "$PWD/bin/nord-up" ~/.local/bin/nord-up   # editable: runs src/ in place
pip install -e .                                # or install the package
```

## Cheat sheet

| Task | Command |
|---|---|
| Connect, fastest server anywhere | `sudo -E nord-up` |
| Connect to a country | `sudo -E nord-up -c <code\|name>` |
| Stay attached instead of returning | `sudo -E nord-up -c <country> -f` |
| Show the live connection | `nord-up -s` |
| Disconnect and clean up | `nord-up -d` |
| List countries (no token needed) | `nord-up -l` |
| Print the config, no root, no tunnel | `nord-up -c <country> --dry-run` |
| Pin a resolver (default: leave DNS alone) | `--dns 10.0.0.1` |
| Full-MTU path / unusual path | `--mtu 1420` / `--mtu 1280` |
| More failover candidates | `--servers 10` |

The token comes from `NORD_TOKEN` or `--token`; `sudo -E` keeps it across sudo.

## Lifecycle

- `up` — preflight, resolve the country (its code names the link), open the
  workspace, recover a leftover config, then `wg-quick up` per candidate until one
  holds. An already-live link is refused (exit 7) instead of being replaced.
- `return` — config and `state.json` stay in the workspace, the lock is released
  and the link outlives the process. `-f/--foreground` waits for Ctrl+C instead,
  disconnecting on the way out.
- `-d/--disconnect` — `wg-quick down`, then every artifact is deleted. A failure
  deletes nothing, so the command can simply be retried.

### DNS

By default the generated config carries no `DNS` directive: `wg-quick` leaves
`/etc/resolv.conf` alone, so the resolver the network handed out (Wi-Fi DHCP,
systemd-resolved, ...) keeps working. This also keeps wg-quick's `resolvconf`
plumbing out of the picture — it otherwise needs a working systemd-resolved or
openresolv backend and fails the whole `up` when neither is available.

`--dns ADDR` opts into pinning: NordVPN's public resolvers are replaced by `ADDR`
in every managed config, for example a local DNSCrypt-proxy on `127.0.0.1`.
When `/etc/resolv.conf` already resolves *only* through `ADDR` the rewrite is
skipped, since it would change nothing. Otherwise wg-quick applies the pin
through `resolvconf`, so that path needs systemd-resolved or openresolv.

### MTU

The generated config pins `MTU = 1392`. WireGuard's outer packet adds 60 bytes
over an IPv4 endpoint, so 1392 leaves a 1452-byte packet — fitting the smallest
common WAN path (PPPoE 1492, DS-Lite 1452). `wg-quick`'s own derivation
(physical MTU - 80) assumes the whole path is 1500 and silently blackholes
larger packets behind a reduced-MTU WAN: the link looks up, pings and local DNS
work, but TLS handshakes stall.

Raise it with `--mtu 1420` on a full-MTU path, or lower it to `--mtu 1280` on an
unusual one. The path MTU can be measured with
`ping -M do -s <payload> <endpoint>`: the largest payload that succeeds plus 28
is the path MTU, and the link MTU is 60 less.

### Upgrading from 1.x

1.x pinned `127.0.0.1` (a local DNSCrypt-proxy) by default and left the MTU to
`wg-quick`. That broke resolution whenever nothing listened there, pushed
wg-quick through `resolvconf`, and blackholed traffic on reduced-MTU paths. 2.0
makes DNS opt-in (`--dns 127.0.0.1` restores the old behaviour) and pins a
safe 1392-byte MTU (`--mtu 1420` restores the old throughput on full-MTU paths).

## Exit codes

| Code | Meaning |
|---|---|
| 0 | connected, disconnected, or dry-run printed |
| 1 | API/transport failure, or `--status` with nothing connected |
| 2 | usage error (bad arguments, unusable config) |
| 3 | token rejected |
| 4 | no/unknown/ambiguous country, no usable server |
| 5 | `wg-quick`/`ip` failure |
| 6 | privileges unavailable |
| 7 | the link is already connected |
| 130 | interrupted |

## Security

* No shell anywhere — every subprocess call is an argument vector.
* API and command-line values are checked for newline injection before they reach
  a config.
* Configs are `0600` in a `0700` tmpfs directory and deleted on disconnect; the
  token and the private key are never written to disk, logged or `repr()`-ed.
