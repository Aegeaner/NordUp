# nord-up

Stateless NordVPN **NordLynx** (WireGuard) connector for Linux.

A run asks the live API for the fastest servers, renders a config into a RAM
workspace, pins `DNS` to the local resolver (DNSCrypt-proxy on `127.0.0.1`),
brings the link up with `wg-quick` as `nordlynx_<cc>`, prints it and returns.
`nord-up -d` disconnects and deletes every artifact.

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
| Another resolver, or none at all | `--dns 10.0.0.1` / `--no-dns` |
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

NordVPN hands out public resolvers, which would bypass a local stub, cache or
filter; `--dns` (by default the local DNSCrypt-proxy) is pinned into every managed
config first. When `/etc/resolv.conf` already resolves *only* through that
address the rewrite is skipped, keeping wg-quick's `resolvconf` plumbing out of
the picture.

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
