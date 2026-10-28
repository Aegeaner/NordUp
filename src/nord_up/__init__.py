"""nord-up - stateless NordVPN NordLynx (WireGuard) connector.

The process queries the live NordVPN API on every run, renders a WireGuard
configuration into a RAM-backed directory, optionally pins a resolver
(``--dns``) and brings the tunnel up with ``wg-quick``.  Nothing is left
behind: no ``/etc/wireguard`` entry, no cached credentials, no static files.
"""

from __future__ import annotations

__all__ = ["__version__"]

__version__ = "2.0.0"
