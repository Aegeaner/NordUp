#!/usr/bin/env python3
"""End-to-end harness: the real CLI against a mock API and stub wg-quick/ip.

No token, no root, no network beyond localhost.  Fixtures are reserved values
(example.net, RFC 5737 addresses, fake keys, a fictional country).

    python scripts/manual-test.py [-v]      # -v prints child output
"""

from __future__ import annotations

import base64
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
import urllib.parse
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parent.parent
TOKEN = "test-token"
PRIVATE_KEY = "test-private-key"
COUNTRY = {"id": 1, "code": "ZZ", "name": "Zetland"}
LINK = "nordlynx_zz"  # link name is derived from the country code
ENDPOINT_A = "203.0.113.7"
ENDPOINT_B = "203.0.113.8"
RECOMMENDATIONS = [
    {
        "id": 7,
        "hostname": "node7.example.net",
        "station": ENDPOINT_A,
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
        "station": ENDPOINT_B,
        "technologies": [
            {
                "identifier": "wireguard_udp",
                "metadata": [{"name": "public_key", "value": "test-pub-b"}],
            }
        ],
    },
]

FAKE_WG_QUICK = """#!/bin/sh
# Records argv, tracks "interface up" state, refuses a poisoned endpoint.
action="$1"; conf="$2"
printf '%s %s\\n' "$action" "$conf" >> "$NORD_UP_TEST_LOG"
if [ "$action" = "up" ]; then
    if [ -n "$NORD_UP_TEST_FAIL_ENDPOINT" ] &&
       grep -q "Endpoint = $NORD_UP_TEST_FAIL_ENDPOINT" "$conf"; then
        echo "refusing poisoned endpoint" >&2
        exit 1
    fi
    : > "$NORD_UP_TEST_STATE"
    exit 0
fi
rm -f "$NORD_UP_TEST_STATE"
exit 0
"""

FAKE_IP = """#!/bin/sh
# "link show dev <if>" succeeds only while the tunnel is "up".
[ -f "$NORD_UP_TEST_STATE" ] && exit 0
exit 1
"""


class MockApi:
    """The two endpoints the CLI uses, with the exact Basic auth header."""

    def __init__(self) -> None:
        self.requests: list[dict[str, Any]] = []
        outer = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def do_GET(self) -> None:
                path, _, query = self.path.partition("?")
                outer.requests.append({"path": path, "query": dict(urllib.parse.parse_qsl(query))})
                expected = "Basic " + base64.b64encode(b"token:" + TOKEN.encode()).decode()
                if path == "/v1/users/services/credentials":
                    if self.headers.get("Authorization") != expected:
                        self.send_error(400, "Invalid authorization header")
                        return
                    body: Any = {"nordlynx_private_key": PRIVATE_KEY}
                elif path == "/v1/servers/countries":
                    body = [COUNTRY]
                elif path == "/v1/servers/recommendations":
                    body = RECOMMENDATIONS
                else:
                    self.send_error(404)
                    return
                payload = json.dumps(body).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *_args: object) -> None:
                return

        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=self._httpd.serve_forever, daemon=True).start()

    @property
    def base_url(self) -> str:
        host, port = self._httpd.server_address[:2]
        return f"http://{host}:{port}"

    def close(self) -> None:
        self._httpd.shutdown()
        self._httpd.server_close()


class Checks:
    """Prints PASS/FAIL lines and remembers failures."""

    def __init__(self, title: str, verbose: bool) -> None:
        self.verbose = verbose
        self.failures: list[str] = []
        print(f"\n=== {title} ===")

    def ok(self, description: str, condition: bool, detail: str = "") -> None:
        print(f"  [{'PASS' if condition else 'FAIL'}] {description}")
        if not condition:
            self.failures.append(description)
            if detail:
                print(f"        {detail.strip()[:400]}")

    def equal(self, description: str, actual: Any, expected: Any) -> None:
        self.ok(description, actual == expected, f"actual={actual!r} expected={expected!r}")


class Sandbox:
    """A throwaway workspace, stub tools and the environment for one CLI run."""

    def __init__(self, *, resolver: str = "203.0.113.53") -> None:
        self.dir = Path(tempfile.mkdtemp(prefix="nord-up-manual-"))
        self.runtime_dir = self.dir / "run"
        self.config = self.runtime_dir / f"{LINK}.conf"
        self.state_record = self.runtime_dir / f"{LINK}.state.json"
        self.marker = self.dir / "interface-up"
        self.log = self.dir / "wg-quick.log"
        tools = self.dir / "tools"
        tools.mkdir()
        for name, body in (("wg-quick", FAKE_WG_QUICK), ("ip", FAKE_IP)):
            tool = tools / name
            tool.write_text(body)
            tool.chmod(0o755)
        resolv = self.dir / "resolv.conf"
        resolv.write_text(f"nameserver {resolver}\n")
        self.env = {
            **os.environ,
            "PYTHONPATH": str(REPO / "src"),
            "NORD_TOKEN": TOKEN,
            "NORD_UP_RUNTIME_DIR": str(self.runtime_dir),
            "NORD_UP_WG_QUICK": str(tools / "wg-quick"),
            "NORD_UP_IP": str(tools / "ip"),
            "NORD_UP_RESOLV_CONF": str(resolv),
            "NORD_UP_TEST_LOG": str(self.log),
            "NORD_UP_TEST_STATE": str(self.marker),
            "NORD_UP_TEST_FAIL_ENDPOINT": "",
        }

    def argv(self, *extra: str) -> list[str]:
        return [sys.executable, "-m", "nord_up", "-c", COUNTRY["name"], *extra]

    def run(self, *extra: str, timeout: float = 60.0) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            self.argv(*extra),
            cwd=str(REPO),
            env=self.env,
            capture_output=True,
            text=True,
            timeout=timeout,
        )

    def popen(self, *extra: str) -> subprocess.Popen[str]:
        return subprocess.Popen(
            self.argv(*extra),
            cwd=str(REPO),
            env=self.env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )

    def actions(self) -> list[str]:
        return [line.split(" ", 1)[0] for line in self.log.read_text().splitlines() if line.strip()]

    def close(self) -> None:
        shutil.rmtree(self.dir, ignore_errors=True)


def _wait_for(predicate: Callable[[], bool], timeout: float = 20.0) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline and not predicate():
        time.sleep(0.05)
    return predicate()


def check_foreground_and_failover(api: MockApi, *, verbose: bool) -> bool:
    """`--foreground` stays attached, then SIGINT tears everything down."""
    checks = Checks("A: foreground lifecycle and failover", verbose)
    for label, fail_endpoint, server, ups in (
        ("fastest candidate", "", "node7.example.net", 1),
        ("poisoned fastest candidate", ENDPOINT_A, "node8.example.net", 2),
    ):
        sandbox = Sandbox()
        try:
            sandbox.env["NORD_UP_TEST_FAIL_ENDPOINT"] = fail_endpoint
            process = sandbox.popen("--foreground", "--api-base", api.base_url, "-v")
            try:
                checks.ok(f"{label}: tunnel comes up", _wait_for(sandbox.marker.exists))
                text = sandbox.config.read_text() if sandbox.config.exists() else ""
                expected = ENDPOINT_A if ups == 1 else ENDPOINT_B
                checks.ok(f"{label}: {server} selected", f"Endpoint = {expected}:51820" in text)
                checks.ok(f"{label}: DNS pinned in the workspace config", "DNS = 127.0.0.1" in text)
                checks.ok(f"{label}: private key written", PRIVATE_KEY in text)

                process.send_signal(signal.SIGINT)
                stdout, stderr = process.communicate(timeout=30)
                if verbose:
                    print(f"  --- stdout ---\n{stdout}  --- stderr ---\n{stderr}")
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate()

            checks.equal(f"{label}: clean exit after SIGINT", process.returncode, 0)
            actions = sandbox.actions()
            checks.equal(f"{label}: wg-quick up attempts", actions.count("up"), ups)
            checks.equal(f"{label}: wg-quick down called once", actions.count("down"), 1)
            checks.ok(f"{label}: zero residue", not sandbox.runtime_dir.exists())
        finally:
            sandbox.close()
    return not checks.failures


def check_async_status_disconnect(api: MockApi, *, verbose: bool) -> bool:
    """Default mode: connect and return, report status, then disconnect."""
    checks = Checks("B: async connect -> status -> disconnect", verbose)
    sandbox = Sandbox()
    try:
        connect = sandbox.run("--api-base", api.base_url)
        if verbose:
            print(f"  --- connect ---\n{connect.stdout}{connect.stderr}")
        checks.equal("connect returns without blocking", connect.returncode, 0)
        checks.ok("tunnel is up", sandbox.marker.exists())
        checks.ok("state recorded", sandbox.state_record.exists())
        checks.ok("connection printed", "node7.example.net" in connect.stdout, connect.stdout)
        checks.equal("nothing torn down on the way out", sandbox.actions().count("down"), 0)

        again = sandbox.run("--api-base", api.base_url)
        checks.equal("a second connect refuses (exit 7)", again.returncode, 7)

        status = sandbox.run("--status")
        checks.equal("status reports the live link", status.returncode, 0)
        checks.ok("status names the endpoint", ENDPOINT_A in status.stdout, status.stdout)

        down = sandbox.run("-d")
        checks.equal("disconnect exits 0", down.returncode, 0)
        checks.ok("workspace removed (zero residue)", not sandbox.runtime_dir.exists())

        after = sandbox.run("--status")
        checks.equal("status reports nothing afterwards", after.returncode, 1)
    finally:
        sandbox.close()
    return not checks.failures


def check_dns_policies(api: MockApi, *, verbose: bool) -> bool:
    """A foreign resolver is pinned; the local stub is left alone."""
    checks = Checks("C: DNS policy", verbose)
    for resolver, pinned in (("203.0.113.53", True), ("127.0.0.1", False)):
        sandbox = Sandbox(resolver=resolver)
        try:
            result = sandbox.run("--dry-run", "--api-base", api.base_url)
            if verbose:
                print(f"  --- dry-run ({resolver}) ---\n{result.stdout}{result.stderr}")
            checks.equal(f"dry-run with resolver {resolver} exits 0", result.returncode, 0)
            checks.equal(
                f"resolver {resolver}: DNS directive {'pinned' if pinned else 'omitted'}",
                "DNS = 127.0.0.1" in result.stdout,
                pinned,
            )
            checks.ok("dry-run leaves no workspace behind", not sandbox.runtime_dir.exists())
        finally:
            sandbox.close()
    return not checks.failures


def main() -> int:
    verbose = "-v" in sys.argv[1:]
    api = MockApi()
    print(f"mock NordVPN API at {api.base_url} (no token, no root, no real tunnel)")
    try:
        passed = check_foreground_and_failover(api, verbose=verbose)
        passed = check_async_status_disconnect(api, verbose=verbose) and passed
        passed = check_dns_policies(api, verbose=verbose) and passed
    finally:
        api.close()

    print("\n" + ("ALL CHECKS PASSED" if passed else "FAILURES PRESENT"))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
