"""Real TCP listeners for application services.

Each TCP application service in the world (intranet/443, files/445, collector/8443) is backed by a real asyncio
server bound to 127.0.0.1 on an ephemeral port. When the world marks the service stopped the listener is closed
(connections are really refused); when it is started again a listener is reopened. Probes and the evaluator only
report a service as working after a real connection to its listener returned a response that passes
``validate_response``: the right protocol, a success status and the expected service identity. A connection that
succeeds but returns HTTP 503, garbage, a truncated header or another service's banner is NOT healthy;
``probe`` keeps transport success and application health as separate results.

Fidelity: the protocol spoken is a minimal HTTP/1.0 response or banner, not real TLS or SMB.
"""

from __future__ import annotations

import asyncio
import contextlib
from dataclasses import dataclass

BANNERS = {
    "intranet": b"HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n<html><title>Intranet</title>OK</html>\r\n",
    "collector": b'HTTP/1.0 200 OK\r\nContent-Type: application/json\r\n\r\n{"status":"ok"}\r\n',
    "files": b"SMB2 NEGOTIATE OK (emulated banner)\r\n",
}


# Expected identity per service: (protocol, marker that must appear in the body / banner).
EXPECT = {
    "intranet": ("http", b"<title>Intranet</title>"),
    "collector": ("http", b'"status":"ok"'),
    "files": ("banner", b"SMB2 NEGOTIATE OK"),
}


def validate_response(service: str, data: bytes) -> tuple[bool, str]:
    """Application-level health of a raw response. Returns (healthy, reason)."""
    if not data:
        return False, "empty response"
    proto, marker = EXPECT.get(service, ("banner", b"OK"))
    if proto == "http":
        head, sep, body = data.partition(b"\r\n\r\n")
        if not sep:
            return False, "truncated or malformed HTTP response (no header terminator)"
        status_line = head.split(b"\r\n", 1)[0].decode(errors="replace")
        parts = status_line.split(" ", 2)
        if len(parts) < 2 or not parts[0].startswith("HTTP/") or not parts[1].isdigit():
            return False, f"not an HTTP status line: {status_line[:60]!r}"
        code = int(parts[1])
        if not 200 <= code < 300:
            return False, f"HTTP {code} {parts[2] if len(parts) > 2 else ''}".strip()
        if marker not in body:
            return False, f"HTTP {code} but the body does not identify the {service} service"
        return True, f"HTTP {code}"
    if not data.startswith(marker):
        return False, f"unexpected banner for {service}: {data[:40]!r}"
    return True, "banner ok"


@dataclass
class ProbeResult:
    transport_ok: bool  # a TCP connection was established and something was read
    app_ok: bool  # the response passed validate_response
    detail: str
    payload: str = ""


@dataclass
class Listener:
    device: str
    service: str
    port: int
    server: asyncio.base_events.Server | None = None
    response: bytes | None = None  # override (fault/test injection of an application-level failure)


class ServiceHost:
    def __init__(self) -> None:
        self.listeners: dict[tuple[str, str], Listener] = {}

    async def _handle(self, key: tuple[str, str], reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        try:
            with contextlib.suppress(asyncio.TimeoutError):
                await asyncio.wait_for(reader.read(1024), timeout=0.2)
            lst = self.listeners.get(key)
            override = lst.response if lst else None
            writer.write(override if override is not None else BANNERS.get(key[1], b"OK\r\n"))
            await writer.drain()
        finally:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()

    async def open(self, device: str, service: str) -> Listener:
        key = (device, service)
        lst = self.listeners.get(key)
        if lst and lst.server:
            return lst
        port = lst.port if lst else 0
        try:
            server = await asyncio.start_server(lambda r, w: self._handle(key, r, w), "127.0.0.1", port)
        except OSError:
            server = await asyncio.start_server(lambda r, w: self._handle(key, r, w), "127.0.0.1", 0)
        real_port = server.sockets[0].getsockname()[1]
        lst = Listener(device, service, real_port, server, response=lst.response if lst else None)
        self.listeners[key] = lst
        return lst

    async def close(self, device: str, service: str) -> None:
        lst = self.listeners.get((device, service))
        if lst and lst.server:
            lst.server.close()
            await lst.server.wait_closed()
            lst.server = None

    def set_response(self, device: str, service: str, payload: bytes | None) -> None:
        """Make a running listener answer with ``payload`` (None restores the normal response)."""
        self.listeners[(device, service)].response = payload

    async def probe(self, device: str, service: str, timeout: float = 2.0) -> ProbeResult:
        """Really connect to the listener and validate the application response."""
        lst = self.listeners.get((device, service))
        if lst is None:
            return ProbeResult(False, False, "no listener registered")
        try:
            r, w = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", lst.port), timeout=timeout)
        except (ConnectionRefusedError, OSError):
            return ProbeResult(False, False, "connection refused")
        except TimeoutError:
            return ProbeResult(False, False, "timeout")
        try:
            w.write(b"GET / HTTP/1.0\r\n\r\n")
            await w.drain()
            data = b""
            while len(data) < 65536:
                chunk = await asyncio.wait_for(r.read(4096), timeout=timeout)
                if not chunk:
                    break
                data += chunk
                if service in EXPECT and EXPECT[service][0] == "banner":
                    break
        except (TimeoutError, OSError):
            return ProbeResult(True, False, "no response")
        finally:
            w.close()
            with contextlib.suppress(Exception):
                await w.wait_closed()
        ok, why = validate_response(service, data)
        return ProbeResult(bool(data), ok, why, data.decode(errors="replace"))

    async def fetch(self, device: str, service: str, timeout: float = 2.0) -> tuple[bool, str]:
        """Application-healthy check. Returns (healthy, payload if healthy else the reason it is not)."""
        p = await self.probe(device, service, timeout)
        return p.app_ok, (p.payload if p.app_ok else p.detail)

    def ports(self) -> list[int]:
        return [lst.port for lst in self.listeners.values()]

    async def close_all(self) -> None:
        for d, s in list(self.listeners):
            await self.close(d, s)
