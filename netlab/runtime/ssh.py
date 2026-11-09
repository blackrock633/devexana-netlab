"""SSH frontend: one real SSH bastion on 127.0.0.1, real per-device SSH servers reached only through it.

* The bastion authenticates the agent, offers a shell on the HQ ops host, and accepts direct-tcpip channel requests
  (OpenSSH ``-J`` / ProxyJump, asyncssh ``tunnel=``). For each request it resolves the destination with the site
  DNS (from the ops host), evaluates the forwarding plane, and then either fails like a real network would
  (timeout after a delay / connection refused) or attaches the channel to an in-process SSH server for that
  device over a socketpair. No per-device TCP port is ever opened on the host.
* ``<edge>.console`` destinations are out-of-band consoles: they bypass the data plane but need console
  credentials (issued only for remediation runs).
* Port-forwarding to an application service port (e.g. intranet:443) is allowed and lands on the real listener.
"""

from __future__ import annotations

import asyncio
import contextlib
import hmac
import ipaddress
import socket
from typing import TYPE_CHECKING, Any

import asyncssh

from netlab.runtime.cli import CliSession

if TYPE_CHECKING:
    from netlab.runtime.lab import Lab

MAX_CONNECTIONS = 48


class _Pipe(asyncssh.SSHTCPSession):
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        self.reader, self.writer = reader, writer
        self.chan: Any = None
        self.task: asyncio.Task | None = None

    def connection_made(self, chan: Any) -> None:
        self.chan = chan
        self.task = asyncio.ensure_future(self._pump())

    async def _pump(self) -> None:
        try:
            while data := await self.reader.read(65536):
                self.chan.write(data)
        except (ConnectionError, OSError):
            pass
        finally:
            with contextlib.suppress(Exception):
                self.chan.write_eof()
                self.chan.close()

    def data_received(self, data: bytes, datatype: Any) -> None:
        self.writer.write(data)

    def eof_received(self) -> bool:
        with contextlib.suppress(Exception):
            self.writer.write_eof()
        return True

    def connection_lost(self, exc: Exception | None) -> None:
        with contextlib.suppress(Exception):
            self.writer.close()


class _BastionServer(asyncssh.SSHServer):
    def __init__(self, fe: SshFrontend):
        self.fe = fe
        self.user = ""
        self.peer = ""

    def connection_made(self, conn: asyncssh.SSHServerConnection) -> None:
        self.peer = str(conn.get_extra_info("peername"))
        self.fe.active += 1
        if self.fe.active > MAX_CONNECTIONS:
            conn.close()

    def connection_lost(self, exc: Exception | None) -> None:
        self.fe.active -= 1

    def begin_auth(self, username: str) -> bool:
        self.user = username
        return True

    def password_auth_supported(self) -> bool:
        return True

    def validate_password(self, username: str, password: str) -> bool:
        c = self.fe.lab.creds
        ok = username == c["bastion_user"] and hmac.compare_digest(password, c["bastion_password"])
        self.fe.lab.events.add("bastion", "auth", actor=username, target="bastion", ok=ok)
        return ok

    def connection_requested(self, dest_host: str, dest_port: int, orig_host: str, orig_port: int) -> Any:
        return self.fe.open_channel(self.user, dest_host, dest_port)


class _DeviceServer(asyncssh.SSHServer):
    def __init__(self, fe: SshFrontend, device: str, console: bool):
        self.fe, self.device, self.console = fe, device, console

    def begin_auth(self, username: str) -> bool:
        return True

    def password_auth_supported(self) -> bool:
        return True

    def validate_password(self, username: str, password: str) -> bool:
        lab = self.fe.lab
        c = lab.creds
        if self.console:
            ok = (
                lab.opts.mode == "remediation"
                and username == c["console_user"]
                and hmac.compare_digest(password, c["console_password"])
            )
        else:
            ok = (
                username == c["device_user"]
                and hmac.compare_digest(password, c["device_password"])
                and lab.access(self.device) != "no_login"
            )
        lab.events.add("console" if self.console else "ssh", "auth", actor=username, target=self.device, ok=ok)
        return ok


class SshFrontend:
    def __init__(self, lab: Lab):
        self.lab = lab
        self.port = 0
        self.active = 0
        self.server: Any = None
        self.bastion_key = asyncssh.generate_private_key("ssh-ed25519")
        self.fingerprint = self.bastion_key.get_fingerprint()
        self.device_keys = {n: asyncssh.generate_private_key("ssh-ed25519") for n in lab.world.devices}
        self.conns: list[Any] = []

    async def start(self) -> None:
        self.server = await asyncssh.create_server(
            lambda: _BastionServer(self),
            "127.0.0.1",
            0,
            server_host_keys=[self.bastion_key],
            process_factory=lambda p: self._session(p, self.lab.ops, "bastion", False),
            login_timeout=30,
            keepalive_interval=0,
        )
        self.port = self.server.sockets[0].getsockname()[1]

    async def stop(self) -> None:
        for c in list(self.conns):
            with contextlib.suppress(Exception):
                c.close()
        if self.server:
            self.server.close()
            with contextlib.suppress(Exception):
                await self.server.wait_closed()

    async def _session(self, proc: asyncssh.SSHServerProcess, device: str, source: str, console: bool) -> None:
        user = proc.get_extra_info("username") or ""
        sess = CliSession(self.lab, device, user, source, via_console=console)
        try:
            if proc.command:
                for line in proc.command.splitlines() or [proc.command]:
                    proc.stdout.write(await sess.run(line))
                    if sess.closed:
                        break
            else:
                proc.stdout.write(sess.banner() + sess.prompt())
                while not sess.closed:
                    try:
                        line = await proc.stdin.readline()
                    except (asyncssh.BreakReceived, asyncssh.TerminalSizeChanged):
                        continue
                    if not line:
                        break
                    proc.stdout.write(await sess.run(line))
                    if not sess.closed:
                        proc.stdout.write(sess.prompt())
        except (asyncssh.Error, ConnectionError, BrokenPipeError):
            pass
        finally:
            with contextlib.suppress(Exception):
                proc.exit(0)

    async def open_channel(self, user: str, dest_host: str, dest_port: int) -> asyncssh.SSHTCPSession:
        lab, w = self.lab, self.lab.world
        detail: dict[str, Any] = {"dest_host": dest_host, "dest_port": dest_port}
        console = dest_host.endswith(".console")
        if console:
            dev = dest_host.removesuffix(".console")
            if dev not in lab.consoles() or dest_port != 22:
                lab.events.add(
                    "bastion",
                    "channel_open",
                    actor=user,
                    target=dest_host,
                    ok=False,
                    detail={**detail, "error": "refused"},
                )
                raise asyncssh.ChannelOpenError(asyncssh.OPEN_CONNECT_FAILED, "Connection refused")
            service = "ssh"
        else:
            try:
                ip = str(ipaddress.ip_address(dest_host))
            except ValueError:
                ip, status = w.resolve_dns(lab.ops, dest_host)  # type: ignore[assignment]
                fq = dest_host.lower() if "." in dest_host else f"{dest_host.lower()}.{w.topo.domain}"
                rev = lab.reveals_for({("dns", f"record:{fq}", "value")})
                if ip is None:
                    lab.events.add(
                        "bastion",
                        "channel_open",
                        actor=user,
                        target=dest_host,
                        ok=False,
                        detail={**detail, "error": f"resolve: {status}"},
                        reveals=rev,
                        symptoms=lab.symptoms_for(dns=True),
                    )
                    raise asyncssh.ChannelOpenError(
                        asyncssh.OPEN_CONNECT_FAILED, f"{dest_host}: Name or service not known"
                    ) from None
            r = w.path(lab.ops, ip, "tcp", dest_port)
            owner = w.owner_of(ip)
            if not r.ok:
                lab.events.add(
                    "bastion",
                    "channel_open",
                    actor=user,
                    target=dest_host,
                    ok=False,
                    detail={**detail, "ip": ip, "error": r.outcome},
                    symptoms=lab.symptoms_for(r.blocked_at, owner[0].name if owner else None),
                )
                if r.outcome == "refused":
                    raise asyncssh.ChannelOpenError(asyncssh.OPEN_CONNECT_FAILED, "Connection refused")
                await asyncio.sleep(lab.opts.unreachable_delay_s)
                msg = "No route to host" if r.outcome == "net_unreachable" else "Connection timed out"
                raise asyncssh.ChannelOpenError(asyncssh.OPEN_CONNECT_FAILED, msg)
            dev = r.dst_device or ""
            service = r.service or "ssh"
            if service == "ssh" and lab.mgmt_hung(dev):
                lab.events.add(
                    "bastion",
                    "channel_open",
                    actor=user,
                    target=dest_host,
                    ok=False,
                    detail={**detail, "ip": ip, "error": "ssh banner timeout"},
                )
                await asyncio.sleep(lab.opts.unreachable_delay_s)
                raise asyncssh.ChannelOpenError(
                    asyncssh.OPEN_CONNECT_FAILED, "Connection timed out during banner exchange"
                )
        lab.events.add("bastion", "channel_open", actor=user, target=dest_host, detail={**detail, "device": dev})
        if service != "ssh":  # forward to the real application listener
            lst = lab.services.listeners.get((dev, service))
            if lst is None or lst.server is None:
                raise asyncssh.ChannelOpenError(asyncssh.OPEN_CONNECT_FAILED, "Connection refused")
            reader, writer = await asyncio.open_connection("127.0.0.1", lst.port)
            return _Pipe(reader, writer)
        a, b = socket.socketpair()
        task = asyncio.ensure_future(
            asyncssh.run_server(
                a,
                server_factory=lambda: _DeviceServer(self, dev, console),
                server_host_keys=[self.device_keys[dev]],
                process_factory=lambda p: self._session(p, dev, "console" if console else "ssh", console),
                login_timeout=30,
            )
        )
        task.add_done_callback(
            lambda t: self.conns.append(t.result()) if not t.cancelled() and not t.exception() else None
        )
        reader, writer = await asyncio.open_connection(sock=b)
        return _Pipe(reader, writer)
