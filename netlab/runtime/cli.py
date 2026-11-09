"""Device command-line emulation. Every command reads/writes the shared World and is recorded server-side.

Dialects (documented in docs/DEVICE_CLI.md):
* ``ios``: IOS-like exec/config modes; addresses and ACL operands use CIDR notation (e.g. ``10.1.0.0/24``).
* ``linux``: a small POSIX-like shell with systemctl/journalctl/ip/ss and network probes (ping, traceroute, curl,
  nc, nslookup/dig/host), plus the site's ``dns-record`` and ``dhcp-leases`` admin wrappers on the DNS server.
"""

# ruff: noqa: E501  (long user-facing messages)

from __future__ import annotations

import asyncio
import ipaddress
import re
import shlex
from typing import TYPE_CHECKING, Any

from netlab import render
from netlab.schemas import AclRule, Mutation
from netlab.world import PathResult, net

if TYPE_CHECKING:
    from netlab.runtime.lab import Lab

ABBREV = [
    (r"^sh(o(w)?)?\b", "show"),
    (r"\bint(e(r(f(a(c(e)?)?)?)?)?)?\b", "interface"),
    (r"\bbr(i(e(f)?)?)?$", "brief"),
    (r"^conf(i(g(u(r(e)?)?)?)?)?\s+t(e(r(m(i(n(a(l)?)?)?)?)?)?)?$", "configure terminal"),
    (r"\brun\b", "running-config"),
    (r"\bshut\b", "shutdown"),
    (r"\bacc(e(s(s)?)?)?-l(i(s(t(s)?)?)?)?\b", "access-lists"),
    (r"^wr(i(t(e)?)?)?(\s+mem(o(r(y)?)?)?)?$", "write memory"),
]


def _norm_ios(line: str) -> str:
    s = " ".join(line.split())
    for pat, rep in ABBREV:
        if "acc" in pat and not re.match(r"^sh(o(w)?)?\b", s):
            continue  # "access-list" in config mode must not be expanded to "access-lists"
        s = re.sub(pat, rep, s)
    s = re.sub(r"^show ip interface brief$", "show ip interface brief", s)
    return s


def _cidr(tok: str) -> str:
    if tok == "any":
        return "any"
    if tok.startswith("host"):
        tok = tok[4:].strip()
    if "/" not in tok:
        tok += "/32"
    return str(net(tok))


_UNPARSED = (
    "% Invalid input",
    "% Incomplete command",
    "% Invalid interface",
    "bash: ",
    "Unknown command verb",
    "usage:",
    "Usage:",
    "curl: try",
    "curl: (3)",
)


def _unparsed(out: str) -> bool:
    """The device did not understand the command (syntax/unknown command), as opposed to a valid command whose
    result is negative (e.g. an unreachable ping target)."""
    first = out.lstrip("\n").splitlines()[0] if out.strip() else ""
    return first.startswith(_UNPARSED) or (first.startswith("sudo: ") and first.endswith("command not found"))


class CliSession:
    def __init__(self, lab: Lab, device: str, actor: str, source: str, via_console: bool = False):
        self.lab = lab
        self.dev = lab.world.device(device)
        self.name = device
        self.actor = actor
        self.source = source
        self.via_console = via_console
        self.access = "full" if (via_console and lab.opts.mode == "remediation") else lab.access(device)
        self.mode = "exec"
        self.ctx: str | None = None
        self.closed = False
        self.unsaved = False

    # -- prompts ---------------------------------------------------------------------------------------------------
    def prompt(self) -> str:
        h = render.hostname(self.dev)
        if self.dev.os == "linux":
            return f"{self.actor}@{h}:~$ "
        suffix = {"exec": "#", "config": "(config)#", "config-if": "(config-if)#", "config-acl": "(config-ext-nacl)#"}
        return f"{h}{suffix[self.mode]}"

    def banner(self) -> str:
        if self.dev.os == "linux":
            return f"Welcome to Ubuntu 22.04 LTS ({render.hostname(self.dev)})\n"
        return f"\n{render.hostname(self.dev)} - authorized access only\n\n"

    # -- dispatch --------------------------------------------------------------------------------------------------
    async def run(self, line: str) -> str:
        line = line.strip()
        if not line or line.startswith(("!", "#")):
            return ""
        lab = self.lab
        if lab.counters["commands"] >= lab.opts.max_commands:
            lab.events.add(
                self.source,
                "command",
                actor=self.actor,
                target=self.name,
                ok=False,
                detail={"command": line, "error": "command budget exhausted"},
            )
            return "% Command budget for this run is exhausted.\n"
        lab.counters["commands"] += 1
        ann: dict[str, Any] = {"reveals": [], "symptoms": [], "change": None, "denied": False, "observed": set()}
        try:
            out = await (self._ios(line, ann) if self.dev.os == "ios" else self._linux(line, ann))
        except Exception as e:  # never let a parsing bug kill the session; record it
            out = f"% Internal error: {type(e).__name__}\n"
            ann["error"] = repr(e)
        # Three separate facts: was the command understood, did the session identify the device, and did the
        # output carry current state of this device's own resources (health evidence)?
        parsed = "error" not in ann and not _unparsed(out)
        own = sorted(k for k in ann["observed"] if k[0] == self.name)
        health = parsed and not ann["denied"] and bool(own)
        ok = parsed and not ann["denied"]
        lab.events.add(
            self.source,
            "command",
            actor=self.actor,
            target=self.name,
            ok=ok,
            detail={
                "command": line,
                "mode": self.mode,
                "output": out[:4000],
                "denied": ann["denied"],
                "parsed": parsed,
                "identity_observed": True,  # an authenticated session on this device (prompt/hostname)
                "health_evidence": health,
                **({"probe_target": ann["probe_target"]} if parsed and ann.get("probe_target") else {}),
                **({"probe": ann["probe"]} if parsed and ann.get("probe") else {}),
                "observed_resources": [f"{d}|{r}|{f}" for d, r, f in sorted(ann["observed"])][:200],
                **({"error": ann["error"]} if "error" in ann else {}),
            },
            reveals=ann["reveals"],
            symptoms=ann["symptoms"],
            change=ann["change"],
        )
        return out

    def _obs(self, ann: dict[str, Any], keys: Any) -> None:
        """Record exactly which (device, resource, field) values this output contained."""
        ks = set(keys)
        ann["observed"] |= ks
        ann["reveals"] += self.lab.reveals_for(ks)

    def _ifaces(self, names: Any = None, fields: tuple[str, ...] = ("admin",)) -> set[tuple[str, str, str]]:
        names = list(self.dev.interfaces) if names is None else names
        return {(self.name, f"iface:{n}", f) for n in names for f in fields}

    def _acls(self) -> set[tuple[str, str, str]]:
        return {(self.name, f"acl:{a}", "rules") for a in self.dev.acls}

    def _services(self, names: Any = None) -> set[tuple[str, str, str]]:
        names = list(self.dev.services) if names is None else names
        return {(self.name, f"service:{n}", "state") for n in names}

    def _deny(self, ann: dict[str, Any], msg: str) -> str:
        ann["denied"] = True
        return msg

    def _mutate(self, ann: dict[str, Any], m: Mutation) -> None:
        ann["change"] = self.lab.world.apply(m, actor=self.actor)
        self.unsaved = True

    # -- IOS -------------------------------------------------------------------------------------------------------
    async def _ios(self, raw: str, ann: dict[str, Any]) -> str:
        line = _norm_ios(raw)
        w, d = self.lab.world, self.dev
        if line in ("exit", "quit", "logout") and self.mode == "exec":
            self.closed = True
            return ""
        if line == "end":
            self.mode, self.ctx = "exec", None
            return ""
        if line == "exit":
            self.mode, self.ctx = ("config", None) if self.mode in ("config-if", "config-acl") else ("exec", None)
            return ""
        if self.mode == "exec":
            if line == "show version":
                self._obs(ann, {(self.name, "system", "uptime")})
                return (
                    f"{render.software(d)[1]}\n{render.hostname(d)} uptime is 41 weeks, 2 days\n"
                    f"Processor board ID {d.serial}\n"
                )
            if line == "show clock":
                return self.lab.device_ts(self.name).replace("T", " ").replace("Z", " UTC") + "\n"
            if line == "show ip interface brief":
                self._obs(ann, self._ifaces())
                return render.ip_int_brief(w, d)
            if line in ("show interfaces status", "show interface status") and d.kind == "switch":
                ports = [n for n, i in d.interfaces.items() if i.role in ("access", "uplink")]
                self._obs(ann, self._ifaces(ports, ("admin", "vlan")))
                return render.switch_status(w, d)
            if line.startswith("show vlan") and d.kind == "switch":
                self._obs(
                    ann, self._ifaces([n for n, i in d.interfaces.items() if i.role in ("access", "uplink")], ("vlan",))
                )
                return render.vlan_brief(d)
            m = re.match(r"^show interfaces? (\S+)$", line)
            if m:
                out = render.show_interface(w, d, m.group(1))
                if out is None:
                    return "% Invalid input detected at '^' marker.\n"
                self._obs(ann, self._ifaces([m.group(1)], ("admin", "vlan") if d.kind == "switch" else ("admin",)))
                return out
            if line == "show ip route":
                self._obs(ann, {(self.name, "routes", "table")})
                return render.ip_route(w, d)
            if line in ("show access-lists", "show ip access-lists"):
                self._obs(ann, self._acls())
                return render.access_lists(d)
            if line in ("show running-config", "show startup-config"):
                listed = [
                    n
                    for n, i in d.interfaces.items()
                    if not (
                        d.kind == "switch"
                        and i.role in ("access", "uplink")
                        and not i.peer
                        and i.vlan == 1
                        and i.admin_up
                    )
                ]
                fields = ("admin", "vlan") if d.kind == "switch" else ("admin",)
                self._obs(ann, self._ifaces(listed, fields) | {(self.name, "routes", "table")} | self._acls())
                c = self.lab.spec.evidence.collector_of.get(self.name)
                return render.ios_config(w, d, log_host=(w.primary_ip(c) if c else "") or "")
            if line == "show logging":
                return self._logging(ann, 60)
            m = re.match(r"^(ping|traceroute)\s+(\S+)", line)
            if m:
                return await self._probe(m.group(1), m.group(2), ann, ios=True)
            if line == "configure terminal":
                if self.access != "full":
                    return self._deny(ann, "% Authorization failed.\n")
                self.mode = "config"
                return "Enter configuration commands, one per line.  End with CNTL/Z.\n"
            if line in ("write memory", "copy running-config startup-config"):
                if self.access != "full":
                    return self._deny(ann, "% Authorization failed.\n")
                self.unsaved = False
                self.lab.events.add(self.source, "config_saved", actor=self.actor, target=self.name)
                return "Building configuration...\n[OK]\n"
            return "% Invalid input detected at '^' marker.\n"
        if self.mode == "config":
            m = re.match(r"^interface (\S+)$", line)
            if m:
                if m.group(1) not in d.interfaces:
                    return "% Invalid interface.\n"
                self.mode, self.ctx = "config-if", m.group(1)
                return ""
            m = re.match(r"^(no )?ip route (\S+)(?: (\S+))?(?: (\S+))?$", line)
            if m and d.kind == "edge":
                neg, a, b, c = m.groups()
                try:
                    if b and re.match(r"^\d+\.\d+\.\d+\.\d+$", b) and "/" not in a and c:  # "net mask nh" form
                        prefix, nh = str(ipaddress.ip_network(f"{a}/{b}", strict=False)), c
                    else:
                        prefix, nh = str(net(a)), b
                except ValueError:
                    return "% Invalid input detected at '^' marker.\n"
                if neg:
                    self._mutate(
                        ann, Mutation(op="remove_route", device=self.name, args={"prefix": prefix, "next_hop": nh})
                    )
                elif nh:
                    ann["change"] = self.lab.world.add_route(self.name, prefix, nh, self.actor)
                    self.unsaved = True
                else:
                    return "% Incomplete command.\n"
                return ""
            m = re.match(r"^ip access-list extended (\S+)$", line)
            if m and d.kind == "edge":
                self.mode, self.ctx = "config-acl", m.group(1)
                return ""
            if line.startswith(("hostname", "logging", "ntp", "snmp-server")):
                return ""
            return "% Invalid input detected at '^' marker.\n"
        if self.mode == "config-if":
            ifn = self.ctx or ""
            if line in ("shutdown", "no shutdown"):
                self._mutate(
                    ann,
                    Mutation(op="set_iface_admin", device=self.name, args={"iface": ifn, "up": line == "no shutdown"}),
                )
                return ""
            m = re.match(r"^switchport access vlan (\d+)$", line)
            if m and d.kind == "switch":
                self._mutate(
                    ann, Mutation(op="set_port_vlan", device=self.name, args={"iface": ifn, "vlan": int(m.group(1))})
                )
                return ""
            if line.startswith(("description", "switchport mode")):
                return ""
            return "% Invalid input detected at '^' marker.\n"
        if self.mode == "config-acl":
            m = re.match(r"^no (\d+)$", line)
            if m:
                self._mutate(
                    ann,
                    Mutation(op="remove_acl_rule", device=self.name, args={"acl": self.ctx, "seq": int(m.group(1))}),
                )
                return ""
            m = re.match(r"^(\d+) (permit|deny) (ip|tcp|udp|icmp) (host \S+|\S+) (host \S+|\S+)(?: eq (\d+))?$", line)
            if m:
                try:
                    rule = AclRule(
                        seq=int(m.group(1)),
                        action=m.group(2),
                        proto=m.group(3),  # type: ignore[arg-type]
                        src=_cidr(m.group(4)),
                        dst=_cidr(m.group(5)),
                        dport=int(m.group(6)) if m.group(6) else None,
                    )
                except ValueError:
                    return "% Invalid input detected at '^' marker.\n"
                self._mutate(
                    ann,
                    Mutation(op="insert_acl_rule", device=self.name, args={"acl": self.ctx, "rule": rule.model_dump()}),
                )
                return ""
            return "% Invalid input detected at '^' marker.\n"
        return "% Invalid input detected at '^' marker.\n"

    def _logging(self, ann: dict[str, Any], n: int, unit: str | None = None) -> str:
        lines = self.lab.local_logs.get(self.name, [])
        if self.dev.os == "ios":
            horizon = self.lab.now() - 2 * 3600  # local buffer only keeps ~2 hours
            lines = [x for x in lines if x[0] >= horizon]
        if unit:
            lines = [x for x in lines if f"{unit}." in x[1] or x[1].startswith(unit)]
        sel = lines[-n:]
        self._obs(ann, {(self.name, "logs", "local")})
        for _, _, rev in sel:
            ann["reveals"] += [
                r for r in rev if any(f.id == r and self.lab.fault_active(f) for f in self.lab.spec.faults)
            ]
        h = render.hostname(self.dev)
        return "".join(f"{self.lab.device_ts(self.name, t)} {h} {msg}\n" for t, msg, _ in sel)

    # -- probes ----------------------------------------------------------------------------------------------------
    def _resolve(self, target: str, ann: dict[str, Any]) -> tuple[str | None, str]:
        ann["probe_target"] = target  # every network probe (ping/traceroute/curl/nc/nslookup) resolves a target here
        is_name = True
        try:
            ipaddress.ip_address(target)
            is_name = False
        except ValueError:
            pass
        # Evaluator-only probe record: what this probe actually exercised (filled in by the probe that resolved it).
        ann["probe"] = {
            "src": self.name,
            "target": target,
            "proto": None,
            "port": None,
            "hops": [],
            "ingress": [],
            "dst_device": None,
            "by_name": None,
        }
        if is_name:
            fqn = target.lower().rstrip(".")
            ann["probe"]["by_name"] = fqn if "." in fqn else f"{fqn}.{self.lab.world.topo.domain}"
        try:
            ipaddress.ip_address(target)
            return target, "ok"
        except ValueError:
            pass
        ip, status = self.lab.world.resolve_dns(self.name, target)
        fq = target.lower().rstrip(".")
        if "." not in fq:
            fq = f"{fq}.{self.lab.world.topo.domain}"
        self._obs(ann, {("dns", f"record:{fq}", "value")})
        if ip is None:
            ann["symptoms"] += self.lab.symptoms_for(dns=True)
        return ip, status

    async def _slow(self) -> None:
        await asyncio.sleep(min(1.0, self.lab.opts.unreachable_delay_s / 2))

    @staticmethod
    def _record_path(ann: dict[str, Any], r: PathResult, proto: str, port: int | None) -> None:
        if ann.get("probe") is not None:
            ann["probe"].update(
                proto=proto,
                port=port,
                hops=list(r.hops),
                ingress=list(r.ingress),
                decisions=[dict(d) for d in r.decisions],
                dst_ip=r.dst_ip,
                dst_device=r.dst_device if r.ok or r.outcome == "refused" else None,
            )

    async def _probe(self, kind: str, target: str, ann: dict[str, Any], ios: bool = False) -> str:
        w = self.lab.world
        ip, status = self._resolve(target, ann)
        if ip is None:
            return (
                "% Unrecognized host or address, or protocol not running.\n"
                if ios
                else f"{kind}: {target}: {'Name or service not known' if status == 'nxdomain' else 'Temporary failure in name resolution'}\n"
            )
        r = w.path(self.name, ip, "icmp")
        self._record_path(ann, r, "icmp", None)
        if not r.ok:
            ann["symptoms"] += self.lab.symptoms_for(r.blocked_at, w.owner_of(ip)[0].name if w.owner_of(ip) else None)
            await self._slow()
        src_ip = w.primary_ip(self.name)
        if kind == "ping":
            if ios:
                mark = "!!!!!" if r.ok else ("U.U.U" if r.outcome == "net_unreachable" else ".....")
                return (
                    f"Type escape sequence to abort.\nSending 5, 100-byte ICMP Echos to {ip}, timeout is 2 seconds:\n"
                    f"{mark}\nSuccess rate is {100 if r.ok else 0} percent ({5 if r.ok else 0}/5)\n"
                )
            head = f"PING {target} ({ip}) 56(84) bytes of data.\n"
            if r.ok:
                body = "".join(
                    f"64 bytes from {ip}: icmp_seq={i} ttl={64 - len(r.hop_ips)} time={0.4 + 0.3 * len(r.hop_ips) + i * 0.05:.2f} ms\n"
                    for i in range(1, 4)
                )
                return (
                    head
                    + body
                    + f"\n--- {target} ping statistics ---\n3 packets transmitted, 3 received, 0% packet loss\n"
                )
            if r.outcome in ("net_unreachable", "host_unreachable"):
                frm = r.hop_ips[-1] if r.hop_ips else src_ip
                kindtxt = "Net" if r.outcome == "net_unreachable" else "Host"
                body = "".join(f"From {frm} icmp_seq={i} Destination {kindtxt} Unreachable\n" for i in range(1, 4))
                return (
                    head
                    + body
                    + f"\n--- {target} ping statistics ---\n3 packets transmitted, 0 received, +3 errors, 100% packet loss\n"
                )
            return head + f"\n--- {target} ping statistics ---\n3 packets transmitted, 0 received, 100% packet loss\n"
        # traceroute
        out = [f"traceroute to {target} ({ip}), 30 hops max, 60 byte packets"]
        n = 0
        for n, h in enumerate(r.hop_ips, start=1):
            out.append(f" {n}  {h}  {0.5 * n:.3f} ms")
        if r.ok:
            if not r.hop_ips or r.hop_ips[-1] != ip:
                out.append(f" {n + 1}  {ip}  {0.5 * (n + 1):.3f} ms")
        elif r.outcome == "net_unreachable":
            out.append(f" {n + 1}  {r.hop_ips[-1] if r.hop_ips else src_ip}  {0.5 * (n + 1):.3f} ms !N")
        else:
            out += [f" {k}  * * *" for k in range(n + 1, n + 4)]
        return "\n".join(out) + "\n"

    async def _tcp_probe(self, host: str, port: int, ann: dict[str, Any]) -> tuple[str, PathResult | None, str]:
        """Returns (status, path, banner) with status in ok|refused|timeout|noroute|dns."""
        w = self.lab.world
        ip, _ = self._resolve(host, ann)
        if ip is None:
            return "dns", None, ""
        r = w.path(self.name, ip, "tcp", port)
        self._record_path(ann, r, "tcp", port)
        owner = w.owner_of(ip)
        if r.ok and r.service and r.service != "ssh":
            p = await self.lab.services.probe(r.dst_device or "", r.service)
            if p.transport_ok:  # connected: the client sees whatever the application answered, healthy or not
                return "ok", r, p.payload
            r.ok, r.outcome = False, "refused"
        elif r.ok:
            return "ok", r, f"SSH-2.0-OpenSSH_8.9 ({r.dst_device})"
        ann["symptoms"] += self.lab.symptoms_for(r.blocked_at, owner[0].name if owner else None)
        if r.outcome == "refused":
            return "refused", r, ""
        await self._slow()
        return ("noroute" if r.outcome == "net_unreachable" else "timeout"), r, ""

    # -- Linux -----------------------------------------------------------------------------------------------------
    async def _linux(self, line: str, ann: dict[str, Any]) -> str:
        w, d = self.lab.world, self.dev
        try:
            argv = shlex.split(line)
        except ValueError:
            return "bash: syntax error\n"
        if not argv:
            return ""
        sudo = argv[0] == "sudo"
        if sudo:
            argv = argv[1:]
            if self.access != "full":
                return self._deny(ann, f"{self.actor} is not in the sudoers file.  This incident will be reported.\n")
        cmd, args = argv[0], argv[1:]
        if cmd in ("exit", "logout"):
            self.closed = True
            return ""
        if cmd == "hostname":
            return render.hostname(d) + "\n"
        if cmd == "date":
            return self.lab.device_ts(self.name).replace("T", " ").replace("Z", " UTC") + "\n"
        if cmd == "uname":
            return f"Linux {render.hostname(d)} 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux\n"
        if cmd == "uptime":
            self._obs(ann, {(self.name, "system", "uptime")})
            return " 10:02:11 up 63 days,  3:14,  1 user,  load average: 0.08, 0.05, 0.01\n"
        if cmd == "whoami":
            return self.actor + "\n"
        if cmd == "ip" and args[:1] in (["addr"], ["a"], ["address"]):
            i = d.interfaces["eth0"]
            st = "UP" if w.link_up(d, i) else "DOWN"
            self._obs(ann, self._ifaces(["eth0"]))
            return (
                f"1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536\n    inet 127.0.0.1/8 scope host lo\n"
                f"2: eth0: <BROADCAST,MULTICAST,{st}> mtu 1500 state {st}\n    link/ether {d.mac}\n"
                f"    inet {i.ip} brd {net(i.ip or '0.0.0.0/32').broadcast_address} scope global eth0\n"
            )
        if cmd == "ip" and args[:1] in (["route"], ["r"]):
            i = d.interfaces["eth0"]
            return f"default via {d.gateway} dev eth0 proto static\n{net(i.ip or '0.0.0.0/32')} dev eth0 proto kernel scope link src {i.ip.split('/')[0] if i.ip else ''}\n"  # noqa: E501
        if cmd == "cat" and args == ["/etc/resolv.conf"]:
            dns = next(n for n, x in w.devices.items() if "dns" in x.services)
            return f"nameserver {w.primary_ip(dns)}\nsearch {w.topo.domain}\n"
        if cmd == "systemctl":
            return self._systemctl(args, ann, sudo)
        if cmd == "journalctl":
            unit = None
            n = 50
            for k, a in enumerate(args):
                if a == "-u" and k + 1 < len(args):
                    unit = args[k + 1].removesuffix(".service")
                if a == "-n" and k + 1 < len(args) and args[k + 1].isdigit():
                    n = int(args[k + 1])
            return self._logging(ann, n, unit)
        if cmd == "ss":
            self._obs(ann, self._services())
            rows = ["Netid State  Local Address:Port"]
            for s in d.services.values():
                if s.running:
                    rows.append(f"{s.proto:<5} {'LISTEN' if s.proto == 'tcp' else 'UNCONN':<6} 0.0.0.0:{s.port}")
            return "\n".join(rows) + "\n"
        if cmd in ("ping", "traceroute", "tracepath"):
            target = next((a for a in args if not a.startswith("-") and not a.isdigit()), None)
            if not target:
                return f"Usage: {cmd} host\n"
            return await self._probe("ping" if cmd == "ping" else "traceroute", target, ann)
        if cmd in ("nslookup", "host", "dig"):
            name = next((a for a in args if not a.startswith(("-", "+", "@"))), None)
            if not name:
                return "usage: nslookup name\n"
            ip, status = self._resolve(name, ann)
            dns = next(n for n, x in w.devices.items() if "dns" in x.services)
            sip = w.primary_ip(dns)
            if ip:
                if cmd == "dig" and "+short" in args:
                    return ip + "\n"
                return f"Server:\t\t{sip}\nAddress:\t{sip}#53\n\nName:\t{name}\nAddress: {ip}\n"
            if status == "nxdomain":
                return f"Server:\t\t{sip}\nAddress:\t{sip}#53\n\n** server can't find {name}: NXDOMAIN\n"
            await self._slow()
            return ";; connection timed out; no servers could be reached\n"
        if cmd == "curl":
            url = next((a for a in args if "://" in a or (not a.startswith("-") and "." in a)), None)
            if not url:
                return "curl: try 'curl --help' for more information\n"
            m = re.match(r"^(?:(https?)://)?([^/:]+)(?::(\d+))?", url)
            if not m:
                return "curl: (3) URL using bad/illegal format\n"
            scheme, host, port = (
                m.group(1) or "http",
                m.group(2),
                int(m.group(3) or (443 if m.group(1) == "https" else 80)),
            )
            st, r, banner = await self._tcp_probe(host, port, ann)
            if st == "ok":
                show_headers = any(a in ("-i", "-v", "--include") for a in args)
                out = banner if show_headers else banner.split("\r\n\r\n", 1)[-1]
                return out + ("\n" if not out.endswith("\n") else "")
            _ = scheme
            return {
                "dns": f"curl: (6) Could not resolve host: {host}\n",
                "refused": f"curl: (7) Failed to connect to {host} port {port} after 2 ms: Connection refused\n",
                "noroute": f"curl: (7) Failed to connect to {host} port {port} after 3 ms: No route to host\n",
            }.get(st, f"curl: (28) Failed to connect to {host} port {port} after 5000 ms: Timeout was reached\n")
        if cmd in ("nc", "ncat"):
            pos = [a for a in args if not a.startswith("-")]
            pos = [a for k, a in enumerate(pos) if not (k > 0 and args[args.index(a) - 1] == "-w")]
            if len(pos) < 2 or not pos[-1].isdigit():
                return "usage: nc [-zv] host port\n"
            host, port = pos[-2], int(pos[-1])
            if "-u" in "".join(a for a in args if a.startswith("-")):
                ip, _ = self._resolve(host, ann)
                ok = False
                if ip:
                    ur = w.path(self.name, ip, "udp", port)
                    self._record_path(ann, ur, "udp", port)
                    ok = ur.ok
                return f"Connection to {host} {port} port [udp/*] succeeded!\n" if ok else ""
            st, _, _ = await self._tcp_probe(host, port, ann)
            return {
                "ok": f"Connection to {host} {port} port [tcp/*] succeeded!\n",
                "dns": f'nc: getaddrinfo for host "{host}" port {port}: Name or service not known\n',
                "refused": f"nc: connect to {host} port {port} (tcp) failed: Connection refused\n",
                "noroute": f"nc: connect to {host} port {port} (tcp) failed: No route to host\n",
            }.get(st, f"nc: connect to {host} port {port} (tcp) timed out: Operation now in progress\n")
        if cmd == "dns-record" and "dns" in d.services:
            return self._dns_record(args, ann, sudo)
        if cmd == "cat" and args == ["/etc/dnsmasq.hosts"] and "dns" in d.services:
            return self._dns_record(["list"], ann, False)
        if cmd == "dhcp-leases" and "dhcp" in d.services:
            return "".join(f"{ip} {w.device(n).mac} {n}\n" for n, ip in sorted(w.topo.dhcp_leases.items()))
        return f"bash: {cmd}: command not found\n" if not sudo else f"sudo: {cmd}: command not found\n"

    def _unit(self, name: str) -> Any:
        name = name.removesuffix(".service")
        return next((s for s in self.dev.services.values() if s.unit == name or s.name == name), None)

    def _systemctl(self, args: list[str], ann: dict[str, Any], sudo: bool) -> str:
        if not args or args[0] in ("list-units", "--failed", "--type=service"):
            self._obs(ann, self._services())
            rows = []
            for s in self.dev.services.values():
                active = "active running" if s.running else "failed failed"
                if "--failed" in args and s.running:
                    continue
                rows.append(f"  {s.unit}.service loaded {active} {s.name}")
            return "  UNIT LOAD ACTIVE SUB DESCRIPTION\n" + "\n".join(rows) + "\n"
        verb = args[0]
        unit = self._unit(args[1]) if len(args) > 1 else None
        if unit is None:
            return f"Unit {args[1] if len(args) > 1 else ''}.service could not be found.\n"
        if verb in ("status", "is-active"):
            self._obs(ann, self._services([k for k, s in self.dev.services.items() if s is unit]))
            if verb == "is-active":
                return ("active" if unit.running else "failed") + "\n"
            state = "active (running)" if unit.running else "failed (Result: signal)"
            return (
                f"* {unit.unit}.service - {unit.name}\n     Loaded: loaded (/lib/systemd/system/{unit.unit}.service; "
                f"enabled)\n     Active: {state}\n"
            )
        if verb in ("start", "restart", "stop"):
            if not sudo:
                return self._deny(ann, f"Failed to {verb} {unit.unit}.service: Access denied\n")
            want = verb != "stop"
            if unit.running == want and verb != "restart":
                return ""
            name = next(k for k, s in self.dev.services.items() if s is unit)
            self._mutate(ann, Mutation(op="stop_service", device=self.name, args={"service": name, "running": want}))
            return ""
        return f"Unknown command verb {verb}.\n"

    def _dns_record(self, args: list[str], ann: dict[str, Any], sudo: bool) -> str:
        z = self.lab.world.topo.dns_zone
        if not args or args[0] == "list":
            # A complete listing shows every record's value, and absence of any record that should exist.
            names = set(z) | set(self.lab.healthy.topo.dns_zone)
            self._obs(ann, {("dns", f"record:{fq}", "value") for fq in names} | {(self.name, "zone", "records")})
            return "".join(f"{ip}\t{fq}\n" for fq, ip in sorted(z.items()))
        if args[0] in ("set", "delete"):
            if not sudo:
                return self._deny(ann, "dns-record: permission denied (use sudo)\n")
            if len(args) < 2 or (args[0] == "set" and len(args) < 3):
                return "usage: dns-record set <fqdn> <ip> | delete <fqdn>\n"
            fq = args[1].lower().rstrip(".")
            ip = args[2] if args[0] == "set" else None
            if ip:
                try:
                    ipaddress.ip_address(ip)
                except ValueError:
                    return "dns-record: invalid address\n"
            self._mutate(ann, Mutation(op="set_dns_record", args={"name": fq, "ip": ip}))
            return "dns-record: updated 1 record(s); dnsmasq reloaded\n"
        return "usage: dns-record list | set <fqdn> <ip> | delete <fqdn>\n"
