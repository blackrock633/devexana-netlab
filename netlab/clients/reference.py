"""Reference client: a deterministic, rule-based investigator/remediator (no model, no ground-truth access).

It sees only the handoff file and uses only the interfaces offered to any agent under test: the management API
(and its artifacts) and SSH through the bastion (plus OOB consoles in remediation runs). It exists to prove the
lab end to end and to give the evaluator a known reference point; it is not meant to be a strong agent.

Usage: python -m netlab.clients.reference --handoff handoff.json --out report.json
This module must not import anything from netlab except the report schema (enforced by tests/test_isolation.py).
"""

from __future__ import annotations

import argparse
import asyncio
import csv
import io
import ipaddress
import re
import sys
import time
from dataclasses import dataclass, field
from typing import Any

import asyncssh
import httpx

from netlab.schemas import (
    AgentReport,
    Handoff,
    ReportAction,
    ReportDevice,
    ReportFinding,
    ReportUnknown,
    ReportVerification,
)

NAME = "netlab-reference-client"
VERSION = "0.1.0"
SERVICE_PORTS = {"intranet": ("tcp", 443), "files": ("tcp", 445), "dns": ("udp", 53)}


@dataclass
class Rec:
    ip: str
    names: set[str] = field(default_factory=set)
    kind: str = ""
    site: str = ""
    nms_status: str | None = None
    nms_last: str | None = None
    ssh_ok: bool = False
    ssh_error: str = ""
    os: str = ""
    out: dict[str, str] = field(default_factory=dict)  # command -> output (latest pass)

    @property
    def name(self) -> str:
        lower = sorted(n for n in self.names if n == n.lower())
        return (lower or sorted(self.names) or [self.ip])[0]


class Client:
    def __init__(self, h: Handoff):
        self.h = h
        self.http = httpx.AsyncClient(
            base_url=h.api_base, headers={"Authorization": f"Bearer {h.api_token}"}, timeout=20
        )
        self.recs: dict[str, Rec] = {}
        self.absent: list[str] = []
        self.bastion: asyncssh.SSHClientConnection | None = None
        self.conns: dict[str, asyncssh.SSHClientConnection] = {}
        self.domain = ""
        self.artifacts: dict[str, str] = {}
        self.findings: dict[tuple[str, str], ReportFinding] = {}
        self.actions: list[ReportAction] = []
        self.verifications: list[ReportVerification] = []
        self.errors: list[str] = []
        self.fixed: set[tuple[str, str]] = set()
        self.zone: dict[str, str] = {}
        self.listen: dict[int, str] = {}  # tcp/udp port -> ip of device listening
        self.svc_units: dict[str, list[tuple[str, bool]]] = {}  # ip -> [(unit, running)]
        self.probe_results: dict[tuple[str, str], str] = {}
        self.resolved: dict[str, str] = {}  # fqdn -> address returned by nslookup

    # -- plumbing ---------------------------------------------------------------------------------------------------
    async def api(self, path: str, **params: Any) -> Any:
        r = await self.http.get(path, params=params)
        r.raise_for_status()
        return r.json() if "json" in r.headers.get("content-type", "") else r.text

    def rec(self, ip: str) -> Rec:
        return self.recs.setdefault(ip, Rec(ip=ip))

    async def connect_bastion(self) -> None:
        b = self.h.bastion
        self.bastion = await asyncssh.connect(
            b["host"], port=b["port"], username=b["username"], password=b["password"], known_hosts=None
        )

    async def ssh(self, target: str, commands: str, console: bool = False, timeout: float = 25) -> str | None:
        assert self.bastion is not None
        key = ("console:" if console else "") + target
        try:
            conn = self.conns.get(key)
            if conn is None:
                user = self.h.consoles["username"] if console else self.h.device_username
                pw = self.h.consoles["password"] if console else self.h.device_password
                conn = await asyncio.wait_for(
                    asyncssh.connect(
                        f"{target}.console" if console else target,
                        tunnel=self.bastion,
                        username=user,
                        password=pw,
                        known_hosts=None,
                    ),
                    timeout=timeout,
                )
                self.conns[key] = conn
            r = await asyncio.wait_for(conn.run(commands, check=False), timeout=timeout)
            return str(r.stdout)
        except (TimeoutError, asyncssh.Error, OSError) as e:
            self.conns.pop(key, None)
            msg = getattr(e, "reason", "") or type(e).__name__
            if target in self.recs:
                self.recs[target].ssh_error = msg
            return None

    async def local(self, commands: str) -> str:
        assert self.bastion is not None
        r = await self.bastion.run(commands, check=False)
        return str(r.stdout)

    # -- collection -------------------------------------------------------------------------------------------------
    async def collect_records(self) -> None:
        for a in await self.api("/api/v1/artifacts"):
            try:
                self.artifacts[a["path"]] = await self.api(f"/api/v1/artifacts/{a['path']}")
            except httpx.HTTPError as e:
                self.errors.append(f"artifact {a['path']}: {e}")
        inv = self.artifacts.get("inventory.csv", "")
        for row in csv.DictReader(io.StringIO(inv if isinstance(inv, str) else "")):
            if not row.get("IPAddress"):
                if row.get("AssetName"):
                    self.absent.append(row["AssetName"])
                continue
            r = self.rec(row["IPAddress"])
            r.names.add(row["AssetName"])
            r.kind = r.kind or row.get("AssetType", "")
            r.site = row.get("Site", "")
        for line in str(self.artifacts.get("topology.mmd", "")).splitlines():
            m = re.search(r'\["([^<"]+)<br/>([\d.]+)"\]', line)
            if m:
                self.rec(m.group(2)).names.add(m.group(1))
        for p, txt in self.artifacts.items():
            if p.startswith("configs/"):
                for m in re.finditer(r"ip address ([\d.]+)/(\d+)", str(txt)):
                    self.rec(m.group(1)).names.add(p.removeprefix("configs/").removesuffix(".cfg"))
                    break
                m = re.search(r"ip domain-name (\S+)", str(txt))
                if m:
                    self.domain = m.group(1)
        for d in await self.api("/api/v1/devices"):
            if not d.get("mgmt_ip"):
                if d["name"] not in self.absent:
                    self.absent.append(d["name"])
                continue
            r = self.rec(d["mgmt_ip"])
            r.names.add(d["name"])
            r.kind = r.kind or d.get("type", "")
            r.nms_status, r.nms_last = d["status"], d.get("last_polled")
        self.checks = await self.api("/api/v1/checks")

    async def survey(self) -> None:
        targets = [ip for ip, r in sorted(self.recs.items()) if "workstation" not in r.kind.lower()]
        sem = asyncio.Semaphore(6)

        async def one(ip: str) -> None:
            async with sem:
                await self.survey_device(ip)

        await asyncio.gather(*(one(ip) for ip in targets))
        consoles = [t.removesuffix(".console") for t in self.h.consoles.get("targets", [])]
        for ip, r in sorted(self.recs.items()):  # out-of-band fallback for unreachable edge devices
            if not r.ssh_ok and (c := next((n for n in r.names if n in consoles), None)):
                await self.survey_device(ip, console_name=c)

    async def survey_device(self, ip: str, console_name: str | None = None) -> None:
        r = self.rec(ip)
        probe = await self.ssh(console_name or ip, "show version", console=bool(console_name))
        if probe is None:
            r.ssh_ok = False
            return
        r.ssh_ok = True
        r.os = "ios" if "Invalid input" not in probe and "command not found" not in probe else "linux"
        cmds = (
            [
                "show ip interface brief",
                "show ip route",
                "show access-lists",
                "show running-config",
                "show interfaces status",
            ]
            if r.os == "ios"
            else ["hostname", "systemctl list-units", "ss -tuln", "dns-record list", "dhcp-leases"]
        )
        for c in cmds:
            out = await self.ssh(console_name or ip, c, console=bool(console_name))
            if out is not None:
                r.out[c] = out
        if r.os == "linux":
            r.names.add(r.out.get("hostname", "").strip())
            units = re.findall(r"^\s+(\S+)\.service loaded (\S+)", r.out.get("systemctl list-units", ""), re.M)
            self.svc_units[ip] = [(u, st == "active") for u, st in units]
            for _proto, port in re.findall(r"^(tcp|udp)\s+\S+\s+0\.0\.0\.0:(\d+)", r.out.get("ss -tuln", ""), re.M):
                if int(port) != 22:
                    self.listen[int(port)] = ip
            for u, running in self.svc_units[ip]:
                if not running:  # failed units do not listen; remember their port by unit name
                    port = {"nginx": 443, "smbd": 445, "dnsmasq": 53}.get(u)
                    if port:
                        self.listen.setdefault(port, ip)
            for ipz, fq in re.findall(r"^([\d.]+)\t(\S+)$", r.out.get("dns-record list", ""), re.M):
                self.zone[fq] = ipz
            for lip, _mac, n in re.findall(r"^([\d.]+) (\S+) (\S+)$", r.out.get("dhcp-leases", ""), re.M):
                w = self.rec(lip)
                w.names.add(n)
                w.kind = w.kind or "Workstation"
        else:
            m = re.search(r"^hostname (\S+)", r.out.get("show running-config", ""), re.M)
            if m:
                r.names.add(m.group(1))

    def vantage_branch(self) -> str | None:
        for ip, r in self.recs.items():
            if "probe" in r.kind.lower() or any("-mon" in n or "mon" in n for n in r.names if n.islower()):
                return ip
        return None

    async def probes(self) -> dict[tuple[str, str], str]:
        res: dict[tuple[str, str], str] = {}
        svc = [c["check"] for c in self.checks] or list(SERVICE_PORTS)
        br = self.vantage_branch()
        for vantage in ("hq", "branch"):
            if vantage == "branch" and br is None:
                continue
            for s in svc:
                if s not in SERVICE_PORTS:
                    continue
                proto, port = SERVICE_PORTS[s]
                fq = f"{s}.{self.domain}" if self.domain else s
                if proto == "udp":
                    name = next((z for z in sorted(self.zone) if z.startswith("intranet.")), None) or (
                        f"intranet.{self.domain}" if self.domain else "intranet"
                    )
                    cmd = f"nslookup {name}"
                else:
                    cmd = f"nc -zv -w 3 {fq} {port}"
                out = await (self.local(cmd) if vantage == "hq" else self.ssh(br, cmd))  # type: ignore[arg-type]
                res[(vantage, s)] = out if out is not None else "(vantage unreachable)"
                if proto == "tcp":
                    ns = await (self.local(f"nslookup {fq}") if vantage == "hq" else self.ssh(br, f"nslookup {fq}"))  # type: ignore[arg-type]
                    m = re.search(r"Name:\s+\S+\nAddress: ([\d.]+)", ns or "")
                    if m:
                        self.resolved[fq] = m.group(1)
                ip_target = self.listen.get(port)
                if ip_target and proto == "tcp":
                    cmd2 = f"nc -zv -w 3 {ip_target} {port}"
                    out2 = await (self.local(cmd2) if vantage == "hq" else self.ssh(br, cmd2))  # type: ignore[arg-type]
                    res[(vantage, s + "@ip")] = out2 if out2 is not None else "(vantage unreachable)"
        self.probe_results = res
        return res

    # -- diagnosis --------------------------------------------------------------------------------------------------
    def add(self, comp: str, cls: str, text: str, ev: list[str], conf: float) -> None:
        self.findings.setdefault(
            (comp, cls), ReportFinding(component=comp, fault_class=cls, statement=text, evidence=ev, confidence=conf)
        )

    def edges(self) -> list[Rec]:
        return [
            r
            for r in self.recs.values()
            if r.os == "ios"
            and "ip access-list" in r.out.get("show running-config", "")
            or (r.os == "ios" and "Gi0/0" in r.out.get("show ip interface brief", ""))
        ]

    def diagnose(self) -> None:
        self.findings.clear()
        lans: dict[str, list[str]] = {}
        for r in self.edges():
            cfg = r.out.get("show running-config", "")
            lans[r.ip] = [
                str(ipaddress.ip_network(f"{a}/{p}", strict=False))
                for a, p in re.findall(r"ip address ([\d.]+)/(\d+)", cfg)
                if p != "30"
            ]
        for r in self.recs.values():
            if r.os != "ios":
                continue
            brief = r.out.get("show ip interface brief", "")
            for ifn, _st in re.findall(r"^(\S+)\s+\S+\s+YES\s+manual\s+(administratively down)", brief, re.M):
                if ifn.startswith("Gi0/") or ifn.startswith("Gi1/0/"):
                    self.add(
                        f"{r.name}:{ifn}",
                        "interface_down",
                        f"{ifn} on {r.name} is administratively down.",
                        [f"ssh {r.name}: show ip interface brief"],
                        0.9,
                    )
            status = r.out.get("show interfaces status", "")
            for port, desc, _st in re.findall(r"^(Gi1/0/\d+)\s+(\S.{0,24}?)\s+(disabled)\s+\d+", status, re.M):
                if desc.strip():
                    self.add(
                        f"{r.name}:{port}",
                        "interface_down",
                        f"Switch port {port} ({desc.strip()}) on {r.name} is disabled.",
                        [f"ssh {r.name}: show interfaces status"],
                        0.85,
                    )
        # Routing: every edge must route to every other edge's LAN subnets.
        for r in self.edges():
            routes = r.out.get("show ip route", "")
            cfg = r.out.get("show running-config", "")
            if not routes:
                continue
            installed = [ipaddress.ip_network(n) for n in re.findall(r"^[CS]\s+(\S+)", routes, re.M)]
            for other_ip, subs in lans.items():
                if other_ip == r.ip:
                    continue
                for s in subs:
                    sn = ipaddress.ip_network(s)
                    if not any(sn.subnet_of(n) for n in installed):  # type: ignore[arg-type]
                        configured = s in cfg or "0.0.0.0/0" in cfg
                        local_down = re.search(
                            r"^\S+\s+\S+\s+YES\s+manual\s+(?:administratively )?down\s+down$",
                            r.out.get("show ip interface brief", ""),
                            re.M,
                        )
                        if configured and (local_down or any(k[1] == "interface_down" for k in self.findings)):
                            continue  # next hop unreachable because of a down interface: a consequence, not a cause
                        why = "is configured but not installed (next hop unreachable)" if configured else "is missing"
                        self.add(
                            f"{r.name}:route:{s}",
                            "routing",
                            f"{r.name} has no usable route to {s}: route {why}.",
                            [f"ssh {r.name}: show ip route"],
                            0.6 if configured else 0.85,
                        )
        # Services, DNS, VLAN, ACL.
        for ip, units in self.svc_units.items():
            for u, running in units:
                if not running:
                    n = self.rec(ip).name
                    svc = {"nginx": "intranet", "smbd": "files"}.get(u, u)
                    self.add(
                        f"{n}:service:{svc}",
                        "service_down",
                        f"{u}.service on {n} is failed/not running.",
                        [f"ssh {n}: systemctl list-units"],
                        0.9,
                    )
        for fq, zip_ in {**self.resolved, **self.zone}.items():
            s = fq.split(".")[0]
            if s in SERVICE_PORTS and SERVICE_PORTS[s][0] == "tcp":
                real = self.listen.get(SERVICE_PORTS[s][1])
                if real and real != zip_:
                    self.add(
                        f"dns:{fq}",
                        "dns_misconfiguration",
                        f"DNS record {fq} -> {zip_}, but the service listens on {real}.",
                        ["ssh dns server: dns-record list", "ssh servers: ss -tuln"],
                        0.85,
                    )
        for r in self.recs.values():
            cfg = r.out.get("show running-config", "")
            if r.os != "ios" or "switchport access vlan" not in cfg:
                continue
            blocks = re.findall(
                r"interface (\S+)\n(?: description (.*)\n)?(?: ip address .*\n)?(?: switchport access vlan (\d+)\n)?",
                cfg,
            )
            uplink_vlan = {desc.split()[-1]: int(v) for _i, desc, v in blocks if desc.startswith("uplink") and v}
            for ifn, desc, v in blocks:
                if not v or desc.startswith("uplink") or not desc:
                    continue
                srv = next((x for x in self.recs.values() if desc in x.names), None)
                if srv is None:
                    continue
                purpose = None
                for e in self.edges():
                    for blk in e.out.get("show running-config", "").split("interface ")[1:]:
                        mm = re.search(r"description (\S+)\n ip address ([\d.]+)/(\d+)", blk)
                        if mm and ipaddress.ip_address(srv.ip) in ipaddress.ip_network(
                            f"{mm.group(2)}/{mm.group(3)}", strict=False
                        ):
                            purpose = mm.group(1)
                want = uplink_vlan.get(purpose or "")
                if want and int(v) != want:
                    self.add(
                        f"{r.name}:{ifn}",
                        "l2_misconfiguration",
                        f"Port {ifn} on {r.name} (to {desc}) is in VLAN {v}; its subnet's VLAN is {want}.",
                        [f"ssh {r.name}: show running-config"],
                        0.85,
                    )
        for r in self.edges():
            acls = r.out.get("show access-lists", "")
            if "WAN-IN" not in acls:
                continue
            rules = re.findall(r"^\s+(\d+) (permit|deny) (\S+) (\S+) (\S+)(?: eq (\d+))?", acls, re.M)
            for s, (_proto, port) in SERVICE_PORTS.items():
                ip = self.listen.get(port)
                br_fail = self.probe_results.get(("branch", s + "@ip"), "")
                hq_ok = "succeeded" in self.probe_results.get(("hq", s + "@ip"), "")
                if not ip or not br_fail or "succeeded" in br_fail or not hq_ok:
                    continue
                if not any(ipaddress.ip_address(ip) in ipaddress.ip_network(n) for n in lans.get(r.ip, [])):
                    continue
                verdict = None
                for seq, act, pr, src, dst, dp in rules:
                    if pr not in ("ip", _proto) or (
                        dst != "any" and ipaddress.ip_address(ip) not in ipaddress.ip_network(dst)
                    ):
                        continue
                    if dp and int(dp) != port:
                        continue
                    if src == "any" or src.endswith("/24"):
                        verdict = (act, seq)
                        break
                if verdict is None or verdict[0] == "deny":
                    what = f"seq {verdict[1]} denies it" if verdict else "no rule permits it (implicit deny)"
                    self.add(
                        f"{r.name}:acl:WAN-IN",
                        "firewall_block",
                        f"WAN-IN on {r.name} blocks branch tcp/{port} to {ip}: {what}.",
                        [f"ssh {r.name}: show access-lists", f"probe branch -> {ip}:{port} failed, HQ ok"],
                        0.8,
                    )

    # -- remediation ------------------------------------------------------------------------------------------------
    async def run_on(self, name: str, block: str) -> str | None:
        r = next((x for x in self.recs.values() if name in x.names), None)
        out = await self.ssh(r.ip, block) if r else None
        if out is None and name in [t.removesuffix(".console") for t in self.h.consoles.get("targets", [])]:
            out = await self.ssh(name, block, console=True)
        if out is None and r:
            for alias in r.names:
                if alias in [t.removesuffix(".console") for t in self.h.consoles.get("targets", [])]:
                    out = await self.ssh(alias, block, console=True)
                    break
        return out

    async def remediate(self) -> None:
        for (comp, cls), f in list(self.findings.items()):
            if (comp, cls) in self.fixed:
                continue
            dev, _, rest = comp.partition(":")
            block = None
            if cls == "interface_down" and rest:
                block = f"configure terminal\ninterface {rest}\nno shutdown\nend\nwrite memory"
            elif cls == "routing" and rest.startswith("route:"):
                prefix = rest.removeprefix("route:")
                r = next(x for x in self.recs.values() if dev in x.names)
                wan = re.search(
                    r"interface Gi0/0\n(?: description .*\n)? ip address ([\d.]+)/30",
                    r.out.get("show running-config", ""),
                )
                if wan:
                    a = ipaddress.ip_address(wan.group(1))
                    peer = a + 1 if int(a) % 4 == 1 else a - 1
                    block = f"configure terminal\nip route {prefix} {peer}\nend\nwrite memory"
            elif cls == "firewall_block":
                m = re.search(r"tcp/(\d+) to ([\d.]+): (?:seq (\d+) denies)?", f.statement)
                if m:
                    port, ip, seq = m.group(1), m.group(2), m.group(3)
                    r = next(x for x in self.recs.values() if dev in x.names)
                    src = re.search(r"\d+ permit \S+ (\d+\.\d+\.\d+\.\d+/24) ", r.out.get("show access-lists", ""))
                    if seq:
                        block = f"configure terminal\nip access-list extended WAN-IN\nno {seq}\nend\nwrite memory"
                    elif src:
                        block = (
                            f"configure terminal\nip access-list extended WAN-IN\n45 permit tcp {src.group(1)} "
                            f"host {ip} eq {port}\nend\nwrite memory"
                        )
            elif cls == "service_down":
                unit = {"intranet": "nginx", "files": "smbd"}.get(
                    rest.removeprefix("service:"), rest.removeprefix("service:")
                )
                block = f"sudo systemctl restart {unit}"
            elif cls == "dns_misconfiguration":
                fq = rest
                port = SERVICE_PORTS.get(fq.split(".")[0], ("tcp", 0))[1]
                real = self.listen.get(port)
                dns = next(
                    (
                        x
                        for x in self.recs.values()
                        if re.search(r"^[\d.]+\t\S+$", x.out.get("dns-record list", ""), re.M)
                    ),
                    None,
                )
                if real and dns:
                    block = f"sudo dns-record set {fq} {real}"
                    dev = dns.name
            elif cls == "l2_misconfiguration":
                m = re.search(r"its subnet's VLAN is (\d+)", f.statement)
                if m:
                    block = (
                        f"configure terminal\ninterface {rest}\nswitchport access vlan {m.group(1)}\nend\nwrite memory"
                    )
            if block is None:
                continue
            out = await self.run_on(dev, block)
            failed = out is None or any(
                x in out
                for x in (
                    "Authorization failed",
                    "not in the sudoers",
                    "Invalid input",
                    "command not found",
                    "permission denied",
                )
            )
            self.actions.append(
                ReportAction(
                    target=dev,
                    description=f"Fix {cls} on {comp}",
                    commands=block.splitlines(),
                    result="failed: " + ("no access" if out is None else out.strip()[:200]) if failed else "applied",
                )
            )
            if not failed:
                self.fixed.add((comp, cls))

    # -- top level --------------------------------------------------------------------------------------------------
    async def run(self) -> AgentReport:
        t0 = time.monotonic()
        await self.collect_records()
        await self.connect_bastion()
        await self.survey()
        await self.probes()
        self.diagnose()
        before = dict(self.findings)
        if self.h.mode == "remediation":
            for _round in range(3):
                if not self.findings or all(k in self.fixed for k in self.findings):
                    break
                await self.remediate()
                await asyncio.sleep(1)
                for r in self.recs.values():  # re-survey: fixes may have made more devices reachable
                    if "workstation" not in r.kind.lower():
                        await self.survey_device(r.ip)
                for ip in [ip for ip, r in self.recs.items() if not r.ssh_ok and "workstation" not in r.kind.lower()]:
                    await self.survey_device(ip)
                await self.probes()
                self.diagnose()
                for k, v in before.items():
                    self.findings.setdefault(k, v)
                before = dict(self.findings)
            # Verification against the same probes used for diagnosis.
            for (vantage, s), out in sorted(self.probe_results.items()):
                ok = "succeeded" in out or ("Address:" in out and "can't find" not in out and s == "dns")
                self.verifications.append(
                    ReportVerification(check=f"{vantage} -> {s}", passed=ok, detail=out.strip()[:160])
                )
        return self.report(time.monotonic() - t0)

    def report(self, elapsed: float) -> AgentReport:
        devices, status, unknowns = [], {}, []
        failed_devs = {f.component.split(":")[0] for f in self.findings.values()}
        for ip, r in sorted(self.recs.items()):
            devices.append(ReportDevice(name=r.name, ip=ip, kind=r.kind or None, site=r.site or None))
            fixed_all = all(((c, k) in self.fixed) for (c, k) in self.findings if c.split(":")[0] in r.names)
            if r.name in failed_devs or any(n in failed_devs for n in r.names):
                status[r.name] = "healthy" if (self.h.mode == "remediation" and fixed_all) else "failed"
            elif r.ssh_ok:
                status[r.name] = "healthy"
            elif "workstation" in r.kind.lower():
                continue
            else:
                status[r.name] = "unknown"
                why = f"SSH failed ({r.ssh_error or 'unreachable'})"
                if r.nms_status in (None, "unknown"):
                    why += "; no current telemetry"
                else:
                    why += f"; telemetry says {r.nms_status} (last polled {r.nms_last})"
                unknowns.append(ReportUnknown(component=r.name, reason=why))
        for n in self.absent:
            status[n] = "absent"
        links = []
        for r in self.recs.values():
            for _port, desc in re.findall(
                r"^(Gi1/0/\d+)\s+(\S+)\s+connected", r.out.get("show interfaces status", ""), re.M
            ):
                if not desc.startswith("uplink"):
                    links.append((r.name, desc))
        verified = [v.passed for v in self.verifications]
        recovered = (all(verified) and bool(verified)) if self.h.mode == "remediation" else None
        summary = (
            f"{len(self.findings)} fault(s) identified; {len(self.fixed)} fixed; {len(unknowns)} component(s) "
            f"could not be observed."
            if self.findings
            else f"No faults identified in observed components; {len(unknowns)} component(s) could not be observed."
        )
        return AgentReport(
            agent={"name": NAME, "version": VERSION},
            summary=summary,
            healthy_overall=(not self.findings) if not unknowns else None,
            devices=devices,
            links=sorted(set(links)),
            component_status=status,
            findings=list(self.findings.values()),
            unknowns=unknowns,
            actions=self.actions,
            verification=self.verifications,
            claims_recovered=recovered,
            errors=self.errors + [f"elapsed {elapsed:.1f}s"],
        )

    async def close(self) -> None:
        for c in self.conns.values():
            c.close()
        if self.bastion:
            self.bastion.close()
        await self.http.aclose()


async def amain(handoff_path: str, out_path: str) -> int:
    with open(handoff_path) as fh:
        h = Handoff.model_validate_json(fh.read())
    c = Client(h)
    try:
        rep = await c.run()
    except Exception as e:  # report the failure honestly instead of crashing silently
        rep = AgentReport(agent={"name": NAME, "version": VERSION}, summary="client failed", errors=[repr(e)])
    finally:
        await c.close()
    with open(out_path, "w") as f:
        f.write(rep.model_dump_json(indent=1))
    return 0


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--handoff", required=True)
    ap.add_argument("--out", required=True)
    a = ap.parse_args()
    sys.exit(asyncio.run(amain(a.handoff, a.out)))


if __name__ == "__main__":
    main()
