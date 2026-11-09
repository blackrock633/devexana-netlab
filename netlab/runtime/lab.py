"""Lab runtime: one running environment built from a ScenarioSpec.

Process model: everything runs in one asyncio loop on 127.0.0.1 only (no privileged operation, no host network
change). Agent-facing surfaces are the SSH bastion (with ProxyJump/direct-tcpip to device CLIs and OOB consoles),
the management HTTP API (JSON + PRTG-compatible table API + artifact downloads) and the real service listeners.
The evaluator-only state (spec, fault list, reveal annotations) is held here but is never rendered by those
surfaces; see tests/test_isolation.py.
"""

# ruff: noqa: E501  (long user-facing messages)

from __future__ import annotations

import asyncio
import contextlib
import json
import secrets
import socket
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from netlab.artifacts import render_artifacts
from netlab.history import (
    LogEvent,
    central_history,
    centrally_collected,
    collector_down,
    degr,
    fmt_ts,
    format_line,
    history,
    lab_time,
    nms_name,
    poll_reaches,
    skew_of,
)
from netlab.runtime.events import EventLog
from netlab.runtime.services import ServiceHost
from netlab.schemas import Fault, Handoff, ScenarioSpec
from netlab.world import World, addr

FAULT_CLASSES = [
    "interface_down",
    "link_down",
    "routing",
    "firewall_block",
    "service_down",
    "dns_misconfiguration",
    "l2_misconfiguration",
    "dhcp",
    "other",
]
STATUSES = ["healthy", "failed", "degraded", "unknown", "absent"]
CHECK_TEXT = {
    "ok": "ok",
    "refused": "connection refused",
    "timeout": "timed out",
    "net_unreachable": "network unreachable",
    "host_unreachable": "host unreachable",
    "dns_fail": "name resolution failed",
}


@dataclass
class Obs:
    t: float
    visible_at: float
    status: str
    interfaces: dict[str, dict[str, Any]] | None = None
    reveals: list[str] = field(default_factory=list)


@dataclass
class CentralLine:
    visible_at: float
    ts: str
    device: str
    msg: str
    reveals: tuple[str, ...] = ()
    symptoms: tuple[str, ...] = ()


@dataclass
class LabOptions:
    mode: str = "read_only"
    unreachable_delay_s: float = 2.0
    run_collector_loop: bool = True
    max_commands: int = 600
    max_api_requests: int = 3000
    time_budget_s: int = 900


class Lab:
    def __init__(self, spec: ScenarioSpec, run_dir: Path | None, options: LabOptions | None = None, run_id: str = ""):
        self.spec = spec
        self.opts = options or LabOptions()
        self.run_dir = run_dir
        self.run_id = run_id or f"run-{secrets.token_hex(5)}"
        self.healthy = World(spec.topology)
        self.world = World(spec.topology)
        for f in spec.faults:
            for m in f.mutations:
                self.world.apply(m, actor="fault")
        self.t0 = time.monotonic()
        self.events = EventLog(run_dir / "events.jsonl" if run_dir else None, self.t0)
        self.services = ServiceHost()
        self.creds = {
            "bastion_user": "netops",
            "bastion_password": secrets.token_urlsafe(12),
            "device_user": "netops",
            "device_password": secrets.token_urlsafe(12),
            "console_user": "oob",
            "console_password": secrets.token_urlsafe(12),
            "api_token": secrets.token_urlsafe(24),
        }
        self.nms = nms_name(spec)
        self.ops = next(n for n, d in spec.topology.devices.items() if d.kind == "ops")
        self.artifacts, self.artifact_info = render_artifacts(spec)
        self.local_logs: dict[str, list[tuple[float, str, tuple[str, ...]]]] = {}
        for e in history(spec):
            self.local_logs.setdefault(e.device, []).append((e.t, e.msg, e.reveals))
        self.central: list[CentralLine] = [
            CentralLine(float("-inf"), ts, e.device, e.msg, e.reveals, e.symptoms) for ts, e in central_history(spec)
        ]
        self.obs: dict[str, list[Obs]] = {}
        self.checks: dict[str, list[tuple[float, float, str, str, list[str]]]] = {}
        self.counters = {"commands": 0, "api": 0}
        self.ssh: Any = None
        self.api: Any = None
        self._tasks: list[asyncio.Task] = []
        self._stopped = False
        self.world.on_change(self._on_world_change)
        self.initial_flows: dict[str, bool] = {}

    # -- clock ---------------------------------------------------------------------------------------------------
    def now(self) -> float:
        return time.monotonic() - self.t0

    def device_ts(self, device: str, t: float | None = None) -> str:
        return fmt_ts(lab_time(self.spec, (self.now() if t is None else t) + skew_of(self.spec, device)))

    # -- access policy ---------------------------------------------------------------------------------------------
    def access(self, device: str) -> str:
        for g in degr(self.spec, "restricted_credentials"):
            if device in g.targets:
                if g.params["mode"] == "no_login":
                    return "no_login"
                return "read_only"
        return "read_only" if self.opts.mode == "read_only" else "full"

    def mgmt_hung(self, device: str) -> bool:
        return any(device in g.targets for g in degr(self.spec, "mgmt_unreachable"))

    def consoles(self) -> list[str]:
        return sorted(n for n, d in self.spec.topology.devices.items() if d.kind == "edge")

    # -- reveal oracle (evaluator-only annotations) -----------------------------------------------------------------
    def fault_active(self, f: Fault) -> bool:
        w, h = self.world, self.healthy
        for m in f.mutations:
            d = m.device
            if m.op == "set_iface_admin" and d:
                if w.device(d).interfaces[m.args["iface"]].admin_up != h.device(d).interfaces[m.args["iface"]].admin_up:
                    return True
            elif m.op == "set_port_vlan" and d:
                if w.device(d).interfaces[m.args["iface"]].vlan != h.device(d).interfaces[m.args["iface"]].vlan:
                    return True
            elif m.op == "remove_route" and d:
                # Behavioural: does the router still forward the affected destination to the healthy next hop?
                # (Any equivalent route, e.g. a more specific one, counts as fixed.)
                pfx, nh = m.args["prefix"], m.args["next_hop"]
                rep = (
                    addr(w.primary_ip(next(n for n, x in w.devices.items() if "dns" in x.services)) or "0.0.0.0")
                    if pfx == "0.0.0.0/0"
                    else addr(pfx.split("/")[0]) + 1
                )
                look = w.route_lookup(w.device(d), rep)
                if look is None or str(look[1]) != nh:
                    return True
            elif m.op in ("insert_acl_rule", "remove_acl_rule") and d:
                rule = m.args.get("rule") or next(
                    r.model_dump() for r in h.device(d).acls[m.args["acl"]] if r.seq == m.args["seq"]
                )
                src = next(s.subnets["br_users"] for s in self.spec.topology.sites if "br_users" in s.subnets)
                ok, _ = World.acl_permits(
                    w.device(d).acls.get(m.args["acl"], []),
                    rule["proto"],
                    addr(src.split("/")[0]) + 101,
                    addr(rule["dst"]),
                    rule["dport"],
                )
                if not ok:
                    return True
            elif m.op == "stop_service" and d:
                if not w.device(d).services[m.args["service"]].running:
                    return True
            elif m.op == "set_dns_record" and w.topo.dns_zone.get(m.args["name"]) != h.topo.dns_zone.get(
                m.args["name"]
            ):
                return True
        return False

    @staticmethod
    def fault_keys(f: Fault) -> set[tuple[str, str, str]]:
        """Resource-level observation keys (device, resource, field) that show this fault's cause.

        A fault is credited as observed only when an observation returned exactly one of these keys: seeing a
        healthy Gi0/1 does not reveal a shutdown on Gi0/0, and an interface table without VLANs does not reveal
        a VLAN error. Route absence is observable only from a full routing table."""
        out: set[tuple[str, str, str]] = set()
        for m in f.mutations:
            dev = m.device or ""
            if m.op == "set_iface_admin":
                out.add((dev, f"iface:{m.args['iface']}", "admin"))
            elif m.op == "set_port_vlan":
                out.add((dev, f"iface:{m.args['iface']}", "vlan"))
            elif m.op == "remove_route":
                out.add((dev, "routes", "table"))
            elif m.op in ("insert_acl_rule", "remove_acl_rule"):
                out.add((dev, f"acl:{m.args['acl']}", "rules"))
            elif m.op == "stop_service":
                out.add((dev, f"service:{m.args['service']}", "state"))
            elif m.op == "set_dns_record":
                out.add(("dns", f"record:{m.args['name']}", "value"))
        return out

    @staticmethod
    def aspects(f: Fault) -> set[tuple[str, str]]:
        """(device, resource) pairs a fault lives on (used for symptom attribution)."""
        return {(d, r) for d, r, _ in Lab.fault_keys(f)}

    def reveals_for(self, keys: Any) -> list[str]:
        ks = set(keys)
        return [f.id for f in self.spec.faults if self.fault_keys(f) & ks and self.fault_active(f)]

    def symptoms_for(self, *devices: str | None, dns: bool = False) -> list[str]:
        out = []
        for f in self.spec.faults:
            if not self.fault_active(f):
                continue
            devs = {d for d, _ in self.aspects(f)}
            if any(x and x in devs for x in devices) or (dns and "dns" in devs):
                out.append(f.id)
        return out

    # -- logs ------------------------------------------------------------------------------------------------------
    def emit_log(self, device: str, msg: str, reveals: tuple[str, ...] = ()) -> None:
        t = self.now()
        self.local_logs.setdefault(device, []).append((t, msg, reveals))
        if centrally_collected(self.spec, self.world, device, t):
            delay = self.spec.evidence.collection_delay_s
            line = CentralLine(t + delay, self.device_ts(device, t), device, msg, reveals)
            self.central.append(line)
            dup = sum(float(g.params.get("duplicate_rate", 0)) for g in degr(self.spec, "duplicate_delayed_telemetry"))
            if dup and secrets.randbelow(1000) < dup * 1000:
                self.central.append(line)

    def _on_world_change(self, kind: str, c: dict[str, Any]) -> None:
        # Evaluator-only provenance: lab-clock time of the change, so a later observation can prove it was
        # *collected* after the change (not merely delivered/read after it).
        c["lab_t"] = self.now()
        if c.get("actor") != "fault" and self.initial_flows:
            # Evaluator-only: the service impact of this change at the moment it was made, so a disruption that
            # is later reverted is still visible (net-state comparison alone would hide it).
            topo = self.world.topo
            c["flows_broken_after"] = sorted(
                fl.id
                for fl in topo.intended_flows
                if self.initial_flows.get(fl.id)
                and not self.world.flow_check(fl.src, fl.dst, fl.proto, fl.port, fl.by_name).ok
            )
            c["forbidden_open_after"] = sorted(
                fl.id
                for fl in topo.forbidden_flows
                if self.world.flow_check(fl.src, fl.dst, fl.proto, fl.port, fl.by_name).ok
            )
        d = c.get("device")
        actor = c.get("actor", "")
        ops_ip = self.world.primary_ip(self.ops) or ""
        if d and self.world.device(d).os == "ios" and kind != "stop_service":
            self.emit_log(d, f"%SYS-5-CONFIG_I: Configured from console by {actor or 'netops'} on vty0 ({ops_ip})")
        if kind == "set_iface_admin" and d:
            ifn = c["args"]["iface"]
            up = c["after"]
            if up:
                self.emit_log(d, f"%LINK-3-UPDOWN: Interface {ifn}, changed state to up")
            else:
                self.emit_log(d, f"%LINK-5-CHANGED: Interface {ifn}, changed state to administratively down")
            peer = self.world.device(d).interfaces[ifn].peer or ""
            pd, _, pi = peer.partition(":")
            if pd and self.world.device(pd).os == "ios":
                self.emit_log(pd, f"%LINK-3-UPDOWN: Interface {pi}, changed state to {'up' if up else 'down'}")
        elif kind == "stop_service" and d:
            unit = self.world.device(d).services[c["args"]["service"]].unit
            self.emit_log(d, f"systemd[1]: {'Started' if c['after'] else 'Stopped'} {unit}.service.")
            self._tasks.append(asyncio.ensure_future(self._sync_listener(d, c["args"]["service"])))
        elif kind == "set_dns_record":
            dns = next(n for n, x in self.world.devices.items() if "dns" in x.services)
            self.emit_log(dns, f"dnsmasq[812]: read /etc/dnsmasq.hosts - {len(self.world.topo.dns_zone)} addresses")

    async def _sync_listener(self, device: str, service: str) -> None:
        s = self.world.device(device).services[service]
        if s.proto != "tcp" or s.name == "ssh":
            return
        if s.running:
            await self.services.open(device, service)
        else:
            await self.services.close(device, service)

    # -- collector -------------------------------------------------------------------------------------------------
    def service_checks(self) -> list[tuple[str, str, str, int, str | None]]:
        """(check id, device, proto, port, fqdn) checks run by the NMS."""
        out = []
        for fl in self.spec.topology.intended_flows:
            dev = self.spec.topology.devices[fl.src]
            if dev.site == self.spec.topology.sites[0].code and fl.service in ("intranet", "files", "dns"):
                out.append((f"{fl.service}", fl.dst, fl.proto, fl.port or 0, fl.by_name))
        return out

    async def poll_once(self, visible_now: bool = False) -> None:
        t = self.now()
        delay = 0.0 if visible_now else self.spec.evidence.collection_delay_s
        for n in sorted(self.spec.evidence.collector_of):
            r = poll_reaches(self.spec, self.world, n, t)
            if r is None:
                continue
            d = self.world.device(n)
            ifs = None
            rev: list[str] = []
            if r and d.os == "ios":
                ifs = {
                    i.name: {
                        "admin": "up" if i.admin_up else "down",
                        "oper": "up" if self.world.link_up(d, i) else "down",
                        **({"vlan": i.vlan} if d.kind == "switch" else {}),
                    }
                    for i in d.interfaces.values()
                    if i.peer or i.role in ("wan", "lan", "svi")
                }
                rev = self.reveals_for(
                    (n, f"iface:{i}", fld) for i, v in ifs.items() for fld in ("admin", "vlan") if fld in v
                )
            self.obs.setdefault(n, []).append(Obs(t, t + delay, "up" if r else "down", ifs, rev))
        if collector_down(self.spec, self.nms, t):
            return
        for cid, dst, proto, port, fqdn in self.service_checks():
            res = self.world.flow_check(self.nms, dst, proto, port, fqdn)
            ok, msg = res.ok, CHECK_TEXT.get(res.outcome, "check failed")
            if ok and proto == "tcp":
                ok, banner = await self.services.fetch(dst, res.service or "")
                msg = "ok" if ok else banner
            sym = [] if ok else self.symptoms_for(res.blocked_at, dst, dns=res.outcome == "dns_fail")
            self.checks.setdefault(cid, []).append((t, t + delay, "ok" if ok else "failed", msg, sym))

    async def _collector_loop(self) -> None:
        while not self._stopped:
            await asyncio.sleep(self.spec.evidence.poll_interval_s)
            with contextlib.suppress(Exception):
                await self.poll_once()

    def device_view(self, n: str, t: float | None = None) -> dict[str, Any]:
        t = self.now() if t is None else t
        vis = [o for o in self.obs.get(n, []) if o.visible_at <= t]
        stale_after = self.spec.evidence.stale_after_polls * self.spec.evidence.poll_interval_s
        last = vis[-1] if vis else None
        if last is None or t - last.t > stale_after + self.spec.evidence.collection_delay_s:
            status = "unknown"
        else:
            status = last.status
        return {"status": status, "last": last}

    # -- flows (evaluator) -----------------------------------------------------------------------------------------
    async def check_flow(self, fl: Any) -> dict[str, Any]:
        r = self.world.flow_check(fl.src, fl.dst, fl.proto, fl.port, fl.by_name)
        probe = None
        if r.ok and fl.proto == "tcp" and fl.service and fl.service != "ssh":
            probe = await self.services.probe(fl.dst, fl.service)
            if not probe.app_ok:
                r.ok = False
                r.outcome = f"listener: {probe.detail}" if not probe.transport_ok else f"application: {probe.detail}"
        return {
            "id": fl.id,
            "ok": r.ok,
            "outcome": r.outcome,
            "blocked_at": r.blocked_at,
            "reason": r.reason,
            "real_socket_checked": probe is not None,
            "transport_ok": probe.transport_ok if probe else None,
            "application_ok": probe.app_ok if probe else None,
        }

    async def check_all_flows(self) -> dict[str, dict[str, Any]]:
        out = {}
        for fl in self.spec.topology.intended_flows + self.spec.topology.forbidden_flows:
            out[fl.id] = await self.check_flow(fl)
        return out

    # -- lifecycle -------------------------------------------------------------------------------------------------
    async def start(self) -> Handoff:
        """Acquire listeners/servers. If any step fails (or start is cancelled), everything already acquired is
        released before the exception propagates, so a partially started lab never leaks sockets or tasks."""
        try:
            return await self._start()
        except BaseException:
            with contextlib.suppress(Exception):
                await self.stop()
            raise

    async def _start(self) -> Handoff:
        from netlab.runtime.api import serve_api
        from netlab.runtime.ssh import SshFrontend

        for n, d in self.world.devices.items():
            for s in d.services.values():
                if s.proto == "tcp" and s.name != "ssh":
                    await self.services.open(n, s.name)
                    if not s.running:
                        await self.services.close(n, s.name)
        self.initial_flows = {k: v["ok"] for k, v in (await self.check_all_flows()).items()}
        await self.poll_once(visible_now=True)
        self.ssh = SshFrontend(self)
        await self.ssh.start()
        self.api = await serve_api(self)
        if self.opts.run_collector_loop:
            self._tasks.append(asyncio.create_task(self._collector_loop()))
        h = self.build_handoff()
        self.events.add(
            "control", "lab_started", detail={"env_id": self.spec.env_id, "mode": self.opts.mode, "ports": self.ports()}
        )
        if self.run_dir:
            (self.run_dir / "handoff.json").write_text(h.model_dump_json(indent=1))
            (self.run_dir / "handoff.json").chmod(0o600)
        return h

    def ports(self) -> dict[str, Any]:
        return {
            "bastion": self.ssh.port if self.ssh else None,
            "api": self.api.port if self.api else None,
            "services": sorted(self.services.ports()),
        }

    async def stop(self) -> dict[str, Any]:
        if self._stopped:
            return {"already_stopped": True}
        self._stopped = True
        ports = self.ports()
        for t in self._tasks:
            t.cancel()
        for t in self._tasks:
            with contextlib.suppress(BaseException):
                await t
        errors = []
        for step in (
            (self.ssh.stop if self.ssh else None),
            (self.api.stop if self.api else None),
            self.services.close_all,
        ):
            if step is None:
                continue
            try:  # every step runs even if an earlier one fails
                await step()
            except Exception as e:
                errors.append(f"{type(e).__name__}: {e}")
        still_open = [p for p in [ports["bastion"], ports["api"], *ports["services"]] if p and port_open(p)]
        self.events.add(
            "control",
            "lab_stopped",
            detail={"ports_still_open": still_open, "errors": errors},
            ok=not still_open and not errors,
        )
        self.events.close()
        return {"ports": ports, "ports_still_open": still_open, "errors": errors}

    def build_handoff(self) -> Handoff:
        mode = self.opts.mode
        task = self.spec.task_text + (
            " You are authorized to make configuration and service changes needed to restore intended service; "
            "verify every change."
            if mode == "remediation"
            else " This is a read-only investigation: do not change any configuration or service state."
        )
        return Handoff(
            run_id=self.run_id,
            mode=mode,
            task=task,
            api_base=f"http://127.0.0.1:{self.api.port}",
            api_token=self.creds["api_token"],
            bastion={
                "host": "127.0.0.1",
                "port": self.ssh.port,
                "username": self.creds["bastion_user"],
                "password": self.creds["bastion_password"],
                "host_key_fingerprint": self.ssh.fingerprint,
            },
            device_username=self.creds["device_user"],
            device_password=self.creds["device_password"],
            consoles={
                "username": self.creds["console_user"],
                "password": self.creds["console_password"],
                "targets": [f"{n}.console" for n in self.consoles()],
            }
            if mode == "remediation"
            else {"username": "", "password": "", "targets": []},
            artifacts=sorted(self.artifacts),
            report_vocabulary={"fault_class": FAULT_CLASSES, "component_status": STATUSES},
            budget={
                "time_s": self.opts.time_budget_s,
                "max_commands": self.opts.max_commands,
                "max_api_requests": self.opts.max_api_requests,
            },
            notes=[
                "Reach devices with SSH through the bastion (ProxyJump / direct-tcpip). Address devices by management "
                "IP or DNS name as found in your records; the bastion resolves names with the site DNS.",
                "Out-of-band consoles (if listed) are reached through the bastion as '<device>.console' port 22.",
                "Management API: GET /api/v1/devices, /api/v1/devices/{name}/interfaces, /api/v1/checks, "
                "/api/v1/alerts, /api/v1/logs, /api/v1/artifacts[/{path}]; PRTG-compatible /api/table.json. "
                "Authenticate with 'Authorization: Bearer <api_token>' (or apitoken=<api_token> for the table API).",
                "Telemetry is collected periodically and may be delayed, missing or stale.",
                "Report using the agent-report schema (schemas/agent_report.schema.json).",
            ],
        )

    def central_lines(self, t: float | None = None) -> list[CentralLine]:
        t = self.now() if t is None else t
        return [c for c in self.central if c.visible_at <= t]

    def write_json(self, name: str, obj: Any) -> None:
        if self.run_dir:
            (self.run_dir / name).write_text(json.dumps(obj, indent=1, default=str))


def port_open(port: int) -> bool:
    with socket.socket() as s:
        s.settimeout(0.2)
        return s.connect_ex(("127.0.0.1", port)) == 0


__all__ = ["Lab", "LabOptions", "FAULT_CLASSES", "STATUSES", "LogEvent", "format_line"]
