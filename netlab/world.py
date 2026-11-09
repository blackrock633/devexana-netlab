"""Authoritative network state and the emulated forwarding plane.

``World`` is the single source of truth that every exposed interface (SSH CLIs, the management API, the collector,
service listeners) reads and writes. Changes made through one interface are therefore visible to all others; only
the collector adds modelled delay.

Fidelity (see docs/FIDELITY.md): forwarding is a deterministic path walk (L2 segment check, inbound ACL,
longest-prefix-match routing, return-path routing for stateful flows). It is not a kernel network stack: there is
no MTU, no queuing, no ARP timing, no TCP state machine. Service sockets are real (see runtime.services).
"""

from __future__ import annotations

import ipaddress
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from netlab.schemas import AclRule, Device, Interface, Mutation, Route, Topology

Net = ipaddress.IPv4Network
Addr = ipaddress.IPv4Address


def net(cidr: str) -> Net:
    return ipaddress.ip_network(cidr, strict=False)  # type: ignore[return-value]


def addr(cidr_or_ip: str) -> Addr:
    return ipaddress.ip_address(cidr_or_ip.split("/")[0])  # type: ignore[return-value]


@dataclass
class PathResult:
    ok: bool
    outcome: str  # ok | refused | timeout | net_unreachable | host_unreachable | dns_fail
    hops: list[str] = field(default_factory=list)  # device names traversed
    hop_ips: list[str] = field(default_factory=list)  # router ingress IPs (what traceroute shows)
    blocked_at: str | None = None
    reason: str = ""  # evaluator-facing detail; agent-facing renderers must not print it verbatim
    dst_device: str | None = None
    service: str | None = None
    resolved_ip: str | None = None
    ingress: list[str] = field(default_factory=list)  # "device:iface" each hop was entered through
    # Evaluator-only: every router forwarding decision taken (forward and return path), in order:
    # {"device", "dst", "prefix", "source": "connected"|"static", "next_hop", "egress", "direction"}
    decisions: list[dict[str, Any]] = field(default_factory=list)
    dst_ip: str | None = None  # the destination address actually probed


class World:
    """Mutable network state guarded by a lock. All mutation goes through ``apply`` or the typed setters."""

    def __init__(self, topology: Topology):
        self.topo = topology.model_copy(deep=True)
        self.lock = threading.RLock()
        self.version = 0
        self._listeners: list[Callable[[str, dict[str, Any]], None]] = []

    # -- observation hooks -------------------------------------------------------------------------------------
    def on_change(self, fn: Callable[[str, dict[str, Any]], None]) -> None:
        self._listeners.append(fn)

    def _changed(self, kind: str, detail: dict[str, Any]) -> None:
        self.version += 1
        for fn in list(self._listeners):
            fn(kind, detail)

    # -- lookups -------------------------------------------------------------------------------------------------
    @property
    def devices(self) -> dict[str, Device]:
        return self.topo.devices

    def device(self, name: str) -> Device:
        return self.topo.devices[name]

    def owner_of(self, ip: str) -> tuple[Device, Interface] | None:
        a = addr(ip)
        for d in self.topo.devices.values():
            for i in d.interfaces.values():
                if i.ip and addr(i.ip) == a:
                    return d, i
        return None

    def primary_ip(self, name: str) -> str | None:
        d = self.topo.devices[name]
        for i in d.interfaces.values():
            if i.ip and i.role in ("host", "svi"):
                return i.ip.split("/")[0]
        for i in d.interfaces.values():
            if i.ip and i.role == "lan":
                return i.ip.split("/")[0]
        return None

    def mgmt_ip(self, name: str) -> str | None:
        return self.primary_ip(name)

    def resolve_name(self, name: str) -> str | None:
        """Hostname -> device name (accepts device names, aliases, FQDNs and IPs)."""
        n = name.strip().lower().rstrip(".")
        dom = "." + self.topo.domain
        if n.endswith(dom):
            n = n[: -len(dom)]
        for d in self.topo.devices.values():
            if n == d.name.lower() or n in (a.lower() for a in d.aliases):
                return d.name
        try:
            o = self.owner_of(n)
            return o[0].name if o else None
        except ValueError:
            return None

    # -- link state ------------------------------------------------------------------------------------------------
    def _peer(self, ref: str | None) -> tuple[Device, Interface] | None:
        if not ref:
            return None
        dn, _, ifn = ref.partition(":")
        d = self.topo.devices.get(dn)
        if d is None or ifn not in d.interfaces:
            return None
        return d, d.interfaces[ifn]

    def link_up(self, dev: Device, iface: Interface) -> bool:
        """Operational state: admin up and the far end of the physical link admin up."""
        if not iface.admin_up:
            return False
        if iface.role == "svi":
            return True
        p = self._peer(iface.peer)
        return p is not None and p[1].admin_up

    def _attachment(self, dev: Device, iface: Interface) -> tuple[str, int] | None:
        """(switch name, vlan) the interface sits on, if it is up."""
        if iface.role == "svi":
            return (dev.name, iface.vlan or 1) if iface.admin_up else None
        if not iface.admin_up:
            return None
        p = self._peer(iface.peer)
        if p is None:
            return None
        pd, pi = p
        if pd.kind == "switch":
            return (pd.name, pi.vlan or 1) if pi.admin_up else None
        return None

    def same_segment(self, a: tuple[Device, Interface], b: tuple[Device, Interface]) -> bool:
        (ad, ai), (bd, bi) = a, b
        if ai.role == "wan" or bi.role == "wan":
            return ai.peer == f"{bd.name}:{bi.name}" and ai.admin_up and bi.admin_up
        x, y = self._attachment(ad, ai), self._attachment(bd, bi)
        return x is not None and x == y

    # -- forwarding ------------------------------------------------------------------------------------------------
    def connected(self, dev: Device) -> list[tuple[Net, Interface]]:
        return [(net(i.ip), i) for i in dev.interfaces.values() if i.ip and self.link_up(dev, i)]

    def route_lookup(self, dev: Device, dst: Addr) -> tuple[Interface, Addr | None] | None:
        d = self.route_decision(dev, dst)
        return (d[0], d[1]) if d else None

    def route_decision(self, dev: Device, dst: Addr) -> tuple[Interface, Addr | None, str, str] | None:
        """Longest-prefix match: (egress, next hop or None, matched prefix, "connected"|"static")."""
        best: tuple[int, Interface, Addr | None, str, str] | None = None
        conn = self.connected(dev)
        for n, i in conn:
            if dst in n and (best is None or n.prefixlen > best[0]):
                best = (n.prefixlen, i, None, str(n), "connected")
        for r in dev.routes:
            n = net(r.prefix)
            if dst not in n or (best is not None and n.prefixlen <= best[0]):
                continue
            nh = addr(r.next_hop)
            egress = next((i for cn, i in conn if nh in cn), None)
            if egress is not None:
                best = (n.prefixlen, egress, nh, r.prefix, "static")
        return best[1:] if best else None

    @staticmethod
    def acl_permits(
        rules: list[AclRule], proto: str, src: Addr, dst: Addr, dport: int | None
    ) -> tuple[bool, int | None]:
        for r in sorted(rules, key=lambda x: x.seq):
            if r.proto != "ip" and r.proto != proto:
                continue
            if r.src != "any" and src not in net(r.src):
                continue
            if r.dst != "any" and dst not in net(r.dst):
                continue
            if r.dport is not None and r.dport != dport:
                continue
            return r.action == "permit", r.seq
        return False, None  # implicit deny

    def _forward(
        self, src: Device, dst_ip: Addr, proto: str, dport: int | None, check_acl: bool, direction: str = "forward"
    ) -> PathResult:
        ingress_log: list[str] = []
        decisions: list[dict[str, Any]] = []
        r = self._forward_impl(src, dst_ip, proto, dport, check_acl, ingress_log, decisions)
        r.ingress = ingress_log
        r.decisions = [{**d, "direction": direction} for d in decisions]
        r.dst_ip = str(dst_ip)
        return r

    def _forward_impl(
        self,
        src: Device,
        dst_ip: Addr,
        proto: str,
        dport: int | None,
        check_acl: bool,
        ingress_log: list[str],
        decisions: list[dict[str, Any]],
    ) -> PathResult:
        hops = [src.name]
        hop_ips: list[str] = []
        src_ip = addr(self.primary_ip(src.name) or "0.0.0.0")
        cur: Device = src
        ingress: Interface | None = None
        for _ttl in range(12):
            if cur.kind == "edge" and check_acl and ingress is not None and ingress.name in cur.acl_in:
                rules = cur.acls.get(cur.acl_in[ingress.name], [])
                ok, seq = self.acl_permits(rules, proto, src_ip, dst_ip, dport)
                if not ok:
                    acl = cur.acl_in[ingress.name]
                    why = f"acl {acl} seq {seq}" if seq else f"acl {acl} implicit deny"
                    return PathResult(False, "timeout", hops, hop_ips, blocked_at=cur.name, reason=why)
            for i in cur.interfaces.values():
                if i.ip and addr(i.ip) == dst_ip and (i.admin_up or cur is src):
                    return PathResult(True, "ok", hops, hop_ips, dst_device=cur.name)
            if cur.kind == "edge":
                look = self.route_decision(cur, dst_ip)
                if look is None:
                    return PathResult(False, "net_unreachable", hops, hop_ips, blocked_at=cur.name, reason="no route")
                egress, nh, prefix, source = look
                decisions.append(
                    {
                        "device": cur.name,
                        "dst": str(dst_ip),
                        "prefix": prefix,
                        "source": source,
                        "next_hop": str(nh) if nh else None,
                        "egress": egress.name,
                    }
                )
            else:
                egress = next((i for i in cur.interfaces.values() if i.ip and i.role in ("host", "svi")), None)
                if egress is None or not self.link_up(cur, egress):
                    return PathResult(False, "timeout", hops, hop_ips, blocked_at=cur.name, reason="local link down")
                if dst_ip in net(egress.ip):  # type: ignore[arg-type]
                    nh = None
                elif cur.gateway:
                    nh = addr(cur.gateway)
                else:
                    return PathResult(False, "net_unreachable", hops, hop_ips, blocked_at=cur.name, reason="no gateway")
            target = nh or dst_ip
            owner = self.owner_of(str(target))
            if owner is None or not self.same_segment((cur, egress), owner):
                outcome = "host_unreachable"
                return PathResult(False, outcome, hops, hop_ips, blocked_at=cur.name, reason=f"no neighbour {target}")
            nd, ni = owner
            if nd.kind == "edge":
                hop_ips.append(ni.ip.split("/")[0])  # type: ignore[union-attr]
            hops.append(nd.name)
            ingress_log.append(f"{nd.name}:{ni.name}")
            cur, ingress = nd, ni
        return PathResult(False, "timeout", hops, hop_ips, reason="ttl exceeded")

    def path(self, src_name: str, dst_ip: str, proto: str = "icmp", dport: int | None = None) -> PathResult:
        """Full flow evaluation: forward path (with ACLs), service presence, stateful return path (routing only)."""
        with self.lock:
            src = self.topo.devices[src_name]
            try:
                d = addr(dst_ip)
            except ValueError:
                return PathResult(False, "dns_fail", [src_name], reason="not an address")
            fwd = self._forward(src, d, proto, dport, check_acl=True)
            if not fwd.ok:
                return fwd
            dst = self.topo.devices[fwd.dst_device]  # type: ignore[index]
            back_ip = self.primary_ip(src_name)
            if back_ip and dst.name != src.name:
                back = self._forward(dst, addr(back_ip), proto, None, check_acl=False, direction="return")
                fwd.decisions += back.decisions
                if not back.ok:
                    fwd.ok, fwd.outcome = False, "timeout"
                    fwd.blocked_at, fwd.reason = back.blocked_at, f"return path: {back.reason}"
                    return fwd
            if proto in ("tcp", "udp"):
                svc = next((s for s in dst.services.values() if s.proto == proto and s.port == dport), None)
                if svc is None or not svc.running:
                    fwd.ok = False
                    fwd.outcome = "refused" if proto == "tcp" else "timeout"
                    fwd.blocked_at, fwd.reason = dst.name, "no listener"
                    return fwd
                fwd.service = svc.name
            return fwd

    def resolve_dns(self, client: str, fqdn: str) -> tuple[str | None, str]:
        """Resolve via the site DNS server(s) the client is configured with. Returns (ip, status)."""
        with self.lock:
            servers = [d for d in self.topo.devices.values() if "dns" in d.services]
            if not servers:
                return None, "no dns server"
            for s in servers:
                p = self.path(client, self.primary_ip(s.name) or "", "udp", 53)
                if p.ok:
                    name = fqdn.lower().rstrip(".")
                    if "." not in name:
                        name = f"{name}.{self.topo.domain}"
                    ip = self.topo.dns_zone.get(name)
                    return (ip, "ok") if ip else (None, "nxdomain")
            return None, "timeout"

    def flow_check(self, flow_src: str, dst: str, proto: str, port: int | None, by_name: str | None) -> PathResult:
        target_ip: str | None
        if by_name:
            target_ip, status = self.resolve_dns(flow_src, by_name)
            if target_ip is None:
                return PathResult(False, "dns_fail", [flow_src], reason=f"dns {status}")
        else:
            target_ip = self.primary_ip(dst)
        r = self.path(flow_src, target_ip or "", proto, port)
        r.resolved_ip = target_ip
        if r.ok and r.dst_device != dst:
            r.ok, r.outcome, r.reason = False, "timeout", f"reached {r.dst_device} instead of {dst}"
        return r

    # -- mutation --------------------------------------------------------------------------------------------------
    def apply(self, m: Mutation, actor: str = "fault") -> dict[str, Any]:
        """Apply a mutation; returns {"before":..., "after":...}. Used by fault injection and by CLI commands."""
        with self.lock:
            d = self.topo.devices[m.device] if m.device else None
            a = m.args
            before: Any
            after: Any
            if m.op == "set_iface_admin":
                assert d is not None
                i = d.interfaces[a["iface"]]
                before, i.admin_up = i.admin_up, bool(a["up"])
                after = i.admin_up
            elif m.op == "set_port_vlan":
                assert d is not None
                i = d.interfaces[a["iface"]]
                before, i.vlan = i.vlan, int(a["vlan"])
                after = i.vlan
            elif m.op == "remove_route":
                assert d is not None
                before = [r.model_dump() for r in d.routes]
                d.routes = [
                    r for r in d.routes if not (r.prefix == a["prefix"] and (a.get("next_hop") in (None, r.next_hop)))
                ]
                after = [r.model_dump() for r in d.routes]
            elif m.op == "insert_acl_rule":
                assert d is not None
                rules = d.acls.setdefault(a["acl"], [])
                rule = AclRule.model_validate(a["rule"])
                before = [r.model_dump() for r in rules]
                rules[:] = [r for r in rules if r.seq != rule.seq] + [rule]
                rules.sort(key=lambda r: r.seq)
                after = [r.model_dump() for r in rules]
            elif m.op == "remove_acl_rule":
                assert d is not None
                rules = d.acls.setdefault(a["acl"], [])
                before = [r.model_dump() for r in rules]
                rules[:] = [r for r in rules if r.seq != int(a["seq"])]
                after = [r.model_dump() for r in rules]
            elif m.op == "stop_service":
                assert d is not None
                s = d.services[a["service"]]
                before, s.running = s.running, bool(a.get("running", False))
                after = s.running
            elif m.op == "set_dns_record":
                before = self.topo.dns_zone.get(a["name"])
                if a.get("ip"):
                    self.topo.dns_zone[a["name"]] = a["ip"]
                else:
                    self.topo.dns_zone.pop(a["name"], None)
                after = self.topo.dns_zone.get(a["name"])
            else:  # pragma: no cover - schema prevents this
                raise ValueError(m.op)
            change = {
                "op": m.op,
                "device": m.device,
                "args": a,
                "before": before,
                "after": after,
                "actor": actor,
                **self.target_of(m.op, m.device, a),
            }
            self._changed(m.op, change)
            return change

    def add_route(self, device: str, prefix: str, next_hop: str, actor: str) -> dict[str, Any]:
        with self.lock:
            d = self.topo.devices[device]
            before = [r.model_dump() for r in d.routes]
            if not any(r.prefix == prefix and r.next_hop == next_hop for r in d.routes):
                d.routes.append(Route(prefix=str(net(prefix)), next_hop=next_hop))
            change = {
                "op": "add_route",
                "device": device,
                "args": {"prefix": prefix, "next_hop": next_hop},
                "before": before,
                "after": [r.model_dump() for r in d.routes],
                "actor": actor,
                **self.target_of("add_route", device, {}),
            }
            self._changed("add_route", change)
            return change

    def target_of(self, op: str, device: str | None, a: dict[str, Any]) -> dict[str, str]:
        """Which resource a change touched, and the device that owns it (the DNS server for zone records)."""
        if op in ("set_iface_admin", "set_port_vlan"):
            res = f"iface:{a['iface']}:{'admin' if op == 'set_iface_admin' else 'vlan'}"
        elif op in ("remove_route", "add_route"):
            res = "routes"
        elif op in ("insert_acl_rule", "remove_acl_rule"):
            res = f"acl:{a['acl']}"
        elif op == "stop_service":
            res = f"service:{a['service']}"
        elif op == "set_dns_record":
            owner = next((n for n, d in self.topo.devices.items() if "dns" in d.services), "dns")
            return {"owner": owner, "resource": f"record:{a['name']}"}
        else:
            res = op
        return {"owner": device or "", "resource": res}

    def snapshot(self) -> dict[str, Any]:
        with self.lock:
            return self.topo.model_dump()
