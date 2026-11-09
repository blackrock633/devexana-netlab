"""Scenario generation: conventional pseudorandom sampling with explicit rules. No model is involved.

* Fresh seeds come from the operating system's entropy pool (``secrets.randbits``) and are saved in the spec.
  The generator itself is a seeded PRNG (``random.Random``, Mersenne Twister): it is pseudorandom, not physical
  true randomness. Given (seed, config, generation_inputs, GENERATOR_VERSION) the spec is reproduced exactly.
* Every random decision draws from one ``random.Random(seed)`` in a fixed order, so replay is exact.
* Constraints (resource budget, address plan, fault compatibility, remediability) are checked explicitly and
  violations raise ``GenerationError`` rather than silently producing an incoherent environment.
"""

# ruff: noqa: E501  (long user-facing messages)

from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import random
import secrets
from typing import Any

from netlab.schemas import (
    DEGRADATION_TYPES,
    FAMILIES,
    FAULT_TYPES,
    IMPLEMENTED_FAMILIES,
    AclRule,
    Degradation,
    Device,
    Distractor,
    EvidencePolicy,
    Fault,
    Flow,
    GenerationConfig,
    Interface,
    Mutation,
    Route,
    ScenarioSpec,
    Service,
    Site,
    Timeline,
    Topology,
)
from netlab.versions import GENERATOR_VERSION, component_versions
from netlab.world import World

SITE_CODES = ["bos", "chi", "den", "sea", "atl", "phx", "pit", "aus", "slc", "msp", "rdu", "cle"]
DOMAINS = ["corp.example", "office.example", "acme.example", "northwind.example", "contoso.example"]
VENDORS = {
    "edge": [("Cisco", "ISR 1111-8P"), ("Cisco", "ISR 4331"), ("Juniper", "SRX300")],
    "switch": [("Cisco", "C9200L-24T"), ("Aruba", "2930F-24G"), ("Cisco", "C2960X-24")],
    "server": [("Dell", "PowerEdge R250"), ("HPE", "ProLiant DL20"), ("Supermicro", "SYS-5019C")],
    "workstation": [("Dell", "OptiPlex 7010"), ("Lenovo", "ThinkCentre M70q"), ("HP", "EliteDesk 800")],
    "probe": [("Raspberry Pi", "Pi 4B")],
    "ops": [("Dell", "OptiPlex 7010")],
}
TASK_TEMPLATES = [
    "Staff at {br} and {hq} have raised network concerns. Investigate the current state of the network, identify any "
    "faults and their root causes, and state clearly what you could not determine.",
    "Perform a health investigation of the two-site network ({hq} head office, {br} branch). Report devices and "
    "topology you can confirm, any faults with root causes and supporting evidence, and any gaps in what you could "
    "observe.",
    "A routine review of the {hq}/{br} network was requested after recent helpdesk activity. Determine whether "
    "intended services are working, explain any root causes, and identify information you could not obtain.",
]


class GenerationError(ValueError):
    pass


def fresh_seed() -> int:
    """64-bit seed drawn from the OS entropy pool."""
    return secrets.randbits(64)


def _substream(seed: int, name: str) -> int:
    return int.from_bytes(hashlib.sha256(f"{seed}:{name}".encode()).digest()[:8], "big")


def _weighted(rng: random.Random, weights: dict[Any, float]) -> Any:
    items = [(k, w) for k, w in sorted(weights.items(), key=lambda kv: str(kv[0])) if w > 0]
    if not items:
        raise GenerationError("all sampling weights are zero")
    total = sum(w for _, w in items)
    x = rng.random() * total
    for k, w in items:
        x -= w
        if x <= 0:
            return k
    return items[-1][0]


def _canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def spec_digest(spec: ScenarioSpec) -> str:
    d = spec.model_dump(mode="json")
    for k in ("spec_sha256", "component_versions", "seed_source"):
        d.pop(k, None)
    return hashlib.sha256(_canonical(d).encode()).hexdigest()


# ---------------------------------------------------------------------------------------------------------------
# Branch-office family
# ---------------------------------------------------------------------------------------------------------------


class _Names:
    def __init__(self, rng: random.Random):
        self.style = rng.choice(["dash", "compact"])

    def __call__(self, site: str, role: str, n: int = 1) -> str:
        return f"{site}-{role}-{n:02d}" if self.style == "dash" else f"{site}{role}{n}"


def _build_branch_office(rng: random.Random, cfg: GenerationConfig) -> tuple[Topology, dict[str, Any]]:
    domain = rng.choice(DOMAINS)
    hq, br = rng.sample(SITE_CODES, 2)
    nm = _Names(rng)
    a = rng.randint(1, 120)
    b = rng.randint(121, 240)
    w = rng.randint(1, 250)
    u_hq, s_hq, o_hq = rng.choice([10, 11, 12]), rng.choice([20, 21, 22]), rng.choice([99, 250])
    u_br = rng.choice([30, 31, 40])
    v_users, v_srv, v_ops = rng.choice([10, 110]), rng.choice([20, 120]), rng.choice([99, 199])
    sub = {
        "hq_users": f"10.{a}.{u_hq}.0/24",
        "hq_servers": f"10.{a}.{s_hq}.0/24",
        "hq_ops": f"10.{a}.{o_hq}.0/24",
        "br_users": f"10.{b}.{u_br}.0/24",
        "wan": f"172.16.{w}.0/30",
    }

    def ip(subnet: str, host: int, prefix: bool = True) -> str:
        n = ipaddress.ip_network(sub[subnet])
        s = str(n.network_address + host)
        return f"{s}/{n.prefixlen}" if prefix else s

    n_hq_ws = rng.randint(*cfg.hq_workstations)
    n_br_ws = rng.randint(*cfg.branch_workstations)
    with_files = rng.random() < 0.7
    fixed = 2 + 2 + 3 + (1 if with_files else 0) + 1 + 1  # edges, switches, dns/app/nms, file, ops, probe
    while fixed + n_hq_ws + n_br_ws > cfg.max_devices and (n_hq_ws > 1 or n_br_ws > 1):
        if n_br_ws >= n_hq_ws and n_br_ws > 1:
            n_br_ws -= 1
        elif n_hq_ws > 1:
            n_hq_ws -= 1
    if fixed + n_hq_ws + n_br_ws > cfg.max_devices:
        raise GenerationError(f"max_devices={cfg.max_devices} is below the minimum branch-office size")

    devices: dict[str, Device] = {}
    serial_n = [rng.randint(100000, 900000)]

    def hw(kind: str) -> tuple[str, str, str, str]:
        vendor, model = rng.choice(VENDORS[kind])
        serial_n[0] += rng.randint(1, 999)
        mac = "02:" + ":".join(f"{rng.randint(0, 255):02x}" for _ in range(5))
        return vendor, model, f"SN{serial_n[0]}", mac

    hq_edge, br_edge = nm(hq, "edge" if nm.style == "dash" else "rtr"), nm(br, "edge" if nm.style == "dash" else "rtr")
    hq_sw, br_sw = nm(hq, "sw"), nm(br, "sw")
    port_no = {hq_sw: 4, br_sw: 2}

    def attach(sw: str, dev: str, ifn: str, vlan: int, desc: str) -> str:
        port_no[sw] += 1
        if port_no[sw] > 24:
            raise GenerationError(f"switch {sw} has no free access port (24-port model)")
        p = f"Gi1/0/{port_no[sw]}"
        devices[sw].interfaces[p] = Interface(name=p, role="access", vlan=vlan, peer=f"{dev}:{ifn}", description=desc)
        return f"{sw}:{p}"

    for site, edge, sw, _is_hq in ((hq, hq_edge, hq_sw, True), (br, br_edge, br_sw, False)):
        v, m, sn, mac = hw("edge")
        devices[edge] = Device(
            name=edge, kind="edge", site=site, model=f"{v} {m}", os="ios", interfaces={}, serial=sn, mac=mac
        )
        v, m, sn, mac = hw("switch")
        devices[sw] = Device(
            name=sw, kind="switch", site=site, model=f"{v} {m}", os="ios", interfaces={}, serial=sn, mac=mac
        )
        for p in range(1, 25):
            devices[sw].interfaces[f"Gi1/0/{p}"] = Interface(name=f"Gi1/0/{p}", role="access", vlan=1)
    # HQ edge
    e = devices[hq_edge]
    e.interfaces = {
        "Gi0/0": Interface(
            name="Gi0/0", ip=ip("wan", 1), role="wan", peer=f"{br_edge}:Gi0/0", description=f"WAN to {br}"
        ),
        "Gi0/1": Interface(
            name="Gi0/1", ip=ip("hq_users", 1), role="lan", peer=f"{hq_sw}:Gi1/0/1", description="users"
        ),
        "Gi0/2": Interface(
            name="Gi0/2", ip=ip("hq_servers", 1), role="lan", peer=f"{hq_sw}:Gi1/0/2", description="servers"
        ),
        "Gi0/3": Interface(name="Gi0/3", ip=ip("hq_ops", 1), role="lan", peer=f"{hq_sw}:Gi1/0/3", description="ops"),
    }
    sw = devices[hq_sw]
    for p, vl, d in (
        ("Gi1/0/1", v_users, f"uplink {hq_edge} users"),
        ("Gi1/0/2", v_srv, f"uplink {hq_edge} servers"),
        ("Gi1/0/3", v_ops, f"uplink {hq_edge} ops"),
    ):
        sw.interfaces[p] = Interface(name=p, role="uplink", vlan=vl, peer=f"{hq_edge}:Gi0/{p[-1]}", description=d)
    sw.interfaces["Vlan" + str(v_ops)] = Interface(name=f"Vlan{v_ops}", ip=ip("hq_ops", 2), role="svi", vlan=v_ops)
    sw.gateway = ip("hq_ops", 1, False)
    # Branch edge
    e = devices[br_edge]
    e.interfaces = {
        "Gi0/0": Interface(
            name="Gi0/0", ip=ip("wan", 2), role="wan", peer=f"{hq_edge}:Gi0/0", description=f"WAN to {hq}"
        ),
        "Gi0/1": Interface(
            name="Gi0/1", ip=ip("br_users", 1), role="lan", peer=f"{br_sw}:Gi1/0/1", description="users"
        ),
    }
    bsw = devices[br_sw]
    bsw.interfaces["Gi1/0/1"] = Interface(
        name="Gi1/0/1", role="uplink", vlan=v_users, peer=f"{br_edge}:Gi0/1", description=f"uplink {br_edge}"
    )
    bsw.interfaces[f"Vlan{v_users}"] = Interface(name=f"Vlan{v_users}", ip=ip("br_users", 2), role="svi", vlan=v_users)
    bsw.gateway = ip("br_users", 1, False)

    def host(
        name: str,
        kind: str,
        site: str,
        subnet: str,
        hostnum: int,
        sw_name: str,
        vlan: int,
        services: dict[str, Service],
        gw_subnet: str | None = None,
    ) -> None:
        v, m, sn, mac = hw(kind)
        os_name = "linux"
        devices[name] = Device(
            name=name,
            kind=kind,
            site=site,
            model=f"{v} {m}",
            os=os_name,  # type: ignore[arg-type]
            interfaces={},
            services=services,
            serial=sn,
            mac=mac,
            gateway=ip(gw_subnet or subnet, 1, False),
        )
        peer = attach(sw_name, name, "eth0", vlan, name)
        devices[name].interfaces["eth0"] = Interface(name="eth0", ip=ip(subnet, hostnum), role="host", peer=peer)

    ssh = Service(name="ssh", unit="sshd", proto="tcp", port=22)
    dns_n, app_n, nms_n, file_n = nm(hq, "dns"), nm(hq, "app"), nm(hq, "nms"), nm(hq, "file")
    ops_n, mon_n = nm(hq, "ops"), nm(br, "mon")
    host(
        dns_n,
        "server",
        hq,
        "hq_servers",
        10,
        hq_sw,
        v_srv,
        {
            "ssh": ssh.model_copy(),
            "dns": Service(name="dns", unit="dnsmasq", proto="udp", port=53),
            "dhcp": Service(name="dhcp", unit="dnsmasq-dhcp", proto="udp", port=67),
        },
    )
    host(
        app_n,
        "server",
        hq,
        "hq_servers",
        11,
        hq_sw,
        v_srv,
        {"ssh": ssh.model_copy(), "intranet": Service(name="intranet", unit="nginx", proto="tcp", port=443)},
    )
    host(
        nms_n,
        "server",
        hq,
        "hq_servers",
        12,
        hq_sw,
        v_srv,
        {
            "ssh": ssh.model_copy(),
            "syslog": Service(name="syslog", unit="rsyslog", proto="udp", port=514),
            "collector": Service(name="collector", unit="nms-collector", proto="tcp", port=8443),
        },
    )
    if with_files:
        host(
            file_n,
            "server",
            hq,
            "hq_servers",
            13,
            hq_sw,
            v_srv,
            {"ssh": ssh.model_copy(), "files": Service(name="files", unit="smbd", proto="tcp", port=445)},
        )
    host(ops_n, "ops", hq, "hq_ops", 10, hq_sw, v_ops, {"ssh": ssh.model_copy()})
    host(
        mon_n,
        "probe",
        br,
        "br_users",
        5,
        br_sw,
        v_users,
        {"ssh": ssh.model_copy(), "syslog": Service(name="syslog", unit="rsyslog", proto="udp", port=514)},
    )
    leases: dict[str, str] = {}
    for i in range(n_hq_ws):
        n = nm(hq, "ws", i + 1)
        host(n, "workstation", hq, "hq_users", 101 + i, hq_sw, v_users, {})
        leases[n] = ip("hq_users", 101 + i, False)
    for i in range(n_br_ws):
        n = nm(br, "ws", i + 1)
        host(n, "workstation", br, "br_users", 101 + i, br_sw, v_users, {})
        leases[n] = ip("br_users", 101 + i, False)
    for name in (hq_edge, br_edge, hq_sw, br_sw):
        devices[name].services["ssh"] = ssh.model_copy()

    # Routing: HQ has a specific route to the branch; the branch uses either a default or specific routes.
    devices[hq_edge].routes = [Route(prefix=sub["br_users"], next_hop=ip("wan", 2, False))]
    if rng.random() < 0.5:
        devices[br_edge].routes = [Route(prefix="0.0.0.0/0", next_hop=ip("wan", 1, False))]
    else:
        devices[br_edge].routes = [
            Route(prefix=sub[s], next_hop=ip("wan", 1, False)) for s in ("hq_users", "hq_servers", "hq_ops")
        ]
    devices[br_edge].dhcp_helper = {"Gi0/1": ip("hq_servers", 10, False)}

    def host32(n: str) -> str:
        return devices[n].interfaces["eth0"].ip.split("/")[0] + "/32"  # type: ignore[union-attr]

    hq_rules = [
        AclRule(seq=10, action="permit", proto="icmp", src="any", dst="any"),
        AclRule(seq=20, action="permit", proto="udp", src=sub["br_users"], dst=host32(dns_n), dport=53),
        AclRule(seq=30, action="permit", proto="udp", src=sub["br_users"], dst=host32(dns_n), dport=67),
        AclRule(seq=40, action="permit", proto="tcp", src=sub["br_users"], dst=host32(app_n), dport=443),
        AclRule(seq=60, action="permit", proto="udp", src=sub["br_users"], dst=host32(nms_n), dport=514),
        AclRule(seq=70, action="permit", proto="tcp", src=sub["br_users"], dst=host32(nms_n), dport=8443),
    ]
    if with_files:
        hq_rules.append(
            AclRule(seq=50, action="permit", proto="tcp", src=sub["br_users"], dst=host32(file_n), dport=445)
        )
    devices[hq_edge].acls = {"WAN-IN": sorted(hq_rules, key=lambda r: r.seq)}
    devices[hq_edge].acl_in = {"Gi0/0": "WAN-IN"}
    devices[br_edge].acls = {
        "WAN-IN": [
            AclRule(seq=10, action="permit", proto="icmp", src="any", dst="any"),
            AclRule(seq=20, action="permit", proto="tcp", src=sub["hq_ops"], dst=sub["br_users"], dport=22),
        ]
    }
    devices[br_edge].acl_in = {"Gi0/0": "WAN-IN"}

    # Aliases (other sources use other names: inconsistent naming is part of the realism).
    for d in devices.values():
        legacy = d.name.upper().replace("-", "")
        if d.kind == "edge":
            d.aliases = [f"{d.site.upper()}-RTR", legacy]
        elif d.kind == "switch":
            d.aliases = [f"{d.site.upper()}-CORE-SW" if d.site == hq else f"{d.site.upper()}-ACC-SW", legacy]
        else:
            d.aliases = [legacy]
        if d.kind in ("edge", "switch") and rng.random() < 0.5:
            d.hostname = d.aliases[0]

    zone: dict[str, str] = {}
    for d in devices.values():
        if d.kind == "workstation":
            continue
        p = World(
            Topology(
                domain=domain,
                sites=[],
                devices={d.name: d},
                dns_zone={},
                dhcp_leases={},
                intended_flows=[],
                forbidden_flows=[],
            )
        ).primary_ip(d.name)
        if p:
            zone[f"{d.name}.{domain}"] = p
    zone[f"intranet.{domain}"] = ip("hq_servers", 11, False)
    zone[f"nms.{domain}"] = ip("hq_servers", 12, False)
    if with_files:
        zone[f"files.{domain}"] = ip("hq_servers", 13, False)

    hq_ws1, br_ws1 = nm(hq, "ws", 1), nm(br, "ws", 1)
    flows: list[Flow] = []

    def flow(
        src: str, dst: str, proto: str, port: int | None, by_name: str | None = None, svc: str | None = None
    ) -> None:
        flows.append(
            Flow(
                id=f"flow-{len(flows) + 1:02d}",
                src=src,
                dst=dst,
                proto=proto,  # type: ignore[arg-type]
                port=port,
                by_name=by_name,
                service=svc,
            )
        )

    for ws in (hq_ws1, br_ws1):
        flow(ws, app_n, "tcp", 443, f"intranet.{domain}", "intranet")
        if with_files:
            flow(ws, file_n, "tcp", 445, f"files.{domain}", "files")
        flow(ws, dns_n, "udp", 53, None, "dns")
    flow(mon_n, nms_n, "tcp", 8443, None, "collector")
    for n in (hq_edge, br_edge, hq_sw, br_sw, dns_n, app_n, nms_n, mon_n) + ((file_n,) if with_files else ()):
        flow(ops_n, n, "tcp", 22, None, "ssh")
    forbidden = [
        Flow(id="deny-01", src=br_ws1, dst=ops_n, proto="tcp", port=22),
        Flow(id="deny-02", src=br_ws1, dst=dns_n, proto="tcp", port=22),
        Flow(id="deny-03", src=hq_ws1, dst=mon_n, proto="tcp", port=22),
    ]
    topo = Topology(
        domain=domain,
        sites=[
            Site(
                code=hq,
                role="hq",
                subnets={k: v for k, v in sub.items() if k.startswith("hq") or k == "wan"},
                vlans={"users": v_users, "servers": v_srv, "ops": v_ops},
            ),
            Site(
                code=br,
                role="branch",
                subnets={"br_users": sub["br_users"], "wan": sub["wan"]},
                vlans={"users": v_users},
            ),
        ],
        devices=devices,
        dns_zone=dict(sorted(zone.items())),
        dhcp_leases=leases,
        intended_flows=flows,
        forbidden_flows=forbidden,
    )
    ctx = {
        "hq": hq,
        "br": br,
        "hq_edge": hq_edge,
        "br_edge": br_edge,
        "hq_sw": hq_sw,
        "br_sw": br_sw,
        "dns": dns_n,
        "app": app_n,
        "nms": nms_n,
        "file": file_n if with_files else None,
        "ops": ops_n,
        "mon": mon_n,
        "sub": sub,
        "domain": domain,
        "v_users": v_users,
        "nm": nm,
    }
    return topo, ctx


# ---------------------------------------------------------------------------------------------------------------
# Faults
# ---------------------------------------------------------------------------------------------------------------


def _fid(rng: random.Random) -> str:
    return f"f-{rng.getrandbits(24):06x}"


def _make_fault(ftype: str, rng: random.Random, topo: Topology, ctx: dict[str, Any]) -> Fault | None:
    d = topo.devices
    sub = ctx["sub"]
    onset = rng.randint(600, 5 * 3600)
    if ftype == "wan_interface_down":
        edge = rng.choice([ctx["hq_edge"], ctx["br_edge"]])
        return Fault(
            id=_fid(rng),
            type=ftype,
            fault_class="interface_down",
            component=f"{edge}:Gi0/0",
            accepted_components=[edge, f"{edge}:Gi0/0"],
            accepted_classes=["interface_down", "link_down"],
            mutations=[Mutation(op="set_iface_admin", device=edge, args={"iface": "Gi0/0", "up": False})],
            onset_offset_s=onset,
            symptom_flows=[],
            description=f"WAN interface Gi0/0 on {edge} is administratively shut down.",
        )
    if ftype == "static_route_missing":
        edge = rng.choice([ctx["hq_edge"], ctx["br_edge"]])
        routes = d[edge].routes
        r = (
            rng.choice(routes)
            if edge == ctx["hq_edge"]
            else rng.choice([x for x in routes if x.prefix in ("0.0.0.0/0", sub["hq_servers"])])
        )
        return Fault(
            id=_fid(rng),
            type=ftype,
            fault_class="routing",
            component=f"{edge}:route:{r.prefix}",
            accepted_components=[edge, f"{edge}:route:{r.prefix}"],
            accepted_classes=["routing"],
            mutations=[Mutation(op="remove_route", device=edge, args={"prefix": r.prefix, "next_hop": r.next_hop})],
            onset_offset_s=onset,
            symptom_flows=[],
            description=f"Static route {r.prefix} via {r.next_hop} is missing on {edge}.",
        )
    if ftype == "acl_blocks_service":
        edge = ctx["hq_edge"]
        rules = d[edge].acls["WAN-IN"]
        cands = [r for r in rules if r.proto == "tcp" and r.dport in (443, 445)]
        target = rng.choice(cands)
        if rng.random() < 0.6:
            deny = AclRule(
                seq=target.seq - 5, action="deny", proto="tcp", src=sub["br_users"], dst=target.dst, dport=target.dport
            )
            muts = [Mutation(op="insert_acl_rule", device=edge, args={"acl": "WAN-IN", "rule": deny.model_dump()})]
            desc = f"ACL WAN-IN on {edge} has a deny at seq {deny.seq} for tcp/{target.dport} to {target.dst} from the branch."
        else:
            muts = [Mutation(op="remove_acl_rule", device=edge, args={"acl": "WAN-IN", "seq": target.seq})]
            desc = (
                f"ACL WAN-IN on {edge} is missing the permit (seq {target.seq}) for tcp/{target.dport} to {target.dst}."
            )
        return Fault(
            id=_fid(rng),
            type=ftype,
            fault_class="firewall_block",
            component=f"{edge}:acl:WAN-IN",
            accepted_components=[edge, f"{edge}:acl:WAN-IN"],
            accepted_classes=["firewall_block"],
            mutations=muts,
            onset_offset_s=onset,
            symptom_flows=[],
            description=desc,
        )
    if ftype == "service_stopped":
        opts = [(ctx["app"], "intranet")] + ([(ctx["file"], "files")] if ctx["file"] else [])
        server, svc = rng.choice(opts)
        unit = d[server].services[svc].unit
        return Fault(
            id=_fid(rng),
            type=ftype,
            fault_class="service_down",
            component=f"{server}:service:{svc}",
            accepted_components=[server, f"{server}:service:{svc}", f"{server}:service:{unit}"],
            accepted_classes=["service_down"],
            mutations=[Mutation(op="stop_service", device=server, args={"service": svc})],
            onset_offset_s=onset,
            symptom_flows=[],
            description=f"The {svc} service ({unit}) on {server} is stopped.",
        )
    if ftype == "dns_record_stale":
        names = [f"intranet.{ctx['domain']}"] + ([f"files.{ctx['domain']}"] if ctx["file"] else [])
        fqdn = rng.choice(names)
        old = str(ipaddress.ip_network(sub["hq_servers"]).network_address + rng.choice([41, 42, 57, 63]))
        return Fault(
            id=_fid(rng),
            type=ftype,
            fault_class="dns_misconfiguration",
            component=f"dns:{fqdn}",
            accepted_components=[f"dns:{fqdn}", fqdn, ctx["dns"], f"{ctx['dns']}:service:dns"],
            accepted_classes=["dns_misconfiguration"],
            mutations=[Mutation(op="set_dns_record", args={"name": fqdn, "ip": old})],
            onset_offset_s=onset,
            symptom_flows=[],
            description=f"DNS A record {fqdn} points to stale address {old}.",
        )
    if ftype == "access_port_wrong_vlan":
        opts = [ctx["app"]] + ([ctx["file"]] if ctx["file"] else [])
        server = rng.choice(opts)
        sw, port = d[server].interfaces["eth0"].peer.split(":")  # type: ignore[union-attr]
        return Fault(
            id=_fid(rng),
            type=ftype,
            fault_class="l2_misconfiguration",
            component=f"{sw}:{port}",
            accepted_components=[f"{sw}:{port}", sw],
            accepted_classes=["l2_misconfiguration", "interface_down"],
            mutations=[Mutation(op="set_port_vlan", device=sw, args={"iface": port, "vlan": ctx["v_users"]})],
            onset_offset_s=onset,
            symptom_flows=[],
            description=f"Switch port {port} on {sw} (to {server}) is in the wrong access VLAN {ctx['v_users']}.",
        )
    return None


def _broken_flows(topo: Topology, faults: list[Fault]) -> set[str]:
    w = World(topo)
    for f in faults:
        for m in f.mutations:
            w.apply(m)
    return {fl.id for fl in topo.intended_flows if not w.flow_check(fl.src, fl.dst, fl.proto, fl.port, fl.by_name).ok}


def _compatible(faults: list[Fault]) -> bool:
    comps = [f.component for f in faults]
    types = [f.type for f in faults]
    return len(set(comps)) == len(comps) and len(set(types)) == len(types)


# ---------------------------------------------------------------------------------------------------------------
# Evidence policy
# ---------------------------------------------------------------------------------------------------------------


def _make_degradations(
    rng: random.Random, cfg: GenerationConfig, topo: Topology, ctx: dict[str, Any], forced: str | None, history_s: int
) -> list[Degradation]:
    c = cfg.evidence_completeness
    k = max(0, min(len(DEGRADATION_TYPES), round((1 - c) * 5 + rng.uniform(-0.5, 0.5))))
    weights = {t: w for t, w in cfg.degradation_weights.items() if w > 0}
    chosen: list[str] = [forced] if forced else []
    while len(chosen) < k and len(chosen) < len(weights):
        t = _weighted(rng, {t: w for t, w in weights.items() if t not in chosen})
        chosen.append(t)
    sev = 1 - c
    infra = [n for n, d in topo.devices.items() if d.kind in ("edge", "switch", "server")]
    out: list[Degradation] = []
    for t in chosen:
        did = f"d-{rng.getrandbits(24):06x}"
        if t == "collector_outage":
            target = ctx["mon"] if rng.random() < 0.8 else ctx["nms"]
            start = -rng.randint(300, history_s - 600)
            ongoing = rng.random() < 0.5 + 0.4 * sev
            end = None if ongoing else rng.randint(start + 300, 0)
            out.append(
                Degradation(
                    id=did,
                    type=t,
                    targets=[target],
                    params={"start_s": start, "end_s": end},
                    description=f"Collector {target} stopped reporting from t={start}s"
                    + (" and is still down." if ongoing else f" until t={end}s."),
                )
            )
        elif t == "stale_diagram":
            omit = rng.sample([n for n, d in topo.devices.items() if d.kind in ("server", "probe")], 1)
            out.append(
                Degradation(
                    id=did,
                    type=t,
                    targets=omit,
                    params={"age_days": rng.randint(120, 900)},
                    description=f"Topology diagram is outdated and omits {', '.join(omit)}.",
                )
            )
        elif t == "incomplete_inventory":
            pool = [n for n, d in topo.devices.items() if d.kind != "ops"]
            omit = rng.sample(pool, max(1, round(len(pool) * (0.1 + 0.3 * sev))))
            renamed = rng.sample([n for n in pool if n not in omit], 2)
            out.append(
                Degradation(
                    id=did,
                    type=t,
                    targets=sorted(omit),
                    params={"renamed": sorted(renamed)},
                    description=f"Inventory export omits {len(omit)} device(s) and uses legacy names for 2.",
                )
            )
        elif t == "log_gap":
            tg = rng.sample(infra, min(len(infra), rng.randint(1, 3)))
            start = -rng.randint(1800, history_s - 300)
            out.append(
                Degradation(
                    id=did,
                    type=t,
                    targets=sorted(tg),
                    params={"start_s": start, "end_s": start + rng.randint(900, 3 * 3600)},
                    description=f"Syslog from {', '.join(sorted(tg))} is missing for an interval.",
                )
            )
        elif t == "clock_skew":
            tg = rng.choice(infra)
            out.append(
                Degradation(
                    id=did,
                    type=t,
                    targets=[tg],
                    params={"skew_s": rng.choice([-3600, -420, 95, 600, 7200])},
                    description=f"Clock on {tg} is skewed.",
                )
            )
        elif t == "mgmt_unreachable":
            tg = rng.choice([n for n in infra if n != ctx["nms"]])
            out.append(
                Degradation(
                    id=did,
                    type=t,
                    targets=[tg],
                    params={},
                    description=f"SSH management on {tg} does not respond (data plane unaffected).",
                )
            )
        elif t == "restricted_credentials":
            tg = rng.sample(infra, rng.randint(1, 2))
            mode = rng.choice(["read_only", "no_login"])
            out.append(
                Degradation(
                    id=did,
                    type=t,
                    targets=sorted(tg),
                    params={"mode": mode},
                    description=f"Agent account is {mode} on {', '.join(sorted(tg))}.",
                )
            )
        elif t == "duplicate_delayed_telemetry":
            out.append(
                Degradation(
                    id=did,
                    type=t,
                    targets=[],
                    params={
                        "collection_delay_s": round(rng.uniform(15, 45), 1),
                        "duplicate_rate": round(rng.uniform(0.1, 0.35), 2),
                    },
                    description="Telemetry is delayed and some log lines are duplicated.",
                )
            )
        elif t == "stale_config_backup":
            tg = rng.sample([n for n, d in topo.devices.items() if d.kind in ("edge", "switch")], rng.randint(1, 2))
            out.append(
                Degradation(
                    id=did,
                    type=t,
                    targets=sorted(tg),
                    params={"age_days": rng.randint(20, 200)},
                    description=f"Config backups for {', '.join(sorted(tg))} are old.",
                )
            )
    return out


# ---------------------------------------------------------------------------------------------------------------
# Top level
# ---------------------------------------------------------------------------------------------------------------


def coverage_cells(cfg: GenerationConfig) -> list[tuple[str, str]]:
    # Only cells the weights can actually produce: no healthy cell when 0 faults has weight 0, and no fault cells
    # when every positive fault count is 0.
    healthy = ["healthy"] if cfg.fault_count_weights.get(0, 0) > 0 else []
    any_faults = any(w > 0 for k, w in cfg.fault_count_weights.items() if k > 0)
    faults = healthy + ([f for f in FAULT_TYPES if cfg.fault_type_weights.get(f, 0) > 0] if any_faults else [])
    degs = ["none"] + [d for d in DEGRADATION_TYPES if cfg.degradation_weights.get(d, 0) > 0]
    return [(f, d) for f in faults for d in degs]


def choose_balanced_cell(cfg: GenerationConfig, ledger: dict[str, int], seed: int) -> dict[str, Any]:
    cells = coverage_cells(cfg)
    lo = min(ledger.get(f"{f}|{d}", 0) for f, d in cells)
    least = [c for c in cells if ledger.get(f"{c[0]}|{c[1]}", 0) == lo]
    f, d = random.Random(seed ^ 0x5EED).choice(least)
    return {"forced_fault": f, "forced_degradation": None if d == "none" else d, "balanced_cell": f"{f}|{d}"}


def validate_config(cfg: GenerationConfig, inputs: dict[str, Any] | None = None) -> None:
    """Reject unsupported or infeasible sampling configurations before any random draw (GenerationError)."""
    inputs = inputs or {}

    def check_weights(name: str, w: dict[Any, float], allowed: set[Any]) -> None:
        for k, v in w.items():
            if k not in allowed:
                raise GenerationError(
                    f"{name}: unknown key {k!r} (allowed: {', '.join(map(str, sorted(allowed, key=str)))})"
                )
            if not math.isfinite(v) or v < 0:
                raise GenerationError(f"{name}[{k!r}] must be a finite, non-negative number (got {v!r})")

    check_weights("family_weights", cfg.family_weights, set(FAMILIES))
    check_weights("fault_count_weights", cfg.fault_count_weights, {0, 1, 2})
    check_weights("fault_type_weights", cfg.fault_type_weights, set(FAULT_TYPES))
    check_weights("degradation_weights", cfg.degradation_weights, set(DEGRADATION_TYPES))
    if sum(cfg.family_weights.values()) <= 0:
        raise GenerationError("family_weights: at least one family needs a positive weight")
    forced = inputs.get("forced_fault")
    if forced not in (None, "healthy") and forced not in FAULT_TYPES:
        raise GenerationError(f"forced_fault {forced!r} is not a known fault type")
    fd = inputs.get("forced_degradation")
    if fd is not None and fd not in DEGRADATION_TYPES:
        raise GenerationError(f"forced_degradation {fd!r} is not a known degradation type")
    if forced == "healthy":
        return
    if sum(cfg.fault_count_weights.values()) <= 0 and not forced:
        raise GenerationError("fault_count_weights: at least one fault count needs a positive weight")
    available = {t for t, w in cfg.fault_type_weights.items() if w > 0} | ({forced} if forced else set())
    wanted = [k for k, w in cfg.fault_count_weights.items() if w > 0 and k > 0]
    if wanted and not available:
        raise GenerationError("fault_count_weights request faults but every fault type weight is zero")
    too_many = [k for k in wanted if k > len(available)]
    if too_many:
        raise GenerationError(
            f"fault_count_weights request {max(too_many)} distinct simultaneous faults but only {len(available)} fault "
            f"type(s) are enabled ({', '.join(sorted(available))}); faults in one scenario must have distinct types"
        )


def generate(
    config: GenerationConfig | None = None, seed: int | None = None, generation_inputs: dict[str, Any] | None = None
) -> ScenarioSpec:
    cfg = config or GenerationConfig()
    validate_config(cfg, generation_inputs)
    seed_source = "replay" if seed is not None else "os-entropy (secrets.randbits(64))"
    seed = fresh_seed() if seed is None else int(seed)
    inputs = dict(generation_inputs or {})
    rng = random.Random(seed)

    family = _weighted(rng, cfg.family_weights)
    if family not in IMPLEMENTED_FAMILIES:
        raise GenerationError(
            f"environment family '{family}' is not implemented yet (implemented: {', '.join(IMPLEMENTED_FAMILIES)})"
        )
    topo, ctx = _build_branch_office(rng, cfg)

    d = cfg.difficulty
    count_w = {k: v * (1 - 0.5 * d if k == 0 else 1 if k == 1 else 0.5 + d) for k, v in cfg.fault_count_weights.items()}
    n_faults = int(_weighted(rng, count_w))
    forced = inputs.get("forced_fault")
    if forced == "healthy":
        n_faults = 0
    elif forced:
        n_faults = max(1, n_faults)
    ftypes = {t: w for t, w in cfg.fault_type_weights.items() if w > 0}
    faults: list[Fault] = []
    want_interacting = rng.random() < d
    for _attempt in range(12):
        types: list[str] = [forced] if forced and forced != "healthy" else []
        while len(types) < n_faults:
            t = (
                _weighted(rng, {k: v for k, v in ftypes.items() if k not in types})
                if len(ftypes) > len(types)
                else None
            )
            if t is None:
                break
            types.append(t)
        cand = [f for t in types if (f := _make_fault(t, rng, topo, ctx)) is not None]
        if not _compatible(cand):
            continue
        faults = cand
        if n_faults < 2 or len(cand) < 2:
            break
        sym = [_broken_flows(topo, [f]) for f in cand]
        inter = bool(sym[0] & sym[1]) or _broken_flows(topo, cand) != (sym[0] | sym[1])
        if inter == want_interacting:
            break
    if n_faults and not faults:
        raise GenerationError(f"could not sample {n_faults} compatible fault(s) for this topology")
    for f in faults:
        f.symptom_flows = sorted(_broken_flows(topo, [f]))
        if not f.symptom_flows:
            raise GenerationError(f"fault {f.type} has no observable symptom; generation rule defect")
    interacting = False
    if len(faults) == 2:
        s0, s1 = set(faults[0].symptom_flows), set(faults[1].symptom_flows)
        interacting = bool(s0 & s1) or _broken_flows(topo, faults) != (s0 | s1)

    # Independent sub-streams per stage: evidence settings never shift distractors/timeline and vice versa.
    erng, drng, trng = (random.Random(_substream(seed, k)) for k in ("evidence", "distractors", "timeline"))
    history_s = 6 * 3600
    degs = _make_degradations(erng, cfg, topo, ctx, inputs.get("forced_degradation"), history_s)
    poll, delay = 5.0, 2.0
    for g in degs:
        if g.type == "duplicate_delayed_telemetry":
            delay = float(g.params["collection_delay_s"])
    collector_of = {
        n: (ctx["nms"] if dev.site == ctx["hq"] else ctx["mon"])
        for n, dev in topo.devices.items()
        if dev.kind in ("edge", "switch", "server", "probe")
    }
    policy = EvidencePolicy(
        completeness=cfg.evidence_completeness,
        poll_interval_s=poll,
        collection_delay_s=delay,
        collector_of=collector_of,
        degradations=degs,
    )

    # Distractors: benign anomalies that are not faults (claims about them are false positives).
    distractors: list[Distractor] = []
    for _ in range(round(d * 3 + drng.uniform(0, 1))):
        kind = drng.choice(["unused_port_flap", "retired_device", "cpu_spike", "old_ticket"])
        if kind == "retired_device" and not topo.retired_devices:
            name = ctx["nm"](ctx["hq"], "print", 1)
            topo.retired_devices.append(name)
            distractors.append(
                Distractor(kind=kind, target=name, description=f"{name} was retired; records still list it.")
            )
        elif kind == "unused_port_flap":
            sw = drng.choice([ctx["hq_sw"], ctx["br_sw"]])
            p = f"Gi1/0/{drng.randint(18, 24)}"
            distractors.append(
                Distractor(kind=kind, target=f"{sw}:{p}", description=f"Unused port {p} on {sw} flapped.")
            )
        elif kind == "cpu_spike":
            tg = drng.choice([ctx["hq_edge"], ctx["br_edge"], ctx["dns"]])
            distractors.append(Distractor(kind=kind, target=tg, description=f"Transient CPU spike logged on {tg}."))
        elif kind == "old_ticket":
            distractors.append(
                Distractor(kind=kind, target="helpdesk", description="An old, resolved ticket is still open.")
            )

    start_day = trng.randint(0, 300)
    lab_start = f"2026-{1 + start_day // 28 % 12:02d}-{1 + start_day % 28:02d}T{trng.randint(7, 16):02d}:{trng.randint(0, 59):02d}:00+00:00"
    timeline = Timeline(
        lab_start=lab_start,
        history_window_s=history_s,
        backup_offset_s=trng.randint(2 * 3600, 20 * 3600),
        diagram_age_days=trng.randint(10, 60),
    )
    task = trng.choice(TASK_TEMPLATES).format(hq=ctx["hq"].upper(), br=ctx["br"].upper())

    spec = ScenarioSpec(
        env_id=f"env-{hashlib.sha256(str(seed).encode()).hexdigest()[:10]}",
        seed=seed,
        seed_source=seed_source,
        generator_version=GENERATOR_VERSION,
        component_versions=component_versions(),
        config=cfg,
        generation_inputs=inputs,
        family=family,
        topology=topo,
        faults=faults,
        interacting=interacting,
        evidence=policy,
        timeline=timeline,
        distractors=distractors,
        task_text=task,
    )
    validate_spec(spec)
    spec.spec_sha256 = spec_digest(spec)
    return spec


def validate_spec(spec: ScenarioSpec) -> None:
    """Explicit coherence checks. Raises GenerationError."""
    t = spec.topology
    if len(t.devices) > spec.config.max_devices:
        raise GenerationError("resource budget exceeded")
    seen: dict[str, str] = {}
    nets = [ipaddress.ip_network(c) for s in t.sites for c in s.subnets.values()]
    for dev in t.devices.values():
        for i in dev.interfaces.values():
            if i.ip:
                a = i.ip.split("/")[0]
                if a in seen:
                    raise GenerationError(f"duplicate address {a} on {seen[a]} and {dev.name}")
                seen[a] = dev.name
                if not any(ipaddress.ip_address(a) in n for n in nets):
                    raise GenerationError(f"{dev.name} {a} is outside the address plan")
            if i.peer:
                pd, _, pi = i.peer.partition(":")
                if pd not in t.devices or pi not in t.devices[pd].interfaces:
                    raise GenerationError(f"dangling link {dev.name}:{i.name} -> {i.peer}")
    for fqdn, ip in t.dns_zone.items():
        if ip not in seen:
            raise GenerationError(f"DNS record {fqdn} -> {ip} has no owner in the healthy topology")
    w = World(t)
    for fl in t.intended_flows:
        r = w.flow_check(fl.src, fl.dst, fl.proto, fl.port, fl.by_name)
        if not r.ok:
            raise GenerationError(f"healthy topology fails intended flow {fl.id}: {r.reason}")
    for fl in t.forbidden_flows:
        if w.flow_check(fl.src, fl.dst, fl.proto, fl.port, fl.by_name).ok:
            raise GenerationError(f"healthy topology permits forbidden flow {fl.id}")
    if not _compatible(spec.faults):
        raise GenerationError("incompatible faults")


def resource_estimate(spec: ScenarioSpec) -> dict[str, Any]:
    t = spec.topology
    listeners = sum(1 for d in t.devices.values() for s in d.services.values() if s.proto == "tcp" and s.name != "ssh")
    return {
        "devices": len(t.devices),
        "ssh_targets": sum(1 for d in t.devices.values() if "ssh" in d.services),
        "real_tcp_listeners": listeners + 2,  # services + bastion + management API
        "estimated_memory_mb": 60 + 2 * len(t.devices),
        "estimated_startup_s": 1.5,
        "privileged_operations": 0,
        "host_network_exposure": "127.0.0.1 only",
    }
