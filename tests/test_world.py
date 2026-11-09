from __future__ import annotations

from conftest import only

from netlab.history import world_at
from netlab.schemas import AclRule, Mutation
from netlab.world import World, addr


def _broken(spec, world):
    return {
        fl.id
        for fl in spec.topology.intended_flows
        if not world.flow_check(fl.src, fl.dst, fl.proto, fl.port, fl.by_name).ok
    }


def test_each_fault_breaks_exactly_its_symptom_flows_and_reverting_restores():
    for t in (
        "wan_interface_down",
        "static_route_missing",
        "acl_blocks_service",
        "service_stopped",
        "dns_record_stale",
        "access_port_wrong_vlan",
    ):
        s = only(t)
        w = world_at(s, 0)
        assert _broken(s, w) == set(s.faults[0].symptom_flows), t
        healthy = World(s.topology)
        for m in s.faults[0].mutations:  # revert by copying the healthy value back
            if m.op == "set_iface_admin":
                w.apply(Mutation(op=m.op, device=m.device, args={"iface": m.args["iface"], "up": True}))
            elif m.op == "set_port_vlan":
                v = healthy.device(m.device).interfaces[m.args["iface"]].vlan
                w.apply(Mutation(op=m.op, device=m.device, args={"iface": m.args["iface"], "vlan": v}))
            elif m.op == "remove_route":
                w.add_route(m.device, m.args["prefix"], m.args["next_hop"], "test")
            elif m.op == "insert_acl_rule":
                w.apply(
                    Mutation(
                        op="remove_acl_rule", device=m.device, args={"acl": m.args["acl"], "seq": m.args["rule"]["seq"]}
                    )
                )
            elif m.op == "remove_acl_rule":
                rule = next(r for r in healthy.device(m.device).acls[m.args["acl"]] if r.seq == m.args["seq"])
                w.apply(
                    Mutation(
                        op="insert_acl_rule", device=m.device, args={"acl": m.args["acl"], "rule": rule.model_dump()}
                    )
                )
            elif m.op == "stop_service":
                w.apply(
                    Mutation(op="stop_service", device=m.device, args={"service": m.args["service"], "running": True})
                )
            elif m.op == "set_dns_record":
                w.apply(Mutation(op=m.op, args={"name": m.args["name"], "ip": healthy.topo.dns_zone[m.args["name"]]}))
        assert _broken(s, w) == set(), t


def test_acl_first_match_and_implicit_deny():
    rules = [
        AclRule(seq=10, action="deny", proto="tcp", src="10.0.0.0/24", dst="any", dport=443),
        AclRule(seq=20, action="permit", proto="ip", src="10.0.0.0/24", dst="any"),
    ]
    assert World.acl_permits(rules, "tcp", addr("10.0.0.5"), addr("1.1.1.1"), 443) == (False, 10)
    assert World.acl_permits(rules, "tcp", addr("10.0.0.5"), addr("1.1.1.1"), 80) == (True, 20)
    assert World.acl_permits(rules, "udp", addr("10.9.0.5"), addr("1.1.1.1"), 53) == (False, None)


def test_missing_return_route_is_a_timeout_not_unreachable():
    from conftest import find_spec

    from netlab.schemas import GenerationConfig

    cfg = GenerationConfig(
        fault_type_weights={t: float(t == "static_route_missing") for t in GenerationConfig().fault_type_weights},
        fault_count_weights={0: 0, 1: 1, 2: 0},
    )

    def hq(s):
        return next(n for n, d in s.topology.devices.items() if d.kind == "edge" and d.site == s.topology.sites[0].code)

    s = find_spec(lambda s: s.faults[0].mutations[0].device == hq(s), cfg)
    w = world_at(s, 0)
    br_ws = next(
        n for n, d in s.topology.devices.items() if d.kind == "workstation" and d.site == s.topology.sites[1].code
    )
    dns = next(n for n, d in s.topology.devices.items() if "dns" in d.services)
    r = w.path(br_ws, w.primary_ip(dns), "udp", 53)
    assert not r.ok and r.outcome == "timeout" and "return path" in r.reason  # request arrives, reply cannot return


def test_dns_fault_breaks_name_but_not_address():
    s = only("dns_record_stale")
    w = world_at(s, 0)
    fl = next(fl for fl in s.topology.intended_flows if fl.id in s.faults[0].symptom_flows)
    assert not w.flow_check(fl.src, fl.dst, fl.proto, fl.port, fl.by_name).ok
    assert w.flow_check(fl.src, fl.dst, fl.proto, fl.port, None).ok
