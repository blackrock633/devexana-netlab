"""Repair verification must be a relevant, current measurement taken after the repair (netlab-eval-1.3.0).

R1: API check reads verify a service/record repair only through a returned, current sample of a relevant check that
    was COLLECTED after the last change. Empty, stale (unknown) and pre-repair samples earn nothing.
R2: route/interface repairs are verified only by probes whose recorded forwarding decision used a changed route
    prefix (forward or return path) or the repaired interface; transit over an unaffected route earns nothing.
"""

from __future__ import annotations

import httpx
import pytest
from conftest import only, run
from test_evaluator_version import hq_route_spec

from netlab.evaluate import _probe_exercises, evaluate
from netlab.runtime.api import build_app
from netlab.runtime.cli import CliSession
from netlab.runtime.lab import Lab, LabOptions
from netlab.schemas import AgentReport


def _lab(spec):
    lab = Lab(spec, None, LabOptions(mode="remediation", run_collector_loop=False))
    lab.initial_flows = {
        f.id: lab.world.flow_check(f.src, f.dst, f.proto, f.port, f.by_name).ok
        for f in spec.topology.intended_flows + spec.topology.forbidden_flows
    }
    return lab


def _verification(lab) -> float:
    flows = {
        f.id: {"ok": lab.world.flow_check(f.src, f.dst, f.proto, f.port, f.by_name).ok}
        for f in lab.spec.topology.intended_flows + lab.spec.topology.forbidden_flows
    }
    r = evaluate(
        lab.spec,
        AgentReport(agent={"name": "t", "version": "1"}, summary="s", claims_recovered=True),
        lab.events.events,
        mode="remediation",
        initial_flows=lab.initial_flows,
        final_flows=flows,
        final_active={f.id: lab.fault_active(f) for f in lab.spec.faults},
        agent_seconds=1,
        budget_s=60,
        status="completed",
    )
    return r["scores"]["verification"]


async def _get(lab, path):
    async with httpx.AsyncClient(
        transport=httpx.ASGITransport(app=build_app(lab)),
        base_url="http://lab",
        headers={"Authorization": "Bearer " + lab.creds["api_token"]},
    ) as c:
        return await c.get(path)


def _ses(lab, dev):
    return CliSession(lab, dev, "netops", "console", via_console=True)


# -- R1: API check provenance -------------------------------------------------------------------------------------
async def _dns_case(rows_before=None, rows_after=None):
    s = only("dns_record_stale")
    lab = _lab(s)
    dns = next(n for n, d in s.topology.devices.items() if "dns" in d.services)
    fq = s.faults[0].mutations[0].args["name"]
    for cid, row in (rows_before or {}).items():
        lab.checks[cid] = [row(lab)]
    await _ses(lab, dns).run(f"sudo dns-record set {fq} {s.topology.dns_zone[fq]}")
    assert not lab.fault_active(s.faults[0]), "precondition: the repair took effect"
    base = _verification(lab)
    for cid, row in (rows_after or {}).items():
        lab.checks.setdefault(cid, []).append(row(lab))
    resp = await _get(lab, "/api/v1/checks")
    assert resp.status_code == 200
    return lab, fq, base, _verification(lab), lab.events.events[-1]


def _relevant_check(lab, fq):
    return next(c[0] for c in lab.service_checks() if c[4] == fq)


@pytest.mark.parametrize("condition", ["empty", "stale", "before_change"])
def test_api_checks_without_postrepair_sample_earn_no_verification(condition):
    async def go():
        s = only("dns_record_stale")
        lab0 = _lab(s)
        cid = _relevant_check(lab0, s.faults[0].mutations[0].args["name"])
        t = {"stale": -100.0, "before_change": -1.0}.get(condition)
        before = {} if t is None else {cid: lambda lab, t=t: (t, t, "failed", "name resolution failed", [])}
        _lab_, _fq, base, after, ev = await _dns_case(rows_before=before)
        assert after == base == 0.4
        if condition == "before_change":  # current, returned, but collected before the repair
            assert ev.detail["check_samples"][0]["collected_t"] < 0
        else:
            assert "check_samples" not in ev.detail

    run(go())


def test_api_checks_relevant_sample_collected_after_repair_verifies():
    async def go():
        s = only("dns_record_stale")
        cid = _relevant_check(_lab(s), s.faults[0].mutations[0].args["name"])
        _lab_, _fq, base, after, ev = await _dns_case(
            rows_after={cid: lambda lab: (lab.now(), lab.now(), "ok", "ok", [])}
        )
        assert base == 0.4 and after == 1.0
        sample = ev.detail["check_samples"][0]
        assert sample["quality"] == "current" and sample["by_name"] and sample["vantage"]

    run(go())


def test_api_checks_unrelated_current_sample_does_not_verify():
    async def go():
        s = only("dns_record_stale")
        lab0 = _lab(s)
        fq = s.faults[0].mutations[0].args["name"]
        other = [c[0] for c in lab0.service_checks() if c[4] != fq]
        if not other:
            pytest.skip("scenario has no unrelated check")
        _lab_, _fq, base, after, _ev = await _dns_case(
            rows_after={other[0]: lambda lab: (lab.now(), lab.now(), "ok", "ok", [])}
        )
        assert after == base == 0.4

    run(go())


# -- R2: forwarding-decision relevance ----------------------------------------------------------------------------
def _route_lab(prefixes=None):
    s = hq_route_spec()
    m = s.faults[0].mutations[0]
    lab = _lab(s)
    ses = _ses(lab, m.device)
    return s, m, lab, ses, prefixes or [m.args["prefix"]]


async def _repair(ses, m, prefixes):
    await ses.run("configure terminal")
    for p in prefixes:
        await ses.run(f"ip route {p} {m.args['next_hop']}")
    await ses.run("end")


def _kind(s, k):
    return next(n for n, d in s.topology.devices.items() if d.kind == k and d.site == s.topology.sites[0].code)


def test_transit_over_unaffected_connected_route_does_not_verify():
    async def go():
        s, m, lab, ses, pf = _route_lab()
        await _repair(ses, m, pf)
        dns = next(
            n for n, d in s.topology.devices.items() if "dns" in d.services and d.site == s.topology.sites[0].code
        )
        await _ses(lab, _kind(s, "ops")).run(f"ping {lab.world.primary_ip(dns)}")
        probe = lab.events.events[-1].detail["probe"]
        assert m.device in probe["hops"][:-1], "precondition: router was a transit hop"
        assert all(d["source"] == "connected" for d in probe["decisions"] if d["device"] == m.device)
        assert _verification(lab) == 0.4

    run(go())


@pytest.mark.parametrize("variant", ["exact", "equivalent_halves"])
def test_probe_through_repaired_prefix_verifies(variant):
    async def go():
        import ipaddress

        s, m, lab, ses, _ = _route_lab()
        pf = (
            [m.args["prefix"]]
            if variant == "exact"
            else [str(n) for n in ipaddress.ip_network(m.args["prefix"]).subnets(prefixlen_diff=1)]
        )
        await _repair(ses, m, pf)
        assert not lab.fault_active(s.faults[0]) or variant != "exact"
        probe_dev = next(n for n, d in s.topology.devices.items() if d.kind == "probe")
        await _ses(lab, _kind(s, "ops")).run(f"ping {lab.world.primary_ip(probe_dev)}")
        assert lab.events.events[-1].ok
        assert _verification(lab) == 1.0

    run(go())


def test_return_path_through_repaired_prefix_verifies():
    """A probe from the far site back to HQ exercises HQ's repaired route on the return path."""

    async def go():
        s, m, lab, ses, pf = _route_lab()
        await _repair(ses, m, pf)
        probe_dev = next(n for n, d in s.topology.devices.items() if d.kind == "probe")
        if lab.world.device(probe_dev).site == s.topology.sites[0].code:
            pytest.skip("probe is at HQ")
        await _ses(lab, probe_dev).run(f"ping {lab.world.primary_ip(_kind(s, 'ops'))}")
        probe = lab.events.events[-1].detail["probe"]
        assert any(d["direction"] == "return" and d["device"] == m.device for d in probe["decisions"])
        assert _verification(lab) == 1.0

    run(go())


def test_probe_matcher_rejects_malformed_and_irrelevant_probes():
    topo = hq_route_spec().topology
    owner = next(n for n, d in topo.devices.items() if d.kind == "edge")
    pf = {"10.211.30.0/24"}
    good = {"device": owner, "source": "static", "prefix": "10.211.30.0/24", "egress": "Gi0/0"}
    assert _probe_exercises({"decisions": [good], "hops": [owner]}, owner, "routes", topo, pf)
    for bad in (
        {},
        {"decisions": "x"},
        {"decisions": [None, 3, "s"]},
        {"decisions": [{**good, "source": "connected"}]},
        {"decisions": [{**good, "prefix": "10.99.0.0/24"}]},
        {"decisions": [{**good, "device": "someone-else"}]},
        {"dst_ip": "not-an-ip", "hops": [owner]},
        {"dst_ip": "10.99.22.10", "hops": [owner]},  # stopped at owner, but outside the repaired prefix
    ):
        assert not _probe_exercises(bad, owner, "routes", topo, pf), bad
    # Stopped at the owner for lack of a route to the affected range: the repair was exercised (and found wanting).
    assert _probe_exercises({"dst_ip": "10.211.30.7", "hops": ["x", owner]}, owner, "routes", topo, pf)
    # Interfaces: entering via, or forwarded out of, that interface; transit on other ports does not count.
    assert _probe_exercises({"ingress": [f"{owner}:Gi0/1"]}, owner, "iface:Gi0/1:admin", topo)
    assert _probe_exercises({"decisions": [good]}, owner, "iface:Gi0/0:admin", topo)
    assert not _probe_exercises(
        {"ingress": [f"{owner}:Gi0/2"], "decisions": [good], "hops": ["a", owner, "b"]},
        owner,
        "iface:Gi0/1:admin",
        topo,
    )


# -- netlab-eval-1.4.0: relevance to the fault's affected traffic -------------------------------------------------
def _host_in(s, lab, cidr, exclude=()):
    import ipaddress

    n = ipaddress.ip_network(cidr)
    return next(
        d
        for d in s.topology.devices
        if d not in exclude
        and s.topology.devices[d].kind not in ("edge", "switch")
        and lab.world.primary_ip(d)
        and ipaddress.ip_address(lab.world.primary_ip(d)) in n
    )


def test_broad_route_repair_unrelated_destination_does_not_verify():
    """A default-route repair restores the flows, but a ping to a destination outside the removed prefix (which
    matches only the new default route and dies upstream) must not verify the route repair; one into the affected
    range through that same default route must."""

    async def go():
        s, m, lab, ses, _ = _route_lab()
        await _repair(ses, m, ["0.0.0.0/0"])
        assert not lab.fault_active(s.faults[0]), "precondition: the equivalent repair restores reachability"
        ops = _ses(lab, _kind(s, "ops"))
        await ops.run("ping 192.0.2.9")
        probe = lab.events.events[-1].detail["probe"]
        assert any(d["prefix"] == "0.0.0.0/0" and d["device"] == m.device for d in probe["decisions"])
        assert _verification(lab) == 0.4
        await ops.run(f"ping {_host_in(s, lab, m.args['prefix'])}")
        assert lab.events.events[-1].ok
        assert _verification(lab) == 1.0

    run(go())


def _acl_case():
    s = only("acl_blocks_service")
    m = s.faults[0].mutations[0]
    edge = s.topology.devices[m.device]
    sel = (
        m.args["rule"]
        if m.op == "insert_acl_rule"
        else next(r.model_dump() for r in edge.acls["WAN-IN"] if r.seq == m.args["seq"])
    )
    return s, m, sel, _lab(s)


async def _acl_cfg(ses, *lines):
    for c in ("configure terminal", "ip access-list extended WAN-IN", *lines, "end"):
        await ses.run(c)


def _rule_line(seq, action, r):
    def tok(c):
        return "any" if c == "any" else (f"host {c[:-3]}" if c.endswith("/32") else c)

    return f"{seq} {action} {r['proto']} {tok(r['src'])} {tok(r['dst'])}" + (
        f" eq {r['dport']}" if r.get("dport") else ""
    )


def _exact_acl_repair(m, sel):
    if m.op == "insert_acl_rule":
        return [f"no {sel['seq']}"]
    return [_rule_line(sel["seq"], "permit", sel)]


async def _probe_affected(s, lab, sel):
    src = _host_in(s, lab, sel["src"]) if sel["src"] != "any" else _kind(s, "ops")
    await _ses(lab, src).run(f"nc -zv {sel['dst'].split('/')[0]} {sel['dport']}")
    return lab.events.events[-1]


def test_acl_unrelated_permitted_traffic_through_bound_interface_does_not_verify():
    async def go():
        s, m, sel, lab = _acl_case()
        await _acl_cfg(_ses(lab, m.device), *_exact_acl_repair(m, sel))
        assert not lab.fault_active(s.faults[0])
        mon = next(n for n, d in s.topology.devices.items() if d.kind == "probe")
        hq_ip = lab.world.primary_ip(_kind(s, "ops"))
        await _ses(lab, mon).run(f"ping -c 1 {hq_ip}")
        assert any(i.startswith(f"{m.device}:") for i in lab.events.events[-1].detail["probe"]["ingress"])
        assert _verification(lab) == 0.4
        ev = await _probe_affected(s, lab, sel)
        assert ev.detail["probe"]["port"] == sel["dport"]
        assert _verification(lab) == 1.0

    run(go())


def test_acl_broad_permit_repair_verified_only_by_affected_flow():
    """An equivalent repair (a broad permit ahead of the fault) is credited, but only by the affected flow, not by
    other traffic the broad rule happens to select."""

    async def go():
        s, m, sel, lab = _acl_case()
        await _acl_cfg(_ses(lab, m.device), "1 permit ip any any")
        assert not lab.fault_active(s.faults[0]), "precondition: the broad permit repairs the flow"
        mon = next(n for n, d in s.topology.devices.items() if d.kind == "probe")
        await _ses(lab, mon).run(f"ping -c 1 {lab.world.primary_ip(_kind(s, 'ops'))}")
        assert _verification(lab) == 0.4
        await _probe_affected(s, lab, sel)
        assert _verification(lab) == 1.0

    run(go())


def test_acl_matcher_rejects_malformed_and_mismatched_flows():
    s, m, sel, lab = _acl_case()
    topo = s.topology
    bound = next(i for i, a in topo.devices[m.device].acl_in.items() if a == "WAN-IN")
    src = _host_in(s, lab, sel["src"]) if sel["src"] != "any" else _kind(s, "ops")
    ok = {
        "src": src,
        "proto": "tcp",
        "port": sel["dport"],
        "dst_ip": sel["dst"].split("/")[0],
        "ingress": [f"{m.device}:{bound}"],
    }
    scope = {"changed": [sel], "affected": [sel], "src_ip": lab.world.primary_ip}
    assert _probe_exercises(ok, m.device, "acl:WAN-IN", topo, None, scope)
    for bad in (
        {**ok, "proto": "icmp", "port": None},
        {**ok, "port": (sel["dport"] or 0) + 1},
        {**ok, "dst_ip": "192.0.2.9"},
        {**ok, "dst_ip": "not-an-ip"},
        {**ok, "src": "no-such-device"},
        {**ok, "ingress": []},
    ):
        assert not _probe_exercises(bad, m.device, "acl:WAN-IN", topo, None, scope), bad
    assert not _probe_exercises(ok, m.device, "acl:WAN-IN", topo, None, {**scope, "changed": [None, "x", {}]})
