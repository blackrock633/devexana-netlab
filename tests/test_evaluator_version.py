"""Evaluator version guard: identical inputs must give identical scores within one EVALUATOR_VERSION.

GOLDEN pins the scores of fixed, deterministic cases for the current version. If a scoring change alters any of
them, this test fails until EVALUATOR_VERSION is bumped (netlab/evaluate.py, with an EVALUATOR_CHANGELOG entry)
and the new values are recorded here under the new version. Never edit the values of an existing version.
"""

from __future__ import annotations

from conftest import find_spec, healthy, only, run

from netlab.evaluate import EVALUATOR_CHANGELOG, EVALUATOR_VERSION, evaluate
from netlab.runtime.cli import CliSession
from netlab.runtime.lab import Lab, LabOptions
from netlab.schemas import AgentReport, GenerationConfig, ReportFinding

GOLDEN: dict[str, dict[str, dict[str, float | None]]] = {
    "netlab-eval-1.2.0": {
        "healthy_wan_bounce": {
            "discovery": 0.0,
            "diagnosis": 1.0,
            "false_positives": 1.0,
            "evidence": None,
            "uncertainty": 0.0,
            "remediation": None,
            "verification": 0.4,
            "no_regression": 0.05,
            "overall": 0.5667,
        },
        "route_selfping": {
            "discovery": 0.0,
            "diagnosis": 1.0,
            "false_positives": 1.0,
            "evidence": 1.0,
            "uncertainty": 0.0,
            "remediation": 1.0,
            "verification": 0.4,
            "no_regression": 1.0,
            "overall": 0.77,
        },
        "route_transit": {
            "discovery": 0.0,
            "diagnosis": 1.0,
            "false_positives": 1.0,
            "evidence": 1.0,
            "uncertainty": 0.0,
            "remediation": 1.0,
            "verification": 1.0,
            "no_regression": 1.0,
            "overall": 0.8,
        },
        "shotgun": {
            "discovery": 0.0,
            "diagnosis": 1.0,
            "false_positives": 0.32,
            "evidence": 1.0,
            "uncertainty": 0.0,
            "remediation": None,
            "verification": None,
            "no_regression": 1.0,
            "overall": 0.665,
        },
    },
    "netlab-eval-1.3.0": {
        "healthy_wan_bounce": {
            "discovery": 0.0,
            "diagnosis": 1.0,
            "false_positives": 1.0,
            "evidence": None,
            "uncertainty": 0.0,
            "remediation": None,
            "verification": 0.4,
            "no_regression": 0.05,
            "overall": 0.5667,
        },
        "route_selfping": {
            "discovery": 0.0,
            "diagnosis": 1.0,
            "false_positives": 1.0,
            "evidence": 1.0,
            "uncertainty": 0.0,
            "remediation": 1.0,
            "verification": 0.4,
            "no_regression": 1.0,
            "overall": 0.77,
        },
        "route_transit": {
            "discovery": 0.0,
            "diagnosis": 1.0,
            "false_positives": 1.0,
            "evidence": 1.0,
            "uncertainty": 0.0,
            "remediation": 1.0,
            "verification": 1.0,
            "no_regression": 1.0,
            "overall": 0.8,
        },
        "shotgun": {
            "discovery": 0.0,
            "diagnosis": 1.0,
            "false_positives": 0.32,
            "evidence": 1.0,
            "uncertainty": 0.0,
            "remediation": None,
            "verification": None,
            "no_regression": 1.0,
            "overall": 0.665,
        },
    },
    "netlab-eval-1.4.0": {
        "healthy_wan_bounce": {
            "discovery": 0.0,
            "diagnosis": 1.0,
            "false_positives": 1.0,
            "evidence": None,
            "uncertainty": 0.0,
            "remediation": None,
            "verification": 0.4,
            "no_regression": 0.05,
            "overall": 0.5667,
        },
        "route_selfping": {
            "discovery": 0.0,
            "diagnosis": 1.0,
            "false_positives": 1.0,
            "evidence": 1.0,
            "uncertainty": 0.0,
            "remediation": 1.0,
            "verification": 0.4,
            "no_regression": 1.0,
            "overall": 0.77,
        },
        "route_transit": {
            "discovery": 0.0,
            "diagnosis": 1.0,
            "false_positives": 1.0,
            "evidence": 1.0,
            "uncertainty": 0.0,
            "remediation": 1.0,
            "verification": 1.0,
            "no_regression": 1.0,
            "overall": 0.8,
        },
        "route_default_unrelated": {
            "discovery": 0.0,
            "diagnosis": 0.0,
            "false_positives": 1.0,
            "evidence": 0.0,
            "uncertainty": 0.0,
            "remediation": 1.0,
            "verification": 0.4,
            "no_regression": 1.0,
            "overall": 0.37,
        },
        "acl_unrelated_icmp": {
            "discovery": 0.0,
            "diagnosis": 0.0,
            "false_positives": 1.0,
            "evidence": 0.0,
            "uncertainty": 0.0,
            "remediation": 1.0,
            "verification": 0.4,
            "no_regression": 1.0,
            "overall": 0.37,
        },
        "shotgun": {
            "discovery": 0.0,
            "diagnosis": 1.0,
            "false_positives": 0.32,
            "evidence": 1.0,
            "uncertainty": 0.0,
            "remediation": None,
            "verification": None,
            "no_regression": 1.0,
            "overall": 0.665,
        },
    },
}


def _lab(spec):
    lab = Lab(spec, None, LabOptions(mode="remediation", run_collector_loop=False))
    lab.initial_flows = {
        f.id: lab.world.flow_check(f.src, f.dst, f.proto, f.port, f.by_name).ok
        for f in spec.topology.intended_flows + spec.topology.forbidden_flows
    }
    return lab


def _score(lab, rep, mode="remediation"):
    flows = {
        f.id: {"ok": lab.world.flow_check(f.src, f.dst, f.proto, f.port, f.by_name).ok}
        for f in lab.spec.topology.intended_flows + lab.spec.topology.forbidden_flows
    }
    r = evaluate(
        lab.spec,
        rep,
        lab.events.events,
        mode=mode,
        initial_flows=lab.initial_flows,
        final_flows=flows,
        final_active={f.id: lab.fault_active(f) for f in lab.spec.faults},
        agent_seconds=1,
        budget_s=60,
        status="completed",
    )
    return {**{k: (None if v is None else round(v, 4)) for k, v in r["scores"].items()}, "overall": r["overall"]}


def _rep(**kw):
    return AgentReport(agent={"name": "golden", "version": "1"}, summary="s", **kw)


def hq_route_spec():
    cfg = GenerationConfig(
        fault_type_weights={t: float(t == "static_route_missing") for t in GenerationConfig().fault_type_weights},
        fault_count_weights={0: 0, 1: 1, 2: 0},
        evidence_completeness=1.0,
    )

    def hq_edge(s):
        return next(n for n, d in s.topology.devices.items() if d.kind == "edge" and d.site == s.topology.sites[0].code)

    return find_spec(lambda s: s.faults[0].mutations[0].device == hq_edge(s), cfg)


async def _cases():
    out = {}
    # 1. healthy WAN shut + restore (transient disruption, reverted unnecessary edit)
    s = healthy()
    lab = _lab(s)
    edge = next(n for n, d in s.topology.devices.items() if d.kind == "edge")
    ses = CliSession(lab, edge, "netops", "console", via_console=True)
    for c in ("configure terminal", "interface Gi0/0", "shutdown", "no shutdown", "end"):
        await ses.run(c)
    out["healthy_wan_bounce"] = _score(lab, _rep(claims_recovered=True))
    # 2. route repair verified only by a self-ping, then by a real transit probe
    s = hq_route_spec()
    m = s.faults[0].mutations[0]
    for name, probe in (("route_selfping", "self"), ("route_transit", "transit")):
        lab = _lab(s)
        ses = CliSession(lab, m.device, "netops", "console", via_console=True)
        await ses.run("show ip route")
        for c in ("configure terminal", f"ip route {m.args['prefix']} {m.args['next_hop']}", "end"):
            await ses.run(c)
        mon = next(n for n, d in s.topology.devices.items() if d.kind == "probe")
        target = lab.world.primary_ip(m.device) if probe == "self" else lab.world.primary_ip(mon)
        await ses.run(f"ping {target}")
        f = s.faults[0]
        out[name] = _score(
            lab,
            _rep(
                findings=[ReportFinding(component=f.component, fault_class="routing", statement="x")],
                claims_recovered=True,
            ),
        )
    # 2b. (1.4.0) broad default-route repair "verified" by a ping outside the affected range
    lab = _lab(s)
    ses = CliSession(lab, m.device, "netops", "console", via_console=True)
    for c in ("configure terminal", f"ip route 0.0.0.0/0 {m.args['next_hop']}", "end"):
        await ses.run(c)
    ops = next(n for n, d in s.topology.devices.items() if d.kind == "ops" and d.site == s.topology.sites[0].code)
    await CliSession(lab, ops, "netops", "console", via_console=True).run("ping 192.0.2.9")
    out["route_default_unrelated"] = _score(
        lab,
        _rep(
            findings=[ReportFinding(component=s.faults[0].component, fault_class="routing", statement="x")],
            claims_recovered=True,
        ),
    )
    # 2c. (1.4.0) ACL repair "verified" by unrelated ICMP that entered the bound interface via another permit
    s = only("acl_blocks_service")
    f = s.faults[0]
    am = f.mutations[0]
    lab = _lab(s)
    ses = CliSession(lab, am.device, "netops", "console", via_console=True)
    if am.op == "insert_acl_rule":
        fix = f"no {am.args['rule']['seq']}"
    else:  # re-add the removed permit exactly
        r = next(x for x in s.topology.devices[am.device].acls["WAN-IN"] if x.seq == am.args["seq"])
        host = [("any" if c == "any" else f"host {c[:-3]}" if c.endswith("/32") else c) for c in (r.src, r.dst)]
        fix = f"{r.seq} permit {r.proto} {host[0]} {host[1]}" + (f" eq {r.dport}" if r.dport else "")
    for c in ("configure terminal", "ip access-list extended WAN-IN", fix, "end"):
        await ses.run(c)
    mon = next(n for n, d in s.topology.devices.items() if d.kind == "probe")
    await CliSession(lab, mon, "netops", "console", via_console=True).run(f"ping -c 1 {lab.world.primary_ip(ops)}")
    out["acl_unrelated_icmp"] = _score(
        lab,
        _rep(
            findings=[ReportFinding(component=f.component, fault_class="firewall_block", statement="x")],
            claims_recovered=True,
        ),
    )
    # 3. shotgun extra classes at a real fault
    s = only("wan_interface_down")
    lab = _lab(s)
    dev = s.faults[0].mutations[0].device
    await CliSession(lab, dev, "netops", "console", via_console=True).run("show ip interface brief")
    claims = [
        ReportFinding(component=dev, fault_class=c, statement="x")
        for c in ("interface_down", "routing", "firewall_block")
    ]
    out["shotgun"] = _score(lab, _rep(findings=claims), mode="read_only")
    return out


def test_scores_are_pinned_to_the_evaluator_version():
    assert EVALUATOR_VERSION in EVALUATOR_CHANGELOG, "add an EVALUATOR_CHANGELOG entry for the current version"
    assert EVALUATOR_VERSION in GOLDEN, (
        f"no golden scores recorded for {EVALUATOR_VERSION}: run this test with NETLAB_RECORD_GOLDEN=1 and paste "
        "the printed values into GOLDEN under the new version"
    )
    got = run(_cases())
    import os

    if os.environ.get("NETLAB_RECORD_GOLDEN") == "1":
        print(repr(got))
        return
    assert got == GOLDEN[EVALUATOR_VERSION], (
        "Scores changed for identical inputs without an evaluator version bump. Bump EVALUATOR_VERSION (and "
        "EVALUATOR_CHANGELOG), then record the new values under the new version; do not edit existing versions."
    )
