"""Evaluator correctness on synthetic reports and event records (no live lab needed)."""

from __future__ import annotations

import ipaddress

from conftest import healthy, only

from netlab.evaluate import evaluate
from netlab.schemas import AgentReport, ReportDevice, ReportFinding, ReportUnknown, RunEvent
from netlab.world import World


def ev(
    seq,
    target,
    reveals=(),
    symptoms=(),
    source="ssh",
    kind="command",
    ok=True,
    change=None,
    cmd="show run",
    t=1.0,
    health=True,
    probe=None,
):
    return RunEvent(
        seq=seq,
        ts="2026-01-01T00:00:00Z",
        t_rel_s=t,
        source=source,
        kind=kind,
        target=target,
        ok=ok,
        reveals=list(reveals),
        symptoms=list(symptoms),
        change=change,
        detail={
            "command": cmd,
            "parsed": ok,
            "health_evidence": health and ok,
            **({"probe_target": probe if isinstance(probe, str) else "x"} if probe else {}),
            **({"probe": probe} if isinstance(probe, dict) else {}),
        },
    )


def flows_all(spec, ok=True):
    ids = [f.id for f in spec.topology.intended_flows] + [f.id for f in spec.topology.forbidden_flows]
    return {i: {"ok": ok if not i.startswith("deny") else False, "outcome": "ok"} for i in ids}


def score(spec, report, events, mode="read_only", final=None, initial=None, active=None):
    final = final or flows_all(spec)
    initial = initial or {k: v["ok"] for k, v in flows_all(spec).items()}
    return evaluate(
        spec,
        report,
        events,
        mode=mode,
        initial_flows=initial,
        final_flows=final,
        final_active=active or {f.id: True for f in spec.faults},
        agent_seconds=10,
        budget_s=600,
        status="completed",
    )


def rep(findings=(), status=None, unknowns=(), devices=(), **kw):
    return AgentReport(
        agent={"name": "t", "version": "1"},
        summary="s",
        findings=list(findings),
        component_status=status or {},
        unknowns=list(unknowns),
        devices=list(devices),
        **kw,
    )


def test_supported_vs_symptom_vs_lucky_guess():
    s = only("service_stopped")
    f = s.faults[0]
    finding = ReportFinding(component=f.component, fault_class="service_down", statement="x")
    dev = f.mutations[0].device
    full = score(s, rep([finding]), [ev(1, dev, reveals=[f.id])])
    sym = score(s, rep([finding]), [ev(1, dev, symptoms=[f.id])])
    lucky = score(s, rep([finding]), [])
    assert full["scores"]["diagnosis"] == 1.0
    assert sym["scores"]["diagnosis"] == 0.5
    assert lucky["scores"]["diagnosis"] == 0.0
    assert lucky["measurements"]["identified_regardless_of_support"] == 1.0
    assert lucky["measurements"]["unsupported_correct"] == 1


def test_alternative_components_and_aliases_are_accepted():
    s = only("wan_interface_down")
    f = s.faults[0]
    edge = f.mutations[0].device
    alias = s.topology.devices[edge].aliases[0]
    for comp, cls in (
        (f"{alias}:Gi0/0", "interface_down"),
        (edge, "link_down"),
        (f"{edge.upper()}:gi0/0", "interface_down"),
    ):
        r = score(
            s, rep([ReportFinding(component=comp, fault_class=cls, statement="x")]), [ev(1, edge, reveals=[f.id])]
        )
        assert r["scores"]["diagnosis"] == 1.0, comp
    wrong_cls = score(
        s,
        rep([ReportFinding(component=edge, fault_class="dns_misconfiguration", statement="x")]),
        [ev(1, edge, reveals=[f.id])],
    )
    assert wrong_cls["scores"]["diagnosis"] == 0.25 and wrong_cls["measurements"]["false_positive_count"] == 0


def test_healthy_network_penalises_any_fault_claim():
    s = healthy()
    clean = score(s, rep(), [])
    assert clean["scores"]["diagnosis"] == 1.0 and clean["scores"]["false_positives"] == 1.0
    edge = next(n for n, d in s.topology.devices.items() if d.kind == "edge")
    bad = score(s, rep([ReportFinding(component=edge, fault_class="routing", statement="x")]), [ev(1, edge)])
    assert bad["scores"]["diagnosis"] == 0.0 and bad["measurements"]["false_positive_count"] == 1
    assert bad["scores"]["false_positives"] < 1.0


def test_unknown_is_distinguished_from_healthy_and_absent():
    s = healthy()
    infra = [n for n, d in s.topology.devices.items() if d.kind != "workstation"]
    seen = infra[:-1]
    unseen = infra[-1]
    events = [ev(k, n) for k, n in enumerate(seen)]
    good = score(s, rep(status={unseen: "unknown", **{r: "absent" for r in s.topology.retired_devices}}), events)
    over = score(s, rep(status={unseen: "healthy"}, healthy_overall=True), events)
    via_list = score(s, rep(unknowns=[ReportUnknown(component=unseen, reason="ssh timeout")]), events)
    assert good["scores"]["uncertainty"] == 1.0
    assert over["scores"]["uncertainty"] < 0.5 and over["measurements"]["overclaimed_healthy"] == [unseen]
    assert unseen in via_list["measurements"]["acknowledged_unknown"]


def test_remediation_regression_and_security_regression():
    s = only("acl_blocks_service")
    f = s.faults[0]
    m = f.mutations[0]
    edge = m.device
    # The repair's net rule diff and a probe that is the fault's affected flow (netlab-eval-1.4.0 relevance).
    sel = (
        m.args["rule"]
        if m.op == "insert_acl_rule"
        else next(r.model_dump() for r in s.topology.devices[edge].acls["WAN-IN"] if r.seq == m.args["seq"])
    )
    w = World(s.topology)
    br = next(
        d
        for d in s.topology.devices
        if s.topology.devices[d].kind not in ("edge", "switch")
        and w.primary_ip(d)
        and ipaddress.ip_address(w.primary_ip(d)) in ipaddress.ip_network(sel["src"])
    )
    before, after = ([sel], []) if m.op == "insert_acl_rule" else ([], [{**sel, "action": "permit"}])
    change = {
        "op": "insert_acl_rule",
        "device": edge,
        "owner": edge,
        "resource": "acl:WAN-IN",
        "before": before,
        "after": after,
    }
    events = [
        ev(1, edge, reveals=[f.id], t=1),
        ev(2, edge, change=change, t=2),
        ev(
            3,
            edge,
            cmd="nc -zv x 443",
            t=3,
            probe={
                "src": br,
                "hops": [br, edge, "app"],
                "ingress": [f"{edge}:Gi0/0"],
                "dst_device": "app",
                "dst_ip": sel["dst"].split("/")[0],
                "proto": "tcp",
                "port": sel["dport"],
            },
        ),
    ]
    finding = ReportFinding(component=f.component, fault_class="firewall_block", statement="x")
    ok = score(s, rep([finding], claims_recovered=True), events, mode="remediation", active={f.id: False})
    assert (
        ok["scores"]["remediation"] == 1.0
        and ok["scores"]["verification"] == 1.0
        and ok["scores"]["no_regression"] == 1.0
    )
    final = flows_all(s)
    final["deny-01"] = {"ok": True}
    lax = score(s, rep([finding], claims_recovered=True), events, mode="remediation", active={f.id: False}, final=final)
    assert lax["scores"]["no_regression"] == 0.0 and lax["measurements"]["security_regressions"] == ["deny-01"]
    final = flows_all(s)
    final["flow-08"] = {"ok": False, "outcome": "timeout"}
    broke = score(
        s, rep([finding], claims_recovered=True), events, mode="remediation", active={f.id: False}, final=final
    )
    assert broke["measurements"]["regressions"] == ["flow-08"] and broke["scores"]["no_regression"] == 0.0
    not_fixed = score(
        s,
        rep([finding], claims_recovered=True),
        events[:1],
        mode="remediation",
        final={**flows_all(s), **{x: {"ok": False} for x in f.symptom_flows}},
        initial={**{k: v["ok"] for k, v in flows_all(s).items()}, **dict.fromkeys(f.symptom_flows, False)},
    )
    assert not_fixed["scores"]["remediation"] == 0.0


def test_read_only_changes_are_penalised_and_discovery_measured():
    s = healthy()
    edge = next(n for n, d in s.topology.devices.items() if d.kind == "edge")
    r = score(
        s,
        rep(devices=[ReportDevice(name=n) for n in s.topology.devices]),
        [ev(1, edge, change={"op": "set_iface_admin", "device": edge})],
    )
    assert r["scores"]["no_regression"] == 0.0
    assert r["measurements"]["discovery"]["device_recall"] == 1.0
    r2 = score(s, rep(devices=[ReportDevice(name="made-up-router")]), [])
    assert r2["measurements"]["discovery"]["device_precision"] == 0.0


def test_failed_agent_scores_zero_except_regression():
    s = only("service_stopped")
    r = evaluate(
        s,
        None,
        [],
        mode="read_only",
        initial_flows={},
        final_flows={},
        final_active={},
        agent_seconds=1,
        budget_s=10,
        status="agent_timeout",
    )
    assert r["overall"] is not None and r["scores"]["diagnosis"] == 0.0


def test_fresh_api_telemetry_counts_as_live_observation():
    s = healthy()
    infra = [n for n, d in s.topology.devices.items() if d.kind != "workstation"]
    api_ev = RunEvent(
        seq=1,
        ts="t",
        t_rel_s=1,
        source="api",
        kind="request",
        target="/api/table.json",
        detail={"observed_devices": infra[:-1]},
    )
    r = score(s, rep(status={n: "healthy" for n in infra}), [api_ev])
    assert r["measurements"]["unobserved_infra"] == [infra[-1]]
    assert r["measurements"]["overclaimed_healthy"] == [infra[-1]]
