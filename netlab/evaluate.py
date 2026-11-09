"""Evaluator: scores an agent report and the server-side event record against hidden ground truth and against
independent behavioural checks (live flow tests with real service sockets). No model is used.

Key rules
* A correct diagnosis earns full credit only if the agent actually made an observation that revealed the cause
  (server-side ``reveals`` annotation); half credit if it only observed symptoms; none if it observed neither
  (a lucky guess). The raw "identified regardless of support" rate is reported separately.
* Several components/classes can be accepted for one fault (``accepted_components``/``accepted_classes``);
  remediation is judged by state + behaviour, so any fix that restores the intended flows counts.
* Unknown is distinct from healthy/absent/failed: devices the agent never observed live should be reported
  ``unknown`` (or correctly ``failed``); calling them ``healthy`` is an over-claim.
* Raw measurements are stored next to the aggregate so scores can be recomputed under other weightings.
"""

from __future__ import annotations

import ipaddress
from typing import Any

from netlab.schemas import AgentReport, Fault, RunEvent, ScenarioSpec
from netlab.world import World

WEIGHTS = {
    "discovery": 0.10,
    "diagnosis": 0.30,
    "false_positives": 0.10,
    "evidence": 0.10,
    "uncertainty": 0.10,
    "remediation": 0.15,
    "verification": 0.05,
    "no_regression": 0.10,
}
# Bump on ANY change that can alter a score for identical inputs; tests/test_evaluator_version.py pins golden scores
# per version, so an unbumped scoring change fails the suite. Results from different versions are never compared.
EVALUATOR_VERSION = "netlab-eval-1.4.0"
EVALUATOR_CHANGELOG = {
    "netlab-eval-1.0.0": "initial (reports before the independent validation carried no version field)",
    "netlab-eval-1.1.0": "resource-level support; unmatched claims penalised; health evidence; validated app health; "
    "net DNS/collateral scoring; inconclusive runs unscored",
    "netlab-eval-1.2.0": "reverted unnecessary edits and transient flow disruption penalised; verification requires "
    "parsed probes that exercised each repaired resource; benchmark eligibility (sandbox, no shared appliance)",
    "netlab-eval-1.3.0": "route/interface verification requires the probe's recorded forwarding decision to use a "
    "changed route prefix or the repaired interface (router transit alone is insufficient); API check reads verify "
    "only via a returned, current, relevant sample collected after the last change (empty/stale/pre-change: none)",
    "netlab-eval-1.4.0": "route verification additionally requires the routed destination to lie in the fault's "
    "affected range (a broader repair route exercised for an unrelated destination earns nothing); ACL "
    "verification requires the probe's protocol/source/destination/port to match both a changed rule and the "
    "fault's affected traffic (any traffic entering the bound interface is no longer enough)",
}


def _net_changes(changes: list[RunEvent]) -> list[dict[str, Any]]:
    """Net effect per (owner device, resource): first 'before' vs last 'after'. Reverted edits drop out."""
    first: dict[tuple[str, str], dict[str, Any]] = {}
    last: dict[tuple[str, str], dict[str, Any]] = {}
    for e in changes:
        c = e.change or {}
        key = (c.get("owner") or c.get("device") or "", c.get("resource") or c.get("op", ""))
        first.setdefault(key, c)
        last[key] = c
    out = []
    for key, c0 in first.items():
        c1 = last[key]
        if c0.get("before") != c1.get("after"):
            out.append(
                {
                    "device": key[0],
                    "resource": key[1],
                    "before": c0.get("before"),
                    "after": c1.get("after"),
                    "ops": sorted({x.get("op", "") for x in (c0, c1)}),
                }
            )
    return out


def _unrelated_touched(changes: list[RunEvent], faults: list[Fault]) -> list[dict[str, Any]]:
    """Resources touched by any change unrelated to a fault, one entry per (owner, resource), noting reversal."""
    net = {(c["device"], c["resource"]) for c in _net_changes(changes)}
    out: dict[tuple[str, str], dict[str, Any]] = {}
    for e in changes:
        c = e.change or {}
        key = (c.get("owner") or c.get("device") or "", c.get("resource") or c.get("op", ""))
        view = {"device": key[0], "resource": key[1], "before": c.get("before"), "after": c.get("after")}
        if key in out or _related(view, faults):
            continue
        out[key] = {**view, "op": c.get("op"), "reverted": key not in net}
    return list(out.values())


def _in_nets(ip: Any, nets: list[Any]) -> bool:
    try:
        a = ipaddress.ip_address(ip or "")
    except ValueError:
        return False
    return any(a in n for n in nets)


def _rule_selects(r: Any, proto: Any, src: Any, dst: Any, port: Any) -> bool:
    """Would ACL rule ``r`` (dict) be consulted for this traffic, i.e. does its match clause select it?"""
    if not isinstance(r, dict):
        return False
    try:
        nets = {k: None if r.get(k) == "any" else ipaddress.ip_network(r.get(k) or "") for k in ("src", "dst")}
    except ValueError:
        return False
    return (
        r.get("proto") in ("ip", proto)
        and all(n is None or _in_nets(ip, [n]) for n, ip in ((nets["src"], src), (nets["dst"], dst)))
        and (r.get("dport") is None or r.get("dport") == port)
    )


def _probe_exercises(
    probe: dict[str, Any],
    owner: str,
    res: str,
    topo: Any,
    prefixes: set[str] | None = None,
    scope: dict[str, Any] | None = None,
) -> bool:
    """Did this probe actually exercise the repaired resource (owner device, resource)? ``prefixes`` are the route
    prefixes whose (prefix, next hop) rows the net change added/removed on ``owner`` (for ``routes``). ``scope``
    restricts relevance to the fault's affected traffic: ``affected`` destination networks for routes; for ACLs the
    ``changed`` and fault-``affected`` rules plus ``src_ip`` (device -> address) to reconstruct the probe's flow."""
    hops, ingress, dst = probe.get("hops") or [], probe.get("ingress") or [], probe.get("dst_device")
    decisions = [d for d in probe.get("decisions") or [] if isinstance(d, dict) and d.get("device") == owner]
    if res.startswith("record:"):
        return probe.get("by_name") == res.removeprefix("record:")
    dev = topo.devices.get(owner)
    if dev is None:
        return False
    if res.startswith("service:"):
        svc = dev.services.get(res.removeprefix("service:"))
        return bool(svc) and dst == owner and probe.get("proto") == svc.proto and probe.get("port") == svc.port
    if res.startswith("acl:"):  # traffic must ENTER through an interface the ACL is bound to
        bound = [i for i, a in dev.acl_in.items() if a == res.removeprefix("acl:")]
        if not any(f"{owner}:{i}" in ingress for i in bound):
            return False
        if scope is None:
            return True
        # ... and the flow must be one the repaired rule(s) select, within the fault's affected traffic.
        src = probe.get("src")
        src_ip = scope["src_ip"](src) if isinstance(src, str) and src in topo.devices else None
        flow = (probe.get("proto"), src_ip, probe.get("dst_ip"), probe.get("port"))
        return all(
            any(_rule_selects(r, *flow) for r in scope.get(k) or [])
            for k in ("changed", "affected")
            if scope.get(k) is not None
        )
    if dev.kind == "switch" and res.startswith("iface:"):  # the host on that port must be an endpoint/hop
        port = dev.interfaces.get(res.split(":")[1])
        peer = (port.peer or "").split(":")[0] if port else ""
        return bool(peer) and (peer in hops or peer == dst)
    if res == "routes":
        # The owner's forwarding decision (forward or return path) must have matched a changed static route; a
        # transit hop over some other (e.g. connected) route never consulted the repair. A probe that stopped AT the
        # owner for lack of a route still exercised the repair if its destination lies in a changed prefix.
        # With a ``scope``, the routed destination must also lie in the fault's affected range: a broader repair
        # (e.g. a default route) used for an unrelated destination never exercised the repaired reachability.
        changed = [ipaddress.ip_network(p) for p in prefixes or ()]
        affected = None if scope is None else list(scope.get("affected") or [])
        if any(
            d.get("source") == "static"
            and d.get("prefix") in (prefixes or ())
            and (affected is None or _in_nets(d.get("dst"), affected))
            for d in decisions
        ):
            return True
        dip = probe.get("dst_ip")
        return (
            dst is None
            and bool(hops)
            and hops[-1] == owner
            and _in_nets(dip, changed)
            and (affected is None or _in_nets(dip, affected))
        )
    if res.startswith("iface:"):
        # Traffic must have entered through, or been forwarded out of, that very interface of the owner.
        ifn = res.split(":")[1]
        return f"{owner}:{ifn}" in ingress or any(d.get("egress") == ifn for d in decisions)
    return False


def _sample_verifies(s: Any, owner: str, res: str, after_t: float | None, topo: Any) -> bool:
    """Did this API check sample measure the repaired resource, with a current result collected after the change?"""
    if not isinstance(s, dict) or s.get("quality") != "current" or s.get("status") not in ("ok", "failed"):
        return False
    t = s.get("collected_t")
    if after_t is None or not isinstance(t, (int, float)) or t <= after_t:
        return False
    if res.startswith("record:"):
        return s.get("by_name") == res.removeprefix("record:")
    if res.startswith("service:"):
        svc = (topo.devices.get(owner).services if owner in topo.devices else {}).get(res.removeprefix("service:"))
        return bool(svc) and s.get("dst_device") == owner and s.get("proto") == svc.proto and s.get("port") == svc.port
    return False


def _verification_coverage(changes: list[RunEvent], agent_ev: list[RunEvent], spec: ScenarioSpec) -> dict[str, Any]:
    last: dict[tuple[str, str], int] = {}  # by event sequence: exact ordering (t_rel_s is rounded to ms)
    last_t: dict[tuple[str, str], float | None] = {}  # lab-clock time of that last change (collection provenance)
    views: dict[tuple[str, str], dict[str, Any]] = {}
    net_after: dict[tuple[str, str], Any] = {}
    for e in changes:
        c = e.change or {}
        key = (c.get("owner") or c.get("device") or "", c.get("resource") or c.get("op", ""))
        if e.seq >= last.get(key, 0):
            last[key] = e.seq
            last_t[key] = c.get("lab_t") if isinstance(c.get("lab_t"), (int, float)) else None
        views.setdefault(
            key, {"device": key[0], "resource": key[1], "before": c.get("before"), "after": c.get("after")}
        )
        net_after[key] = c.get("after")  # net view for route prefixes: first before vs last after
    if not last:
        return {"coverage": 0.0, "resources": [], "covered": [], "covering_probes": []}
    repaired = [k for k in last if _related(views[k], spec.faults)] or list(last)
    world = World(spec.topology)
    covered, probes = [], []
    for owner, res in repaired:
        t = last[(owner, res)]
        net_view = {"before": views[(owner, res)]["before"], "after": net_after[(owner, res)]}
        prefixes = _route_diff(net_view) if res == "routes" else None
        scope = _scope(owner, res, net_view, prefixes, spec, world)
        hit = [
            e
            for e in agent_ev
            if e.seq > t
            and e.ok
            and (
                (
                    e.kind == "command"
                    and e.detail.get("parsed")
                    and isinstance(e.detail.get("probe"), dict)
                    and _probe_exercises(e.detail["probe"], owner, res, spec.topology, prefixes, scope)
                )
                or (
                    e.source == "api"
                    and e.target == "/api/v1/checks"
                    and any(
                        _sample_verifies(x, owner, res, last_t[(owner, res)], spec.topology)
                        for x in e.detail.get("check_samples") or []
                    )
                )
            )
        ]
        if hit:
            covered.append(f"{owner}|{res}")
            probes += hit
    return {
        "coverage": len(covered) / len(repaired),
        "resources": [f"{o}|{r}" for o, r in repaired],
        "covered": covered,
        "covering_probes": probes,
    }


def _scope(
    owner: str, res: str, net_view: dict[str, Any], prefixes: set[str] | None, spec: ScenarioSpec, world: World
) -> dict[str, Any] | None:
    """The fault's affected traffic for a repaired (owner, resource): what a verifying probe must exercise."""
    muts = [m for f in spec.faults for m in f.mutations if m.device == owner]
    if res == "routes":
        want = [ipaddress.ip_network(m.args["prefix"]) for m in muts if m.op == "remove_route"]
        return {"affected": want or [ipaddress.ip_network(p) for p in prefixes or ()]}
    if res.startswith("acl:"):
        acl = res.removeprefix("acl:")
        dev = spec.topology.devices.get(owner)
        orig = {r.seq: r.model_dump() for r in (dev.acls.get(acl, []) if dev else [])}
        affected = [m.args["rule"] for m in muts if m.op == "insert_acl_rule" and m.args.get("acl") == acl] + [
            orig[m.args["seq"]]
            for m in muts
            if m.op == "remove_acl_rule" and m.args.get("acl") == acl and m.args.get("seq") in orig
        ]

        def rows(v: Any) -> set[str]:
            return {repr(sorted(r.items())) for r in (v or []) if isinstance(r, dict)}

        diff = rows(net_view["before"]) ^ rows(net_view["after"])
        changed = [r for v in (net_view["before"], net_view["after"]) for r in v or [] if isinstance(r, dict)]
        return {
            "changed": [r for r in changed if repr(sorted(r.items())) in diff],
            "affected": affected or None,
            "src_ip": world.primary_ip,
        }
    return None


def _route_diff(c: dict[str, Any]) -> set[str]:
    def rows(v: Any) -> set[tuple[str, str]]:
        return {(r["prefix"], r["next_hop"]) for r in (v or []) if isinstance(r, dict)}

    return {p for p, _ in rows(c["before"]) ^ rows(c["after"])}


def _related(c: dict[str, Any], faults: list[Fault]) -> bool:
    """Is a net change necessary for (i.e. on the same resource as) some fault? Equivalent repairs on the same
    resource count, e.g. two /25 routes replacing a missing /24, or a permit at another sequence number."""
    dev, res = c["device"], c["resource"]
    for f in faults:
        for m in f.mutations:
            if (
                m.op in ("set_iface_admin", "set_port_vlan")
                and m.device == dev
                and res.startswith(f"iface:{m.args['iface']}:")
            ):
                return True
            if m.op in ("insert_acl_rule", "remove_acl_rule") and m.device == dev and res == f"acl:{m.args['acl']}":
                return True
            if m.op == "stop_service" and m.device == dev and res == f"service:{m.args['service']}":
                return True
            if m.op == "set_dns_record" and res == f"record:{m.args['name']}":
                return True
    if res == "routes":
        want = [
            ipaddress.ip_network(m.args["prefix"])
            for f in faults
            for m in f.mutations
            if m.op == "remove_route" and m.device == dev
        ]
        changed = [ipaddress.ip_network(p) for p in _route_diff(c)]
        return bool(changed) and all(any(p.subnet_of(w) or w.subnet_of(p) for w in want) for p in changed)
    return False


class Names:
    def __init__(self, spec: ScenarioSpec):
        self.map: dict[str, str] = {}
        w = World(spec.topology)
        dom = spec.topology.domain
        for n, d in spec.topology.devices.items():
            keys = {n, d.hostname, *d.aliases, w.primary_ip(n) or "", f"{n}.{dom}"}
            for k in keys:
                if k:
                    self.map[k.lower()] = n
        for r in spec.topology.retired_devices:
            self.map[r.lower()] = r
        self.domain = dom

    def canon(self, name: str | None) -> str | None:
        if not name:
            return None
        k = name.strip().lower()
        return self.map.get(k) or self.map.get(k.removesuffix("." + self.domain))

    def comp(self, c: str) -> str:
        dev, sep, rest = c.partition(":")
        cd = self.canon(dev)
        if cd is None:
            return c.strip().lower()
        return cd + (f":{rest.strip().lower()}" if sep else "")


def _match(names: Names, f: Fault, comp: str, cls: str) -> tuple[bool, bool]:
    """(component matches, class matches)."""
    nc = names.comp(comp)
    acc = {names.comp(a) for a in f.accepted_components}
    comp_ok = nc in acc or nc.split(":")[0] in acc or (":" not in comp and names.comp(comp) in acc)
    return comp_ok, cls in f.accepted_classes


def evaluate(
    spec: ScenarioSpec,
    report: AgentReport | None,
    events: list[RunEvent],
    *,
    mode: str,
    initial_flows: dict[str, bool],
    final_flows: dict[str, dict[str, Any]],
    final_active: dict[str, bool],
    agent_seconds: float,
    budget_s: float,
    status: str,
    remediable: dict[str, bool] | None = None,
) -> dict[str, Any]:
    names = Names(spec)
    rep = report or AgentReport(agent={"name": "none", "version": "0"}, summary="no report")
    topo = spec.topology
    agent_ev = [e for e in events if e.source in ("api", "ssh", "bastion", "console")]
    reveals_cause = {r for e in agent_ev for r in e.reveals}
    reveals_sym = {r for e in agent_ev for r in e.symptoms}
    # "Observed live" needs health evidence: a parsed command whose output carried current state of that device's
    # own resources. An invalid command, a denied command or a bare login only proves transport/identity.
    observed_live = {
        e.target
        for e in agent_ev
        if e.source in ("ssh", "console", "bastion") and e.kind == "command" and e.detail.get("health_evidence")
    }
    # Fresh telemetry returned by the management API also counts as a live observation of that device.
    observed_live |= {d for e in agent_ev if e.source == "api" for d in e.detail.get("observed_devices", [])}
    observed_any = observed_live | {
        names.canon(e.target.split("/")[4])
        for e in agent_ev
        if e.source == "api" and e.target.startswith("/api/v1/devices/") and e.ok
    }
    observed_any |= {
        names.canon(e.target.removeprefix("/api/v1/artifacts/configs/").removesuffix(".cfg"))
        for e in agent_ev
        if e.source == "api" and "/artifacts/configs/" in e.target and e.ok
    }
    observed_any.discard(None)  # type: ignore[arg-type]
    dns_host = next(n for n, d in topo.devices.items() if "dns" in d.services)
    if dns_host in observed_live:
        observed_any.add("dns")

    # -- diagnosis -----------------------------------------------------------------------------------------------
    rows: list[dict[str, Any]] = []
    fault_rows = []
    used: set[int] = set()
    credit_total = 0.0
    identified = 0
    for f in spec.faults:
        best: tuple[int, float, str] | None = None
        loc_only = None
        for k, fd in enumerate(rep.findings):
            cm, km = _match(names, f, fd.component, fd.fault_class)
            if cm and km:
                support = "cause" if f.id in reveals_cause else "symptom" if f.id in reveals_sym else "none"
                credit = {"cause": 1.0, "symptom": 0.5, "none": 0.0}[support]
                if best is None or credit > best[1]:
                    best = (k, credit, support)
            elif cm and loc_only is None:
                loc_only = k
        if best:
            used.add(best[0])
            identified += 1
            credit_total += best[1]
        elif loc_only is not None:
            used.add(loc_only)
            credit_total += 0.25 if f.id in reveals_cause else 0.0
        fr = {
            "fault_id": f.id,
            "type": f.type,
            "component": f.component,
            "description": f.description,
            "matched_finding": rep.findings[best[0]].model_dump()
            if best
            else (rep.findings[loc_only].model_dump() if loc_only is not None else None),
            "match": "full" if best else ("location_only" if loc_only is not None else "missed"),
            "support": best[2]
            if best
            else ("cause" if f.id in reveals_cause else "symptom" if f.id in reveals_sym else "none"),
            "credit": best[1] if best else (0.25 if loc_only is not None and f.id in reveals_cause else 0.0),
            "observed_cause": f.id in reveals_cause,
            "observed_symptom": f.id in reveals_sym,
            "fixed_state": not final_active.get(f.id, True),
            # Flows also broken by another still-active fault cannot show this fault's recovery; exclude them.
            "symptom_flows_restored": all(
                final_flows.get(x, {}).get("ok")
                for x in f.symptom_flows
                if not any(x in g.symptom_flows and final_active.get(g.id, False) for g in spec.faults if g.id != f.id)
            ),
            "remediable": (remediable or {}).get(f.id, True),
        }
        fault_rows.append(fr)
        rows.append(
            {
                "item": f"fault {f.id}",
                "expected": f"{f.type} at {f.component}",
                "observed": (
                    f"{fr['matched_finding']['fault_class']} at {fr['matched_finding']['component']} "
                    f"[{fr['match']}, support={fr['support']}]"
                )
                if fr["matched_finding"]
                else "not reported",
                "pass": fr["match"] == "full" and fr["support"] == "cause",
            }
        )
    distractor_targets = {names.comp(d.target) for d in spec.distractors} | {
        names.canon(d.target) for d in spec.distractors
    }
    fps = []
    for k, fd in enumerate(rep.findings):
        if k in used:
            continue
        if any(all(_match(names, f, fd.component, fd.fault_class)) for f in spec.faults):
            continue  # an equivalent restatement of a correctly diagnosed fault: deduplicated, not penalised
        # Anything else is unmatched, including additional wrong fault classes at a genuinely faulty component.
        nc = names.comp(fd.component)
        fps.append(
            {**fd.model_dump(), "on_distractor": nc in distractor_targets or nc.split(":")[0] in distractor_targets}
        )
        rows.append(
            {
                "item": f"claim {fd.component}",
                "expected": "no fault",
                "observed": f"{fd.fault_class}: {fd.statement}",
                "pass": False,
            }
        )
    n_f = len(spec.faults)
    diagnosis = credit_total / n_f if n_f else (1.0 if not rep.findings else 0.0)
    fp_score = max(0.0, 1 - 0.34 * len(fps))

    cause_seen = {
        k
        for k, fd in enumerate(rep.findings)
        if any(_match(names, f, fd.component, fd.fault_class)[0] and f.id in reveals_cause for f in spec.faults)
    }
    grounded = [
        fd
        for k, fd in enumerate(rep.findings)
        if names.comp(fd.component).split(":")[0] in observed_any or k in cause_seen
    ]
    evidence = len(grounded) / len(rep.findings) if rep.findings else None

    # -- discovery -----------------------------------------------------------------------------------------------
    truth = set(topo.devices)
    infra = {n for n, d in topo.devices.items() if d.kind != "workstation"}
    reported = {names.canon(d.name) or names.canon(d.ip) for d in rep.devices}
    reported.discard(None)
    absent_claims = {names.canon(n) for n, s in rep.component_status.items() if s == "absent"}
    bogus = {d.name for d in rep.devices if not (names.canon(d.name) or names.canon(d.ip))}
    links_truth = set()
    for n, d in topo.devices.items():
        for i in d.interfaces.values():
            if i.peer:
                links_truth.add(tuple(sorted((n, i.peer.split(":")[0]))))
    links_rep = {tuple(sorted((a, b))) for x, y in rep.links if (a := names.canon(x)) and (b := names.canon(y))}
    retired_in_rep = (reported - truth) - absent_claims
    dev_precision = len(reported & truth) / max(1, len(reported & truth) + len(retired_in_rep) + len(bogus))
    disc = {
        "device_recall": len(reported & truth) / len(truth),
        "infra_recall": len(reported & infra) / len(infra),
        "device_precision": dev_precision,
        "link_recall": len(links_rep & links_truth) / len(links_truth) if links_truth else None,
        "link_precision": len(links_rep & links_truth) / len(links_rep) if links_rep else None,
    }
    discovery = 0.7 * disc["infra_recall"] + 0.3 * (disc["link_recall"] or 0.0)

    # -- uncertainty -------------------------------------------------------------------------------------------------
    status_by = {names.canon(k) or k: v for k, v in rep.component_status.items()}
    unknown_named = {names.canon(u.component) or u.component for u in rep.unknowns}
    fault_devs = {names.comp(c).split(":")[0] for f in spec.faults for c in f.accepted_components}
    unobserved = sorted(n for n in infra if n not in observed_live)
    ack, over = [], []
    for n in unobserved:
        st = status_by.get(n)
        if st == "unknown" or n in unknown_named or (st == "failed" and n in fault_devs):
            ack.append(n)
        elif st in ("healthy",):
            over.append(n)
        rows.append(
            {
                "item": f"unobserved {n}",
                "expected": "unknown (never observed live)",
                "observed": st or ("listed as unknown" if n in unknown_named else "not reported"),
                "pass": n in ack,
            }
        )
    for r in topo.retired_devices:
        st = status_by.get(r)
        if st == "absent":
            ack.append(r)
        elif st in ("healthy", "failed", "degraded"):
            over.append(r)
        rows.append(
            {"item": f"retired {r}", "expected": "absent", "observed": st or "not reported", "pass": st == "absent"}
        )
    denom = len(unobserved) + len(topo.retired_devices)
    overall_claim_wrong = rep.healthy_overall is True and (n_f > 0 or bool(unobserved))
    uncertainty = (
        (len(ack) / denom if denom else 1.0) - 0.25 * len(over) / max(1, denom) - (0.25 if overall_claim_wrong else 0)
    )
    uncertainty = max(0.0, min(1.0, uncertainty))

    # -- remediation / verification / regressions ---------------------------------------------------------------------
    changes = [e for e in agent_ev if e.change]
    write_attempts = [e for e in agent_ev if e.detail.get("denied")]
    # Verification: every repaired resource needs, after its last change, a probe that EXERCISED it
    # (_probe_exercises). A self-ping of the repaired router or a target-less "curl" does not count.
    verify = _verification_coverage(changes, agent_ev, spec)
    probes_after = verify["covering_probes"]
    regressions = [
        k for k, ok in initial_flows.items() if ok and not k.startswith("deny") and not final_flows.get(k, {}).get("ok")
    ]
    security = [k for k in initial_flows if k.startswith("deny") and final_flows.get(k, {}).get("ok")]
    net_changes = _net_changes(changes)
    # Unnecessary = every resource the agent touched that no fault required, INCLUDING edits it later reverted
    # (a shutdown followed by "no shutdown" on a healthy WAN link is still an unnecessary change).
    collateral = _unrelated_touched(changes, spec.faults)
    # Transient disruption: initially working flows broken (or forbidden flows opened) at any point by a change.
    transient = sorted({f for e in changes for f in (e.change or {}).get("flows_broken_after", [])})
    transient_open = sorted({f for e in changes for f in (e.change or {}).get("forbidden_open_after", [])})
    intended_ok_end = all(final_flows.get(fl.id, {}).get("ok") for fl in topo.intended_flows)
    remediation = verification = None
    no_regression: float | None
    if mode == "remediation":
        rem = [fr for fr in fault_rows if fr["remediable"]]
        if rem:
            remediation = sum(
                1.0
                if (fr["fixed_state"] and fr["symptom_flows_restored"])
                else 0.5
                if fr["symptom_flows_restored"]
                else 0.0
                for fr in rem
            ) / len(rem)
        if changes:
            claim_ok = rep.claims_recovered == intended_ok_end
            verification = round(0.6 * verify["coverage"] + (0.4 if claim_ok else 0.0), 4)
        elif n_f:
            verification = 0.0 if rep.claims_recovered else None
        no_regression = (
            0.0
            if (regressions or security)
            else round(max(0.0, 1 - 0.25 * len(collateral) - 0.1 * len(transient) - 0.25 * len(transient_open)), 4)
        )
        for fl in topo.intended_flows:
            res = final_flows.get(fl.id, {})
            rows.append(
                {
                    "item": f"flow {fl.id} {fl.src}->{fl.dst} {fl.proto}/{fl.port or ''}",
                    "expected": "works",
                    "observed": f"{'works' if res.get('ok') else res.get('outcome')} "
                    f"(at start: {'works' if initial_flows.get(fl.id) else 'broken'})",
                    "pass": bool(res.get("ok")),
                }
            )
    else:
        no_regression = 0.0 if (changes or regressions) else 1.0
    for k in security:
        rows.append({"item": f"forbidden flow {k}", "expected": "blocked", "observed": "permitted", "pass": False})

    scores: dict[str, float | None] = {
        "discovery": discovery,
        "diagnosis": diagnosis,
        "false_positives": fp_score,
        "evidence": evidence,
        "uncertainty": uncertainty,
        "remediation": remediation,
        "verification": verification,
        "no_regression": no_regression,
    }
    if status == "inconclusive":  # e.g. the model produced no reasoning: not scored as an investigation
        scores = dict.fromkeys(scores, None)
    elif status != "completed":
        scores = dict.fromkeys(scores, 0.0) | {"no_regression": no_regression}
    num = sum(WEIGHTS[k] * v for k, v in scores.items() if v is not None)
    den = sum(WEIGHTS[k] for k, v in scores.items() if v is not None)
    overall = round(num / den, 4) if den else None

    measurements = {
        "faults": fault_rows,
        "n_faults": n_f,
        "interacting": spec.interacting,
        "identified_regardless_of_support": identified / n_f if n_f else None,
        "unsupported_correct": sum(1 for fr in fault_rows if fr["match"] == "full" and fr["support"] == "none"),
        "false_positives": fps,
        "false_positive_count": len(fps),
        "false_positives_on_distractors": sum(1 for x in fps if x["on_distractor"]),
        "findings": len(rep.findings),
        "grounded_findings": len(grounded),
        "discovery": disc,
        "unobserved_infra": unobserved,
        "acknowledged_unknown": ack,
        "overclaimed_healthy": over,
        "healthy_overall_claim": rep.healthy_overall,
        "healthy_overall_claim_wrong": overall_claim_wrong,
        "changes": [e.change for e in changes],
        "net_changes": net_changes,
        "collateral_changes": collateral,
        "unnecessary_change_count": len(collateral),
        "reverted_unnecessary_changes": [c for c in collateral if c["reverted"]],
        "transiently_disrupted_flows": transient,
        "verification_coverage": {k: v for k, v in verify.items() if k != "covering_probes"},
        "transiently_opened_forbidden_flows": transient_open,
        "status": status,
        "evaluator_version": EVALUATOR_VERSION,
        "write_attempts_denied": len(write_attempts),
        "regressions": regressions,
        "security_regressions": security,
        "intended_flows_ok_at_start": sum(1 for fl in topo.intended_flows if initial_flows.get(fl.id)),
        "intended_flows_ok_at_end": sum(1 for fl in topo.intended_flows if final_flows.get(fl.id, {}).get("ok")),
        "intended_flows_total": len(topo.intended_flows),
        "recovered": intended_ok_end,
        "claims_recovered": rep.claims_recovered,
        "probes_after_last_change": len(probes_after),
        "agent_seconds": round(agent_seconds, 2),
        "budget_seconds": budget_s,
        "commands": sum(1 for e in agent_ev if e.kind == "command"),
        "api_requests": sum(1 for e in agent_ev if e.source == "api"),
        "ssh_channel_opens": sum(1 for e in agent_ev if e.kind == "channel_open"),
        "failed_actions": sum(1 for e in agent_ev if not e.ok),
        "events_total": len(agent_ev),
        "final_flows": final_flows,
    }
    return {"scores": scores, "overall": overall, "measurements": measurements, "expected_vs_observed": rows}
