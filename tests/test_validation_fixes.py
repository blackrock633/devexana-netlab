"""Regression tests for the independent validation findings (devexana-netlab-validation/REPORT.md, F1-F10)."""

from __future__ import annotations

import asyncio
import contextlib
import json
import socket
import sys
import textwrap

import asyncssh
import httpx
import pytest
from conftest import healthy, only, run

from netlab import isolation
from netlab import orchestrate as orch
from netlab.artifacts import inventory_csv
from netlab.clients import devexana_os as adapter
from netlab.evaluate import evaluate
from netlab.generate import GenerationError, generate
from netlab.render import software
from netlab.runtime.api import build_app
from netlab.runtime.cli import CliSession
from netlab.runtime.lab import Lab, LabOptions, port_open
from netlab.runtime.services import validate_response
from netlab.schemas import AgentReport, GenerationConfig, ReportFinding
from netlab.store import key_path


def lab_for(spec, mode="remediation"):
    lab = Lab(spec, None, LabOptions(mode=mode, run_collector_loop=False, unreachable_delay_s=0.01))
    lab.initial_flows = {
        f.id: lab.world.flow_check(f.src, f.dst, f.proto, f.port, f.by_name).ok
        for f in spec.topology.intended_flows + spec.topology.forbidden_flows
    }
    return lab


def score(lab, rep, mode="read_only"):
    flows = {
        f.id: {"ok": lab.world.flow_check(f.src, f.dst, f.proto, f.port, f.by_name).ok}
        for f in lab.spec.topology.intended_flows + lab.spec.topology.forbidden_flows
    }
    return evaluate(
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


def report(**kw):
    return AgentReport(agent={"name": "t", "version": "1"}, summary="s", **kw)


# -- F1: ground truth unreadable by the agent ------------------------------------------------------------------------


def test_sandboxed_agent_cannot_read_any_evaluator_state(tmp_path):
    """The real boundary: a client launched by the orchestrator tries to read the sealed spec, the key, the events
    and to list $NETLAB_VAR. Every attempt must fail, while its own handoff stays readable (positive control)."""
    spec = only("service_stopped")
    saved = orch.save_spec(spec)
    var = orch.var_dir()
    probe = tmp_path / "probe_client.py"
    probe.write_text(
        textwrap.dedent(f"""
        import json, os, sys
        out = sys.argv[sys.argv.index("--out") + 1]
        hand = sys.argv[sys.argv.index("--handoff") + 1]
        res = {{"handoff_readable": bool(open(hand).read())}}
        for name, p in {{"spec": {str(saved)!r}, "key": {str(key_path(var))!r}, "var": {str(var)!r},
                         "runs": {str(var / "runs")!r}}}.items():
            try:
                if os.path.isdir(p):
                    os.listdir(p)
                else:
                    open(p, "rb").read()
                res[name] = "READ"
            except Exception as e:
                res[name] = type(e).__name__
        json.dump({{"agent": {{"name": "probe", "version": "1"}}, "summary": json.dumps(res)}}, open(out, "w"))
    """)
    )
    r = run(orch.run_scenario(spec, client=f"{sys.executable} {probe}", time_budget_s=60, unreachable_delay_s=0.01))
    rep = json.loads((var / "runs" / r.run_id / "report.json").read_text())
    res = json.loads(rep["summary"])
    assert res["handoff_readable"] is True
    assert {res[k] for k in ("spec", "key", "var", "runs")} == {"PermissionError"}, res
    assert r.measurements["isolation"].startswith("sandbox-exec")


def test_at_rest_files_are_sealed_and_tamper_evident():
    spec = only("service_stopped")
    p = orch.save_spec(spec)
    raw = p.read_bytes()
    assert raw.startswith(b"NETLAB-SEALED-1") and b"service_stopped" not in raw
    assert orch.load_spec(spec.env_id) == spec
    p.write_bytes(raw[:-1] + bytes([raw[-1] ^ 1]))
    with pytest.raises(Exception):  # noqa: B017 - AES-GCM authentication failure
        orch.load_spec(spec.env_id)


def test_no_sandbox_refuses_unless_explicitly_cooperative(monkeypatch):
    monkeypatch.setattr(isolation, "mechanism", lambda: "none")
    monkeypatch.delenv("NETLAB_ALLOW_UNISOLATED", raising=False)
    spec = healthy()
    started = {}
    with pytest.raises(isolation.IsolationUnavailable):
        run(
            orch.run_scenario(
                spec,
                time_budget_s=30,
                unreachable_delay_s=0.01,
                on_start=lambda lab: started.setdefault("ports", lab.ports()),
            )
        )
    assert not port_open(started["ports"]["bastion"]) and not port_open(started["ports"]["api"])
    r = run(orch.run_scenario(spec, time_budget_s=60, unreachable_delay_s=0.01, allow_unisolated=True))
    assert r.measurements["isolation"].startswith("none") and any("UNISOLATED" in n for n in r.notes)


# -- F2: resource-specific support, unmatched claims, parse vs health evidence ------------------------------------


def test_observation_credit_is_resource_and_field_specific():
    s = only("wan_interface_down")
    dev = s.faults[0].mutations[0].device
    claim = report(findings=[ReportFinding(component=dev, fault_class="interface_down", statement="x")])

    async def go(cmd):
        lab = lab_for(s)
        await CliSession(lab, dev, "netops", "ssh").run(cmd)
        return score(lab, claim)["scores"]["diagnosis"]

    assert run(go("show interfaces Gi0/1")) == 0.0  # healthy neighbour interface only
    assert run(go("show ip route")) == 0.0  # routing table does not show admin state
    assert run(go("show interfaces Gi0/0")) == 1.0
    assert run(go("show ip interface brief")) == 1.0
    v = only("access_port_wrong_vlan")
    sw = v.faults[0].mutations[0].device

    async def vlan(cmd):
        lab = lab_for(v)
        await CliSession(lab, sw, "netops", "ssh").run(cmd)
        return lab.events.events[-1].reveals

    assert run(vlan("show ip interface brief")) == []  # no VLAN column: VLAN error not revealed
    assert run(vlan("show vlan brief")) == [v.faults[0].id]


def test_wrong_extra_classes_at_a_real_fault_are_false_positives_but_restatements_are_not():
    s = only("service_stopped")
    f = s.faults[0]
    dev = f.mutations[0].device

    async def go(findings):
        lab = lab_for(s)
        await CliSession(lab, dev, "netops", "ssh").run("systemctl list-units")
        return score(lab, report(findings=findings))

    good = ReportFinding(component=f.component, fault_class="service_down", statement="x")
    same = ReportFinding(component=dev, fault_class="service_down", statement="restated")
    wrong = [ReportFinding(component=dev, fault_class=c, statement="y") for c in ("routing", "dns_misconfiguration")]
    a, b, c = run(go([good])), run(go([good, same])), run(go([good, *wrong]))
    assert a["measurements"]["false_positive_count"] == b["measurements"]["false_positive_count"] == 0
    assert c["measurements"]["false_positive_count"] == 2 and c["overall"] < a["overall"]


def test_invalid_or_denied_commands_are_not_health_evidence():
    s = healthy()

    async def go():
        lab = lab_for(s, mode="read_only")
        edge = next(n for n, d in s.topology.devices.items() if d.kind == "edge")
        srv = next(n for n, d in s.topology.devices.items() if "dns" in d.services)
        for dev, cmd in (
            (edge, "nonsense"),
            (edge, "show interfaces Gi9/9"),
            (edge, "configure terminal"),
            (srv, "frobnicate"),
            (srv, "hostname"),
            (srv, "nslookup intranet"),
        ):
            await CliSession(lab, dev, "netops", "ssh").run(cmd)
        ev = [e for e in lab.events.events if e.kind == "command"]
        assert [e.detail["parsed"] for e in ev] == [False, False, True, False, True, True]
        assert not any(e.detail["health_evidence"] for e in ev)
        assert {edge, srv} <= set(score(lab, report())["measurements"]["unobserved_infra"])
        await CliSession(lab, edge, "netops", "ssh").run("show ip interface brief")
        assert edge not in score(lab, report())["measurements"]["unobserved_infra"]

    run(go())


# -- F4: application health ---------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "payload, ok",
    [
        (b"HTTP/1.0 200 OK\r\n\r\n<html><title>Intranet</title></html>", True),
        (b"HTTP/1.0 503 Service Unavailable\r\n\r\nbackend unavailable", False),
        (b"HTTP/1.0 200 OK\r\n\r\n<html><title>Other app</title></html>", False),
        (b"HTTP/1.0 200 OK\r\nContent-Type: text/html", False),  # truncated headers
        (b"\x00\x01garbage", False),
        (b"SMB2 NEGOTIATE OK (emulated banner)\r\n", False),  # wrong service
    ],
)
def test_validate_response(payload, ok):
    assert validate_response("intranet", payload)[0] is ok


def test_live_http_503_is_unhealthy_but_transport_up():
    s = healthy()

    async def go():
        lab = Lab(s, None, LabOptions(run_collector_loop=False, unreachable_delay_s=0.01))
        await lab.start()
        try:
            app = next(n for n, d in s.topology.devices.items() if "intranet" in d.services)
            lab.services.set_response(app, "intranet", b"HTTP/1.0 503 Service Unavailable\r\n\r\ndown\r\n")
            p = await lab.services.probe(app, "intranet")
            assert p.transport_ok and not p.app_ok and "503" in p.detail
            fl = next(f for f in s.topology.intended_flows if f.service == "intranet")
            res = await lab.check_flow(fl)
            assert res["ok"] is False and res["transport_ok"] is True and res["application_ok"] is False
            lab.services.set_response(app, "intranet", None)
            assert (await lab.check_flow(fl))["ok"] is True
        finally:
            await lab.stop()

    run(go())


# -- F5: cleanup on every failure path -----------------------------------------------------------------------------


def test_lab_start_failure_rolls_back_partial_acquisition(monkeypatch):
    import netlab.runtime.api as api_mod

    async def boom(_lab):
        raise RuntimeError("api failed to bind")

    monkeypatch.setattr(api_mod, "serve_api", boom)
    lab = Lab(healthy(), None, LabOptions(run_collector_loop=False))
    with pytest.raises(RuntimeError):
        run(lab.start())
    assert lab._stopped and lab.ssh is not None and not port_open(lab.ssh.port)
    assert all(lst.server is None for lst in lab.services.listeners.values())


def test_missing_client_executable_stops_lab_and_persists_aborted_result():
    seen = {}
    with pytest.raises(FileNotFoundError):
        run(
            orch.run_scenario(
                healthy(),
                client="/no/such/agent",
                time_budget_s=10,
                unreachable_delay_s=0.01,
                on_start=lambda lab: seen.setdefault("ports", lab.ports()),
            )
        )
    assert not port_open(seen["ports"]["bastion"]) and not port_open(seen["ports"]["api"])
    run_id = sorted(p.name for p in (orch.var_dir() / "runs").iterdir())[-1]
    assert orch.load_result(run_id).status == "aborted"
    assert json.loads((orch.var_dir() / "runs" / run_id / "meta.json").read_text())["status"] == "aborted"


def test_cancellation_kills_agent_group_and_stops_lab(tmp_path):
    marker = tmp_path / "child.pid"
    script = tmp_path / "hang.py"
    script.write_text(
        textwrap.dedent(f"""
        import subprocess, sys, time
        c = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(600)"])
        open({str(marker)!r}, "w").write(str(c.pid))
        time.sleep(600)
    """)
    )
    seen = {}

    async def go():
        t = asyncio.create_task(
            orch.run_scenario(
                healthy(),
                client=f"{sys.executable} {script}",
                time_budget_s=300,
                unreachable_delay_s=0.01,
                on_start=lambda lab: seen.setdefault("ports", lab.ports()),
            )
        )
        for _ in range(100):
            if marker.exists() and marker.read_text():
                break
            await asyncio.sleep(0.1)
        t.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await t

    run(go())
    import os

    child = int(marker.read_text())
    for _ in range(20):
        try:
            os.kill(child, 0)
        except ProcessLookupError:
            break
        import time

        time.sleep(0.1)
    else:
        raise AssertionError("agent child process survived cancellation")
    assert not port_open(seen["ports"]["bastion"]) and not port_open(seen["ports"]["api"])
    assert not list((orch.var_dir() / "procs").iterdir())


# -- F6: missing model output ------------------------------------------------------------------------------------


def test_missing_or_unsupported_deo_output_is_never_a_health_claim():
    for r in (adapter.translate(None, [], [], []), adapter.translate({}, [], [], [])):
        assert r.healthy_overall is None and r.outcome == "inconclusive" and r.unknowns
    no_evidence = adapter.translate({"summary": "all fine", "facts": [{"text": "ok", "evidence": []}]}, [], [], [])
    assert no_evidence.healthy_overall is None
    supported = adapter.translate({"summary": "ok", "facts": [{"text": "links up", "evidence": ["E1"]}]}, [], [], [])
    assert supported.healthy_overall is True


def test_inconclusive_agent_exit_is_not_scored(tmp_path):
    script = tmp_path / "noreason.py"
    script.write_text(
        textwrap.dedent("""
        import json, sys
        out = sys.argv[sys.argv.index("--out") + 1]
        json.dump({"agent": {"name": "x", "version": "1"}, "summary": "no model", "outcome": "inconclusive"},
                  open(out, "w"))
        sys.exit(3)
    """)
    )
    r = run(
        orch.run_scenario(
            only("service_stopped"), client=f"{sys.executable} {script}", time_budget_s=60, unreachable_delay_s=0.01
        )
    )
    assert r.status == "inconclusive" and r.overall is None and set(r.scores.values()) == {None}


def test_devexana_report_is_run_scoped_with_pagination(monkeypatch):
    """Persistent appliance holding entities from two earlier runs plus >1 page of entities."""
    state = {
        "entities": [
            {
                "id": f"old{i}",
                "name": f"old-{i}",
                "type": "device",
                "status": "up",
                "provenance": {"data_source_name": "netlab run-old inventory"},
            }
            for i in range(600)
        ],
        "calls": [],
    }

    class R:
        def __init__(self, data=None, text=""):
            self.data, self.text = data, text

        def json(self):
            return self.data

        def raise_for_status(self):
            return self

    class LabClient:
        def __init__(self, *a, **kw):
            pass

        def get(self, path):
            if path == "/api/v1/artifacts":
                return R([{"path": "inventory.csv"}, {"path": "logs/syslog-history.log"}])
            return R(text="AssetName\nnew-device\n")

    class App:
        def post(self, path, **kw):
            if path.endswith("/import/upload"):
                state["entities"].append(
                    {
                        "id": "new1",
                        "name": "new-device",
                        "type": "device",
                        "status": "up",
                        "provenance": {"data_source_name": "netlab run-new inventory"},
                    }
                )
            if path.endswith("/sync"):
                return R({"job_id": "j1"})
            if path.endswith("/runs"):
                return R({"status": "failed", "error": {"code": "model_unavailable"}, "result": None})
            return R({"id": "x"})

        def get(self, path, params=None):
            state["calls"].append((path, params))
            if path.endswith("/syncs"):
                return R([{"job_id": "j1", "job_status": "succeeded", "outcome": "ok"}])
            if path == "/agents":
                return R([{"id": "deo", "name": "Deo triage"}])
            ents = state["entities"]
            off, lim = params["offset"], params["limit"]
            return R({"items": ents[off : off + lim], "total": len(ents), "limit": lim, "offset": off})

    class Dx:
        def __init__(self, *a):
            self.c = App()

        def integration(self, *a):
            return "i"

        def version(self):
            return "t"

    monkeypatch.setattr(adapter.httpx, "Client", LabClient)
    monkeypatch.setattr(adapter, "Devexana", Dx)
    for k in ("DEVEXANA_URL", "DEVEXANA_USERNAME", "DEVEXANA_PASSWORD"):
        monkeypatch.setenv(k, "x")
    from types import SimpleNamespace

    created = {"integrations": [], "documents": []}
    rep = adapter.run(
        SimpleNamespace(api_base="http://lab", api_token="t", run_id="run-new", task="t", mode="read_only"),
        False,
        created,
    )
    assert [d.name for d in rep.devices] == ["new-device"]
    assert rep.outcome == "inconclusive" and rep.healthy_overall is None
    assert any(p.endswith("/syncs") for p, _ in state["calls"])  # waited for the job, no fixed sleep
    pages = [p for p, prm in state["calls"] if p == "/inventory/entities"]
    assert len(pages) == 2 and created["integrations"] == ["i", "i"] and len(created["documents"]) >= 1


# -- F7: unnecessary changes ---------------------------------------------------------------------------------------


def test_unnecessary_dns_change_is_collateral_but_equivalent_repairs_are_not():
    s = healthy()

    async def dns_write():
        lab = lab_for(s)
        dns = next(n for n, d in s.topology.devices.items() if "dns" in d.services)
        await CliSession(lab, dns, "netops", "ssh").run(f"sudo dns-record set unused.{s.topology.domain} 192.0.2.9")
        return score(lab, report(claims_recovered=True), mode="remediation")

    r = run(dns_write())
    assert r["measurements"]["unnecessary_change_count"] == 1 and r["scores"]["no_regression"] == 0.75
    assert r["measurements"]["collateral_changes"][0]["resource"].startswith("record:unused.")

    async def reverted():  # change then undo: no NET change, but still an unnecessary, disruptive edit
        lab = lab_for(s)
        edge = next(n for n, d in s.topology.devices.items() if d.kind == "edge")
        ses = CliSession(lab, edge, "netops", "ssh")
        for c in ("configure terminal", "interface Gi0/1", "shutdown", "no shutdown", "end"):
            await ses.run(c)
        return score(lab, report(claims_recovered=True), mode="remediation")

    rv = run(reverted())
    assert rv["measurements"]["net_changes"] == [] and rv["measurements"]["unnecessary_change_count"] == 1
    assert rv["measurements"]["reverted_unnecessary_changes"] and rv["measurements"]["transiently_disrupted_flows"]
    assert rv["scores"]["no_regression"] < 0.75
    rs = only("static_route_missing")
    m = rs.faults[0].mutations[0]

    async def two_halves():
        import ipaddress

        lab = lab_for(rs)
        ses = CliSession(lab, m.device, "netops", "ssh")
        await ses.run("configure terminal")
        for p in ipaddress.ip_network(m.args["prefix"]).subnets(prefixlen_diff=1):
            await ses.run(f"ip route {p} {m.args['next_hop']}")
        await ses.run("end")
        return score(lab, report(claims_recovered=True), mode="remediation")

    r2 = run(two_halves())
    assert r2["scores"]["remediation"] == 1 and r2["scores"]["no_regression"] == 1.0


# -- F8: live log gaps ---------------------------------------------------------------------------------------------


def test_live_log_gap_both_sides_and_delayed_delivery():
    cfg = GenerationConfig(
        fault_count_weights={0: 1, 1: 0, 2: 0}, evidence_completeness=0.0, degradation_weights={"log_gap": 1}
    )
    s = generate(cfg, seed=17, generation_inputs={"forced_fault": "healthy", "forced_degradation": "log_gap"})
    assert [d.type for d in s.evidence.degradations] == ["log_gap"]
    g = s.evidence.degradations[0]
    dev = g.targets[0]
    g.params = {"start_s": 5, "end_s": 20}
    from netlab.history import delivered
    from netlab.world import World

    assert delivered(s, World(s.topology), dev, 0)  # precondition: only the gap can suppress collection

    async def lines(lab):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=build_app(lab)),
            base_url="http://l",
            headers={"Authorization": "Bearer " + lab.creds["api_token"]},
        ) as c:
            return (await c.get("/api/v1/logs", params={"limit": 5000})).json()["lines"]

    async def go():
        lab = lab_for(s)
        lab.emit_log(dev, "BEFORE-GAP")  # t~0
        lab.t0 -= 6
        lab.events.t0 -= 6
        lab.emit_log(dev, "INSIDE-GAP")  # t~6
        lab.t0 -= 20
        lab.emit_log(dev, "AFTER-GAP")  # t~26, visible only after the collection delay
        now = await lines(lab)
        assert any("BEFORE-GAP" in x for x in now) and not any("INSIDE-GAP" in x for x in now)
        assert not any("AFTER-GAP" in x for x in now)
        lab.t0 -= s.evidence.collection_delay_s + 0.1
        later = await lines(lab)
        assert any("AFTER-GAP" in x for x in later) and not any("INSIDE-GAP" in x for x in later)
        assert any(m == "INSIDE-GAP" for _, m, _ in lab.local_logs[dev])  # device-local copy unaffected

    run(go())


# -- F9: hardware / software coherence ---------------------------------------------------------------------------


def test_vendor_software_labels_agree_on_every_surface():
    for seed in range(40):
        s = generate(seed=seed)
        inv = {row.split(",")[0]: row for row in inventory_csv(s).splitlines()[1:]}
        lab = Lab(s, None, LabOptions(run_collector_loop=False))
        for n, d in s.topology.devices.items():
            if d.os != "ios":
                continue
            os_label, banner = software(d)
            if n in inv:
                assert f",{os_label}," in inv[n]
            out = run(CliSession(lab, n, "netops", "ssh").run("show version"))
            assert out.startswith(banner)
            if not d.model.startswith("Cisco"):
                assert "IOS XE" not in out and "17.9" not in out and "Junos" not in inv.get(n, "")


# -- F10: infeasible configurations ------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "cfg, msg",
    [
        (
            GenerationConfig(fault_count_weights={0: 0, 1: 0, 2: 1}, fault_type_weights={"service_stopped": 1}),
            "distinct",
        ),
        (GenerationConfig(fault_count_weights={0: 0, 1: 1, 2: 0}, fault_type_weights={}), "fault type weight"),
        (GenerationConfig(fault_type_weights={"nope": 1}), "unknown key"),
        (GenerationConfig(fault_count_weights={0: -1, 1: 1}), "non-negative"),
        (GenerationConfig(family_weights={"branch_office": 0}), "family"),
    ],
)
def test_infeasible_configs_rejected(cfg, msg):
    with pytest.raises(GenerationError, match=msg):
        generate(cfg, seed=1)


def test_infeasible_shuffle_is_http_422():
    from fastapi.testclient import TestClient

    from netlab.control.server import create_app

    c = TestClient(create_app("op"))
    r = c.post(
        "/api/shuffle",
        json={"fault_count_weights": {"0": 0, "1": 0, "2": 1}, "fault_type_weights": {"service_stopped": 1}},
        headers={"x-operator-token": "op"},
    )
    assert r.status_code == 422 and "distinct" in r.json()["detail"]


def test_balanced_cells_respect_fault_count_weights():
    from netlab.generate import coverage_cells

    assert not any(f == "healthy" for f, _ in coverage_cells(GenerationConfig(fault_count_weights={0: 0, 1: 1})))
    assert {f for f, _ in coverage_cells(GenerationConfig(fault_count_weights={0: 1, 1: 0, 2: 0}))} == {"healthy"}


# -- live sockets: full SSH path after the observation changes ----------------------------------------------------


def test_live_ssh_invalid_command_and_resource_reveal_over_real_proxyjump():
    with socket.socket() as sk:
        sk.bind(("127.0.0.1", 0))  # this suite requires localhost binds (no skip: failures must be visible)
    s = only("wan_interface_down")
    f = s.faults[0]
    edge = f.mutations[0].device

    async def go():
        lab = Lab(s, None, LabOptions(mode="remediation", run_collector_loop=False, unreachable_delay_s=0.01))
        h = await lab.start()
        b = h.bastion
        try:
            async with asyncssh.connect(
                b["host"], port=b["port"], username=b["username"], password=b["password"], known_hosts=None
            ) as bast:
                target, user, pw = f"{edge}.console", h.consoles["username"], h.consoles["password"]
                async with asyncssh.connect(target, tunnel=bast, username=user, password=pw, known_hosts=None) as c:
                    await c.run("show interfaces Gi0/1", check=False)
                    await c.run("nonsense", check=False)
                    await c.run("show interfaces Gi0/0", check=False)
        finally:
            await lab.stop()
        cmds = [e for e in lab.events.events if e.kind == "command"]
        assert [(e.detail["command"], e.ok, e.detail["health_evidence"], bool(e.reveals)) for e in cmds] == [
            ("show interfaces Gi0/1", True, True, False),
            ("nonsense", False, False, False),
            ("show interfaces Gi0/0", True, True, True),
        ]

    run(go())


# -- follow-up findings (second validation round) -------------------------------------------------------------------


def test_shared_appliance_refused_by_default(monkeypatch, tmp_path):
    h = tmp_path / "h.json"
    from netlab.schemas import Handoff

    h.write_text(
        Handoff(
            run_id="r",
            mode="read_only",
            task="t",
            api_base="http://x",
            api_token="t",
            bastion={},
            device_username="u",
            device_password="p",
            consoles={},
            artifacts=[],
            report_vocabulary={},
            budget={},
            notes=[],
        ).model_dump_json()
    )
    for k in ("DEVEXANA_BACKEND_DIR", "DEVEXANA_ALLOW_SHARED"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("DEVEXANA_URL", "http://127.0.0.1:9")
    monkeypatch.setattr(sys, "argv", ["x", "--handoff", str(h), "--out", str(tmp_path / "o.json")])
    with pytest.raises(SystemExit, match="disposable appliance"):
        adapter.main()


def test_shared_appliance_and_unsandboxed_results_are_excluded_from_benchmarks(tmp_path):
    script = tmp_path / "shared.py"
    script.write_text(
        textwrap.dedent("""
        import json, sys
        out = sys.argv[sys.argv.index("--out") + 1]
        json.dump({"agent": {"name": "dx", "version": "1", "appliance_isolation": "shared"}, "summary": "x"},
                  open(out, "w"))
    """)
    )
    spec = healthy()
    orch.save_spec(spec)
    r = run(
        orch.run_scenario(
            spec, client=f"{sys.executable} {script}", label="A", time_budget_s=60, unreachable_delay_s=0.01
        )
    )
    assert r.measurements["benchmark_eligible"] is False and any(
        "shared" in x for x in r.measurements["ineligible_reasons"]
    )
    run(orch.run_scenario(spec, client="reference", label="B", time_budget_s=60, unreachable_delay_s=0.01))
    c = orch.compare("A", "B")
    assert c["paired_scenarios"] == 0 and c["skipped_ineligible_results"] == 1
    assert orch.benchmark_ineligibility("agent_failed", "sandbox-exec: x", {}) == []  # failures stay comparable
    assert orch.benchmark_ineligibility("completed", "none: cooperative", {}) == ["agent not sandboxed"]


def test_malformed_probe_earns_no_verification_credit():
    s = only("service_stopped")
    dev = s.faults[0].mutations[0].device
    unit = s.topology.devices[dev].services[s.faults[0].mutations[0].args["service"]].unit
    ops = next(n for n, d in s.topology.devices.items() if d.kind == "ops")

    async def go(probe):
        lab = lab_for(s)
        await CliSession(lab, dev, "netops", "ssh").run(f"sudo systemctl restart {unit}")
        lab.t0 -= 1
        lab.events.t0 -= 1
        if probe:
            await CliSession(lab, ops, "netops", "bastion").run(probe)
        return score(lab, report(claims_recovered=True), mode="remediation")["scores"]["verification"]

    assert run(go(None)) == 0.4
    for bad in ("curl", "ping", "nc -zv", "nslookup", "curl -x"):
        assert run(go(bad)) == 0.4, bad
    svc = s.topology.devices[dev].services[s.faults[0].mutations[0].args["service"]]
    ip = lab_for(s).world.primary_ip(dev)
    assert run(go(f"ping -c 1 {ip}")) == 0.4  # reaches the server but does not exercise the repaired service
    assert run(go(f"nc -zv {ip} {svc.port + 1}")) == 0.4  # wrong port
    assert run(go(f"nc -zv {ip} {svc.port}")) == 1.0


def test_temporary_wan_outage_is_penalised_even_when_restored():
    s = healthy()
    edge = next(n for n, d in s.topology.devices.items() if d.kind == "edge")

    async def go():
        lab = lab_for(s)
        ses = CliSession(lab, edge, "netops", "console", via_console=True)
        for c in ("configure terminal", "interface Gi0/0", "shutdown", "no shutdown", "end"):
            await ses.run(c)
        return score(lab, report(claims_recovered=True), mode="remediation")

    r = run(go())
    m = r["measurements"]
    assert m["regressions"] == [] and m["net_changes"] == []
    assert m["unnecessary_change_count"] == 1 and len(m["transiently_disrupted_flows"]) >= 5
    # 1 unnecessary change (-0.25) and >=5 transiently broken flows (-0.1 each)
    assert r["scores"]["no_regression"] <= 0.25


def test_disposable_appliance_removes_directory_when_setup_fails(monkeypatch, tmp_path):
    import subprocess
    import tempfile

    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path))

    def leftovers():
        return [p for p in tmp_path.iterdir() if p.name.startswith("netlab-dx-")]

    monkeypatch.setattr(adapter.shutil, "which", lambda _x: None)  # fails before any process exists
    with pytest.raises(RuntimeError, match="uv is required"), adapter.disposable_appliance(str(tmp_path)):
        pass
    assert leftovers() == []
    monkeypatch.setattr(adapter.shutil, "which", lambda _x: "/usr/bin/true")

    def bad_admin(*a, **kw):
        raise subprocess.CalledProcessError(1, "create-admin")

    monkeypatch.setattr(adapter.subprocess, "run", bad_admin)
    with pytest.raises(subprocess.CalledProcessError), adapter.disposable_appliance(str(tmp_path)):
        pass
    assert leftovers() == []


def test_unrelated_self_ping_earns_no_route_repair_verification():
    from test_evaluator_version import hq_route_spec

    s = hq_route_spec()
    m = s.faults[0].mutations[0]
    ops = next(n for n, d in s.topology.devices.items() if d.kind == "ops")
    mon = next(n for n, d in s.topology.devices.items() if d.kind == "probe")

    async def go(vantage, target_dev):
        lab = lab_for(s)
        ses = CliSession(lab, m.device, "netops", "console", via_console=True)
        for c in ("configure terminal", f"ip route {m.args['prefix']} {m.args['next_hop']}", "end"):
            await ses.run(c)
        probe_ses = ses if vantage == "router" else CliSession(lab, ops, "netops", "bastion")
        await probe_ses.run(f"ping {lab.world.primary_ip(target_dev)}")
        r = score(lab, report(claims_recovered=True), mode="remediation")
        return r["scores"]["verification"], r["measurements"]["verification_coverage"]["covered"]

    assert run(go("router", m.device)) == (0.4, [])  # self-ping: never consults the repaired route
    assert run(go("ops", m.device)) == (0.4, [])  # ping that ENDS at the router: not forwarded by it
    v, covered = run(go("router", mon))  # from the router, through the repaired route
    assert v == 1.0 and covered == [f"{m.device}|routes"]
    assert run(go("ops", mon))[0] == 1.0  # from HQ, transiting the repaired router
