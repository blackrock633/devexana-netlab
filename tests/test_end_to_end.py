"""Full runs: lab + real client subprocess + evaluator, for a healthy case and fault cases."""

from __future__ import annotations

import io
import json
import zipfile

from conftest import healthy, only, run

from netlab import orchestrate as orch


def test_healthy_read_only_run_end_to_end():
    spec = healthy()
    orch.save_spec(spec)
    r = run(orch.run_scenario(spec, client="reference", mode="read_only", time_budget_s=120, unreachable_delay_s=0.1))
    assert r.status == "completed"
    assert r.measurements["false_positive_count"] == 0
    assert r.scores["diagnosis"] == 1.0 and r.scores["no_regression"] == 1.0
    d = orch.var_dir() / "runs" / r.run_id
    for f in ("events.jsonl", "report.json", "result.json.enc", "meta.json", "spec.json.enc", "handoff.json"):
        assert (d / f).exists(), f
    for f in ("result.json.enc", "spec.json.enc"):  # ground truth and results are sealed at rest
        assert (d / f).read_bytes().startswith(b"NETLAB-SEALED-1")
    meta = json.loads((d / "meta.json").read_text())
    assert "seed" not in meta and meta["isolation"].startswith("sandbox-exec")
    assert r.measurements["isolation"].startswith("sandbox-exec")
    assert r.measurements["teardown"]["ports_still_open"] == []


def test_fault_remediation_run_recovers_and_export_has_no_credentials():
    spec = only("service_stopped")
    orch.save_spec(spec)
    r = run(orch.run_scenario(spec, client="reference", mode="remediation", time_budget_s=120, unreachable_delay_s=0.1))
    assert r.status == "completed"
    assert r.measurements["recovered"] is True, r.expected_vs_observed
    assert r.scores["remediation"] == 1.0 and r.scores["diagnosis"] == 1.0
    h = json.loads((orch.var_dir() / "runs" / r.run_id / "handoff.json").read_text())
    secrets = [h["api_token"], h["bastion"]["password"], h["device_password"], h["consoles"]["password"]]
    z = zipfile.ZipFile(io.BytesIO(orch.export_run(r.run_id)))
    names = z.namelist()
    assert not any(n.endswith("handoff.json") for n in names)
    blob = "".join(z.read(n).decode() for n in names)
    assert not any(s in blob for s in secrets if s)


def test_missing_devexana_appliance_is_reported_as_agent_failure(monkeypatch):
    monkeypatch.delenv("DEVEXANA_URL", raising=False)
    spec = healthy()
    r = run(orch.run_scenario(spec, client="devexana", mode="read_only", time_budget_s=60, unreachable_delay_s=0.1))
    assert r.status == "agent_failed"
    log = (orch.var_dir() / "runs" / r.run_id / "client.log").read_text()
    assert "DEVEXANA_URL" in log


def test_batch_and_compare_on_identical_scenarios():
    specs = [only("dns_record_stale"), healthy()]
    for s in specs:
        orch.save_spec(s)
    ids = [s.env_id for s in specs]
    a = run(orch.run_batch(ids, "reference", "read_only", label="ref-A", time_budget_s=120))
    b = run(orch.run_batch(ids, "reference", "read_only", label="ref-B", time_budget_s=120))
    assert len(a["runs"]) == 2 and all(x["status"] == "completed" for x in a["runs"] + b["runs"])
    c = orch.compare("ref-A", "ref-B")
    assert c["paired_scenarios"] == 2
