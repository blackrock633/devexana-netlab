"""Operator API flow: shuffle -> replay check -> lab start/reset/stop -> run -> live events -> result -> reveal -> export."""

from __future__ import annotations

import io
import time
import zipfile

from fastapi.testclient import TestClient

from netlab.control.server import create_app
from netlab.runtime.lab import port_open

H = {"x-operator-token": "op"}


def test_operator_flow():
    with TestClient(create_app("op")) as c:
        d = c.get("/api/config/defaults", headers=H).json()
        assert "branch_office" in d["implemented_families"] and "campus" in d["families"]
        s = c.post(
            "/api/shuffle",
            json={
                **d["config"],
                "fault_count_weights": {"0": 0, "1": 1, "2": 0},
                "fault_type_weights": {**{k: 0 for k in d["fault_types"]}, "service_stopped": 1},
            },
            headers=H,
        ).json()
        env = s["env_id"]
        assert s["resource_estimate"]["privileged_operations"] == 0
        assert c.post(f"/api/scenarios/{env}/replay", headers=H).json()["spec_identical"]
        lab = c.post("/api/lab/start", json={"env_id": env, "mode": "read_only"}, headers=H).json()
        p1 = lab["ports"]["bastion"]
        assert port_open(p1)
        lab2 = c.post("/api/lab/reset", headers=H).json()
        assert not port_open(p1) and port_open(lab2["ports"]["bastion"])
        c.post("/api/lab/stop", headers=H)
        assert not port_open(lab2["ports"]["bastion"])
        assert c.get("/api/lab", headers=H).json()["running"] is False

        run_id = c.post(
            "/api/runs",
            json={
                "env_id": env,
                "client": "reference",
                "mode": "remediation",
                "label": "ref-test",
                "time_budget_s": 120,
            },
            headers=H,
        ).json()["run_id"]
        assert c.get(f"/api/runs/{run_id}/truth", headers=H).status_code == 403
        for _ in range(240):
            info = c.get(f"/api/runs/{run_id}", headers=H).json()
            if info["finished"]:
                break
            time.sleep(0.5)
        assert info["finished"]
        events = c.get(f"/api/runs/{run_id}/events", headers=H).json()
        assert any(e["kind"] == "command" for e in events)
        res = c.get(f"/api/runs/{run_id}/result", headers=H).json()
        assert res["status"] == "completed" and res["overall"] is not None
        truth = c.get(f"/api/runs/{run_id}/truth", headers=H).json()
        assert truth["faults"][0]["type"] == "service_stopped"
        z = zipfile.ZipFile(io.BytesIO(c.get(f"/api/runs/{run_id}/export", headers=H).content))
        assert any(n.endswith("result.json") for n in z.namelist())
        assert "ref-test" in c.get("/api/labels", headers=H).json()
