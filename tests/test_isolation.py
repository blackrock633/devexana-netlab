"""Ground-truth isolation: nothing an agent can reach reveals fault identity, labels, seeds or evaluator secrets."""

from __future__ import annotations

import ast
import json
from pathlib import Path

import asyncssh
import httpx
from conftest import find_spec, healthy, run
from fastapi.testclient import TestClient

from netlab.artifacts import render_artifacts
from netlab.control.server import create_app
from netlab.generate import generate
from netlab.runtime.lab import Lab, LabOptions
from netlab.schemas import DEGRADATION_TYPES, FAULT_TYPES

ROOT = Path(__file__).resolve().parents[1]


def forbidden_strings(spec):
    out = {f.id for f in spec.faults} | {d.id for d in spec.evidence.degradations}
    out |= set(FAULT_TYPES) | set(DEGRADATION_TYPES) | {str(spec.seed), spec.env_id, spec.spec_sha256}
    out |= {"ground truth", "ground_truth", "reveals", "symptom_flows", "accepted_components", "distractor"}
    out |= {f.description for f in spec.faults} | {d.description for d in spec.evidence.degradations}
    return {s for s in out if s and len(s) >= 6}


async def collect_agent_surface(spec):
    lab = Lab(spec, None, LabOptions(mode="remediation", unreachable_delay_s=0.01, run_collector_loop=False))
    h = await lab.start()
    texts = [h.model_dump_json()]
    async with httpx.AsyncClient(base_url=h.api_base, headers={"Authorization": f"Bearer {h.api_token}"}) as c:
        for p in (
            "/api/v1/devices",
            "/api/v1/checks",
            "/api/v1/alerts",
            "/api/v1/logs?limit=5000",
            "/api/v1/artifacts",
            "/api/table.json?content=devices",
            "/api/table.json?content=sensors",
        ):
            texts.append((await c.get(p)).text)
        for d in (await c.get("/api/v1/devices")).json():
            texts.append((await c.get(f"/api/v1/devices/{d['name']}/interfaces")).text)
        for a in (await c.get("/api/v1/artifacts")).json():
            texts.append((await c.get(f"/api/v1/artifacts/{a['path']}")).text)
        texts.append((await c.get("/api/v1/nonexistent")).text)
    b = h.bastion
    async with asyncssh.connect(
        b["host"], port=b["port"], username=b["username"], password=b["password"], known_hosts=None
    ) as bast:
        for n, d in spec.topology.devices.items():
            if d.kind == "workstation":
                continue
            cmds = (
                [
                    "show running-config",
                    "show logging",
                    "show ip route",
                    "show access-lists",
                    "show version",
                    "show interfaces status",
                    "bogus command",
                ]
                if d.os == "ios"
                else [
                    "systemctl list-units",
                    "journalctl -n 500",
                    "ss -tuln",
                    "dns-record list",
                    "dhcp-leases",
                    "ping -c 1 intranet",
                    "curl https://intranet/",
                    "nslookup intranet",
                    "bogus",
                ]
            )
            try:
                async with asyncssh.connect(
                    lab.world.primary_ip(n),
                    tunnel=bast,
                    username=h.device_username,
                    password=h.device_password,
                    known_hosts=None,
                ) as c:
                    for cmd in cmds:
                        texts.append((await c.run(cmd, check=False)).stdout)
            except (asyncssh.Error, OSError) as e:
                texts.append(str(e))
    await lab.stop()
    return texts


def test_agent_surface_never_leaks_hidden_state():
    specs = [
        find_spec(lambda s: len(s.faults) == 2 and len(s.evidence.degradations) >= 2, start=1000),
        healthy(),
        find_spec(lambda s: any(f.type == "dns_record_stale" for f in s.faults), start=500),
    ]
    for spec in specs:
        texts = run(collect_agent_surface(spec))
        blob = "\n".join(texts)
        leaked = [s for s in forbidden_strings(spec) if s in blob]
        assert not leaked, f"{spec.env_id} leaked {leaked}"


def test_handoff_shape_and_artifact_names_do_not_depend_on_faults():
    names = set()
    for seed in range(40):
        s = generate(seed=seed)
        files, _ = render_artifacts(s)
        names.add(tuple(sorted(p for p in files if not p.startswith("configs/"))))
        cfgs = {p.removeprefix("configs/").removesuffix(".cfg") for p in files if p.startswith("configs/")}
        assert cfgs == {n for n, d in s.topology.devices.items() if d.os == "ios"}
    assert len(names) == 1


def test_reference_client_imports_no_ground_truth_modules():
    tree = ast.parse((ROOT / "netlab/clients/reference.py").read_text())
    mods = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module} | {
        a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names
    }
    netlab_mods = {m for m in mods if m.startswith("netlab")}
    assert netlab_mods == {"netlab.schemas"}
    tree = ast.parse((ROOT / "netlab/clients/devexana_os.py").read_text())
    mods = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
    assert {m for m in mods if m.startswith("netlab")} == {"netlab.schemas"}


def test_control_api_rejects_agent_credentials_and_hides_truth_until_finished(tmp_path):
    app = create_app("operator-secret")
    c = TestClient(app)
    assert c.get("/api/scenarios").status_code == 401
    assert c.get("/api/scenarios", headers={"x-operator-token": "agent-token"}).status_code == 401
    H = {"x-operator-token": "operator-secret"}
    s = c.post("/api/shuffle", json={}, headers=H).json()
    assert "faults" not in json.dumps(s) and "degradations" not in json.dumps(s)
    from netlab import orchestrate as orch

    d = orch.var_dir() / "runs" / "run-unfinished"
    d.mkdir(parents=True)
    from netlab.store import seal

    seal(orch.var_dir(), d / "spec.json.enc", orch.load_spec(s["env_id"]).model_dump_json())
    (d / "events.jsonl").write_text(
        json.dumps(
            {"seq": 1, "ts": "x", "t_rel_s": 0, "source": "ssh", "kind": "command", "reveals": ["f-1"], "symptoms": []}
        )
        + "\n"
    )
    assert c.get("/api/runs/run-unfinished/truth", headers=H).status_code == 403
    ev = c.get("/api/runs/run-unfinished/events", headers=H).json()
    assert "reveals" not in ev[0]
    assert c.get("/api/runs/..%2Fscenarios/truth", headers=H).status_code in (404, 405)
