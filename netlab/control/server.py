"""Operator control server (human reviewer UI + JSON API). Binds 127.0.0.1 only.

Authentication uses an operator token generated at startup (printed once, stored 0600 in $NETLAB_VAR/operator.token).
Agents under test never receive it; the lab's agent-facing API token is rejected here (tests/test_isolation.py).
Ground truth (``/api/runs/{id}/truth``) is served only after the run has finished.
"""

from __future__ import annotations

import asyncio
import contextlib
import hmac
import json
import secrets
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from pydantic import BaseModel

from netlab import orchestrate as orch
from netlab.generate import GenerationError, coverage_cells
from netlab.runtime.lab import Lab, LabOptions
from netlab.schemas import DEGRADATION_TYPES, FAMILIES, FAULT_TYPES, IMPLEMENTED_FAMILIES, GenerationConfig

STATIC = Path(__file__).parent / "static"


class RunBody(BaseModel):
    env_id: str
    client: str = "reference"
    mode: str = "read_only"
    label: str | None = None
    time_budget_s: int = 600


class LabBody(BaseModel):
    env_id: str
    mode: str = "read_only"


class BatchBody(BaseModel):
    env_ids: list[str] = []
    shuffle_count: int = 0
    config: GenerationConfig | None = None
    client: str = "reference"
    mode: str = "read_only"
    label: str | None = None
    time_budget_s: int = 600


def create_app(token: str | None = None) -> FastAPI:
    tok = token or secrets.token_urlsafe(24)

    @contextlib.asynccontextmanager
    async def lifespan(app: FastAPI) -> Any:
        yield
        with contextlib.suppress(Exception):  # reliable teardown when the server exits
            await app.state.shutdown()
        orch.teardown_stale()

    app = FastAPI(title="netlab control", docs_url=None, redoc_url=None, lifespan=lifespan)
    app.state.token = tok
    state: dict[str, Any] = {"lab": None, "lab_env": None, "lab_mode": None, "running": {}, "batches": {}}

    def auth(request: Request) -> None:
        given = request.headers.get("x-operator-token") or request.query_params.get("token") or ""
        if not given or not hmac.compare_digest(given, app.state.token):
            raise HTTPException(401, "operator token required")

    A = Depends(auth)

    @app.get("/")
    def index() -> FileResponse:
        return FileResponse(STATIC / "index.html")

    @app.get("/api/config/defaults", dependencies=[A])
    def defaults() -> dict[str, Any]:
        return {
            "config": GenerationConfig().model_dump(),
            "fault_types": list(FAULT_TYPES),
            "degradation_types": list(DEGRADATION_TYPES),
            "families": list(FAMILIES),
            "implemented_families": list(IMPLEMENTED_FAMILIES),
            "coverage_cells": len(coverage_cells(GenerationConfig())),
            "ledger": orch.ledger(),
        }

    @app.post("/api/shuffle", dependencies=[A])
    def shuffle(cfg: GenerationConfig) -> dict[str, Any]:
        try:
            spec = orch.shuffle(cfg)
        except GenerationError as e:
            raise HTTPException(422, str(e)) from None
        return orch.public_summary(spec)

    @app.get("/api/scenarios", dependencies=[A])
    def scenarios() -> list[dict[str, Any]]:
        return [orch.public_summary(s) for s in orch.list_specs()]

    @app.post("/api/scenarios/{env_id}/replay", dependencies=[A])
    def replay(env_id: str) -> dict[str, Any]:
        return orch.replay_spec(orch.load_spec(env_id))

    # -- manual lab ------------------------------------------------------------------------------------------------
    async def stop_lab() -> dict[str, Any] | None:
        lab: Lab | None = state["lab"]
        state["lab"] = None
        return await lab.stop() if lab else None

    @app.post("/api/lab/start", dependencies=[A])
    async def lab_start(body: LabBody) -> dict[str, Any]:
        if state["running"]:
            raise HTTPException(409, "a run is in progress")
        await stop_lab()
        spec = orch.load_spec(body.env_id)
        run_dir = orch.var_dir() / "runs" / f"manual-{body.env_id}-{secrets.token_hex(3)}"
        run_dir.mkdir(mode=0o700)
        lab = Lab(spec, run_dir, LabOptions(mode=body.mode))
        h = await lab.start()
        state.update(lab=lab, lab_env=body.env_id, lab_mode=body.mode)
        return {
            "env_id": body.env_id,
            "mode": body.mode,
            "ports": lab.ports(),
            "handoff_path": str(run_dir / "handoff.json"),
            "api_base": h.api_base,
            "bastion": {k: v for k, v in h.bastion.items() if k != "password"},
        }

    @app.post("/api/lab/stop", dependencies=[A])
    async def lab_stop() -> dict[str, Any]:
        return {"stopped": await stop_lab()}

    @app.post("/api/lab/reset", dependencies=[A])
    async def lab_reset() -> dict[str, Any]:
        env, mode = state["lab_env"], state["lab_mode"]
        if not env:
            raise HTTPException(409, "no lab to reset")
        await stop_lab()
        return await lab_start(LabBody(env_id=env, mode=mode))

    @app.get("/api/lab", dependencies=[A])
    def lab_status() -> dict[str, Any]:
        lab: Lab | None = state["lab"]
        return {
            "running": lab is not None,
            "env_id": state["lab_env"] if lab else None,
            "mode": state["lab_mode"] if lab else None,
            "ports": lab.ports() if lab else None,
            "uptime_s": round(lab.now(), 1) if lab else None,
        }

    # -- runs ------------------------------------------------------------------------------------------------------
    @app.post("/api/runs", dependencies=[A])
    async def start_run(body: RunBody) -> dict[str, Any]:
        if state["running"]:
            raise HTTPException(409, "a run is already in progress")
        await stop_lab()
        spec = orch.load_spec(body.env_id)
        started: asyncio.Future = asyncio.get_running_loop().create_future()

        async def go() -> None:
            try:
                await orch.run_scenario(
                    spec,
                    client=body.client,
                    mode=body.mode,
                    label=body.label,
                    time_budget_s=body.time_budget_s,
                    on_start=lambda lab: started.done() or started.set_result(lab.run_id),
                )
            except Exception as e:
                if not started.done():
                    started.set_exception(e)
            finally:
                state["running"].clear()

        task = asyncio.create_task(go())
        run_id = await asyncio.wait_for(started, timeout=30)
        state["running"][run_id] = task
        return {"run_id": run_id}

    @app.get("/api/runs", dependencies=[A])
    def runs() -> list[dict[str, Any]]:
        return orch.list_runs()

    def run_dir(run_id: str) -> Path:
        d = orch.var_dir() / "runs" / run_id
        if not d.is_dir() or "/" in run_id or ".." in run_id:
            raise HTTPException(404, "no such run")
        return d

    @app.get("/api/runs/{run_id}", dependencies=[A])
    def run_info(run_id: str) -> dict[str, Any]:
        d = run_dir(run_id)
        done = orch.has_result(d)
        meta = json.loads((d / "meta.json").read_text()) if (d / "meta.json").exists() else {}
        return {"run_id": run_id, "finished": done, "running": run_id in state["running"], **meta}

    @app.get("/api/runs/{run_id}/events", dependencies=[A])
    def run_events(run_id: str, after: int = 0) -> list[dict[str, Any]]:
        d = run_dir(run_id)
        done = orch.has_result(d)
        out = []
        p = d / "events.jsonl"
        if not p.exists():
            return []
        for line in p.read_text().splitlines()[after:]:
            e = json.loads(line)
            if not done:  # evaluator annotations are hidden from the live view until the run is over
                e.pop("reveals", None)
                e.pop("symptoms", None)
            out.append(e)
        return out

    @app.get("/api/runs/{run_id}/result", dependencies=[A])
    def run_result(run_id: str) -> Response:
        if not orch.has_result(run_dir(run_id)):
            raise HTTPException(409, "run not finished")
        return Response(orch.load_result(run_id).model_dump_json(), media_type="application/json")

    @app.get("/api/runs/{run_id}/report", dependencies=[A])
    def run_report(run_id: str) -> Response:
        p = run_dir(run_id) / "report.json"
        if not p.exists():
            raise HTTPException(404, "no report")
        return Response(p.read_text(), media_type="application/json")

    @app.get("/api/runs/{run_id}/truth", dependencies=[A])
    def run_truth(run_id: str) -> dict[str, Any]:
        d = run_dir(run_id)
        if not orch.has_result(d):
            raise HTTPException(403, "ground truth is revealed only after the run has finished")
        return orch.truth_view(orch.run_spec(run_id))

    @app.get("/api/runs/{run_id}/export", dependencies=[A])
    def run_export(run_id: str) -> Response:
        run_dir(run_id)
        return Response(
            orch.export_run(run_id),
            media_type="application/zip",
            headers={"Content-Disposition": f'attachment; filename="{run_id}.zip"'},
        )

    @app.post("/api/runs/{run_id}/rerun", dependencies=[A])
    async def rerun(run_id: str) -> dict[str, Any]:
        meta = json.loads((run_dir(run_id) / "meta.json").read_text())
        return await start_run(
            RunBody(
                env_id=meta["env_id"],
                client=meta["client"],
                mode=meta["mode"],
                label=meta.get("agent", {}).get("label"),
            )
        )

    # -- batches ---------------------------------------------------------------------------------------------------
    @app.post("/api/batches", dependencies=[A])
    async def batch(body: BatchBody) -> dict[str, Any]:
        if state["running"]:
            raise HTTPException(409, "a run is already in progress")
        await stop_lab()
        envs = list(body.env_ids)
        for _ in range(body.shuffle_count):
            envs.append(orch.shuffle(body.config or GenerationConfig()).env_id)
        if not envs:
            raise HTTPException(422, "no scenarios selected")
        bid = f"pending-{secrets.token_hex(3)}"
        prog = {"id": bid, "done": 0, "total": len(envs), "rows": [], "summary": None}
        state["batches"][bid] = prog

        async def go() -> None:
            state["running"]["batch"] = True
            try:
                prog["summary"] = await orch.run_batch(
                    envs,
                    body.client,
                    body.mode,
                    body.label,
                    body.time_budget_s,
                    progress=lambda k, n, row: (prog.update(done=k), prog["rows"].append(row)),
                )
            except Exception as e:
                prog["error"] = repr(e)
            finally:
                state["running"].clear()

        asyncio.create_task(go())
        return {"batch": bid, "total": len(envs)}

    @app.get("/api/batches/{bid}", dependencies=[A])
    def batch_status(bid: str) -> dict[str, Any]:
        if bid in state["batches"]:
            return state["batches"][bid]
        p = orch.var_dir() / "batches" / f"{bid}.json"
        if not p.exists():
            raise HTTPException(404, "no such batch")
        return {"summary": json.loads(p.read_text())}

    @app.get("/api/compare", dependencies=[A])
    def compare(a: str, b: str, mode: str | None = None) -> dict[str, Any]:
        return orch.compare(a, b, mode)

    @app.get("/api/labels", dependencies=[A])
    def labels() -> list[str]:
        out = set()
        for m in orch.list_runs():
            ag = m.get("agent", {})
            out.add(ag.get("label") or f"{ag.get('name')}@{ag.get('version')}")
        return sorted(out)

    @app.exception_handler(FileNotFoundError)
    async def nf(_r: Request, _e: FileNotFoundError) -> JSONResponse:
        return JSONResponse({"detail": "not found"}, status_code=404)

    app.state.shutdown = stop_lab
    return app
