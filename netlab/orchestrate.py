"""Run orchestration and persistence.

Layout under ``$NETLAB_VAR`` (default ``./var``):
  keys/evaluator.key            AES-256-GCM key for sealed (*.enc) files                    0600
  scenarios/<env_id>.json.enc   hidden scenario spec (seed, config, inputs, versions), sealed
  coverage.json                 balanced-mode coverage ledger
  runs/<run_id>/                0700
    spec.json.enc               copy of the spec used (hidden), sealed
    meta.json                   run metadata (client, mode, timings, versions, isolation; no seed)
    handoff.json                agent handoff incl. credentials (0600; excluded from export)
    events.jsonl                server-side event record (with evaluator-only annotations)
    report.json                 the agent's report
    result.json.enc             evaluation (raw measurements + scores), sealed
    client.log                  client stdout/stderr
  batches/<batch_id>.json
  procs/<pid>                   pid files of running client processes (for teardown)

The agent under test runs as a separate process in a fresh temporary working directory that contains only its
handoff file, inside a sandbox that cannot read $NETLAB_VAR at all (netlab.isolation).
"""

from __future__ import annotations

import asyncio
import contextlib
import io
import json
import os
import resource
import secrets
import shutil
import signal
import sys
import tempfile
import time
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from netlab.evaluate import EVALUATOR_VERSION, evaluate
from netlab.generate import choose_balanced_cell, generate, spec_digest
from netlab.history import degr
from netlab.isolation import wrap
from netlab.runtime.events import load_events
from netlab.runtime.lab import Lab, LabOptions
from netlab.schemas import AgentReport, GenerationConfig, RunResult, ScenarioSpec
from netlab.store import seal, unseal
from netlab.versions import component_versions

AGENT_ENV = (
    "PATH",
    "HOME",
    "LANG",
    "PYTHONPATH",
    "VIRTUAL_ENV",
    "DEVEXANA_URL",
    "DEVEXANA_USERNAME",
    "DEVEXANA_PASSWORD",
    "DEVEXANA_BACKEND_DIR",
    "DEVEXANA_SEED_LOCAL_MODEL_URL",
    "DEVEXANA_SEED_LOCAL_MODEL_NAME",
    "DEVEXANA_ALLOW_SHARED",
)
INCONCLUSIVE_EXIT = 3  # agent ran but produced no reasoning (e.g. no model): not scored as an investigation

CLIENTS: dict[str, list[str]] = {
    "reference": [sys.executable, "-m", "netlab.clients.reference"],
    "devexana": [sys.executable, "-m", "netlab.clients.devexana_os"],
}


def var_dir() -> Path:
    p = Path(os.environ.get("NETLAB_VAR", "var")).resolve()
    for sub in ("scenarios", "runs", "batches", "procs"):
        (p / sub).mkdir(parents=True, exist_ok=True)
    with contextlib.suppress(OSError):
        p.chmod(0o700)
    return p


def _write_private(path: Path, text: str) -> None:
    path.write_text(text)
    path.chmod(0o600)


# -- scenarios -------------------------------------------------------------------------------------------------------


def save_spec(spec: ScenarioSpec) -> Path:
    var = var_dir()
    return seal(var, var / "scenarios" / f"{spec.env_id}.json.enc", spec.model_dump_json(indent=1))


def load_spec(env_id: str) -> ScenarioSpec:
    var = var_dir()
    return ScenarioSpec.model_validate_json(unseal(var, var / "scenarios" / f"{env_id}.json.enc"))


def list_specs() -> list[ScenarioSpec]:
    var = var_dir()
    return [ScenarioSpec.model_validate_json(unseal(var, p)) for p in sorted((var / "scenarios").glob("*.json.enc"))]


def run_spec(run_id: str) -> ScenarioSpec:
    var = var_dir()
    return ScenarioSpec.model_validate_json(unseal(var, var / "runs" / run_id / "spec.json.enc"))


def has_result(run_dir: Path) -> bool:
    return (run_dir / "result.json.enc").exists()


def ledger() -> dict[str, int]:
    p = var_dir() / "coverage.json"
    return json.loads(p.read_text()) if p.exists() else {}


def shuffle(config: GenerationConfig | None = None) -> ScenarioSpec:
    """Generate a fresh environment from OS entropy and save it. Balanced mode targets the least-covered cell."""
    cfg = config or GenerationConfig()
    inputs: dict[str, Any] = {}
    seed = None
    if cfg.balanced:
        from netlab.generate import fresh_seed

        seed = fresh_seed()
        inputs = choose_balanced_cell(cfg, ledger(), seed)
    spec = generate(cfg, seed=seed, generation_inputs=inputs)
    if seed is not None:
        spec.seed_source = "os-entropy (secrets.randbits(64))"
    save_spec(spec)
    led = ledger()
    fault = "healthy" if not spec.faults else spec.faults[0].type
    degs = [d.type for d in spec.evidence.degradations] or ["none"]
    for f in [fault] if not spec.faults else [f.type for f in spec.faults]:
        for d in degs:
            led[f"{f}|{d}"] = led.get(f"{f}|{d}", 0) + 1
    (var_dir() / "coverage.json").write_text(json.dumps(led, indent=1, sort_keys=True))
    return spec


def replay_spec(spec: ScenarioSpec) -> dict[str, Any]:
    """Regenerate from (seed, config, inputs) and compare digests of spec and initial artifacts."""
    from netlab.artifacts import manifest, render_artifacts

    again = generate(spec.config, seed=spec.seed, generation_inputs=spec.generation_inputs)
    a1, a2 = manifest(render_artifacts(spec)[0]), manifest(render_artifacts(again)[0])
    return {
        "env_id": spec.env_id,
        "seed": spec.seed,
        "generator_version": spec.generator_version,
        "saved_sha256": spec.spec_sha256,
        "replayed_sha256": again.spec_sha256,
        "recomputed_saved_sha256": spec_digest(spec),
        "spec_identical": again.spec_sha256 == spec.spec_sha256 == spec_digest(spec),
        "artifacts_identical": a1 == a2,
        "artifact_manifest": a2,
    }


def public_summary(spec: ScenarioSpec) -> dict[str, Any]:
    """What the UI shows before a run: no faults, no degradations (they are revealed after the run)."""
    from netlab.generate import resource_estimate

    t = spec.topology
    return {
        "env_id": spec.env_id,
        "seed": str(spec.seed),
        "family": spec.family,
        "domain": t.domain,
        "sites": [s.code for s in t.sites],
        "devices": len(t.devices),
        "kinds": {
            k: sum(1 for d in t.devices.values() if d.kind == k) for k in sorted({d.kind for d in t.devices.values()})
        },
        "difficulty": spec.config.difficulty,
        "evidence_completeness": spec.config.evidence_completeness,
        "balanced": spec.config.balanced,
        "generator_version": spec.generator_version,
        "spec_sha256": spec.spec_sha256,
        "resource_estimate": resource_estimate(spec),
    }


def truth_view(spec: ScenarioSpec) -> dict[str, Any]:
    return {
        "env_id": spec.env_id,
        "seed": str(spec.seed),
        "interacting": spec.interacting,
        "faults": [
            {
                "id": f.id,
                "type": f.type,
                "component": f.component,
                "description": f.description,
                "symptom_flows": f.symptom_flows,
                "onset_minutes_before_start": round(f.onset_offset_s / 60),
            }
            for f in spec.faults
        ],
        "degradations": [
            {"id": d.id, "type": d.type, "description": d.description} for d in spec.evidence.degradations
        ],
        "distractors": [d.model_dump() for d in spec.distractors],
        "flows": [fl.model_dump() for fl in spec.topology.intended_flows + spec.topology.forbidden_flows],
    }


# -- runs ------------------------------------------------------------------------------------------------------------


def remediable_map(spec: ScenarioSpec, mode: str) -> dict[str, bool]:
    restricted = {t for g in degr(spec, "restricted_credentials") for t in g.targets}
    restricted |= {t for g in degr(spec, "mgmt_unreachable") for t in g.targets}  # no working management session
    out = {}
    for f in spec.faults:
        devs = {m.device for m in f.mutations if m.device} or {
            next(n for n, d in spec.topology.devices.items() if "dns" in d.services)
        }
        out[f.id] = mode == "remediation" and all(
            d not in restricted or spec.topology.devices[d].kind == "edge" for d in devs
        )
    return out


def _limits(cpu_s: int) -> Any:
    def apply() -> None:
        with contextlib.suppress(Exception):
            resource.setrlimit(resource.RLIMIT_CPU, (cpu_s, cpu_s + 5))
        with contextlib.suppress(Exception):
            resource.setrlimit(resource.RLIMIT_NOFILE, (512, 512))

    return apply


async def run_scenario(
    spec: ScenarioSpec,
    client: str = "reference",
    mode: str = "read_only",
    time_budget_s: int = 600,
    label: str | None = None,
    client_args: list[str] | None = None,
    on_start: Any = None,
    unreachable_delay_s: float = 2.0,
    allow_unisolated: bool = False,
) -> RunResult:
    """Start the lab, run the agent in a sandbox, evaluate, and ALWAYS release everything acquired.

    Cleanup is guaranteed across spawn failures, callback errors, cancellation, timeouts and evaluation errors:
    the agent's process group is killed and reaped, the log is closed, pid/temp state is removed and a started
    (or partially started) lab is stopped. An exception before a result exists persists an 'aborted' result."""
    run_id = f"run-{datetime.now(UTC).strftime('%Y%m%d-%H%M%S')}-{secrets.token_hex(3)}"
    var = var_dir()
    run_dir = var / "runs" / run_id
    run_dir.mkdir(mode=0o700)
    seal(var, run_dir / "spec.json.enc", spec.model_dump_json(indent=1))
    started = datetime.now(UTC).isoformat()
    lab: Any = None
    lab_stopped = False
    proc: asyncio.subprocess.Process | None = None
    log = None
    pidf: Path | None = None
    work: Path | None = None
    isolation = "not started"
    result: RunResult | None = None
    meta: dict[str, Any] = {
        "run_id": run_id,
        "env_id": spec.env_id,
        "client": client,
        "mode": mode,
        "started_at": started,
        "component_versions": component_versions(),
        "generator_version": spec.generator_version,
        "evaluator_version": EVALUATOR_VERSION,
        "time_budget_s": time_budget_s,
        "agent": {"name": client, "version": "unknown", **({"label": label} if label else {})},
    }
    try:
        lab = Lab(
            spec,
            run_dir,
            LabOptions(mode=mode, time_budget_s=time_budget_s, unreachable_delay_s=unreachable_delay_s),
            run_id=run_id,
        )
        handoff = await lab.start()
        if on_start:
            on_start(lab)
        work = Path(tempfile.mkdtemp(prefix="netlab-agent-"))
        _write_private(work / "handoff.json", handoff.model_dump_json(indent=1))
        base = CLIENTS.get(client, client.split())
        exe = shutil.which(base[0]) if base else None
        if exe is None:
            raise FileNotFoundError(f"agent executable not found: {base[0] if base else client!r}")
        cmd = [
            exe,
            *base[1:],
            "--handoff",
            str(work / "handoff.json"),
            "--out",
            str(work / "report.json"),
            *(client_args or []),
        ]
        cmd, isolation = wrap(cmd, [var], work, allow_unisolated)
        env = {k: v for k, v in os.environ.items() if k in AGENT_ENV}
        lab.events.add("control", "agent_started", detail={"client": client, "mode": mode, "isolation": isolation})
        t0 = time.monotonic()
        status = "completed"
        log = open(run_dir / "client.log", "wb")  # noqa: SIM115 - closed in finally below
        proc = await asyncio.create_subprocess_exec(
            *cmd, cwd=work, env=env, stdout=log, stderr=log, preexec_fn=_limits(time_budget_s), start_new_session=True
        )
        pidf = var / "procs" / str(proc.pid)
        pidf.write_text(run_id)
        try:
            rc = await asyncio.wait_for(proc.wait(), timeout=time_budget_s)
            if rc == INCONCLUSIVE_EXIT:
                status = "inconclusive"
            elif rc != 0:
                status = "agent_failed"
        except TimeoutError:
            status = "agent_timeout"
        agent_s = time.monotonic() - t0
        _kill_group(proc)
        await proc.wait()
        lab.events.add("control", "agent_finished", detail={"status": status, "seconds": round(agent_s, 2)})
        report: AgentReport | None = None
        if (work / "report.json").exists():
            try:
                report = AgentReport.model_validate_json((work / "report.json").read_text())
                shutil.copy(work / "report.json", run_dir / "report.json")
                if report.outcome == "inconclusive" and status == "completed":
                    status = "inconclusive"
            except ValueError as e:
                status = "agent_failed"
                (run_dir / "report_invalid.txt").write_text(f"{e}\n\n{(work / 'report.json').read_text()[:20000]}")
        elif status == "completed":
            status = "agent_failed"
        final_flows = await lab.check_all_flows()
        final_active = {f.id: lab.fault_active(f) for f in spec.faults}
        initial = dict(lab.initial_flows)
        teardown = await lab.stop()
        lab_stopped = True
        events = load_events(run_dir / "events.jsonl")
        ev = evaluate(
            spec,
            report,
            events,
            mode=mode,
            initial_flows=initial,
            final_flows=final_flows,
            final_active=final_active,
            agent_seconds=agent_s,
            budget_s=time_budget_s,
            status=status,
            remediable=remediable_map(spec, mode),
        )
        agent = dict(report.agent) if report else {"name": client, "version": "unknown"}
        if label:
            agent["label"] = label
        why = benchmark_ineligibility(status, isolation, agent)
        eligible = not why
        notes = [
            "Timing-dependent fields (timestamps, durations, collector poll alignment) are not "
            "reproducible across runs; scenario spec and initial artifacts are."
        ]
        if why:
            notes.append("NOT benchmark-eligible: " + "; ".join(why))
        if isolation.startswith("none"):
            notes.append("UNISOLATED cooperative-client run: the agent could have read evaluator state.")
        result = RunResult(
            run_id=run_id,
            env_id=spec.env_id,
            spec_sha256=spec.spec_sha256,
            agent=agent,
            mode=mode,
            started_at=started,
            finished_at=datetime.now(UTC).isoformat(),
            status=status,  # type: ignore[arg-type]
            measurements=ev["measurements"]
            | {"teardown": teardown, "isolation": isolation, "benchmark_eligible": eligible, "ineligible_reasons": why},
            scores=ev["scores"],
            overall=ev["overall"],
            expected_vs_observed=ev["expected_vs_observed"],
            notes=notes,
        )
        seal(var, run_dir / "result.json.enc", result.model_dump_json(indent=1))
        meta.update(agent=agent, status=status, isolation=isolation)
        return result
    except BaseException as e:
        meta.update(status="aborted", isolation=isolation, error=f"{type(e).__name__}: {e}")
        raise
    finally:
        if proc is not None:
            _kill_group(proc)
            with contextlib.suppress(Exception):
                await asyncio.wait_for(proc.wait(), timeout=5)
        if log is not None:
            log.close()
        if pidf is not None:
            pidf.unlink(missing_ok=True)
        if work is not None:
            shutil.rmtree(work, ignore_errors=True)
        if lab is not None and not lab_stopped:
            with contextlib.suppress(Exception):
                await lab.stop()
        if result is None:
            with contextlib.suppress(Exception):
                seal(
                    var,
                    run_dir / "result.json.enc",
                    RunResult(
                        run_id=run_id,
                        env_id=spec.env_id,
                        spec_sha256=spec.spec_sha256,
                        agent=meta["agent"],
                        mode=mode,
                        started_at=started,
                        finished_at=datetime.now(UTC).isoformat(),
                        status="aborted",
                        measurements={"error": meta.get("error", "aborted"), "isolation": isolation},
                        scores={},
                        overall=None,
                        expected_vs_observed=[],
                        notes=["Run aborted before evaluation."],
                    ).model_dump_json(indent=1),
                )
        with contextlib.suppress(Exception):
            (run_dir / "meta.json").write_text(json.dumps(meta, indent=1))


def benchmark_ineligibility(status: str, isolation: str, agent: dict[str, str]) -> list[str]:
    """Integrity reasons a run must not enter comparisons or batch means (empty list = eligible).

    Status is deliberately NOT a reason: a failed or timed-out agent keeps its zero score so regressions stay
    visible; inconclusive runs already carry no score."""
    why = []
    _ = status
    if not isolation.startswith(("sandbox-exec", "bwrap")):
        why.append("agent not sandboxed")
    if agent.get("appliance_isolation") == "shared":
        why.append("shared Devexana appliance: earlier runs' data was retrievable")
    return why


def _kill_group(proc: asyncio.subprocess.Process) -> None:
    """Kill the agent's whole process group (also children it left behind after the leader exited)."""
    with contextlib.suppress(ProcessLookupError, PermissionError):
        os.killpg(proc.pid, signal.SIGKILL)


def load_result(run_id: str) -> RunResult:
    var = var_dir()
    return RunResult.model_validate_json(unseal(var, var / "runs" / run_id / "result.json.enc"))


def list_runs() -> list[dict[str, Any]]:
    out = []
    for d in sorted((var_dir() / "runs").iterdir(), reverse=True):
        m = d / "meta.json"
        if m.exists():
            meta = json.loads(m.read_text())
            if has_result(d):
                with contextlib.suppress(Exception):
                    meta["overall"] = load_result(d.name).overall
            out.append(meta)
    return out


def export_run(run_id: str) -> bytes:
    """Zip of the run without credentials: handoff.json is excluded and any credential value is scrubbed."""
    d = var_dir() / "runs" / run_id
    secrets_vals: list[str] = []
    h = d / "handoff.json"
    if h.exists():
        hd = json.loads(h.read_text())
        secrets_vals = [
            hd["api_token"],
            hd["bastion"]["password"],
            hd["device_password"],
            hd["consoles"].get("password", ""),
        ]
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for p in sorted(d.iterdir()):
            if p.name == "handoff.json" or not p.is_file():
                continue
            name = p.name
            if name.endswith(".enc"):  # exports are for human reviewers: include the decrypted content
                txt, name = unseal(var_dir(), p), name.removesuffix(".enc")
            else:
                txt = p.read_text(errors="replace")
            for s in secrets_vals:
                if s:
                    txt = txt.replace(s, "[redacted]")
            z.writestr(f"{run_id}/{name}", txt)
    return buf.getvalue()


# -- batches / comparison ----------------------------------------------------------------------------------------------


async def run_batch(
    env_ids: list[str], client: str, mode: str, label: str | None = None, time_budget_s: int = 600, progress: Any = None
) -> dict[str, Any]:
    batch_id = f"batch-{datetime.now(UTC).strftime('%Y%m%d-%H%M%S')}-{secrets.token_hex(2)}"
    rows = []
    for k, e in enumerate(env_ids):
        r = await run_scenario(load_spec(e), client=client, mode=mode, label=label, time_budget_s=time_budget_s)
        ok = bool(r.measurements.get("benchmark_eligible"))
        rows.append(
            {
                "env_id": e,
                "run_id": r.run_id,
                "status": r.status,
                "overall": r.overall,
                "scores": r.scores,
                "benchmark_eligible": ok,
            }
        )
        if progress:
            progress(k + 1, len(env_ids), rows[-1])
    summary = {
        "batch_id": batch_id,
        "client": client,
        "mode": mode,
        "label": label,
        "runs": rows,
        "mean_overall": _mean([x["overall"] for x in rows if x["benchmark_eligible"]]),
        "eligible_runs": sum(1 for x in rows if x["benchmark_eligible"]),
        "mean_scores": {
            k: _mean([x["scores"].get(k) for x in rows if x["benchmark_eligible"]])
            for k in (rows[0]["scores"] if rows else {})
        },
    }
    (var_dir() / "batches" / f"{batch_id}.json").write_text(json.dumps(summary, indent=1))
    return summary


def _mean(xs: list[Any]) -> float | None:
    v = [x for x in xs if x is not None]
    return round(sum(v) / len(v), 4) if v else None


def compare(label_a: str, label_b: str, mode: str | None = None) -> dict[str, Any]:
    """Compare two agent versions/labels on the scenarios both have run (paired by env_id + spec hash)."""
    by: dict[str, dict[tuple[str, str], RunResult]] = {label_a: {}, label_b: {}}
    skipped_other_evaluator = 0
    skipped_ineligible = 0
    for d in (var_dir() / "runs").iterdir():
        if not has_result(d):
            continue
        r = load_result(d.name)
        if mode and r.mode != mode:
            continue
        if not r.measurements.get("benchmark_eligible"):
            skipped_ineligible += 1  # unisolated or shared-appliance runs
            continue
        if r.measurements.get("evaluator_version") != EVALUATOR_VERSION:
            skipped_other_evaluator += 1  # scores from another evaluator version are not comparable
            continue
        lab = r.agent.get("label") or f"{r.agent.get('name')}@{r.agent.get('version')}"
        if lab in by:
            by[lab][(r.env_id, r.spec_sha256)] = r
    common = sorted(set(by[label_a]) & set(by[label_b]))
    rows = [
        {
            "env_id": e,
            "a": by[label_a][(e, h)].overall,
            "b": by[label_b][(e, h)].overall,
            "delta": None
            if by[label_a][(e, h)].overall is None or by[label_b][(e, h)].overall is None
            else round(by[label_b][(e, h)].overall - by[label_a][(e, h)].overall, 4),
        }
        for e, h in common
    ]  # type: ignore[operator]
    return {
        "a": label_a,
        "b": label_b,
        "paired_scenarios": len(rows),
        "evaluator_version": EVALUATOR_VERSION,
        "skipped_results_from_other_evaluator_versions": skipped_other_evaluator,
        "skipped_ineligible_results": skipped_ineligible,
        "rows": rows,
        "mean_a": _mean([r["a"] for r in rows]),
        "mean_b": _mean([r["b"] for r in rows]),
        "b_better": sum(1 for r in rows if (r["delta"] or 0) > 0),
        "a_better": sum(1 for r in rows if (r["delta"] or 0) < 0),
    }


def teardown_stale() -> list[int]:
    """Kill client processes left behind by a crashed orchestrator. Lab sockets die with their process."""
    killed = []
    for p in (var_dir() / "procs").iterdir():
        try:
            pid = int(p.name)
            os.killpg(pid, signal.SIGKILL)
            killed.append(pid)
        except (ValueError, ProcessLookupError, PermissionError):
            pass
        p.unlink(missing_ok=True)
    return killed
