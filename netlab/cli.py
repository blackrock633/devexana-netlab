"""netlab command line. Run ``netlab --help``."""

# ruff: noqa: E501  (long user-facing messages)

from __future__ import annotations

import argparse
import asyncio
import json
import os
import signal
import sys
from pathlib import Path

from netlab import orchestrate as orch
from netlab.schemas import AgentReport, GenerationConfig, Handoff, RunEvent, RunResult, ScenarioSpec


def _cfg(a: argparse.Namespace) -> GenerationConfig:
    base = json.loads(Path(a.config).read_text()) if getattr(a, "config", None) else {}
    cfg = GenerationConfig.model_validate(base)
    if getattr(a, "difficulty", None) is not None:
        cfg.difficulty = a.difficulty
    if getattr(a, "completeness", None) is not None:
        cfg.evidence_completeness = a.completeness
    if getattr(a, "balanced", False):
        cfg.balanced = True
    return cfg


def _print(obj: object) -> None:
    print(json.dumps(obj, indent=1, default=str))


def cmd_shuffle(a: argparse.Namespace) -> None:
    cfg = _cfg(a)
    for _ in range(a.count):
        _print(orch.public_summary(orch.shuffle(cfg)))


def cmd_scenarios(_a: argparse.Namespace) -> None:
    for s in orch.list_specs():
        print(
            f"{s.env_id}  seed={s.seed}  {s.family}  devices={len(s.topology.devices)}  "
            f"difficulty={s.config.difficulty} completeness={s.config.evidence_completeness}"
        )


def cmd_replay(a: argparse.Namespace) -> None:
    r = orch.replay_spec(orch.load_spec(a.env_id))
    r.pop("artifact_manifest")
    _print(r)
    sys.exit(0 if r["spec_identical"] and r["artifacts_identical"] else 1)


def _summ(r: RunResult) -> None:
    print(f"run {r.run_id}  scenario {r.env_id}  agent {r.agent}  mode {r.mode}  status {r.status}")
    print(f"overall {r.overall}")
    for k, v in r.scores.items():
        print(f"  {k:<16} {'n/a' if v is None else f'{v:.3f}'}")
    m = r.measurements
    print(
        f"  time {m['agent_seconds']}s  commands {m['commands']}  api {m['api_requests']}  "
        f"flows ok {m['intended_flows_ok_at_start']}->{m['intended_flows_ok_at_end']}/{m['intended_flows_total']}"
    )
    for row in r.expected_vs_observed:
        print(
            f"  {'PASS' if row['pass'] else 'FAIL'}  {row['item']}: expected {row['expected']}; observed {row['observed']}"
        )


def cmd_run(a: argparse.Namespace) -> None:
    spec = orch.load_spec(a.env_id)
    r = asyncio.run(orch.run_scenario(spec, client=a.client, mode=a.mode, label=a.label, time_budget_s=a.budget))
    _summ(r)


def cmd_batch(a: argparse.Namespace) -> None:
    envs = list(a.env or [])
    if a.all:
        envs += [s.env_id for s in orch.list_specs()]
    for _ in range(a.shuffle):
        envs.append(orch.shuffle(_cfg(a)).env_id)
    if not envs:
        sys.exit("no scenarios: use --env, --all or --shuffle N")
    s = asyncio.run(
        orch.run_batch(
            envs,
            a.client,
            a.mode,
            a.label,
            a.budget,
            progress=lambda k, n, row: print(
                f"[{k}/{n}] {row['env_id']} {row['status']} overall={row['overall']}", flush=True
            ),
        )
    )
    print(f"batch {s['batch_id']}: mean overall {s['mean_overall']}")
    _print(s["mean_scores"])


def cmd_compare(a: argparse.Namespace) -> None:
    _print(orch.compare(a.a, a.b, a.mode))


def cmd_reveal(a: argparse.Namespace) -> None:
    d = orch.var_dir() / "runs" / a.run_id
    if not orch.has_result(d):
        sys.exit("ground truth is revealed only after the run has finished")
    _print(orch.truth_view(orch.run_spec(a.run_id)))


def cmd_export(a: argparse.Namespace) -> None:
    out = Path(a.output or f"{a.run_id}.zip")
    out.write_bytes(orch.export_run(a.run_id))
    print(out)


def cmd_start(a: argparse.Namespace) -> None:
    """Run a lab in the foreground for manual exploration (Ctrl-C to tear down)."""
    from netlab.runtime.lab import Lab, LabOptions

    async def go() -> None:
        spec = orch.load_spec(a.env_id)
        d = orch.var_dir() / "runs" / f"manual-{spec.env_id}-{os.getpid()}"
        d.mkdir(mode=0o700, exist_ok=True)
        lab = Lab(spec, d, LabOptions(mode=a.mode))
        h = await lab.start()
        print(
            f"lab up: api {h.api_base}  bastion 127.0.0.1:{h.bastion['port']}  handoff {d / 'handoff.json'}", flush=True
        )
        stop = asyncio.Event()
        loop = asyncio.get_running_loop()
        for sig in (signal.SIGINT, signal.SIGTERM):
            loop.add_signal_handler(sig, stop.set)
        await stop.wait()
        print(json.dumps(await lab.stop()))

    asyncio.run(go())


def cmd_serve(a: argparse.Namespace) -> None:
    import secrets

    import uvicorn

    from netlab.control.server import create_app

    tok = secrets.token_urlsafe(24)
    p = orch.var_dir() / "operator.token"
    p.write_text(tok)
    p.chmod(0o600)
    print(f"netlab control: http://127.0.0.1:{a.port}/?token={tok}", flush=True)
    uvicorn.run(create_app(tok), host="127.0.0.1", port=a.port, log_level="warning")


def cmd_teardown(_a: argparse.Namespace) -> None:
    print(json.dumps({"killed_client_pids": orch.teardown_stale()}))


def cmd_schemas(a: argparse.Namespace) -> None:
    out = Path(a.output)
    out.mkdir(parents=True, exist_ok=True)
    for name, model in {
        "generation_config": GenerationConfig,
        "scenario_spec": ScenarioSpec,
        "handoff": Handoff,
        "run_event": RunEvent,
        "agent_report": AgentReport,
        "run_result": RunResult,
    }.items():
        (out / f"{name}.schema.json").write_text(json.dumps(model.model_json_schema(), indent=1) + "\n")
        print(out / f"{name}.schema.json")


def main() -> None:
    ap = argparse.ArgumentParser(prog="netlab", description="Randomized network testing lab for Devexana")
    sp = ap.add_subparsers(dest="cmd", required=True)

    def gen_opts(p: argparse.ArgumentParser) -> None:
        p.add_argument("--config", help="GenerationConfig JSON file (weights etc.)")
        p.add_argument("--difficulty", type=float)
        p.add_argument("--completeness", type=float, help="evidence completeness 0..1")
        p.add_argument("--balanced", action="store_true", help="balanced coverage mode")

    def run_opts(p: argparse.ArgumentParser) -> None:
        p.add_argument("--client", default="reference", help="reference | devexana | '<command>'")
        p.add_argument("--mode", default="read_only", choices=["read_only", "remediation"])
        p.add_argument("--label", help="version label used for comparisons")
        p.add_argument("--budget", type=int, default=600, help="time budget in seconds")

    p = sp.add_parser("shuffle", help="generate fresh environment(s) from OS entropy")
    gen_opts(p)
    p.add_argument("--count", type=int, default=1)
    p.set_defaults(fn=cmd_shuffle)
    sp.add_parser("scenarios", help="list saved scenarios").set_defaults(fn=cmd_scenarios)
    p = sp.add_parser("replay", help="regenerate a saved scenario from its seed and verify it is identical")
    p.add_argument("env_id")
    p.set_defaults(fn=cmd_replay)
    p = sp.add_parser("run", help="run an agent against a saved scenario and evaluate it")
    p.add_argument("env_id")
    run_opts(p)
    p.set_defaults(fn=cmd_run)
    p = sp.add_parser("batch", help="regression batch over saved/new scenarios")
    p.add_argument("--env", action="append")
    p.add_argument("--all", action="store_true")
    p.add_argument("--shuffle", type=int, default=0)
    gen_opts(p)
    run_opts(p)
    p.set_defaults(fn=cmd_batch)
    p = sp.add_parser("compare", help="compare two agent labels on paired scenarios")
    p.add_argument("a")
    p.add_argument("b")
    p.add_argument("--mode")
    p.set_defaults(fn=cmd_compare)
    p = sp.add_parser("reveal", help="show ground truth for a finished run")
    p.add_argument("run_id")
    p.set_defaults(fn=cmd_reveal)
    p = sp.add_parser("export", help="export a run as a zip without credentials")
    p.add_argument("run_id")
    p.add_argument("-o", "--output")
    p.set_defaults(fn=cmd_export)
    p = sp.add_parser("start", help="start a lab in the foreground for manual testing")
    p.add_argument("env_id")
    p.add_argument("--mode", default="read_only", choices=["read_only", "remediation"])
    p.set_defaults(fn=cmd_start)
    p = sp.add_parser("serve", help="operator UI")
    p.add_argument("--port", type=int, default=8780)
    p.set_defaults(fn=cmd_serve)
    sp.add_parser("teardown", help="kill client processes left by a crashed run").set_defaults(fn=cmd_teardown)
    p = sp.add_parser("schemas", help="write versioned JSON schemas")
    p.add_argument("-o", "--output", default="schemas")
    p.set_defaults(fn=cmd_schemas)
    a = ap.parse_args()
    a.fn(a)


if __name__ == "__main__":
    main()
