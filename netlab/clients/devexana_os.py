"""Devexana OS client: drives a running Devexana appliance against the lab through Devexana's own HTTP API.

Integration points used (all verified to exist in devexana-os @ 59fe083 by reading the source; the live run against
an appliance is NOT verified in this repository, see docs/DEVEXANA_INTEGRATION.md):

  files/logs   inventory.csv -> csv_inventory integration (POST /integrations, /integrations/{id}/import/upload)
               config backups, syslog history, tickets -> knowledge documents (POST /knowledge/documents)
  HTTP API     the lab's PRTG-compatible /api/table.json -> Devexana's prtg integration (POST /integrations/{id}/sync)
  agent        Deo triage (POST /agents/{id}/runs) with the lab task text
  probe        Deo's network.check_reachability tool reaches lab addresses only if they are routable from the
               appliance; the lab's addresses are emulated, so this tool is expected to fail (documented gap)
  SSH/commands Devexana has no SSH or command-execution capability: not exercised (documented gap)
  remediation  Devexana only changes infrastructure through adapter write capabilities after approval; there is
               no adapter for lab devices, so remediation runs report no actions (documented gap)

Deo's result (summary, facts with evidence keys, hypotheses, next_steps, insufficient_evidence) is translated into
the lab's AgentReport by explicit keyword/name rules in ``translate`` (no model). The translation is lossy: a
correct diagnosis phrased unusually may be missed. Set DEVEXANA_URL, DEVEXANA_USERNAME, DEVEXANA_PASSWORD.
"""

from __future__ import annotations

import argparse
import contextlib
import csv
import io
import os
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

import httpx

from netlab.schemas import AgentReport, Handoff, ReportDevice, ReportFinding, ReportUnknown

NAME = "devexana-os"
CSRF = {"X-Devexana-Request": "1"}
CLASS_RULES: list[tuple[str, str]] = [
    (r"administratively down|shut ?down|interface .* down|link .* down|port .* disabled", "interface_down"),
    (r"\bvlan\b", "l2_misconfiguration"),
    (r"access[- ]list|\bacl\b|firewall|denied|blocked", "firewall_block"),
    (r"\broute\b|routing|no route|next[- ]hop", "routing"),
    (r"\bdns\b|resolv|a record|nxdomain|stale address", "dns_misconfiguration"),
    (
        r"service\b.*\b(stopped|down|failed)\b|\bnot running\b|\binactive\b|\bexited\b|\bkilled\b|failed with result",
        "service_down",
    ),
]
STATUS_MAP = {"up": "healthy", "down": "failed", "degraded": "degraded", "unknown": "unknown", "paused": "unknown"}


def classify(text: str) -> str | None:
    t = text.lower()
    for pat, cls in CLASS_RULES:
        if re.search(pat, t):
            return cls
    return None


def mentioned(text: str, names: list[str]) -> str | None:
    t = text.lower()
    hits = [n for n in names if re.search(rf"(?<![\w-]){re.escape(n.lower())}(?![\w-])", t)]
    return max(hits, key=len) if hits else None


INCONCLUSIVE_EXIT = 3  # must match netlab.orchestrate.INCONCLUSIVE_EXIT


def translate(
    result: dict[str, Any] | None,
    plan: list[dict[str, Any]],
    names: list[str],
    entities: list[dict[str, Any]],
    include_hypotheses: bool = False,
) -> AgentReport:
    """Deterministic Deo-result -> AgentReport translation (unit-tested in tests/test_devexana_translate.py).

    No result (model unavailable, failed run) is INCONCLUSIVE: never translated into a health claim. An affirmative
    ``healthy_overall`` requires a result with at least one evidence-backed fact, no findings and no
    insufficient-evidence flag."""
    errors = [
        f"tool {p.get('tool')}: {p.get('status')}"
        for p in plan
        if p.get("kind") == "tool_call" and p.get("status") not in ("ok", "succeeded")
    ][:50]
    if not result:
        return AgentReport(
            agent={"name": NAME, "version": "unknown"},
            summary="Devexana produced no investigation result.",
            outcome="inconclusive",
            healthy_overall=None,
            unknowns=[ReportUnknown(component="network", reason="no reasoning output from Devexana")],
            errors=errors + ["missing Deo result"],
        )
    res = result
    findings: list[ReportFinding] = []
    items = [(f.get("text", ""), f.get("evidence", []), 0.7) for f in res.get("facts", [])]
    if include_hypotheses:
        items += [(h.get("text", "") if isinstance(h, dict) else str(h), [], 0.3) for h in res.get("hypotheses", [])]
    for text, ev, conf in items:
        cls = classify(text)
        comp = mentioned(text, names)
        fq = re.search(r"\b([a-z0-9-]+\.[a-z0-9.-]+\.example)\b", text.lower())
        if cls == "dns_misconfiguration" and fq:
            comp = f"dns:{fq.group(1)}"
        if cls and comp:
            findings.append(
                ReportFinding(
                    component=comp,
                    fault_class=cls,
                    statement=text[:500],
                    evidence=[str(e) for e in ev],
                    confidence=conf,
                )
            )
    devices = []
    status: dict[str, str] = {}
    for e in entities:
        if e.get("type") != "device":
            continue
        a = e.get("attributes") or {}
        devices.append(ReportDevice(name=e["name"], ip=a.get("mgmt_ip") or a.get("ip"), kind=a.get("role")))
        if e.get("status") in STATUS_MAP:
            status[e["name"]] = STATUS_MAP[e["status"]]
    unknowns = [
        ReportUnknown(component=n, reason="Devexana records show no current status")
        for n, s in status.items()
        if s == "unknown"
    ]
    if res.get("insufficient_evidence"):
        unknowns.append(ReportUnknown(component="network", reason="Devexana reported insufficient evidence"))
    supported_facts = any(f.get("evidence") for f in res.get("facts", []))
    healthy = None
    if not res.get("insufficient_evidence"):
        healthy = False if findings else (True if supported_facts else None)
    return AgentReport(
        agent={"name": NAME, "version": "unknown"},
        summary=str(res.get("summary", ""))[:2000],
        healthy_overall=healthy,
        devices=devices,
        component_status=status,
        findings=findings,
        unknowns=unknowns,
        errors=errors,
    )


def _run_scoped(entity: dict[str, Any], tag: str) -> bool:
    """Was this entity produced by one of THIS run's integrations? (data source name = integration name)"""
    prov = entity.get("provenance") or {}
    return str(prov.get("data_source_name") or "").startswith(f"netlab {tag} ")


class Devexana:
    def __init__(self, url: str, username: str, password: str):
        self.c = httpx.Client(base_url=url.rstrip("/") + "/api/v1", headers=CSRF, timeout=900)
        self.c.post("/auth/login", json={"username": username, "password": password}).raise_for_status()

    def version(self) -> str:
        try:
            v = self.c.get("/system/version").json()
            return f"{v.get('app_version', 'unknown')}+schema{v.get('schema_revision', '?')}"
        except (httpx.HTTPError, ValueError):
            return "unknown"

    def integration(self, kind: str, name: str, config: dict[str, Any], credentials: dict[str, str] | None) -> str:
        r = self.c.post(
            "/integrations",
            json={
                "kind": kind,
                "name": name,
                "config": config,
                **({"credentials": credentials} if credentials else {}),
            },
        )
        r.raise_for_status()
        return str(r.json()["id"])


def _wait_sync(dx: Any, integration_id: str, job_id: str | None, timeout_s: float = 180) -> str:
    """Poll the sync job to completion instead of sleeping a fixed time. Returns the outcome."""
    if not job_id:
        return "no job"
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        for j in dx.c.get(f"/integrations/{integration_id}/syncs", params={"limit": 20}).json():
            if j.get("job_id") == job_id and j.get("job_status") in ("succeeded", "failed"):
                return str(j.get("outcome") or j.get("job_status"))
        time.sleep(0.5)
    return "timeout"


def _entities(dx: Any, tag: str, page: int = 500, max_pages: int = 50) -> list[dict[str, Any]]:
    """All device entities produced by this run's integrations (paginated, provenance-filtered)."""
    out: list[dict[str, Any]] = []
    seen: set[str] = set()
    for k in range(max_pages):
        data = dx.c.get("/inventory/entities", params={"type": "device", "limit": page, "offset": k * page}).json()
        items = data.get("items", []) if isinstance(data, dict) else data
        new = [e for e in items if (e.get("id") or e.get("name")) not in seen]
        seen |= {e.get("id") or e.get("name") for e in items}
        out += [e for e in new if _run_scoped(e, tag)]
        total = data.get("total") if isinstance(data, dict) else None
        if len(items) < page or not new or (total is not None and (k + 1) * page >= total):
            break
    return out


def run(h: Any, include_hypotheses: bool, created: dict[str, list[str]] | None = None) -> AgentReport:
    """Ingest the lab into Devexana (scoped to this run), run Deo, translate. ``created`` collects the ids of
    integrations and knowledge documents this run made, so the caller can clean up a shared appliance."""
    created = created if created is not None else {"integrations": [], "documents": []}
    url, user, pw = (os.environ.get(k, "") for k in ("DEVEXANA_URL", "DEVEXANA_USERNAME", "DEVEXANA_PASSWORD"))
    if not (url and user and pw):
        raise SystemExit("DEVEXANA_URL / DEVEXANA_USERNAME / DEVEXANA_PASSWORD are not set")
    lab = httpx.Client(base_url=h.api_base, headers={"Authorization": f"Bearer {h.api_token}"}, timeout=30)
    arts = {a["path"]: lab.get(f"/api/v1/artifacts/{a['path']}").text for a in lab.get("/api/v1/artifacts").json()}
    dx = Devexana(url, user, pw)
    tag = h.run_id
    inv_id = dx.integration(
        "csv_inventory", f"netlab {tag} inventory", {"format": "csv", "complete_snapshot": True}, None
    )
    created["integrations"].append(inv_id)
    # The upload import runs its sync synchronously on the appliance.
    dx.c.post(
        f"/integrations/{inv_id}/import/upload",
        files={"file": ("inventory.csv", arts.get("inventory.csv", "").encode(), "text/csv")},
    ).raise_for_status()
    prtg_id = dx.integration(
        "prtg", f"netlab {tag} monitoring", {"base_url": h.api_base, "verify_tls": False}, {"apitoken": h.api_token}
    )
    created["integrations"].append(prtg_id)
    r = dx.c.post(f"/integrations/{prtg_id}/sync")
    r.raise_for_status()
    sync_outcome = _wait_sync(dx, prtg_id, (r.json() or {}).get("job_id") if r.json() is not None else None)
    for path, body in arts.items():
        if path.startswith("configs/"):
            kind, title = "config_snapshot", f"Config backup {path.removeprefix('configs/')}"
        elif path.endswith(".log"):
            kind, title = "document", "Syslog history (central collector)"
        elif path == "tickets.json":
            kind, title = "ticket", "Open helpdesk tickets"
        else:
            continue
        d = dx.c.post(
            "/knowledge/documents",
            json={
                "kind": kind,
                "title": f"[netlab {tag}] {title}",
                "body": body[:200000],
                "attributes": {"netlab_run": tag},
            },
        )
        d.raise_for_status()
        doc_id = (d.json() or {}).get("id") if d.json() is not None else None
        if doc_id:
            created["documents"].append(str(doc_id))
    agents = dx.c.get("/agents").json()
    agents = agents["items"] if isinstance(agents, dict) else agents
    deo = next(a for a in agents if a["name"] == "Deo triage")
    run_out = dx.c.post(f"/agents/{deo['id']}/runs", json={"task": h.task, "wait": True}).json()
    ents = _entities(dx, tag)
    names = sorted(
        {row["AssetName"] for row in csv.DictReader(io.StringIO(arts.get("inventory.csv", "")))}
        | {e["name"] for e in ents}
    )
    ok = run_out.get("status") == "succeeded" and bool(run_out.get("result"))
    rep = translate(run_out.get("result") if ok else None, run_out.get("plan", []), names, ents, include_hypotheses)
    if not ok:
        rep.outcome = "inconclusive"
        rep.devices = [ReportDevice(name=e["name"]) for e in ents]  # what ingestion produced, provenance-scoped
        rep.errors.append(f"Deo run status {run_out.get('status')}: {run_out.get('error')}")
    rep.agent = {"name": NAME, "version": dx.version()}
    rep.errors.append(f"monitoring sync outcome: {sync_outcome}")
    rep.errors += ["Devexana has no SSH/command-execution interface: device sessions were not exercised."]
    if h.mode == "remediation":
        rep.errors.append("No Devexana write adapter exists for lab devices: remediation was not attempted.")
    return rep


def cleanup_shared(dx: Devexana, created: dict[str, list[str]]) -> list[str]:
    """Best-effort cleanup on a shared appliance: delete this run's documents, disable its integrations.
    Devexana has no integration DELETE, so their entities remain (visible to later Deo retrieval): use a
    disposable appliance (DEVEXANA_BACKEND_DIR) for isolated runs."""
    notes = []
    for doc in created["documents"]:
        try:
            dx.c.delete(f"/knowledge/documents/{doc}").raise_for_status()
        except httpx.HTTPError as e:
            notes.append(f"document {doc} not deleted: {e}")
    for iid in created["integrations"]:
        try:
            dx.c.patch(f"/integrations/{iid}", json={"enabled": False}).raise_for_status()
        except httpx.HTTPError as e:
            notes.append(f"integration {iid} not disabled: {e}")
    return notes


@contextlib.contextmanager
def disposable_appliance(backend: str, boot_timeout_s: float = 120) -> Any:
    """A fresh Devexana appliance (own data directory/database) for exactly one run, destroyed afterwards."""
    data = Path(tempfile.mkdtemp(prefix="netlab-dx-"))
    proc = None
    log = None
    try:  # everything after the directory exists is inside the cleanup scope
        with socket.socket() as s:
            s.bind(("127.0.0.1", 0))
            port = s.getsockname()[1]
        pw = secrets.token_urlsafe(18)
        env = {**os.environ, "DEVEXANA_DATA_DIR": str(data), "DEVEXANA_PORT": str(port)}
        for k in ("DEVEXANA_URL", "DEVEXANA_USERNAME", "DEVEXANA_PASSWORD", "VIRTUAL_ENV"):
            env.pop(k, None)
        uv = shutil.which("uv")
        if uv is None:
            raise RuntimeError("uv is required to start a disposable Devexana appliance")
        subprocess.run(  # noqa: S603 - fixed argv
            [uv, "run", "devexana", "create-admin", "--username", "netlab", "--password-stdin"],
            cwd=backend,
            env=env,
            input=pw + "\n",
            text=True,
            check=True,
            capture_output=True,
            timeout=300,
        )
        log = open(data / "serve.log", "wb")  # noqa: SIM115 - closed with the process below
        proc = subprocess.Popen(  # noqa: S603 - fixed argv
            [uv, "run", "devexana", "serve"], cwd=backend, env=env, stdout=log, stderr=log, start_new_session=True
        )
        url = f"http://127.0.0.1:{port}"
        deadline = time.monotonic() + boot_timeout_s
        while True:
            try:
                if httpx.get(url + "/api/v1/health/live", timeout=1).status_code == 200:
                    break
            except httpx.HTTPError:
                pass
            if proc.poll() is not None or time.monotonic() > deadline:
                raise RuntimeError(f"disposable appliance did not start (see {data / 'serve.log'})")
            time.sleep(0.5)
        yield url, "netlab", pw
    finally:
        if proc is not None:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(proc.pid, signal.SIGTERM)
            try:
                proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(proc.pid, signal.SIGKILL)
                proc.wait()
        if log is not None:
            log.close()
        shutil.rmtree(data, ignore_errors=True)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--handoff", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--hypotheses-as-findings", action="store_true")
    a = ap.parse_args()
    with open(a.handoff) as fh:
        h = Handoff.model_validate_json(fh.read())
    backend = os.environ.get("DEVEXANA_BACKEND_DIR")
    created: dict[str, list[str]] = {"integrations": [], "documents": []}
    if backend:
        with disposable_appliance(backend) as (url, user, pw):
            os.environ.update(DEVEXANA_URL=url, DEVEXANA_USERNAME=user, DEVEXANA_PASSWORD=pw)
            rep = run(h, a.hypotheses_as_findings, created)
        rep.agent["appliance_isolation"] = "disposable"
        rep.errors.append("appliance isolation: disposable (fresh data directory, destroyed after the run)")
    elif os.environ.get("DEVEXANA_ALLOW_SHARED") != "1":
        raise SystemExit(
            "Isolated benchmarking requires a disposable appliance: set DEVEXANA_BACKEND_DIR to a devexana-os "
            "backend checkout. A shared appliance (DEVEXANA_URL) keeps entities from earlier runs that Deo can "
            "retrieve; set DEVEXANA_ALLOW_SHARED=1 to run anyway (the result is excluded from benchmarks)."
        )
    else:
        try:
            rep = run(h, a.hypotheses_as_findings, created)
        finally:
            url, user, pw = (os.environ[k] for k in ("DEVEXANA_URL", "DEVEXANA_USERNAME", "DEVEXANA_PASSWORD"))
            notes = cleanup_shared(Devexana(url, user, pw), created)
        rep.agent["appliance_isolation"] = "shared"
        rep.errors += notes + [
            "appliance isolation: SHARED appliance; inventory in this report is run-scoped, but "
            "entities from earlier runs remain visible to Deo retrieval"
        ]
    with open(a.out, "w") as f:
        f.write(rep.model_dump_json(indent=1))
    sys.exit(INCONCLUSIVE_EXIT if rep.outcome == "inconclusive" else 0)


if __name__ == "__main__":
    main()
