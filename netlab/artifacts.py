"""Initial downloadable artifacts, rendered deterministically from the scenario spec.

Artifacts are what an operations team would hand an investigator: an asset inventory export (Lansweeper-style
CSV that Devexana's ``csv_inventory`` integration can import as-is), nightly config backups, a topology diagram,
the centrally collected syslog history and helpdesk tickets. Each may be incomplete, stale or inconsistent
according to the evidence policy. Filenames are fixed and never depend on faults.

Returns the files plus an evaluator-only map of which fault causes each artifact reveals.
"""

from __future__ import annotations

import csv
import hashlib
import io
import json
import random
from datetime import timedelta
from typing import Any

from netlab.generate import VENDORS
from netlab.history import central_history, degr, fmt_ts, format_line, lab_time, world_at
from netlab.render import ios_config, software
from netlab.schemas import ScenarioSpec
from netlab.world import World

ASSET_TYPES = {
    "edge": "Router / Firewall",
    "switch": "Switch",
    "server": "Server",
    "workstation": "Workstation",
    "probe": "Monitoring probe",
    "ops": "Workstation",
}
TICKET_TEXT = {
    "intranet": ["Intranet page will not load from {site}", "Can't reach the intranet since this morning"],
    "files": ["Shared drive (files) not opening at {site}", "Mapped drive disconnected, can't save documents"],
    "dns": ["Websites and internal names not loading at {site}", "Everything says 'server not found'"],
}


def config_backups(spec: ScenarioSpec) -> tuple[dict[str, str], dict[str, list[str]]]:
    out: dict[str, str] = {}
    reveals: dict[str, list[str]] = {}
    stale = {t: g.params["age_days"] for g in degr(spec, "stale_config_backup") for t in g.targets}
    for n, d in sorted(spec.topology.devices.items()):
        if d.os != "ios":
            continue
        t = -float(stale[n]) * 86400 if n in stale else -float(spec.timeline.backup_offset_s)
        w = world_at(spec, t)
        path = f"configs/{n}.cfg"
        header = f"! Configuration backup of {d.hostname or n} taken {fmt_ts(lab_time(spec, t))} by nightly job\n"
        out[path] = header + ios_config(w, w.device(n), log_host=_log_host(spec, w, n))
        reveals[path] = [
            f.id for f in spec.faults if t >= -f.onset_offset_s and any(m.device == n for m in f.mutations)
        ]
    return out, reveals


def _log_host(spec: ScenarioSpec, w: World, n: str) -> str:
    c = spec.evidence.collector_of.get(n)
    return (w.primary_ip(c) if c else None) or "0.0.0.0"


def inventory_csv(spec: ScenarioSpec) -> str:
    rng = random.Random(spec.seed ^ 0x1A7E)
    inc = degr(spec, "incomplete_inventory")
    omit = {t for g in inc for t in g.targets}
    renamed = {t for g in inc for t in g.params.get("renamed", [])}
    w = World(spec.topology)
    buf = io.StringIO()
    cols = [
        "AssetName",
        "AssetType",
        "IPAddress",
        "MACAddress",
        "Manufacturer",
        "Model",
        "SerialNumber",
        "Site",
        "OS",
        "LastSeen",
    ]
    wr = csv.writer(buf, lineterminator="\n")
    wr.writerow(cols)
    rows = []
    for n, d in sorted(spec.topology.devices.items()):
        if n in omit:
            continue
        vendor, model = next(
            ((v, d.model[len(v) + 1 :]) for vs in VENDORS.values() for v, _ in vs if d.model.startswith(v + " ")),
            ("", d.model),
        )
        os_name = software(d)[0]
        last = lab_time(spec, -rng.uniform(600, 86400 * 2))
        rows.append(
            [
                d.aliases[-1] if n in renamed else n,
                ASSET_TYPES[d.kind],
                w.primary_ip(n) or "",
                d.mac,
                vendor,
                model,
                d.serial,
                d.site.upper(),
                os_name,
                last.strftime("%Y-%m-%d %H:%M:%S"),
            ]
        )
    for n in spec.topology.retired_devices:
        rows.append(
            [
                n,
                "Printer",
                "",
                "",
                "HP",
                "LaserJet M507",
                f"SN{rng.randint(100000, 999999)}",
                spec.topology.sites[0].code.upper(),
                "",
                (lab_time(spec, -86400 * rng.randint(90, 400))).strftime("%Y-%m-%d %H:%M:%S"),
            ]
        )
    rows.sort(key=lambda r: r[0].lower())
    wr.writerows(rows)
    return buf.getvalue()


def diagram(spec: ScenarioSpec) -> str:
    sd = degr(spec, "stale_diagram")
    omit = {t for g in sd for t in g.targets}
    age = max([g.params["age_days"] for g in sd] or [spec.timeline.diagram_age_days])
    topo = spec.topology
    rev = (lab_time(spec, 0) - timedelta(days=age)).strftime("%Y-%m-%d")
    lines = [f"%% Network diagram, revision {rev} (exported from drawing tool)", "graph LR"]
    seen: set[tuple[str, str]] = set()
    ws_count: dict[str, int] = {}
    for n, d in sorted(topo.devices.items()):
        if n in omit:
            continue
        if d.kind == "workstation":
            ws_count[d.site] = ws_count.get(d.site, 0) + 1
            continue
        ip = World(topo).primary_ip(n) or ""
        lines.append(f'  {n.replace("-", "_")}["{n}<br/>{ip}"]')
    for site, c in sorted(ws_count.items()):
        lines.append(f'  {site}_ws["{site.upper()} workstations x{c}"]')
    for n, d in sorted(topo.devices.items()):
        if n in omit:
            continue
        for i in d.interfaces.values():
            if not i.peer:
                continue
            pd = i.peer.split(":")[0]
            if pd in omit:
                continue
            a = n if d.kind != "workstation" else f"{d.site}_ws"
            b = pd if topo.devices[pd].kind != "workstation" else f"{topo.devices[pd].site}_ws"
            key = tuple(sorted((a, b)))
            if a != b and key not in seen:
                seen.add(key)  # type: ignore[arg-type]
                lines.append(f"  {a.replace('-', '_')} --- {b.replace('-', '_')}")
    return "\n".join(lines) + "\n"


def tickets(spec: ScenarioSpec) -> tuple[list[dict[str, Any]], list[str]]:
    rng = random.Random(spec.seed ^ 0x71C7)
    flows = {f.id: f for f in spec.topology.intended_flows}
    out: list[dict[str, Any]] = []
    sym_faults: list[str] = []
    drop = (1 - spec.evidence.completeness) * 0.5
    n = 4100 + rng.randint(0, 800)
    for f in spec.faults:
        for fid in f.symptom_flows:
            fl = flows[fid]
            if fl.service not in TICKET_TEXT or rng.random() < drop:
                continue
            site = spec.topology.devices[fl.src].site
            opened = -rng.uniform(60, max(120, f.onset_offset_s - 30))
            n += rng.randint(1, 9)
            out.append(
                {
                    "id": f"INC{n}",
                    "opened": fmt_ts(lab_time(spec, opened)),
                    "status": "open",
                    "requester_site": site.upper(),
                    "subject": rng.choice(TICKET_TEXT[fl.service]).format(site=site.upper()),
                    "body": "User reports the problem started recently. No further details.",
                }
            )
            sym_faults.append(f.id)
    if not spec.faults and rng.random() < 0.4:
        n += rng.randint(1, 9)
        out.append(
            {
                "id": f"INC{n}",
                "opened": fmt_ts(lab_time(spec, -rng.uniform(600, 7200))),
                "status": "open",
                "requester_site": spec.topology.sites[1].code.upper(),
                "subject": rng.choice(["Intranet felt slow this morning", "Printer queue stuck"]),
                "body": "Seems fine now, logging for reference.",
            }
        )
    for d in spec.distractors:
        if d.kind == "old_ticket":
            n += rng.randint(1, 9)
            out.append(
                {
                    "id": f"INC{n - 900}",
                    "opened": fmt_ts(lab_time(spec, -86400 * rng.randint(20, 90))),
                    "status": "open",
                    "requester_site": spec.topology.sites[0].code.upper(),
                    "subject": "Wi-Fi drops in conference room",
                    "body": "Closed by phone, ticket never updated.",
                }
            )
    out.sort(key=lambda x: x["opened"])
    # dedupe identical subjects (several flows of one fault)
    seen, uniq = set(), []
    for t in out:
        if t["subject"] not in seen:
            seen.add(t["subject"])
            uniq.append(t)
    return uniq, sorted(set(sym_faults))


def render_artifacts(spec: ScenarioSpec) -> tuple[dict[str, bytes], dict[str, dict[str, list[str]]]]:
    files: dict[str, bytes] = {}
    info: dict[str, dict[str, list[str]]] = {}
    cfgs, cfg_rev = config_backups(spec)
    for p, txt in cfgs.items():
        files[p] = txt.encode()
        info[p] = {"reveals": cfg_rev[p], "symptoms": []}
    files["inventory.csv"] = inventory_csv(spec).encode()
    info["inventory.csv"] = {"reveals": [], "symptoms": []}
    files["topology.mmd"] = diagram(spec).encode()
    info["topology.mmd"] = {"reveals": [], "symptoms": []}
    hist = central_history(spec)
    files["logs/syslog-history.log"] = ("\n".join(format_line(spec, ts, e) for ts, e in hist) + "\n").encode()
    info["logs/syslog-history.log"] = {
        "reveals": sorted({r for _, e in hist for r in e.reveals}),
        "symptoms": sorted({r for _, e in hist for r in e.symptoms}),
    }
    tk, sym = tickets(spec)
    files["tickets.json"] = (json.dumps(tk, indent=1) + "\n").encode()
    info["tickets.json"] = {"reveals": [], "symptoms": sym}
    return dict(sorted(files.items())), info


def manifest(files: dict[str, bytes]) -> dict[str, str]:
    return {p: hashlib.sha256(b).hexdigest() for p, b in sorted(files.items())}
