"""Agent-facing management API (an NMS-like service). Everything it returns comes from the collector's view of the
world (delayed, possibly stale or missing), never directly from ground truth.

Endpoints are listed in docs/ADAPTER_CONTRACT.md. ``/api/table.json`` is shaped like PRTG's table API so that
Devexana's existing ``prtg`` integration can sync from the lab without code changes.
"""

from __future__ import annotations

import asyncio
import contextlib
import hmac
import socket
import time
from typing import TYPE_CHECKING, Any

import uvicorn
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse, PlainTextResponse, Response

from netlab.history import fmt_ts, lab_time

if TYPE_CHECKING:
    from netlab.runtime.lab import Lab

RATE_PER_S = 40
PRTG_STATUS = {"up": (3, "Up"), "down": (5, "Down"), "unknown": (1, "Unknown")}


def build_app(lab: Lab) -> FastAPI:
    app = FastAPI(title="Site management API", docs_url=None, redoc_url=None, openapi_url=None)
    bucket = {"t": time.monotonic(), "n": 0}

    def names() -> dict[str, str]:
        """NMS display name per device (the configured hostname: may differ from DNS / inventory)."""
        return {n: (d.hostname or n) for n, d in lab.world.devices.items() if n in lab.spec.evidence.collector_of}

    def by_display(name: str) -> str | None:
        for n, disp in names().items():
            if name in (n, disp):
                return n
        return None

    def authorized(request: Request) -> bool:
        tok = request.query_params.get("apitoken") or ""
        h = request.headers.get("authorization", "")
        if h.lower().startswith("bearer "):
            tok = h[7:]
        return bool(tok) and hmac.compare_digest(tok, lab.creds["api_token"])

    @app.middleware("http")
    async def record(request: Request, call_next: Any) -> Response:
        request.state.reveals = []
        request.state.symptoms = []
        request.state.observed = []  # devices whose current (non-unknown) telemetry this response carried
        request.state.check_samples = []  # evaluator-only provenance of each current check result returned
        now = time.monotonic()
        if now - bucket["t"] >= 1:
            bucket["t"], bucket["n"] = now, 0
        bucket["n"] += 1
        path = request.url.path
        params = {k: v for k, v in request.query_params.items() if k != "apitoken"}
        if not authorized(request):
            resp: Response = JSONResponse({"error": "unauthorized"}, status_code=401)
        elif bucket["n"] > RATE_PER_S:
            resp = JSONResponse({"error": "rate limited"}, status_code=429)
        elif lab.counters["api"] >= lab.opts.max_api_requests:
            resp = JSONResponse({"error": "request budget exhausted"}, status_code=429)
        else:
            lab.counters["api"] += 1
            resp = await call_next(request)
        lab.events.add(
            "api",
            "request",
            actor="api-token",
            target=path,
            ok=resp.status_code < 400,
            detail={
                "method": request.method,
                "path": path,
                "params": params,
                "status": resp.status_code,
                **({"observed_devices": sorted(set(request.state.observed))} if request.state.observed else {}),
                **({"check_samples": request.state.check_samples} if request.state.check_samples else {}),
            },
            reveals=request.state.reveals,
            symptoms=request.state.symptoms,
        )
        return resp

    def ts(t: float | None) -> str | None:
        return fmt_ts(lab_time(lab.spec, t)) if t is not None else None

    @app.get("/api/v1/devices")
    def devices(request: Request) -> list[dict[str, Any]]:
        out = []
        for n, disp in sorted(names().items(), key=lambda kv: kv[1]):
            v = lab.device_view(n)
            last = v["last"]
            if v["status"] != "unknown":
                request.state.observed.append(n)
            out.append(
                {
                    "name": disp,
                    "mgmt_ip": lab.world.primary_ip(n),
                    "site": lab.world.device(n).site.upper(),
                    "type": lab.world.device(n).kind,
                    "status": v["status"],
                    "last_polled": ts(last.t) if last else None,
                    "collector": names().get(lab.spec.evidence.collector_of[n], lab.spec.evidence.collector_of[n]),
                }
            )
        for r in lab.spec.topology.retired_devices:
            out.append(
                {
                    "name": r,
                    "mgmt_ip": None,
                    "site": lab.spec.topology.sites[0].code.upper(),
                    "type": "printer",
                    "status": "down",
                    "last_polled": ts(-86400 * 120.0),
                    "collector": names().get(lab.nms),
                }
            )
        return out

    @app.get("/api/v1/devices/{name}/interfaces")
    def interfaces(name: str, request: Request) -> dict[str, Any]:
        n = by_display(name)
        if n is None:
            raise HTTPException(404, "unknown device")
        vis = [o for o in lab.obs.get(n, []) if o.visible_at <= lab.now() and o.interfaces is not None]
        if not vis:
            return {"device": name, "interfaces": [], "observed_at": None, "note": "no interface data collected"}
        o = vis[-1]
        request.state.reveals += o.reveals
        if lab.device_view(n)["status"] != "unknown":
            request.state.observed.append(n)
        return {
            "device": name,
            "observed_at": ts(o.t),
            "interfaces": [{"name": k, **v} for k, v in sorted(o.interfaces.items())],
        }  # type: ignore[union-attr]

    @app.get("/api/v1/checks")
    def checks(request: Request) -> list[dict[str, Any]]:
        out = []
        stale = lab.spec.evidence.stale_after_polls * lab.spec.evidence.poll_interval_s
        specs = {c[0]: c for c in lab.service_checks()}
        for cid, rows in sorted(lab.checks.items()):
            vis = [r for r in rows if r[1] <= lab.now()]
            if not vis or lab.now() - vis[-1][0] > stale + lab.spec.evidence.collection_delay_s:
                out.append(
                    {
                        "check": cid,
                        "status": "unknown",
                        "last_checked": ts(vis[-1][0]) if vis else None,
                        "message": "no recent result",
                    }
                )
                continue
            t, _, st, msg, sym = vis[-1]
            request.state.symptoms += sym
            spec = specs.get(cid)
            request.state.check_samples.append(
                {
                    "check": cid,
                    "status": st,
                    "quality": "current",
                    "collected_t": t,
                    "vantage": lab.nms,
                    **({"dst_device": spec[1], "proto": spec[2], "port": spec[3], "by_name": spec[4]} if spec else {}),
                }
            )
            out.append({"check": cid, "status": st, "last_checked": ts(t), "message": msg})
        return out

    @app.get("/api/v1/alerts")
    def alerts(request: Request) -> list[dict[str, Any]]:
        out = []
        for d in devices(request):
            if d["status"] in ("down", "unknown"):
                out.append(
                    {
                        "severity": "critical" if d["status"] == "down" else "warning",
                        "object": d["name"],
                        "message": f"Device {d['status']}",
                        "since": d["last_polled"],
                    }
                )
        for c in checks(request):
            if c["status"] != "ok":
                out.append(
                    {
                        "severity": "critical" if c["status"] == "failed" else "warning",
                        "object": c["check"],
                        "message": f"Service check {c['status']}: {c['message']}",
                        "since": c["last_checked"],
                    }
                )
        return out

    @app.get("/api/v1/logs")
    def logs(
        request: Request,
        device: str | None = None,
        q: str | None = None,
        since: str | None = None,
        until: str | None = None,
        limit: int = Query(default=500, ge=1, le=5000),
    ) -> dict[str, Any]:
        n = by_display(device) if device else None
        rows = []
        for c in lab.central_lines():
            if device and c.device != n and (lab.world.device(c.device).hostname or c.device) != device:
                continue
            if q and q.lower() not in c.msg.lower():
                continue
            if since and c.ts < since:
                continue
            if until and c.ts > until:
                continue
            rows.append(c)
        rows = rows[-limit:]
        for c in rows:
            request.state.reveals += [
                r for r in c.reveals if any(f.id == r and lab.fault_active(f) for f in lab.spec.faults)
            ]
            request.state.symptoms += list(c.symptoms)
        return {
            "count": len(rows),
            "lines": [f"{c.ts} {lab.world.device(c.device).hostname or c.device} {c.msg}" for c in rows],
        }

    @app.get("/api/v1/artifacts")
    def artifacts() -> list[dict[str, Any]]:
        return [{"path": p, "bytes": len(b)} for p, b in sorted(lab.artifacts.items())]

    @app.get("/api/v1/artifacts/{path:path}")
    def artifact(path: str, request: Request) -> Response:
        if path not in lab.artifacts:
            raise HTTPException(404, "no such artifact")
        info = lab.artifact_info.get(path, {})
        request.state.reveals += [
            r for r in info.get("reveals", []) if any(f.id == r and lab.fault_active(f) for f in lab.spec.faults)
        ]
        request.state.symptoms += info.get("symptoms", [])
        media = "text/csv" if path.endswith(".csv") else "application/json" if path.endswith(".json") else "text/plain"
        return PlainTextResponse(lab.artifacts[path].decode(), media_type=media)

    @app.get("/api/table.json")
    def prtg_table(request: Request, content: str = "devices", count: int = 2500) -> dict[str, Any]:
        devs = devices(request)
        if content == "devices":
            rows = []
            for k, d in enumerate(devs):
                raw, txt = PRTG_STATUS.get(d["status"], (1, "Unknown"))
                rows.append(
                    {
                        "objid": 2000 + k,
                        "device": d["name"],
                        "host": d["mgmt_ip"] or "",
                        "group": d["site"],
                        "probe": d["collector"],
                        "status": txt,
                        "statusraw": raw,
                        "message": "",
                        "lastup": d["last_polled"] if d["status"] == "up" else "",
                        "lastdown": "",
                    }
                )
            return {"devices": rows[:count]}
        if content == "sensors":
            rows = []
            for k, d in enumerate(devs):
                raw, txt = PRTG_STATUS.get(d["status"], (1, "Unknown"))
                rows.append(
                    {
                        "objid": 5000 + k,
                        "sensor": "Ping",
                        "device": d["name"],
                        "parentid": 2000 + k,
                        "status": txt,
                        "statusraw": raw,
                        "lastvalue": "",
                        "message": "",
                    }
                )
            nms_idx = next((k for k, d in enumerate(devs) if d["name"] == names().get(lab.nms)), 0)
            for j, c in enumerate(checks(request)):
                raw, txt = {"ok": (3, "Up"), "failed": (5, "Down")}.get(c["status"], (1, "Unknown"))
                rows.append(
                    {
                        "objid": 6000 + j,
                        "sensor": f"Service {c['check']}",
                        "device": devs[nms_idx]["name"],
                        "parentid": 2000 + nms_idx,
                        "status": txt,
                        "statusraw": raw,
                        "lastvalue": "",
                        "message": c["message"],
                    }
                )
            return {"sensors": rows[:count]}
        raise HTTPException(400, "unsupported content")

    return app


class ApiServer:
    def __init__(self, server: uvicorn.Server, task: asyncio.Task, port: int):
        self.server, self.task, self.port = server, task, port

    async def stop(self) -> None:
        self.server.should_exit = True
        with contextlib.suppress(Exception):
            await asyncio.wait_for(self.task, timeout=5)


async def serve_api(lab: Lab) -> ApiServer:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    cfg = uvicorn.Config(build_app(lab), log_level="warning", access_log=False, lifespan="off")
    server = uvicorn.Server(cfg)
    task = asyncio.create_task(server.serve(sockets=[sock]))
    for _ in range(200):
        if server.started:
            break
        await asyncio.sleep(0.01)
    return ApiServer(server, task, port)
