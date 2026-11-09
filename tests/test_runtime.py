"""Live runtime tests over real sockets: SSH via the bastion, the management API, service listeners, teardown."""

from __future__ import annotations

import asyncio
import contextlib

import asyncssh
import httpx
from conftest import healthy, only, run

from netlab.runtime.lab import Lab, LabOptions, port_open


@contextlib.asynccontextmanager
async def lab_ctx(spec, mode="remediation"):
    lab = Lab(spec, None, LabOptions(mode=mode, unreachable_delay_s=0.05, run_collector_loop=False))
    h = await lab.start()
    b = h.bastion
    bast = await asyncssh.connect(
        b["host"], port=b["port"], username=b["username"], password=b["password"], known_hosts=None
    )
    api = httpx.AsyncClient(base_url=h.api_base, headers={"Authorization": f"Bearer {h.api_token}"})
    try:
        yield lab, h, bast, api
    finally:
        bast.close()
        await api.aclose()
        await lab.stop()


async def sh(bast, h, target, cmd, console=False):
    user, pw = (h.consoles["username"], h.consoles["password"]) if console else (h.device_username, h.device_password)
    async with asyncssh.connect(
        f"{target}.console" if console else target, tunnel=bast, username=user, password=pw, known_hosts=None
    ) as c:
        return (await c.run(cmd, check=False)).stdout


def edge_of(spec, fault):
    return fault.mutations[0].device


async def advance(lab, seconds):
    """Move the lab clock forward deterministically (tests do not sleep for the collector)."""
    lab.t0 -= seconds
    lab.events.t0 -= seconds


def test_ssh_change_is_reflected_in_api_after_collection_delay_and_in_logs():
    spec = only("wan_interface_down")
    f = spec.faults[0]
    edge = edge_of(spec, f)

    async def go():
        async with lab_ctx(spec) as (lab, h, bast, api):
            target = (
                lab.world.primary_ip(edge)
                if edge == lab.ops or lab.world.path(lab.ops, lab.world.primary_ip(edge), "tcp", 22).ok
                else None
            )
            out = await sh(bast, h, target or edge, "show ip interface brief", console=target is None)
            assert "administratively down" in out
            name = lab.world.device(edge).hostname or edge
            before = (await api.get(f"/api/v1/devices/{name}/interfaces")).json()
            await sh(
                bast, h, target or edge, "configure terminal\ninterface Gi0/0\nno shutdown\nend", console=target is None
            )
            # Ground truth changed immediately; other CLIs see it immediately (no collection delay on live reads)
            assert lab.world.device(edge).interfaces["Gi0/0"].admin_up
            # The management API only shows it after the next poll plus the modelled collection delay.
            await lab.poll_once()
            mid = (await api.get(f"/api/v1/devices/{name}/interfaces")).json()
            assert mid["interfaces"] == before["interfaces"] or before["interfaces"] == []
            await advance(lab, spec.evidence.collection_delay_s + 0.1)
            after = (await api.get(f"/api/v1/devices/{name}/interfaces")).json()
            gi0 = next((i for i in after["interfaces"] if i["name"] == "Gi0/0"), None)
            assert gi0 and gi0["admin"] == "up"
            logs = (await api.get("/api/v1/logs", params={"q": "changed state to up"})).json()
            assert logs["count"] >= 1
            assert all(fl_ok for fl_ok in [(await lab.check_flow(fl))["ok"] for fl in spec.topology.intended_flows])

    run(go())


def test_service_restart_reopens_real_listener_and_check_recovers():
    spec = only("service_stopped")
    f = spec.faults[0]
    server, svc = f.mutations[0].device, f.mutations[0].args["service"]

    async def go():
        async with lab_ctx(spec) as (lab, h, bast, api):
            assert (await lab.services.fetch(server, svc))[0] is False  # really refused
            checks = {c["check"]: c for c in (await api.get("/api/v1/checks")).json()}
            assert checks[svc]["status"] == "failed"
            ip = lab.world.primary_ip(server)
            out = await sh(bast, h, ip, f"systemctl status {lab.world.device(server).services[svc].unit}")
            assert "failed" in out
            await sh(bast, h, ip, f"sudo systemctl restart {lab.world.device(server).services[svc].unit}")
            await asyncio.sleep(0.05)
            ok, banner = await lab.services.fetch(server, svc)
            assert ok and banner
            await lab.poll_once(visible_now=True)
            checks = {c["check"]: c for c in (await api.get("/api/v1/checks")).json()}
            assert checks[svc]["status"] == "ok"
            # data plane from the bastion through a real forwarded channel to the listener
            port = lab.world.device(server).services[svc].port
            r, w = await bast.open_connection(ip, port)
            w.write(b"GET / HTTP/1.0\r\n\r\n")
            data = await r.read(200)
            assert data

    run(go())


def test_dns_change_visible_from_other_hosts_immediately():
    spec = only("dns_record_stale")
    fq = spec.faults[0].mutations[0].args["name"]

    async def go():
        async with lab_ctx(spec) as (lab, h, bast, api):
            dns = next(n for n, d in lab.world.devices.items() if "dns" in d.services)
            good = lab.healthy.topo.dns_zone[fq]
            out = (await bast.run(f"nslookup {fq}", check=False)).stdout
            assert good not in out
            await sh(bast, h, lab.world.primary_ip(dns), f"sudo dns-record set {fq} {good}")
            out = (await bast.run(f"nslookup {fq}", check=False)).stdout
            assert good in out

    run(go())


def test_collector_outage_makes_branch_unknown_not_down():
    from conftest import find_spec

    spec = find_spec(
        lambda s: (
            not s.faults
            and any(
                d.type == "collector_outage" and d.params["end_s"] is None and d.targets[0].endswith(("mon-01", "mon1"))
                for d in s.evidence.degradations
            )
        )
    )

    async def go():
        async with lab_ctx(spec, mode="read_only") as (lab, h, bast, api):
            await advance(lab, 60)
            await lab.poll_once()
            await advance(lab, spec.evidence.collection_delay_s + 0.1)
            devs = {d["name"]: d for d in (await api.get("/api/v1/devices")).json()}
            br = spec.topology.sites[1].code
            br_devs = [d for d in devs.values() if d["site"] == br.upper()]
            assert br_devs and all(d["status"] == "unknown" for d in br_devs)
            hq_devs = [d for d in devs.values() if d["site"] == spec.topology.sites[0].code.upper() and d["mgmt_ip"]]
            assert all(d["status"] == "up" for d in hq_devs)
            # ...while the devices themselves are reachable over SSH (the evidence gap is in telemetry only)
            br_edge = next(n for n, d in spec.topology.devices.items() if d.kind == "edge" and d.site == br)
            if lab.access(br_edge) != "no_login" and not lab.mgmt_hung(br_edge):
                assert "Interface" in await sh(bast, h, lab.world.primary_ip(br_edge), "show ip interface brief")

    run(go())


def test_mgmt_unreachable_times_out_while_telemetry_says_up():
    from conftest import find_spec

    spec = find_spec(lambda s: any(d.type == "mgmt_unreachable" for d in s.evidence.degradations) and not s.faults)
    target = next(d for d in spec.evidence.degradations if d.type == "mgmt_unreachable").targets[0]

    async def go():
        async with lab_ctx(spec, mode="read_only") as (lab, h, bast, api):
            try:
                await sh(bast, h, lab.world.primary_ip(target), "hostname")
                raise AssertionError("expected timeout")
            except asyncssh.ChannelOpenError as e:
                assert "timed out" in e.reason.lower()
            name = lab.world.device(target).hostname or target
            devs = {d["name"]: d for d in (await api.get("/api/v1/devices")).json()}
            assert devs[name]["status"] == "up"

    run(go())


def test_read_only_mode_denies_changes_and_records_them():
    spec = healthy()

    async def go():
        async with lab_ctx(spec, mode="read_only") as (lab, h, bast, api):
            edge = next(
                n
                for n, d in spec.topology.devices.items()
                if d.kind == "edge" and lab.access(n) != "no_login" and not lab.mgmt_hung(n)
            )
            out = await sh(bast, h, lab.world.primary_ip(edge), "configure terminal")
            assert "Authorization failed" in out
            assert any(e.detail.get("denied") for e in lab.events.events)
            assert h.consoles["targets"] == []

    run(go())


def test_bad_credentials_rejected():
    spec = healthy()

    async def go():
        async with lab_ctx(spec) as (lab, h, bast, api):
            assert (
                await httpx.AsyncClient().get(h.api_base + "/api/v1/devices", headers={"Authorization": "Bearer nope"})
            ).status_code == 401
            try:
                await asyncssh.connect(
                    h.bastion["host"], port=h.bastion["port"], username="netops", password="wrong", known_hosts=None
                )
                raise AssertionError("login should fail")
            except asyncssh.PermissionDenied:
                pass

    run(go())


def test_teardown_closes_every_port_and_reset_restores_initial_state():
    spec = only("acl_blocks_service")

    async def go():
        lab = Lab(spec, None, LabOptions(mode="remediation", run_collector_loop=True, unreachable_delay_s=0.05))
        await lab.start()
        ports = lab.ports()
        snap0 = lab.world.snapshot()
        lab.world.apply(
            spec.faults[0]
            .mutations[0]
            .model_copy(
                update={
                    "op": "stop_service",
                    "device": next(n for n, d in spec.topology.devices.items() if "intranet" in d.services),
                    "args": {"service": "intranet"},
                }
            )
        )
        res = await lab.stop()
        assert res["ports_still_open"] == []
        for p in [ports["bastion"], ports["api"], *ports["services"]]:
            assert not port_open(p)
        lab2 = Lab(spec, None, LabOptions(mode="remediation", run_collector_loop=False))
        await lab2.start()
        assert lab2.world.snapshot() == snap0 and lab2.artifacts == lab.artifacts
        await lab2.stop()
        for _ in range(3):  # repeated cycles do not leak listeners
            lx = Lab(spec, None, LabOptions(run_collector_loop=False))
            await lx.start()
            assert (await lx.stop())["ports_still_open"] == []

    run(go())
