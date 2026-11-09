"""Deterministic pre-start history and the causal evidence-collection model.

The same functions decide, for history (t < 0) and for the live runtime (t >= 0), whether an observation reaches
the central management system:

* every monitored device has an assigned collector (HQ NMS, or the branch collector which relays over the WAN);
* a log line or poll result is collected only if the forwarding plane at that moment carries it
  (device -> collector udp/514, collector -> NMS tcp/8443) and no modelled collector outage covers that moment;
* central-side degradations (log gaps, duplicates, delays) are applied after collection; device clock skew is
  applied at the source, so it affects both device-local logs and centrally collected copies.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from netlab.schemas import Degradation, ScenarioSpec
from netlab.world import World


@dataclass
class LogEvent:
    t: float  # lab-relative seconds (negative = before lab start)
    device: str
    msg: str
    reveals: tuple[str, ...] = ()  # fault ids whose cause this line shows
    symptoms: tuple[str, ...] = ()  # fault ids whose symptom this line shows
    meta: dict = field(default_factory=dict)


def lab_time(spec: ScenarioSpec, t: float) -> datetime:
    return datetime.fromisoformat(spec.timeline.lab_start) + timedelta(seconds=t)


def fmt_ts(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def degr(spec: ScenarioSpec, kind: str) -> list[Degradation]:
    return [d for d in spec.evidence.degradations if d.type == kind]


def skew_of(spec: ScenarioSpec, device: str) -> float:
    return float(sum(d.params["skew_s"] for d in degr(spec, "clock_skew") if device in d.targets))


def collector_down(spec: ScenarioSpec, collector: str, t: float) -> bool:
    for d in degr(spec, "collector_outage"):
        if collector in d.targets and t >= d.params["start_s"] and (d.params["end_s"] is None or t < d.params["end_s"]):
            return True
    return False


def nms_name(spec: ScenarioSpec) -> str:
    return next(n for n, d in spec.topology.devices.items() if "collector" in d.services)


def world_at(spec: ScenarioSpec, t: float) -> World:
    w = World(spec.topology)
    for f in spec.faults:
        if t >= -f.onset_offset_s:
            for m in f.mutations:
                w.apply(m)
    return w


def delivered(spec: ScenarioSpec, w: World, device: str, t: float, kind: str = "syslog") -> bool:
    """Would an observation produced by ``device`` at lab time ``t`` reach the NMS (given world state ``w``)?"""
    nms = nms_name(spec)
    c = spec.evidence.collector_of.get(device)
    if c is None or collector_down(spec, nms, t):
        return False
    if c != nms:
        if collector_down(spec, c, t):
            return False
        if device != c and not w.path(device, w.primary_ip(c) or "", "udp", 514).ok:
            return False
        return w.path(c, w.primary_ip(nms) or "", "tcp", 8443).ok
    if device == nms:
        return True
    return w.path(device, w.primary_ip(nms) or "", "udp", 514).ok


def in_log_gap(spec: ScenarioSpec, device: str, t: float) -> bool:
    """A modelled central log gap (e.g. collector-side buffer loss) covers this device at lab time t."""
    for g in degr(spec, "log_gap"):
        end = g.params.get("end_s")
        if device in g.targets and g.params["start_s"] <= t and (end is None or t < end):
            return True
    return False


def centrally_collected(spec: ScenarioSpec, w: World, device: str, t: float) -> bool:
    """Single collection policy for syslog, shared by history and the live runtime: causal delivery + log gaps.
    Device-local logs are never affected; only the central copy."""
    return delivered(spec, w, device, t) and not in_log_gap(spec, device, t)


def poll_reaches(spec: ScenarioSpec, w: World, device: str, t: float) -> bool | None:
    """Collector poll of ``device``: True (answers), False (no answer), None (result never reaches the NMS)."""
    nms = nms_name(spec)
    c = spec.evidence.collector_of.get(device)
    if c is None or collector_down(spec, nms, t) or collector_down(spec, c, t):
        return None
    if c != nms and not w.path(c, w.primary_ip(nms) or "", "tcp", 8443).ok:
        return None
    if device == c:
        return True
    return w.path(c, w.primary_ip(device) or "", "icmp").ok


# ---------------------------------------------------------------------------------------------------------------
# History generation
# ---------------------------------------------------------------------------------------------------------------

_IOS_NOISE = [
    "%SEC_LOGIN-5-LOGIN_SUCCESS: Login Success [user: netadmin] [Source: {ops}] [localport: 22]",
    "%SYS-6-LOGGINGHOST_STARTSTOP: Logging to host {log} port 514 started - CLI initiated",
    "%SSH-5-SSH2_SESSION: SSH2 Session request from {ops} (tty = 0) using crypto cipher 'aes256-ctr', succeeded",
    "%SYS-5-CONFIG_I: Configured from console by netadmin on vty0 ({ops})",
]
_LINUX_NOISE = [
    "CRON[{pid}]: (root) CMD (run-parts --report /etc/cron.hourly)",
    "systemd[1]: logrotate.service: Succeeded.",
    "sshd[{pid}]: Accepted publickey for backup from {ops} port {port} ssh2",
    "systemd[1]: Started Daily apt download activities.",
]


def history(spec: ScenarioSpec) -> list[LogEvent]:
    """All log events produced by devices during the history window (device-local truth, before collection)."""
    rng = random.Random(spec.seed ^ 0x4C06)
    t0 = -spec.timeline.history_window_s
    topo = spec.topology
    w0 = World(topo)
    ops = next(n for n, d in topo.devices.items() if d.kind == "ops")
    ops_ip = w0.primary_ip(ops) or ""
    evs: list[LogEvent] = []
    infra = [n for n, d in sorted(topo.devices.items()) if d.kind in ("edge", "switch", "server", "probe")]
    for n in infra:
        d = topo.devices[n]
        log_host = w0.primary_ip(spec.evidence.collector_of.get(n, ops)) or ""
        t = t0 + rng.uniform(60, 1800)
        while t < 0:
            pool = _IOS_NOISE if d.os == "ios" else _LINUX_NOISE
            msg = rng.choice(pool).format(
                ops=ops_ip, log=log_host, pid=rng.randint(900, 32000), port=rng.randint(40000, 60000)
            )
            evs.append(LogEvent(t, n, msg))
            if "dns" in d.services and rng.random() < 0.5:
                ws = rng.choice(sorted(topo.dhcp_leases))
                evs.append(
                    LogEvent(
                        t + 3, n, f"dnsmasq-dhcp[812]: DHCPACK(eth0) {topo.dhcp_leases[ws]} {topo.devices[ws].mac} {ws}"
                    )
                )
            t += rng.uniform(900, 2700)
    # Periodic collector heartbeats on the branch probe (local journal shows upload success/failure).
    mon = next((n for n, d in topo.devices.items() if d.kind == "probe"), None)
    nms = nms_name(spec)
    if mon:
        t = t0 + 30.0
        while t < 0:
            w = world_at(spec, t)
            ok = w.path(mon, w.primary_ip(nms) or "", "tcp", 8443).ok and not collector_down(spec, mon, t)
            sym = tuple(f.id for f in spec.faults if t >= -f.onset_offset_s) if not ok else ()
            if collector_down(spec, mon, t):
                msg = None
            elif ok:
                msg = f"nms-agent[1422]: upload ok ({rng.randint(180, 260)} metrics)"
            else:
                msg = f"nms-agent[1422]: upload to {nms}:8443 failed: connection timed out"
            if msg:
                evs.append(LogEvent(t, mon, msg, symptoms=sym))
            t += 300.0
    # Fault onsets.
    for f in spec.faults:
        t = -float(f.onset_offset_s)
        for m in f.mutations:
            dev = m.device
            if m.op == "set_iface_admin" and dev:
                peer = topo.devices[dev].interfaces[m.args["iface"]].peer or ""
                evs.append(
                    LogEvent(t - 2, dev, f"%SYS-5-CONFIG_I: Configured from console by netadmin on vty0 ({ops_ip})")
                )
                evs.append(
                    LogEvent(
                        t,
                        dev,
                        f"%LINK-5-CHANGED: Interface {m.args['iface']}, changed state to administratively down",
                        reveals=(f.id,),
                    )
                )
                evs.append(
                    LogEvent(
                        t + 1,
                        dev,
                        f"%LINEPROTO-5-UPDOWN: Line protocol on Interface {m.args['iface']}, changed state to down",
                        reveals=(f.id,),
                    )
                )
                pd, _, pi = peer.partition(":")
                if pd:
                    evs.append(
                        LogEvent(t + 1, pd, f"%LINK-3-UPDOWN: Interface {pi}, changed state to down", symptoms=(f.id,))
                    )
            elif m.op in ("remove_route", "remove_acl_rule", "set_port_vlan") and dev:
                evs.append(LogEvent(t, dev, f"%SYS-5-CONFIG_I: Configured from console by netadmin on vty0 ({ops_ip})"))
            elif m.op == "insert_acl_rule" and dev:
                evs.append(LogEvent(t, dev, f"%SYS-5-CONFIG_I: Configured from console by netadmin on vty0 ({ops_ip})"))
                r = m.args["rule"]
                br_ws = sorted(
                    n for n, d in topo.devices.items() if d.kind == "workstation" and d.site != topo.devices[dev].site
                )
                tt = t + rng.uniform(120, 600)
                while tt < 0 and br_ws:
                    src = topo.dhcp_leases[rng.choice(br_ws)]
                    evs.append(
                        LogEvent(
                            tt,
                            dev,
                            f"%SEC-6-IPACCESSLOGP: list {m.args['acl']} denied tcp {src}"
                            f"({rng.randint(49152, 65000)}) -> {r['dst'].split('/')[0]}({r['dport']}), "
                            "1 packet",
                            reveals=(f.id,),
                        )
                    )
                    tt += rng.uniform(300, 1500)
            elif m.op == "stop_service" and dev:
                unit = topo.devices[dev].services[m.args["service"]].unit
                evs.append(
                    LogEvent(
                        t,
                        dev,
                        f"systemd[1]: {unit}.service: Main process exited, code=killed, status=9/KILL",
                        reveals=(f.id,),
                    )
                )
                evs.append(
                    LogEvent(t + 0.2, dev, f"systemd[1]: {unit}.service: Failed with result 'signal'.", reveals=(f.id,))
                )
            elif m.op == "set_dns_record":
                dns = next(n for n, d in topo.devices.items() if "dns" in d.services)
                evs.append(LogEvent(t, dns, f"dnsmasq[812]: read /etc/dnsmasq.hosts - {len(topo.dns_zone)} addresses"))
    # Benign noise that looks like the above (so its presence alone never implies a fault).
    for _ in range(rng.randint(1, 3)):
        n = rng.choice([x for x in infra if topo.devices[x].os == "ios"])
        evs.append(
            LogEvent(
                rng.uniform(t0, -60), n, f"%SYS-5-CONFIG_I: Configured from console by netadmin on vty0 ({ops_ip})"
            )
        )
    dns = next(n for n, d in topo.devices.items() if "dns" in d.services)
    evs.append(
        LogEvent(rng.uniform(t0, -60), dns, f"dnsmasq[812]: read /etc/dnsmasq.hosts - {len(topo.dns_zone)} addresses")
    )
    for ds in spec.distractors:
        tt = rng.uniform(t0, -120)
        if ds.kind == "unused_port_flap":
            sw, _, p = ds.target.partition(":")
            for k in range(rng.randint(2, 5)):
                evs.append(LogEvent(tt + k * 37, sw, f"%LINK-3-UPDOWN: Interface {p}, changed state to down"))
                evs.append(LogEvent(tt + k * 37 + 9, sw, f"%LINK-3-UPDOWN: Interface {p}, changed state to up"))
        elif ds.kind == "cpu_spike":
            msg = (
                "%SYS-3-CPUHOG: Task is running for (2004)msecs, more than (2000)msecs (0/0),process = Exec"
                if topo.devices[ds.target].os == "ios"
                else "kernel: INFO: task jbd2/sda1-8:312 blocked for more than 120 seconds."
            )
            evs.append(LogEvent(tt, ds.target, msg))
    evs.sort(key=lambda e: (e.t, e.device, e.msg))
    return [e for e in evs if e.t >= t0]


def central_history(spec: ScenarioSpec, evs: list[LogEvent] | None = None) -> list[tuple[str, LogEvent]]:
    """History as the NMS collected it: (timestamp text, event). Applies causality, gaps, skew and duplicates."""
    evs = history(spec) if evs is None else evs
    rng = random.Random(spec.seed ^ 0xC011)
    onsets = sorted({-float(f.onset_offset_s) for f in spec.faults})
    worlds = {o: world_at(spec, o) for o in onsets}
    base = world_at(spec, -spec.timeline.history_window_s - 1)
    dup_rate = sum(float(d.params.get("duplicate_rate", 0)) for d in degr(spec, "duplicate_delayed_telemetry"))
    out: list[tuple[str, LogEvent]] = []
    for e in evs:
        active = [o for o in onsets if o <= e.t]
        w = worlds[active[-1]] if active else base
        if not centrally_collected(spec, w, e.device, e.t):
            continue
        ts = fmt_ts(lab_time(spec, e.t + skew_of(spec, e.device)))
        out.append((ts, e))
        if dup_rate and rng.random() < dup_rate:
            out.append((ts, e))
    return out


def format_line(spec: ScenarioSpec, ts: str, e: LogEvent) -> str:
    d = spec.topology.devices[e.device]
    return f"{ts} {d.hostname or d.name} {e.msg}"
