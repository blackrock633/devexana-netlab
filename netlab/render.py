"""Text renderers shared by device CLIs and config-backup artifacts (so both always agree for the same state)."""

from __future__ import annotations

from netlab.schemas import AclRule, Device
from netlab.world import World, addr, net


def hostname(d: Device) -> str:
    return d.hostname or d.name


NORMALIZED_OS = "netlab-normalized 1.0 (IOS-like CLI emulation)"


def software(d: Device) -> tuple[str, str]:
    """(inventory OS label, `show version` first line), identical on every surface.

    Only an IOS-like dialect is emulated. Cisco hardware reports IOS-XE; any other vendor's hardware is presented
    as running the lab's normalized emulator, so no surface implies vendor-specific (Junos/ArubaOS) fidelity.
    """
    if d.os == "linux":
        return "Ubuntu 22.04", "Linux 5.15.0-91-generic (Ubuntu 22.04)"
    if d.model.startswith("Cisco"):
        return "IOS-XE 17.9", f"Cisco IOS XE Software, Version 17.9.4 ({d.model})"
    return NORMALIZED_OS, f"netlab normalized network OS, Version 1.0 (IOS-like CLI emulation) on {d.model} hardware"


def acl_line(r: AclRule) -> str:
    s = f"{r.seq} {r.action} {r.proto} {r.src} {r.dst}"
    return s + (f" eq {r.dport}" if r.dport is not None else "")


def ios_config(w: World, d: Device, log_host: str = "") -> str:
    lines = ["!", f"hostname {hostname(d)}", f"ip domain-name {w.topo.domain}", "!"]
    for i in sorted(d.interfaces.values(), key=lambda x: (x.role == "svi", x.name)):
        if d.kind == "switch" and i.role in ("access", "uplink") and not i.peer and i.vlan == 1 and i.admin_up:
            continue  # unused default ports are not listed (as on real gear with default config)
        lines.append(f"interface {i.name}")
        if i.description:
            lines.append(f" description {i.description}")
        if i.ip:
            lines.append(f" ip address {i.ip}")
        if d.kind == "switch" and i.role in ("access", "uplink"):
            lines.append(f" switchport access vlan {i.vlan}")
        if i.name in d.acl_in:
            lines.append(f" ip access-group {d.acl_in[i.name]} in")
        if i.name in d.dhcp_helper:
            lines.append(f" ip helper-address {d.dhcp_helper[i.name]}")
        lines.append(" shutdown" if not i.admin_up else " no shutdown")
        lines.append("!")
    for r in d.routes:
        lines.append(f"ip route {r.prefix} {r.next_hop}")
    if d.gateway and d.kind == "switch":
        lines.append(f"ip default-gateway {d.gateway}")
    for name, rules in d.acls.items():
        lines.append("!")
        lines.append(f"ip access-list extended {name}")
        lines.extend(f" {acl_line(r)}" for r in sorted(rules, key=lambda x: x.seq))
    lines += [
        "!",
        "logging host " + (log_host or w.primary_ip(_nms(w)) or "0.0.0.0"),
        "line vty 0 4",
        " transport input ssh",
        "end",
    ]
    return "\n".join(lines) + "\n"


def _nms(w: World) -> str:
    return next((n for n, d in w.devices.items() if "collector" in d.services), "")


def ip_int_brief(w: World, d: Device) -> str:
    out = [f"{'Interface':<14}{'IP-Address':<18}{'OK?':<5}{'Method':<8}{'Status':<24}Protocol"]
    for i in sorted(d.interfaces.values(), key=lambda x: x.name):
        if d.kind == "switch" and i.role == "access" and not i.peer and i.admin_up:
            status = "down"
        elif not i.admin_up:
            status = "administratively down"
        else:
            status = "up" if w.link_up(d, i) else "down"
        proto = "up" if status == "up" else "down"
        ip = i.ip.split("/")[0] if i.ip else "unassigned"
        out.append(f"{i.name:<14}{ip:<18}{'YES':<5}{'manual':<8}{status:<24}{proto}")
    return "\n".join(out) + "\n"


def show_interface(w: World, d: Device, name: str) -> str | None:
    i = d.interfaces.get(name)
    if i is None:
        return None
    if not i.admin_up:
        st = "administratively down, line protocol is down"
    elif w.link_up(d, i):
        st = "up, line protocol is up"
    else:
        st = "down, line protocol is down"
    lines = [f"{i.name} is {st}"]
    if i.description:
        lines.append(f"  Description: {i.description}")
    if i.ip:
        lines.append(f"  Internet address is {i.ip}")
    if i.vlan is not None and d.kind == "switch":
        lines.append(f"  Access VLAN {i.vlan}")
    lines.append("  MTU 1500 bytes, BW 1000000 Kbit/sec")
    return "\n".join(lines) + "\n"


def ip_route(w: World, d: Device) -> str:
    out = ["Codes: C - connected, S - static", ""]
    rows = []
    for n, i in w.connected(d):
        rows.append((n, f"C    {n} is directly connected, {i.name}"))
    for r in d.routes:
        n = net(r.prefix)
        nh = addr(r.next_hop)
        if any(nh in cn for cn, _ in w.connected(d)):  # static routes with an unreachable next hop are not installed
            rows.append((n, f"S    {n} [1/0] via {r.next_hop}"))
    rows.sort(key=lambda x: (x[0].network_address, x[0].prefixlen))
    if any(r[0].prefixlen == 0 for r in rows):
        out.insert(1, f"Gateway of last resort is {next(r.next_hop for r in d.routes if r.prefix == '0.0.0.0/0')}")
    else:
        out.insert(1, "Gateway of last resort is not set")
    out += [r[1] for r in rows]
    return "\n".join(out) + "\n"


def access_lists(d: Device) -> str:
    out = []
    for name, rules in d.acls.items():
        out.append(f"Extended IP access list {name}")
        out.extend(f"    {acl_line(r)}" for r in sorted(rules, key=lambda x: x.seq))
    return "\n".join(out) + "\n" if out else "\n"


def switch_status(w: World, d: Device) -> str:
    out = [f"{'Port':<10}{'Name':<26}{'Status':<12}{'Vlan':<6}"]
    for i in sorted(
        (x for x in d.interfaces.values() if x.role in ("access", "uplink")), key=lambda x: int(x.name.split("/")[-1])
    ):
        if not i.admin_up:
            st = "disabled"
        elif i.peer and w.link_up(d, i):
            st = "connected"
        else:
            st = "notconnect"
        out.append(f"{i.name:<10}{i.description[:25]:<26}{st:<12}{i.vlan or 1:<6}")
    return "\n".join(out) + "\n"


def vlan_brief(d: Device) -> str:
    vl: dict[int, list[str]] = {}
    for i in d.interfaces.values():
        if i.role in ("access", "uplink"):
            vl.setdefault(i.vlan or 1, []).append(i.name)
    out = [f"{'VLAN':<6}Ports"]
    for v in sorted(vl):
        out.append(f"{v:<6}{', '.join(sorted(vl[v], key=lambda n: int(n.split('/')[-1])))}")
    return "\n".join(out) + "\n"
