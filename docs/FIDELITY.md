# Fidelity: what is real, emulated or fixture

| Element | How it is produced | Fidelity notes |
|---|---|---|
| SSH (bastion, device sessions, OOB consoles) | **Real** asyncssh servers. Device servers run on socketpairs behind the bastion's direct-tcpip | Real auth, host keys, exec and shell, ProxyJump. Device CLIs are emulations of IOS-like and Linux-like shells, not real OSes |
| Management HTTP API | **Real** FastAPI server on 127.0.0.1 | NMS-like. The PRTG table API shape matches what Devexana's adapter expects; not a full PRTG |
| Application services | **Real** TCP listeners, closed when stopped and reopened on restart | Speak a minimal HTTP/1.0 or banner. "https" is plain TCP (no TLS); SMB is a banner only. Health = validated response (status + service identity), not just a connection; listeners can be made to serve an application failure (`ServiceHost.set_response`) |
| Network OS | One **IOS-like** CLI dialect | Cisco hardware reports IOS-XE 17.9. Other vendors' hardware (Juniper, Aruba) is consistently reported, in the inventory and in `show version`, as running the lab's *normalized* IOS-like emulator. No surface claims Junos or ArubaOS fidelity |
| Forwarding (switching, routing, firewall) | **Emulated** deterministic path evaluator | L2 segment by switch and VLAN; longest-prefix match over connected and static routes; static routes are installed only if the next hop is connected and up; inbound first-match ACLs; stateful return (no ACL on replies) with return-path routing. No MTU, queuing, ARP timing, TCP state, NAT, IPv6 or dynamic routing |
| DNS | **Emulated** resolver over the zone, reached through the forwarding plane (udp/53) | No real UDP server; no caching or TTLs |
| DHCP | **Emulated** lease table plus a relay (`ip helper-address`) in configs | No DHCP protocol; leases are fixed at generation |
| Telemetry | **Emulated** collector polling the world every 5 s | Causal: poll results and syslog are delivered only along working paths (device → collector udp/514, branch collector → NMS tcp/8443) and only outside modelled outages. History and live logs share one collection policy (`history.centrally_collected`), so log gaps also apply to live logs; device-local logs are never affected |
| Initial artifacts and history | **Fixtures** rendered deterministically from the spec | Config backups come from the world at backup time (so they may predate a fault); history logs follow the same causal delivery |
| Clocks | Lab time = synthetic `lab_start` + elapsed wall time; device skew applied at the source | — |

## Why emulation instead of containers or network namespaces

The development host is macOS with no Docker, Podman or Colima, and network namespaces are Linux-only.
Installing a container runtime would need the user's decision and several GB of disk; the host had about 5 GB
free. The runtime is therefore an unprivileged single process. A Linux backend (netns + veth + iproute2/nftables
+ dnsmasq) could implement the same `World` contract. That is future work: it is not implemented and was not
tested here.

## Non-reproducible runtime behaviour

Recorded, but not reproducible across runs:

- event wall-clock timestamps and `t_rel_s`
- when collector polls fall relative to agent actions, and therefore exactly when a change shows up in the API
- network and SSH timing, and the order of concurrent agent actions
- per-run credentials and host keys
- random duplication of live syslog lines (history duplication is seeded and does reproduce)
