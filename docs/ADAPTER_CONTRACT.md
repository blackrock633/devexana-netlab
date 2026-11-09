# Adapter contract (agent under test ⇄ lab)

Any agent can be tested without changing the generator, runtime or evaluator. It needs to:

1. accept `--handoff <path> --out <path>` (extra arguments can be passed through `client_args`);
2. read the `Handoff` JSON (schema `schemas/handoff.schema.json`, version 1.0);
3. investigate, and in `remediation` mode fix, using only the interfaces listed below;
4. write an `AgentReport` JSON (schema `schemas/agent_report.schema.json`, version 1.0) and exit 0.

Register it in `orchestrate.CLIENTS`, or pass the command line as `--client "<command>"`.

## Handoff (agent-visible)

| Field | Meaning |
|---|---|
| `run_id`, `mode` | `read_only` (all device accounts read-only; no consoles) or `remediation` |
| `task` | Task text from a fixed pool, independent of the faults |
| `api_base`, `api_token` | Management API (Bearer token, or `apitoken=` query for the table API) |
| `bastion` | host, port, username, password, host-key fingerprint |
| `device_username`, `device_password` | Account on devices (privilege can differ per device) |
| `consoles` | OOB console credentials and `<edge>.console` targets (remediation only) |
| `artifacts` | Downloadable artifact paths |
| `report_vocabulary` | Allowed `fault_class` and `component_status` values |
| `budget` | Time, command and API-request budgets |

## Interfaces

**SSH.** Connect to the bastion, then reach devices by management IP or DNS name with ProxyJump/direct-tcpip
(`ssh -J netops@127.0.0.1:<port> netops@10.x.y.z`, or asyncssh `tunnel=`). The bastion resolves names with the
site DNS server, so DNS faults affect name-based access. Unreachable devices fail the way a real network does:
a timeout after a delay, "No route to host", or "Connection refused". Port-forwarding to application ports
(e.g. 443) reaches the real service listener. A shell on the bastion is the HQ ops host.

**Management API** (all `GET`):

| Path | Returns |
|---|---|
| `/api/v1/devices` | name (configured hostname), mgmt IP, site, type, status `up` / `down` / `unknown`, last poll, collector |
| `/api/v1/devices/{name}/interfaces` | last collected interface table (may be stale or empty) |
| `/api/v1/checks` | service checks run from HQ: `ok` / `failed` / `unknown` |
| `/api/v1/alerts` | derived alerts |
| `/api/v1/logs?device=&q=&since=&until=&limit=` | centrally collected syslog (gaps, skew, duplicates, delay) |
| `/api/v1/artifacts`, `/api/v1/artifacts/{path}` | `inventory.csv`, `configs/<device>.cfg`, `topology.mmd`, `logs/syslog-history.log`, `tickets.json` |
| `/api/table.json?content=devices\|sensors` | PRTG-compatible table API (what Devexana's `prtg` adapter calls) |

**Device CLI dialects.**

- IOS-like (edges and switches):
  - `show ip interface brief`, `show interfaces [X|status]`, `show vlan brief`, `show ip route`,
    `show access-lists`, `show running-config`, `show logging`, `show clock`, `show version`
  - `ping`, `traceroute`
  - `configure terminal` → `interface X` → `[no] shutdown`, `switchport access vlan N`
  - `[no] ip route <prefix/len|net mask> <next-hop>`
  - `ip access-list extended NAME` → `<seq> permit|deny <proto> <src> <dst> [eq <port>]`, `no <seq>`
  - `end`, `write memory`

  Addresses use CIDR or `host a.b.c.d` or `any`. Common abbreviations work (`sh ip int br`, `conf t`).
- Linux-like (servers, ops, probe):
  - `hostname`, `date`, `ip addr`, `ip route`, `cat /etc/resolv.conf`
  - `systemctl status|list-units|--failed`, `sudo systemctl start|stop|restart <unit>`
  - `journalctl [-u unit] [-n N]`, `ss -tuln`
  - `ping`, `traceroute`, `curl`, `nc -zv [-u]`, `nslookup`, `dig`, `host`
  - on the DNS server: `dns-record list`, `sudo dns-record set <fqdn> <ip>`, `sudo dns-record delete <fqdn>`,
    `dhcp-leases`

  Multi-line exec commands run in one session, so a whole config change can be sent as one exec.

Changes made in one interface are visible immediately to every CLI. The management API sees them after the
next poll plus the collection delay (2 s by default; 15–45 s with the `duplicate_delayed_telemetry` degradation).

## Report (agent → lab)

```json
{"schema_version": "1.0", "agent": {"name": "...", "version": "..."}, "summary": "...",
 "healthy_overall": null,
 "devices": [{"name": "bos-edge-01", "ip": "10.2.30.1", "kind": "edge", "site": "BOS"}],
 "links": [["bos-sw-01", "bos-ws-01"]],
 "component_status": {"bos-edge-01": "healthy", "chi-print-01": "absent", "chi-dns-01": "unknown"},
 "findings": [{"component": "chi-edge-01:acl:WAN-IN", "fault_class": "firewall_block",
               "statement": "...", "evidence": ["ssh chi-edge-01: show access-lists"], "confidence": 0.8}],
 "unknowns": [{"component": "chi-dns-01", "reason": "SSH timed out; no current telemetry"}],
 "actions": [{"target": "chi-edge-01", "description": "...", "commands": ["..."], "result": "applied"}],
 "verification": [{"check": "branch -> intranet", "passed": true, "detail": "..."}],
 "claims_recovered": true, "errors": []}
```

`component` is `<device>` or `<device>:<detail>`, using any name the device goes by (DNS name, configured
hostname, inventory legacy name, or IP). The suggested detail forms are `:<iface>`, `:route:<prefix>`,
`:acl:<name>`, `:service:<name>`, and `dns:<fqdn>`. The evaluator accepts device-level components and
alternative classes where they are equally valid.

## Report outcome

`outcome` (report schema 1.1) is `completed`, `inconclusive` (the agent ran but produced no investigation, e.g.
no model) or `failed`. An agent can also exit with code **3** to signal inconclusive. Inconclusive runs get
status `inconclusive` and **no scores** (`overall: null`); they are excluded from batch means and comparisons.
Never report `healthy_overall: true` without evidence-backed observations.

## What counts as an observation

Every command event records separately (run-event schema 1.1, `detail`):

- `parsed`: the device understood the command.
- `identity_observed`: an authenticated session on that device.
- `health_evidence`: the output carried current state of that device's own resources.
- `observed_resources`: exactly which `(device, resource, field)` values the output contained, e.g.
  `edge|iface:Gi0/1|admin`, `edge|routes|table`, `edge|acl:WAN-IN|rules`, `srv|service:intranet|state`,
  `dns|record:<fqdn>|value`.

Invalid commands, denied commands and identity-only commands (`hostname`, a DNS lookup run from a host) are not
health evidence. A device counts as "observed live" only through health evidence (or fresh API telemetry for it).
Cause-level support for a fault requires an observation of that exact resource and field. For example, a VLAN
error is not revealed by an interface table that has no VLAN column.

## How results are scored

`evaluate.py`; weights in `WEIGHTS`. Raw measurements are always stored.

| Score | Definition |
|---|---|
| discovery | 0.7 × infrastructure-device recall + 0.3 × link recall (device precision and link precision are reported) |
| diagnosis | Per fault: 1.0 if correct and the agent observed a cause-revealing record; 0.5 if it observed only symptoms; 0 for a correct but unsupported claim (counted as `unsupported_correct`); 0.25 for the right location but the wrong class with cause observed. Healthy network: 1 if no claims, else 0 |
| false_positives | 1 − 0.34 × unmatched claims. A claim is matched only if both component and class match a fault, so additional wrong classes at a genuinely faulty component ARE false positives. Equivalent restatements of a correctly diagnosed fault are deduplicated, and one wrong-class claim at an otherwise-missed fault earns the 0.25 location credit instead of a penalty. Claims on planted distractors are counted separately |
| evidence | Fraction of claims whose component the agent actually observed (or whose cause it saw) |
| uncertainty | Infrastructure devices never observed live (no successful CLI session and no fresh telemetry), plus retired devices, should be `unknown`, `absent`, or correctly `failed`. Calling them `healthy`, or claiming `healthy_overall` while faults or blind spots exist, is penalized |
| remediation | Per remediable fault: 1 if the state is fixed and its symptom flows pass, 0.5 if only the flows pass. Faults on devices with no usable management path are excluded |
| verification | 0.6 × (fraction of repaired resources that were exercised by a probe made after their last change) + 0.4 if `claims_recovered` matches reality. A probe counts only if it parsed and its recorded path exercised the resource: **routes**, the router's recorded forwarding decision (forward or return path) matched a route prefix the repair added or changed, or the probe stopped at that router for lack of a route to an address inside that prefix (transit over another, e.g. connected, route, a self-ping or a ping ending at the router does not count; equivalent repairs such as two /25s for a /24 do); **edge interfaces**, the traffic entered through or was forwarded out of that interface; **ACLs**, traffic entered through the bound interface; **services**, a TCP/UDP probe to that service's port on that server (a ping does not count); **DNS**, the repaired name was resolved; **switch ports**, the attached host is on the path. A `/api/v1/checks` read covers a service or DNS repair only if the response returned a current (not `unknown`) result of a check that measures that service/name and that was *collected* after the repair; empty, stale and pre-repair results earn nothing, however late they are read. Target-less commands (bare `curl`, `ping`) earn nothing |
| no_regression | Remediation: 0 if any intended flow that worked at start fails at the end, or any forbidden flow is permitted at the end. Otherwise 1 − 0.25 × unnecessary changes − 0.1 × transiently disrupted flows − 0.25 × transiently opened forbidden flows. *Unnecessary* = every resource touched that no fault required (per owner device and resource), **including edits later reverted**; DNS records count too. *Transient disruption* = initially working flows broken at any moment by a change (recorded at change time), so a WAN shutdown restored minutes later is still penalised. Equivalent repairs on the fault's own resource (two /25 routes for a missing /24, a permit at another sequence) are not unnecessary. Read-only: 0 if anything was changed |

Behavioural checks are live: after the agent exits, every intended and forbidden flow is evaluated on the
current world, and TCP services are checked by really connecting to their listeners and **validating the
response**: correct protocol, a 2xx status and the expected service identity. A connection that returns HTTP 503,
garbage, truncated headers or another service's banner is transport-up but application-unhealthy, and both are
recorded (`transport_ok`, `application_ok`).

Scores are tagged with `evaluator_version` (currently `netlab-eval-1.4.0`; history in `EVALUATOR_CHANGELOG`). Any change that can alter a score for identical inputs must bump it: `tests/test_evaluator_version.py` pins golden scores per version and fails otherwise. Results recorded under 1.1.0 while the second round of scoring changes was being made are ambiguous, so discard or re-run them. Results from 1.2.0 credited unaffected-route transit and pre-repair/empty check reads as verification; they keep their 1.2.0 label, never pair with later results, and must be re-run to compare. Results from 1.3.0 credited a broader repair route used for an unrelated destination, and any traffic entering an ACL's bound interface, as verification; likewise keep their 1.3.0 label and re-run them under 1.4.0 before comparing. Every result also carries
`benchmark_eligible` and `ineligible_reasons`. A run is ineligible when the agent was not sandboxed, or when the
Devexana client used a shared appliance (earlier runs' data was retrievable). Failed and timed-out runs stay
eligible with their zero score, so regressions remain visible. `netlab compare` and batch means use only eligible
results from the current evaluator version, and report how many they skipped.
