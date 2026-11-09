# Devexana integration

Source inspected: `github.com/blackrock633/devexana-os` @ `59fe083` (cloned to `~/devexana-os`, unmodified).

## Devexana's actual interfaces (from source)

| Interface | Where | How the lab uses it |
|---|---|---|
| CSV/JSON inventory import | `integrations/adapters/csv_inventory.py`; `POST /api/v1/integrations`, `/integrations/{id}/import/upload` | The lab's `inventory.csv` uses Lansweeper-style headers matching the adapter's aliases |
| PRTG adapter (HTTP API pull) | `integrations/adapters/prtg.py` calls `GET {base_url}/api/table.json?content=devices|sensors&apitoken=` | The lab serves a compatible `/api/table.json` |
| Knowledge documents | `POST /api/v1/knowledge/documents` (kinds `config_snapshot`, `ticket`, `document`, …) | Config backups, syslog history and tickets are loaded |
| Deo triage agent | `agents_runtime/service.py` (built in); `POST /api/v1/agents/{id}/runs` returns `summary`, `facts[{text, evidence}]`, `hypotheses`, `next_steps`, `insufficient_evidence` | Run with the lab task; the result is translated into an `AgentReport` |
| TCP reachability probe | `network.check_reachability` tool (refuses loopback and link-local) | Lab addresses are emulated, so this tool cannot reach them (gap) |
| SNMP adapter | `integrations/adapters/snmp.py` | Not used: the lab has no SNMP agent (future work) |
| Writes | Only adapter write capabilities, through operations: proposal → approval → execute → verify | No adapter exists for lab devices, so Devexana cannot remediate in the lab (gap) |
| SSH and command execution | **None in Devexana** | Cannot be exercised (gap) |

## What was verified live (2026-11-08)

A local appliance (`devexana serve`, data directory in a scratch folder, admin `labadmin`, **no model assigned**)
was driven by `netlab run <env> --client devexana`. Observed:

- Login, `csv_inventory` integration creation and upload import: succeeded.
- `prtg` integration pointed at the lab and synced. The lab recorded Devexana's unmodified adapter calling
  `GET /api/table.json` with `content=devices` and then `content=sensors`, using its production column lists.
  Afterwards Devexana held 28 device entities with statuses from the lab's telemetry.
- Knowledge documents were created for all config backups, the syslog history and the tickets.
- Deo triage failed with `model_unavailable` ("No model is assigned to the 'agent' role"), as expected. So **Deo's
  investigation quality against the lab is untested.**
- On 6 hard scenarios (difficulty 0.9, completeness 0.2) Devexana without a model averaged 0.41 overall, against
  0.93 for the reference client. Its credit came only from discovery and from not breaking anything. It also
  marked a retired printer `failed` instead of `absent`. See EXAMPLE_RUN.md. *Superseded:* under evaluator 1.1
  such runs are `inconclusive` and unscored, because benchmarking an unavailable model as an investigation was
  itself a defect.

## Run isolation on the appliance (updated after independent validation, 2026-11-08)

Devexana has no API to delete integrations, and a fresh integration's `complete_snapshot` only covers its own
data source. Entities from earlier runs therefore persist and stay visible to Deo's retrieval. Two modes:

- **Disposable appliance (isolated, recommended).** Set `DEVEXANA_BACKEND_DIR=~/devexana-os/backend`. The client
  creates a fresh data directory and admin, starts `devexana serve` on a free port, runs, then kills the server
  and deletes the directory. The directory is created first and everything after it (port selection, admin
creation, server start, health wait) is inside the cleanup scope, so a failure at any setup step still removes
it (tested by failing `uv` lookup and `create-admin`). To give Deo a model, also set `DEVEXANA_SEED_LOCAL_MODEL_URL` and
  `DEVEXANA_SEED_LOCAL_MODEL_NAME` (passed through; whether Devexana then assigns the `agent` role automatically
  is unverified). **Verified live:** two consecutive runs on different scenarios. The second report contained only
  its own 21 devices, none of the first run's 28. Sync jobs were awaited to completion. No appliance directory or
  `devexana serve` process remained afterwards. Both runs executed inside the agent sandbox.
- **Shared appliance** (`DEVEXANA_URL` and friends). **Refused by default**: the client exits with an error
  unless `DEVEXANA_ALLOW_SHARED=1`, because Deo's retrieval can still see earlier runs' entities. If allowed, the
  report's agent carries `appliance_isolation: shared` and the result is marked `benchmark_eligible: false`,
  which excludes it from comparisons and batch means. Everything the run creates is tagged `netlab <run_id>`. The
  report's inventory is paginated and filtered by provenance (`data_source_name` starts with `netlab <run_id> `).
  Afterwards the client deletes the run's knowledge documents and disables its integrations. Their entities
  remain, so the report is labelled *SHARED appliance: entities from earlier runs remain visible to Deo
  retrieval*. Scoping and pagination are tested against a mock appliance; the cleanup calls have **not** been
  run against a live appliance.

A failed or missing Deo result produces `outcome: inconclusive` (exit code 3), status `inconclusive` and no
scores. It is never translated into a healthy-network claim.

## Translation (Deo result → AgentReport)

`clients/devexana_os.translate` uses explicit rules: keyword patterns for `fault_class`, longest device-name
mention for `component`, an FQDN for DNS findings, and entity status for `component_status`. Facts become
findings; hypotheses do so only with `--hypotheses-as-findings`. This step is **lossy**: a correct diagnosis
phrased unusually can be missed. Unit tests: `tests/test_devexana_translate.py`. When comparing Devexana
versions, keep the translation version fixed, or record it in `--label`.

## Next steps to complete the integration

1. Assign a model (e.g. the Qwen2.5-3B llama.cpp baseline) to the `agent` role and run
   `netlab batch --shuffle N --client devexana --label devexana@<rev>`.
2. To exercise remediation through Devexana's real safety path, add a Devexana `IntegrationAdapter` (for example
   `netlab_device`) whose write capabilities call the lab's device CLI through the bastion. That is a change in
   devexana-os and needs its owners' agreement; it was deliberately not made here.
3. To exercise SNMP, add an SNMP agent to the lab (Devexana's tests already use `snmpsim`).
