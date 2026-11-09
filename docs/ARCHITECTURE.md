# Architecture

```
 generate.py ──► ScenarioSpec (hidden) ──► artifacts.py / history.py (deterministic initial evidence)
      │                │
      │                └──► runtime/lab.py  World (ground truth, mutable) ◄── fault mutations
      │                        ├─ runtime/ssh.py   bastion :rand ─direct-tcpip─► in-process device SSH (socketpair)
      │                        │                    └─ runtime/cli.py  IOS-like / Linux-like CLIs over the World
      │                        ├─ runtime/api.py   management API :rand (JSON, PRTG table API, artifacts)
      │                        ├─ runtime/services.py  real TCP listeners for app services
      │                        ├─ collector (poll loop; causal delivery, delay, staleness)
      │                        └─ runtime/events.py  server-side event log (+ evaluator-only annotations)
      │
 orchestrate.py ── spawns agent process (clients/reference.py | clients/devexana_os.py | any command)
      │             with ONLY handoff.json in a fresh temp dir; RLIMIT_CPU / RLIMIT_NOFILE; wall-clock budget
      └─► evaluate.py  (spec + events + report + live flow checks) ──► result.json
 control/server.py + static/index.html: operator UI (separate token; truth only after a run finishes)
```

## Separation of concerns

| Concern | Module | Notes |
|---|---|---|
| Environment generation | `generate.py` | Seeded `random.Random`, separate sub-streams per stage (topology+faults, evidence, distractors, timeline), explicit constraint checks (`validate_spec`). |
| Ground truth | `world.py` | The only mutable network state. Every interface reads and writes it. |
| Evidence production | `history.py`, `artifacts.py`, collector in `runtime/lab.py`, renderers in `render.py` | History and live telemetry share the same causal delivery rules. |
| Runtime orchestration | `runtime/lab.py`, `orchestrate.py` | Start, stop, reset, budgets, process isolation, persistence. |
| Integration | `clients/*`, `schemas.Handoff`, `schemas.AgentReport` | Contract in ADAPTER_CONTRACT.md. |
| Evaluation | `evaluate.py` | No model. Raw measurements plus weighted aggregate. |

## Versioned schemas

`schemas.py` (pydantic). JSON Schema exports are in `schemas/`. Every model carries `schema_version`.

- `GenerationConfig` 1.0: weights, difficulty, evidence completeness, balanced mode, size limits.
- `ScenarioSpec` 1.0 (hidden): seed, seed source, generator and component versions, config, generation inputs
  (the balanced-mode cell), topology, faults, evidence policy, timeline, distractors, task text, `spec_sha256`.
- `EvidencePolicy` 1.0: collector assignment, poll interval, collection delay, staleness, degradations.
- `Handoff` 1.0: the only thing an agent receives.
- `RunEvent` 1.0: the server-side record, with evaluator-only `reveals`, `symptoms` and `change`.
- `AgentReport` 1.0: what an agent returns.
- `RunResult` 1.0: measurements, scores, `expected_vs_observed`.

## Randomness and replay

- Seeds: `secrets.randbits(64)` (OS entropy), saved in the spec. Generation itself is pseudorandom (Mersenne
  Twister) and makes no claim to physical randomness.
- Replay: `generate(config, seed, generation_inputs)` reproduces the spec byte for byte (`spec_sha256`), and
  `render_artifacts` reproduces every initial artifact (sha256 manifest). `netlab replay` checks both.
- What does not replay: wall-clock timestamps of live events, collector poll alignment with agent actions, SSH and
  agent timing, the order of concurrent agent actions, per-run credentials and host keys, and the random
  duplication of live syslog lines. These are recorded in `events.jsonl`, so a given run can be inspected exactly,
  but a re-run will not be identical. Bumping `GENERATOR_VERSION` / `ARTIFACT_VERSION` is required whenever rules
  change in a way that would alter the output for an existing seed.

## Ground-truth isolation

- Agent-facing surfaces (bastion, device CLIs, management API, service listeners) render state but never the
  spec. Fault records, degradation records, labels, seed and `env_id` never appear on them.
  `tests/test_isolation.py` scans every endpoint, every artifact and many commands on every device for leaks.
- Fault identity is never encoded in names: `env_id` is a hash of the seed, fault and degradation ids are random,
  artifact filenames are fixed, and the task text comes from a pool chosen independently of the faults.
- Benign look-alike log lines (config changes, dnsmasq reloads) also appear in healthy scenarios, so their
  presence alone does not reveal a fault.
- **Filesystem boundary (enforced).** Every agent process runs inside a kernel sandbox (`netlab/isolation.py`):
  macOS `sandbox-exec` with a profile that denies all reads and writes under `$NETLAB_VAR`; Linux `bwrap` with an
  empty tmpfs over it (implemented, untested here). Inside the sandbox the agent can read its own handoff in a fresh
  temporary directory, and nothing in `$NETLAB_VAR`: no specs, results, events, operator token or key.
  `tests/test_validation_fixes.py::test_sandboxed_agent_cannot_read_any_evaluator_state` checks this through the
  real orchestrator launch path. If no sandbox is available the run is **refused**, unless the caller opts into a
  labelled cooperative-client run (`allow_unisolated=True` / `NETLAB_ALLOW_UNISOLATED=1`). The isolation label is
  recorded in `meta.json` and in `result.measurements.isolation`.
- **At-rest sealing (defence in depth).** Scenario specs and results are AES-256-GCM sealed (`*.json.enc`,
  `netlab/store.py`) with a key in `$NETLAB_VAR/keys/`, and `meta.json` no longer contains the seed. A process
  outside the sandbox that reads a spec file sees ciphertext. This is not the boundary: a same-user process
  outside the sandbox that also reads the key can decrypt. Protecting against arbitrary processes of the same OS
  user needs a separate OS user or host. The lab binds to 127.0.0.1, so that would need an SSH tunnel (future
  work).
- The sandbox restricts the filesystem only. It does not restrict the agent's network access to other local
  services (e.g. a Devexana appliance), and it is no defence against kernel exploits.
- Evaluator and operator credentials are separate: the control server has its own token, the lab API token is
  rejected there, and `/truth` returns 403 until the sealed result exists.

## Resource limits and teardown

- Per-run limits: command budget (600), API request budget (3000), API rate limit (40/s), 48 concurrent SSH
  connections, client `RLIMIT_CPU` and `RLIMIT_NOFILE`, and a wall-clock budget after which the client's process
  group is killed.
- No privileged operations. Only 127.0.0.1 ephemeral ports are used; no host routes, interfaces or firewall rules
  change.
- `orchestrate.run_scenario` holds everything it acquires (lab, agent process group, log file, pid file, temp
  directory) under one `try/finally`. Spawn errors, a missing executable, callback errors, cancellation, timeouts
  and evaluation errors all stop the lab, kill and reap the agent's process group and persist an `aborted`
  result. `Lab.start()` rolls back a partial start (e.g. the API failing to bind after SSH started), and each
  `Lab.stop()` step runs even if an earlier one fails.
- `Lab.stop()` closes every listener and verifies each port is closed (`ports_still_open` is recorded in the
  result). The control server tears down on shutdown. `netlab teardown` kills orphaned client process groups
  from `$NETLAB_VAR/procs`.
