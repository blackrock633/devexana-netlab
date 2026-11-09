# devexana-netlab

A randomized network testing lab for Devexana. Press **Shuffle** to generate a fresh, plausible two-site
branch-office network with hidden faults and imperfect evidence. Run Devexana (or the reference client) against it
through SSH, an HTTP management API, logs and downloadable artifacts. Then score the run against hidden ground
truth and against live behavioural checks.

Built as a separate project next to `devexana-os` (Devexana's appliance, `~/devexana-os`, commit `59fe083`). It
follows that repo's conventions: uv, Python 3.12, pydantic v2, FastAPI, ruff at 120 columns, pytest. Devexana's
code and its SFT simulator/data factory are untouched. The factory is not in `devexana-os`, and this lab does not
replace it.

## Status at a glance

| Area | Status |
|---|---|
| Shuffle: OS-entropy seeds, weights, difficulty and evidence completeness as independent knobs, balanced coverage mode | **Implemented, tested** |
| Exact replay of spec and initial artifacts (sha256-verified); generator and component versions recorded | **Implemented, tested** |
| Branch-office family: 2 sites, routing, stateful edge firewalls, DNS, DHCP, 13–24 devices, real SSH, HTTP API, logs, artifacts | **Implemented, tested** |
| 6 fault types plus a healthy case; single faults and interacting pairs; distractors | **Implemented, tested** |
| 9 causal evidence degradations | **Implemented, tested** |
| Runtime: unprivileged, 127.0.0.1 only, resource limits; teardown guaranteed on start/spawn/cancel/evaluation failures | **Implemented, tested (live sockets)** |
| Ground-truth isolation from the agent | **Enforced** by a kernel sandbox around every agent process (macOS `sandbox-exec`; Linux `bwrap` untested). Runs are refused without a sandbox unless explicitly labelled cooperative. Specs and results are also sealed at rest. A same-user process *outside* the sandbox that also reads the key can still decrypt; see ARCHITECTURE |
| L2/L3 forwarding and firewalling | **Emulated** by a deterministic path evaluator over shared state. Not a kernel network stack; see [docs/FIDELITY.md](docs/FIDELITY.md) |
| Application services (intranet, file share, collector) | **Real TCP listeners**, minimal protocol (HTTP/1.0 or a banner, not real TLS or SMB) |
| DNS, DHCP | **Emulated** (no real UDP servers) |
| Reference client: rule-based, no model, same interfaces as Devexana | **Implemented, tested** |
| Devexana OS client (inventory import, PRTG sync, knowledge docs, Deo triage, result translation) | **Implemented. Ingestion and per-run disposable appliances verified live; Deo reasoning NOT verified (no model was available)**. See [docs/DEVEXANA_INTEGRATION.md](docs/DEVEXANA_INTEGRATION.md) |
| Devexana SSH, command execution and remediation | **Not possible today**: Devexana has no SSH or command interface, and no write adapter for lab devices |
| Evaluator 1.1: no model; resource/field-specific support; unmatched claims penalised; parse vs identity vs health evidence; validated application health; net resource-level unnecessary-change scoring; inconclusive runs unscored | **Implemented, tested** |
| Operator UI: shuffle/config/estimate, start/stop/reset, run, live timeline, results, ground-truth reveal, export, batch, compare | **Implemented. API covered by tests; page not checked in a real browser** |
| Families small_office, campus, hybrid_cloud | **Future work.** Listed in the UI as "planned"; generation refuses them |
| Linux network-namespace / container backend | **Future work**: not feasible on this macOS host (no Docker, no netns) |

## Setup

Requires [uv](https://docs.astral.sh/uv/). uv provides Python 3.12. No root, no Docker.

```bash
cd ~/devexana-netlab
uv sync
uv run pytest            # 77 tests, about 75 s (needs localhost binds)
uv run ruff check netlab tests
```

## Use

```bash
uv run netlab serve                     # operator UI: open the printed http://127.0.0.1:8780/?token=... URL
uv run netlab shuffle --difficulty 0.7 --completeness 0.4    # new scenario from OS entropy
uv run netlab scenarios
uv run netlab replay  <env_id>          # regenerate from the saved seed; verifies spec + artifacts are identical
uv run netlab run     <env_id> --mode read_only|remediation --client reference|devexana --label <version>
uv run netlab reveal  <run_id>          # ground truth, only after the run has finished
uv run netlab export  <run_id> -o run.zip   # no credentials
uv run netlab batch   --all | --env <id> ... | --shuffle N  --client ... --mode ... --label ...
uv run netlab compare <label A> <label B> [--mode read_only]
uv run netlab start   <env_id>          # foreground lab for manual poking; prints the handoff path
uv run netlab teardown                  # kills client processes left behind by a crashed orchestrator
uv run netlab schemas -o schemas        # versioned JSON schemas
```

Run state lives under `$NETLAB_VAR` (default `./var`). The layout is in `netlab/orchestrate.py`.

To run Devexana: start a devexana-os appliance and assign a model to the `agent` role (Administration › Models).
Then set `DEVEXANA_URL`, `DEVEXANA_USERNAME` and `DEVEXANA_PASSWORD` and use `--client devexana`.

## Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md): components, data flow, isolation model, schemas.
- [docs/ADAPTER_CONTRACT.md](docs/ADAPTER_CONTRACT.md): what an agent under test receives and must return; API and device-CLI reference.
- [docs/FIDELITY.md](docs/FIDELITY.md): what is real, what is emulated, and what cannot be replayed exactly.
- [docs/DEVEXANA_INTEGRATION.md](docs/DEVEXANA_INTEGRATION.md): Devexana's actual interfaces, what is verified, and the gaps.
- [docs/EXAMPLE_RUN.md](docs/EXAMPLE_RUN.md): a recorded session (shuffle, replay, runs, reveal, export, batch, compare).

## Known limitations (summary)

- The reference client and the generator were written by the same author. High reference scores show the lab
  works end to end; they are **not** evidence that the lab is hard or realistic for Devexana.
- Agents are sandboxed away from `$NETLAB_VAR`. Arbitrary *other* processes of the same OS user are not; for that,
  run the agent under another OS user or on another host (see ARCHITECTURE).
- Evidence-support scoring relies on server-side annotations of exactly which resources and fields each output
  contained. Symptom-level (0.5) credit is still attributed by device, which is coarser.
