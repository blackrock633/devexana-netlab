# Example run (recorded 2026-11-08, macOS arm64, Python 3.12.14)

> Recorded with evaluator 1.0, before the independent-validation fixes. Since then, results and specs are sealed
> (`*.json.enc`), runs report their isolation mode, and runs without a model are `inconclusive` and unscored
> rather than scored 0.41. The scores below are kept as recorded.

The output below is verbatim from the commands shown. Long JSON is trimmed only where marked, and passing
intended-flow rows are omitted from the `run` output.

## 1. Shuffle (seed from OS entropy) and replay check

```
$ netlab shuffle --difficulty 0.7 --completeness 0.4
{
 "env_id": "env-83cfe5c90a",
 "seed": "17234270514847953881",
 "family": "branch_office",
 "domain": "office.example",
 "sites": [
  "rdu",
  "msp"
 ],
 "devices": 15,
 "kinds": {
  "edge": 2,
  "ops": 1,
  "probe": 1,
  "server": 4,
  "switch": 2,
  "workstation": 5
 },
 "difficulty": 0.7,
 "evidence_completeness": 0.4,
 "balanced": false,
 "generator_version": "netlab-gen-1.0.0",
 "spec_sha256": "4d5ccd14a29ea894b4314a42115bcff43f8abcc5124de146291a4d8bd30a976e",
 "resource_estimate": {
  "devices": 15,
  "ssh_targets": 10,
  "real_tcp_listeners": 5,
  "estimated_memory_mb": 90,
  "estimated_startup_s": 1.5,
  "privileged_operations": 0,
  "host_network_exposure": "127.0.0.1 only"
 }
}

$ netlab replay env-83cfe5c90a
{
 "env_id": "env-83cfe5c90a",
 "seed": 17234270514847953881,
 "generator_version": "netlab-gen-1.0.0",
 "saved_sha256": "4d5ccd14a29ea894b4314a42115bcff43f8abcc5124de146291a4d8bd30a976e",
 "replayed_sha256": "4d5ccd14a29ea894b4314a42115bcff43f8abcc5124de146291a4d8bd30a976e",
 "recomputed_saved_sha256": "4d5ccd14a29ea894b4314a42115bcff43f8abcc5124de146291a4d8bd30a976e",
 "spec_identical": true,
 "artifacts_identical": true
}
```

## 2. Reference client: read-only, then remediation

```
$ netlab run env-83cfe5c90a --mode read_only --label reference@0.1.0
run run-20261108-213732-3122bc  scenario env-83cfe5c90a  agent {'name': 'netlab-reference-client', 'version': '0.1.0', 'label': 'reference@0.1.0'}  mode read_only  status completed
overall 0.992
  discovery        0.936
  diagnosis        1.000
  false_positives  1.000
  evidence         1.000
  uncertainty      1.000
  remediation      n/a
  verification     n/a
  no_regression    1.000
  time 4.31s  commands 68  api 11  flows ok 15->15/16
  PASS  fault f-781e0e: expected acl_blocks_service at rdu-edge-01:acl:WAN-IN; observed firewall_block at rdu-edge-01:acl:WAN-IN [full, support=cause]
  PASS  retired rdu-print-01: expected absent; observed absent

$ netlab run env-83cfe5c90a --mode remediation --label reference@0.1.0
run run-20261108-213737-c0ef96  scenario env-83cfe5c90a  agent {'name': 'netlab-reference-client', 'version': '0.1.0', 'label': 'reference@0.1.0'}  mode remediation  status completed
overall 0.9936
  discovery        0.936
  diagnosis        1.000
  false_positives  1.000
  evidence         1.000
  uncertainty      1.000
  remediation      1.000
  verification     1.000
  no_regression    1.000
  time 13.49s  commands 147  api 11  flows ok 15->16/16
  PASS  fault f-781e0e: expected acl_blocks_service at rdu-edge-01:acl:WAN-IN; observed firewall_block at rdu-edge-01:acl:WAN-IN [full, support=cause]
  PASS  retired rdu-print-01: expected absent; observed absent

```

## 3. Ground truth (reviewer only, after the run) and export

```
$ netlab reveal run-20261108-213737-c0ef96   # 'flows' list trimmed
{
 "env_id": "env-83cfe5c90a",
 "seed": "17234270514847953881",
 "interacting": false,
 "faults": [
  {
   "id": "f-781e0e",
   "type": "acl_blocks_service",
   "component": "rdu-edge-01:acl:WAN-IN",
   "description": "ACL WAN-IN on rdu-edge-01 has a deny at seq 35 for tcp/443 to 10.117.22.11/32 from the branch.",
   "symptom_flows": [
    "flow-04"
   ],
   "onset_minutes_before_start": 75
  }
 ],
 "degradations": [
  {
   "id": "d-d928d6",
   "type": "collector_outage",
   "description": "Collector msp-mon-01 stopped reporting from t=-16827s until t=-10114s."
  },
  {
   "id": "d-ffe995",
   "type": "log_gap",
   "description": "Syslog from msp-edge-01, rdu-dns-01 is missing for an interval."
  },
  {
   "id": "d-f169f9",
   "type": "mgmt_unreachable",
   "description": "SSH management on rdu-dns-01 does not respond (data plane unaffected)."
  }
 ],
 "distractors": [
  {
   "kind": "retired_device",
   "target": "rdu-print-01",
   "description": "rdu-print-01 was retired; records still list it."
  },
  {
   "kind": "cpu_spike",
   "target": "msp-edge-01",
   "description": "Transient CPU spike logged on msp-edge-01."
  }
 ]
}
$ netlab export run-20261108-213737-c0ef96 -o run.zip && unzip -l run.zip
---------  ---------- -----   ----
        0  11-08-2026 14:42   run-20261108-213737-c0ef96/client.log
    92665  11-08-2026 14:42   run-20261108-213737-c0ef96/events.jsonl
      641  11-08-2026 14:42   run-20261108-213737-c0ef96/meta.json
     5116  11-08-2026 14:42   run-20261108-213737-c0ef96/report.json
    11272  11-08-2026 14:42   run-20261108-213737-c0ef96/result.json
    31901  11-08-2026 14:42   run-20261108-213737-c0ef96/spec.json
---------                     -------
   141595                     6 files
```

`handoff.json` (credentials) is excluded, and every credential value is scrubbed from the other files.

## 4. Regression batch on hard scenarios and version comparison

Six new scenarios (`netlab shuffle --count 6 --difficulty 0.9 --completeness 0.2`) were run with the reference
client and then with Devexana OS (local appliance at devexana-os 59fe083, **no model assigned**, so Deo failed
with `model_unavailable`).

```
$ netlab batch <the 6 new scenarios> --mode read_only --label reference@0.1.0   # progress lines 1-3 trimmed
[4/6] env-87bd449130 completed overall=0.7914
[5/6] env-a72af18f96 completed overall=0.993
[6/6] env-e262635f47 completed overall=0.8439
batch batch-20261108-213840-a098: mean overall 0.9314
{
 "discovery": 0.8886,
 "diagnosis": 0.8542,
 "false_positives": 1.0,
 "evidence": 1.0,
 "uncertainty": 1.0,
 "remediation": null,
 "verification": null,
 "no_regression": 1.0
}
$ netlab batch <the same 6> --client devexana --mode read_only --label devexana@0.1.0-nomodel   # progress lines 1-3 trimmed
[4/6] env-87bd449130 completed overall=0.4125
[5/6] env-a72af18f96 completed overall=0.3857
[6/6] env-e262635f47 completed overall=0.4286
batch batch-20261108-213945-4127: mean overall 0.4137
{
 "discovery": 0.7,
 "diagnosis": 0.0,
 "false_positives": 1.0,
 "evidence": null,
 "uncertainty": 0.1958,
 "remediation": null,
 "verification": null,
 "no_regression": 1.0
}
$ netlab compare reference@0.1.0 devexana@0.1.0-nomodel --mode read_only
{
 "a": "reference@0.1.0",
 "b": "devexana@0.1.0-nomodel",
 "paired_scenarios": 6,
 "rows": [ ...6 paired rows trimmed... ],
 "mean_a": 0.9314,
 "mean_b": 0.4137,
 "b_better": 0,
 "a_better": 6
}

```

What this shows: the harness pairs runs by `env_id` and spec hash, so two agent versions are compared on
identical scenarios. The low Devexana score here is a statement about this setup (no model), not about Deo.
