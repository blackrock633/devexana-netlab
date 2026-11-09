from __future__ import annotations

import ipaddress
from collections import Counter

import pytest

from netlab.generate import (
    GenerationError,
    choose_balanced_cell,
    coverage_cells,
    fresh_seed,
    generate,
    resource_estimate,
    validate_spec,
)
from netlab.schemas import DEGRADATION_TYPES, FAULT_TYPES, GenerationConfig
from netlab.world import World

SEEDS = range(0, 200)


def test_many_seeds_are_coherent():
    kinds = Counter()
    for seed in SEEDS:
        s = generate(seed=seed)
        validate_spec(s)  # raises on incoherence
        assert len(s.topology.devices) <= s.config.max_devices
        ips = [i.ip.split("/")[0] for d in s.topology.devices.values() for i in d.interfaces.values() if i.ip]
        assert len(ips) == len(set(ips))
        nets = [ipaddress.ip_network(c) for site in s.topology.sites for c in site.subnets.values()]
        assert all(any(ipaddress.ip_address(a) in n for n in nets) for a in ips)
        assert len({f.component for f in s.faults}) == len(s.faults)
        assert len({f.type for f in s.faults}) == len(s.faults)
        for f in s.faults:
            assert f.symptom_flows, "every fault must be observable through at least one intended flow"
            assert f.fault_class in f.accepted_classes and f.component in f.accepted_components
        kinds["healthy" if not s.faults else f"{len(s.faults)}-fault"] += 1
        kinds["interacting"] += s.interacting
    assert kinds["healthy"] > 10 and kinds["1-fault"] > 40 and kinds["2-fault"] > 20 and kinds["interacting"] > 5


def test_every_fault_and_degradation_type_is_generated():
    ft, dt = set(), set()
    for seed in range(400):
        s = generate(seed=seed)
        ft |= {f.type for f in s.faults}
        dt |= {d.type for d in s.evidence.degradations}
    assert ft == set(FAULT_TYPES)
    assert dt == set(DEGRADATION_TYPES)


def test_fault_type_weights_are_respected():
    cfg = GenerationConfig(
        fault_type_weights={t: (1.0 if t == "service_stopped" else 0.0) for t in FAULT_TYPES},
        fault_count_weights={0: 0, 1: 1, 2: 0},
    )
    for seed in range(40):
        s = generate(cfg, seed=seed)
        assert [f.type for f in s.faults] == ["service_stopped"]


def test_healthy_only_weights():
    cfg = GenerationConfig(fault_count_weights={0: 1, 1: 0, 2: 0}, difficulty=1.0)
    assert all(not generate(cfg, seed=s).faults for s in range(30))


def test_difficulty_and_completeness_are_independent():
    for seed in range(30):
        a = generate(GenerationConfig(evidence_completeness=1.0), seed=seed)
        b = generate(GenerationConfig(evidence_completeness=0.0), seed=seed)
        assert [f.model_dump() for f in a.faults] == [f.model_dump() for f in b.faults]
        assert a.topology == b.topology
        assert a.evidence.degradations == []
    many = sum(
        len(generate(GenerationConfig(evidence_completeness=0.0), seed=s).evidence.degradations) for s in range(30)
    )
    assert many / 30 >= 4
    hard = sum(len(generate(GenerationConfig(difficulty=1.0), seed=s).faults) for s in range(60))
    easy = sum(len(generate(GenerationConfig(difficulty=0.0), seed=s).faults) for s in range(60))
    assert hard > easy


def test_resource_constraints():
    with pytest.raises(GenerationError):
        generate(GenerationConfig(max_devices=8), seed=1)
    s = generate(GenerationConfig(max_devices=14, hq_workstations=(5, 5), branch_workstations=(6, 6)), seed=3)
    assert len(s.topology.devices) <= 14
    est = resource_estimate(s)
    assert est["privileged_operations"] == 0 and est["host_network_exposure"] == "127.0.0.1 only"


def test_unimplemented_family_is_refused():
    with pytest.raises(GenerationError, match="not implemented"):
        generate(GenerationConfig(family_weights={"campus": 1.0}), seed=1)


def test_balanced_mode_targets_least_covered_cell():
    cfg = GenerationConfig(balanced=True)
    cells = coverage_cells(cfg)
    ledger = {f"{f}|{d}": 5 for f, d in cells}
    ledger["dns_record_stale|log_gap"] = 0
    inp = choose_balanced_cell(cfg, ledger, seed=99)
    assert inp["balanced_cell"] == "dns_record_stale|log_gap"
    s = generate(cfg, seed=99, generation_inputs=inp)
    assert "dns_record_stale" in [f.type for f in s.faults]
    assert "log_gap" in [d.type for d in s.evidence.degradations]
    h = generate(cfg, seed=5, generation_inputs={"forced_fault": "healthy", "forced_degradation": None})
    assert h.faults == []


def test_seeds_come_from_entropy_and_differ():
    seeds = {fresh_seed() for _ in range(50)}
    assert len(seeds) == 50
    s = generate()
    assert "os-entropy" in s.seed_source and s.seed >= 0


def test_healthy_topology_forbidden_flows_blocked_and_intended_flows_work():
    s = generate(seed=11)
    w = World(s.topology)
    for fl in s.topology.intended_flows:
        assert w.flow_check(fl.src, fl.dst, fl.proto, fl.port, fl.by_name).ok, fl.id
    for fl in s.topology.forbidden_flows:
        assert not w.flow_check(fl.src, fl.dst, fl.proto, fl.port, fl.by_name).ok, fl.id
