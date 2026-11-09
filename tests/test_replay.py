from __future__ import annotations

from netlab import orchestrate as orch
from netlab.artifacts import manifest, render_artifacts
from netlab.generate import generate, spec_digest
from netlab.schemas import GenerationConfig, ScenarioSpec
from netlab.versions import GENERATOR_VERSION


def test_same_seed_same_spec_and_artifacts():
    for seed in (0, 17, 2**63 + 5):
        a, b = generate(seed=seed), generate(seed=seed)
        assert a.spec_sha256 == b.spec_sha256 == spec_digest(a)
        assert manifest(render_artifacts(a)[0]) == manifest(render_artifacts(b)[0])


def test_different_seeds_differ():
    assert len({generate(seed=s).spec_sha256 for s in range(20)}) == 20


def test_saved_spec_replays_exactly(tmp_path):
    spec = orch.shuffle(GenerationConfig(difficulty=0.8, evidence_completeness=0.2))
    loaded = orch.load_spec(spec.env_id)
    r = orch.replay_spec(loaded)
    assert r["spec_identical"] and r["artifacts_identical"]
    assert loaded.generator_version == GENERATOR_VERSION
    assert {"netlab", "generator", "python", "asyncssh"} <= set(loaded.component_versions)


def test_balanced_shuffle_replays_with_recorded_inputs():
    spec = orch.shuffle(GenerationConfig(balanced=True))
    assert "balanced_cell" in spec.generation_inputs
    assert orch.replay_spec(orch.load_spec(spec.env_id))["spec_identical"]


def test_tampered_spec_is_detected():
    spec = generate(seed=3)
    d = spec.model_dump()
    d["topology"]["dns_zone"]["evil.example"] = "10.0.0.1"
    bad = ScenarioSpec.model_validate(d)
    assert spec_digest(bad) != bad.spec_sha256
    assert not orch.replay_spec(bad)["spec_identical"]
