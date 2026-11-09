from __future__ import annotations

import asyncio
import os
from collections.abc import Callable
from typing import Any

import pytest

from netlab.generate import generate
from netlab.schemas import GenerationConfig, ScenarioSpec


@pytest.fixture(autouse=True)
def _var(tmp_path, monkeypatch):
    monkeypatch.setenv("NETLAB_VAR", str(tmp_path / "var"))
    yield


def run(coro: Any) -> Any:
    return asyncio.run(coro)


def find_spec(
    pred: Callable[[ScenarioSpec], bool], cfg: GenerationConfig | None = None, start: int = 0, limit: int = 3000
) -> ScenarioSpec:
    """Deterministically search seeds for a scenario with a property (tests stay reproducible)."""
    for seed in range(start, start + limit):
        s = generate(cfg, seed=seed)
        if pred(s):
            return s
    raise AssertionError("no seed found for predicate")


def only(*types: str, n: int = 1, degradations: tuple[str, ...] = (), completeness: float = 1.0) -> ScenarioSpec:
    """A scenario with exactly the given fault types and only the given degradation types."""
    cfg = GenerationConfig(
        fault_type_weights={t: (1.0 if t in types else 0.0) for t in GenerationConfig().fault_type_weights},
        fault_count_weights={0: 0.0, 1: 1.0 if n == 1 else 0.0, 2: 1.0 if n == 2 else 0.0},
        degradation_weights={d: (1.0 if d in degradations else 0.0) for d in GenerationConfig().degradation_weights},
        evidence_completeness=completeness,
    )
    return find_spec(
        lambda s: (
            sorted(f.type for f in s.faults) == sorted(types)
            and all(d.type in degradations for d in s.evidence.degradations)
            and (not degradations or {d.type for d in s.evidence.degradations} == set(degradations))
        ),
        cfg,
    )


def healthy(completeness: float = 1.0) -> ScenarioSpec:
    cfg = GenerationConfig(fault_count_weights={0: 1.0, 1: 0.0, 2: 0.0}, evidence_completeness=completeness)
    return generate(cfg, seed=7)


os.environ.setdefault("PYTHONHASHSEED", "0")
