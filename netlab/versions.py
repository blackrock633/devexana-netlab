"""Version identifiers recorded with every generated scenario and every run result."""

from __future__ import annotations

import platform
import sys
from importlib import metadata

NETLAB_VERSION = "0.1.0"
# Bump GENERATOR_VERSION whenever a change to generation rules would make an existing seed produce a different spec.
GENERATOR_VERSION = "netlab-gen-1.0.0"
# Bump ARTIFACT_VERSION whenever initial artifact rendering changes for the same spec.
ARTIFACT_VERSION = "netlab-art-1.1.0"  # 1.1.0: inventory OS labels coherent with emulated dialect

SCHEMA_VERSIONS = {
    "generation_config": "1.0",
    "scenario_spec": "1.0",
    "evidence_policy": "1.0",
    "handoff": "1.0",
    "run_event": "1.1",
    "agent_report": "1.1",
    "run_result": "1.1",
}


def _pkg(name: str) -> str:
    try:
        return metadata.version(name)
    except metadata.PackageNotFoundError:
        return "not-installed"


def component_versions() -> dict[str, str]:
    return {
        "netlab": NETLAB_VERSION,
        "generator": GENERATOR_VERSION,
        "artifacts": ARTIFACT_VERSION,
        "python": sys.version.split()[0],
        "platform": f"{platform.system()}-{platform.machine()}",
        "asyncssh": _pkg("asyncssh"),
        "fastapi": _pkg("fastapi"),
        "pydantic": _pkg("pydantic"),
    }
