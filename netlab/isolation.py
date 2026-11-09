"""Agent isolation: run the agent under test in a kernel-enforced sandbox that cannot read evaluator state.

* macOS: ``/usr/bin/sandbox-exec`` (Seatbelt) with a profile that denies every file read/write under the protected
  paths ($NETLAB_VAR: scenario specs, run directories, results, events, the operator token and the at-rest key).
  Everything else (Python, the venv, network to 127.0.0.1) stays allowed. Verified in tests/test_isolation.py.
* Linux: ``bwrap`` (bubblewrap) mounts an empty tmpfs over each protected path. Implemented but NOT tested here
  (the development host is macOS).
* Neither available: the run is refused unless the caller explicitly allows an unisolated ("cooperative client")
  run, which is then labelled as such in meta.json and result.json.

Limits: the sandbox restricts the filesystem only. It is not a defence against kernel exploits, nor does it
restrict network access to other local services. For adversarial agents, use a separate OS user or host.
"""

from __future__ import annotations

import os
import platform
import shutil
from pathlib import Path

SANDBOX_EXEC = "/usr/bin/sandbox-exec"


class IsolationUnavailable(RuntimeError):
    pass


def mechanism() -> str:
    if platform.system() == "Darwin" and os.access(SANDBOX_EXEC, os.X_OK):
        return "sandbox-exec"
    if platform.system() == "Linux" and shutil.which("bwrap"):
        return "bwrap"
    return "none"


def _sb_quote(p: str) -> str:
    return '"' + p.replace("\\", "\\\\").replace('"', '\\"') + '"'


def seatbelt_profile(protected: list[Path]) -> str:
    paths = " ".join(f"(subpath {_sb_quote(os.path.realpath(p))})" for p in protected)
    return f"(version 1)\n(allow default)\n(deny file-read* file-write* {paths})\n"


def wrap(cmd: list[str], protected: list[Path], workdir: Path, allow_unisolated: bool = False) -> tuple[list[str], str]:
    """Return (command to execute, isolation label)."""
    m = mechanism()
    if m == "sandbox-exec":
        prof = workdir / "agent.sb"
        prof.write_text(seatbelt_profile(protected))
        return [SANDBOX_EXEC, "-f", str(prof), *cmd], "sandbox-exec: evaluator state unreadable"
    if m == "bwrap":
        mounts = [x for p in protected for x in ("--tmpfs", os.path.realpath(p))]
        return [
            "bwrap",
            "--dev-bind",
            "/",
            "/",
            *mounts,
            "--die-with-parent",
            "--",
            *cmd,
        ], "bwrap: evaluator state hidden (untested on this host)"
    if allow_unisolated or os.environ.get("NETLAB_ALLOW_UNISOLATED") == "1":
        return cmd, "none: cooperative client (agent could read evaluator state)"
    raise IsolationUnavailable(
        "No sandbox mechanism (sandbox-exec or bwrap) is available, so the agent could read ground truth. "
        "Install bubblewrap, run the agent on another host/user, or set NETLAB_ALLOW_UNISOLATED=1 to run a "
        "labelled cooperative-client evaluation."
    )
