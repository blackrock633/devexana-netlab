"""Server-side run event log: the authoritative record of everything the agent under test did and saw."""

from __future__ import annotations

import json
import threading
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from netlab.schemas import RunEvent

SECRET_KEYS = {"password", "api_token", "apitoken", "token", "secret", "authorization"}


def scrub(obj: Any) -> Any:
    if isinstance(obj, dict):
        return {k: ("[redacted]" if k.lower() in SECRET_KEYS else scrub(v)) for k, v in obj.items()}
    if isinstance(obj, list):
        return [scrub(x) for x in obj]
    return obj


class EventLog:
    def __init__(self, path: Path | None, t0_mono: float):
        self.path = path
        self.t0 = t0_mono
        self.lock = threading.Lock()
        self.events: list[RunEvent] = []
        self._fh = path.open("a", encoding="utf-8") if path else None

    def t_rel(self) -> float:
        return round(time.monotonic() - self.t0, 3)

    def add(
        self,
        source: str,
        kind: str,
        *,
        actor: str = "",
        target: str = "",
        detail: dict[str, Any] | None = None,
        ok: bool = True,
        reveals: list[str] | None = None,
        symptoms: list[str] | None = None,
        change: dict[str, Any] | None = None,
    ) -> RunEvent:
        with self.lock:
            ev = RunEvent(
                seq=len(self.events) + 1,
                ts=datetime.now(UTC).isoformat(timespec="milliseconds"),
                t_rel_s=self.t_rel(),
                source=source,
                kind=kind,
                actor=actor,
                target=target,  # type: ignore[arg-type]
                detail=scrub(detail or {}),
                ok=ok,
                reveals=sorted(set(reveals or [])),
                symptoms=sorted(set(symptoms or [])),
                change=scrub(change) if change else None,
            )
            self.events.append(ev)
            if self._fh:
                self._fh.write(ev.model_dump_json() + "\n")
                self._fh.flush()
            return ev

    def since(self, seq: int) -> list[RunEvent]:
        with self.lock:
            return list(self.events[seq:])

    def close(self) -> None:
        if self._fh:
            self._fh.close()
            self._fh = None


def load_events(path: Path) -> list[RunEvent]:
    if not path.exists():
        return []
    return [RunEvent.model_validate(json.loads(line)) for line in path.read_text().splitlines() if line.strip()]
