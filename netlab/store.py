"""Evaluator-private storage: ground truth (scenario specs) and results are encrypted at rest (AES-256-GCM).

This is defence in depth, not the isolation boundary. The boundary is ``netlab.isolation``: every agent under test
runs in a kernel-enforced sandbox that cannot read ``$NETLAB_VAR``, which holds both these files and the key.
At-rest encryption additionally means that a process outside the sandbox that reads a scenario file directly sees
only ciphertext. A same-user process outside the sandbox that ALSO reads the key file can decrypt; protecting
against arbitrary same-user processes needs a separate OS user or host (see docs/ARCHITECTURE.md).
"""

from __future__ import annotations

import os
import secrets
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

MAGIC = b"NETLAB-SEALED-1\n"


def key_path(var: Path) -> Path:
    return var / "keys" / "evaluator.key"


def _key(var: Path) -> bytes:
    p = key_path(var)
    if not p.exists():
        p.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(secrets.token_bytes(32))
    k = p.read_bytes()
    if len(k) != 32:
        raise ValueError(f"evaluator key {p} is corrupt")
    return k


def seal(var: Path, path: Path, text: str) -> Path:
    """Encrypt ``text`` to ``path`` (authenticated; the file name is bound as associated data)."""
    nonce = secrets.token_bytes(12)
    ct = AESGCM(_key(var)).encrypt(nonce, text.encode(), path.name.encode())
    tmp = path.with_suffix(path.suffix + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(MAGIC + nonce + ct)
    os.replace(tmp, path)
    return path


def unseal(var: Path, path: Path) -> str:
    raw = path.read_bytes()
    if not raw.startswith(MAGIC):
        raise ValueError(f"{path} is not a sealed netlab file")
    body = raw[len(MAGIC) :]
    return AESGCM(_key(var)).decrypt(body[:12], body[12:], path.name.encode()).decode()
