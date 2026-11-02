"""Small file-backed state store for simulated connectors.

The simulators are deliberately boring: JSON on disk, an exclusive file lock
around each mutation, and an atomic replace. This keeps demo state inspectable
and avoids a database dependency.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

from ..errors import ConnectorError
from ..util import atomic_write

try:  # POSIX
    import fcntl
except ImportError:  # pragma: no cover - Windows fallback
    fcntl = None  # type: ignore[assignment]


class JsonState:
    def __init__(self, path: Path) -> None:
        self.path = path

    def read(self, default: dict[str, Any] | None = None) -> dict[str, Any]:
        if not self.path.is_file():
            return dict(default or {})
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ConnectorError(f"state file {self.path} is unreadable or corrupt: {exc}") from exc
        if not isinstance(data, dict):
            raise ConnectorError(f"state file {self.path} does not contain a JSON object")
        return data

    def update(
        self, mutator: Callable[[dict[str, Any]], Any], default: dict[str, Any] | None = None
    ) -> Any:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        lock_path = self.path.with_suffix(self.path.suffix + ".lock")
        lock_handle = lock_path.open("a+", encoding="utf-8")
        try:
            if fcntl is not None:
                fcntl.flock(lock_handle.fileno(), fcntl.LOCK_EX)
            data = self.read(default)
            result = mutator(data)
            atomic_write(self.path, json.dumps(data, indent=2, sort_keys=True) + "\n")
            return result
        finally:
            try:
                if fcntl is not None:
                    fcntl.flock(lock_handle.fileno(), fcntl.LOCK_UN)
            finally:
                lock_handle.close()
