"""Run store and evidence chain.

Layout for each run::

    runs/<run_id>/
      run.json
      report.md
      report.html
      stages/01-intake.json
      ...
      manifest.json
      manifest.sha256

Every write is redacted, atomic, and mode 0600. The manifest is a SHA-256 chain
over the run record, stage records, and reports so a reviewer can detect a
modified artifact.
"""

from __future__ import annotations

import dataclasses
import json
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .config import Settings
from .errors import EvidenceError, StateError
from .models import STAGE_LABELS, RunState, StageRecord
from .report import render_html, render_markdown
from .util import (
    atomic_write,
    read_json,
    safe_name,
    sha256_file,
    utc_now,
)


class RunStore:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings
        self.root = settings.runs_dir
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            os.chmod(self.root, 0o700)
        except OSError:
            pass

    # -- creation / loading --------------------------------------------

    def new_run_id(self, target: str) -> str:
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        return f"{stamp}-{safe_name(target)}-{secrets.token_hex(3)}"

    def run_dir(self, run_id: str) -> Path:
        return self.root / run_id

    def create(
        self,
        target: dict[str, Any],
        options: dict[str, Any],
        source: dict[str, Any],
        *,
        run_id: str | None = None,
    ) -> RunState:
        run_id = run_id or self.new_run_id(str(target.get("value") or "run"))
        run = RunState.new(run_id, target, options, source)
        directory = self.run_dir(run_id)
        directory.mkdir(parents=True, exist_ok=False)
        try:
            os.chmod(directory, 0o700)
        except OSError:
            pass
        (directory / "stages").mkdir(mode=0o700)
        self.save(run)
        return run

    def load(self, run_id_or_prefix: str) -> RunState:
        directory = self.root / run_id_or_prefix
        if not directory.is_dir():
            matches = sorted(
                path for path in self.root.iterdir() if path.is_dir() and path.name.startswith(run_id_or_prefix)
            )
            if not matches:
                raise StateError(f"run {run_id_or_prefix!r} not found under {self.root}")
            if len(matches) > 1:
                names = ", ".join(path.name for path in matches[:8])
                raise StateError(
                    f"run prefix {run_id_or_prefix!r} is ambiguous: {names}"
                )
            directory = matches[0]
        path = directory / "run.json"
        if not path.is_file():
            raise StateError(f"run {directory.name} has no run.json")
        data = read_json(path)
        if not isinstance(data, dict):
            raise StateError(f"run {directory.name} run.json is not an object")
        field_names = {field.name for field in dataclasses.fields(RunState)}
        filtered = {key: value for key, value in data.items() if key in field_names}
        return RunState(**filtered)

    def list_runs(self) -> list[dict[str, Any]]:
        summaries: list[dict[str, Any]] = []
        if not self.root.is_dir():
            return summaries
        for directory in self.root.iterdir():
            path = directory / "run.json"
            if not path.is_file():
                continue
            try:
                data = read_json(path)
            except (OSError, ValueError):
                continue
            summaries.append(
                {
                    "run_id": data.get("run_id", directory.name),
                    "created_at": data.get("created_at"),
                    "status": data.get("status"),
                    "target": (data.get("target") or {}).get("value"),
                    "assets": len(data.get("exposure") or []),
                }
            )
        summaries.sort(key=lambda item: item.get("created_at") or "", reverse=True)
        return summaries

    # -- writes ---------------------------------------------------------

    def save(self, run: RunState) -> None:
        run.updated_at = utc_now()
        directory = self.run_dir(run.run_id)
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        text = json.dumps(run.to_dict(), indent=2, sort_keys=False, default=str) + "\n"
        path = directory / "run.json"
        atomic_write(path, self.settings.redact(text))
        self._secure(path)

    def write_stage(
        self,
        run: RunState,
        stage: str,
        payload: dict[str, Any],
        *,
        summary: str,
        status: str = "complete",
        started_at: str | None = None,
        unknowns: list[dict[str, str]] | None = None,
        errors: list[str] | None = None,
        source_calls: list[dict[str, Any]] | None = None,
    ) -> StageRecord:
        index = len(run.stages) + 1
        rel_path = f"stages/{index:02d}-{safe_name(stage)}.json"
        path = self.run_dir(run.run_id) / rel_path
        text = json.dumps(payload, indent=2, sort_keys=False, default=str) + "\n"
        atomic_write(path, self.settings.redact(text))
        self._secure(path)
        record = StageRecord(
            stage=stage,
            name=STAGE_LABELS.get(stage, stage.replace("_", " ").title()),
            status=status,
            started_at=started_at or utc_now(),
            finished_at=utc_now(),
            summary=summary,
            data_ref=rel_path,
            unknowns=unknowns or [],
            errors=errors or [],
            source_calls=(source_calls or [])[-50:],
        )
        run.stages[stage] = record.to_dict()
        self.save(run)
        return record

    def write_reports(self, run: RunState) -> None:
        directory = self.run_dir(run.run_id)
        run.artifacts.update(
            {
                "run": "run.json",
                "markdown": "report.md",
                "html": "report.html",
            }
        )
        markdown = self.settings.redact(render_markdown(run))
        html = self.settings.redact(render_html(run))
        atomic_write(directory / "report.md", markdown)
        atomic_write(directory / "report.html", html)
        self._secure(directory / "report.md")
        self._secure(directory / "report.html")
        self.save(run)

    def finalize(self, run: RunState) -> dict[str, Any]:
        """Write reports, hash every artifact, and emit the manifest."""
        run.artifacts["manifest"] = "manifest.json"
        run.artifacts["manifest_sha256"] = "manifest.sha256"
        self.write_reports(run)
        directory = self.run_dir(run.run_id)
        files: dict[str, str] = {}
        for path in sorted(directory.rglob("*")):
            if not path.is_file():
                continue
            if path.name in {"manifest.json", "manifest.sha256"}:
                continue
            if path.suffix == ".lock":
                continue
            rel = path.relative_to(directory).as_posix()
            files[rel] = sha256_file(path)
        manifest = {
            "run_id": run.run_id,
            "generated_at": utc_now(),
            "algorithm": "sha256",
            "files": files,
            "note": (
                "Hashes cover every artifact in this directory except the manifest "
                "itself. Recompute with `secops evidence --run <id> --verify`."
            ),
        }
        manifest_path = directory / "manifest.json"
        atomic_write(manifest_path, json.dumps(manifest, indent=2, sort_keys=True) + "\n")
        lines = [f"{digest}  {rel}" for rel, digest in sorted(files.items())]
        atomic_write(directory / "manifest.sha256", "\n".join(lines) + "\n")
        self._secure(manifest_path)
        self._secure(directory / "manifest.sha256")
        run.artifacts["manifest"] = "manifest.json"
        run.artifacts["manifest_sha256"] = "manifest.sha256"
        return manifest

    def verify_manifest(self, run_id_or_path: str) -> dict[str, Any]:
        path = Path(run_id_or_path)
        directory = path if path.is_dir() else self.run_dir(run_id_or_path)
        manifest_path = directory / "manifest.json"
        if not manifest_path.is_file():
            raise EvidenceError(
                f"no manifest.json in {directory}; run `secops evidence --run {directory.name}` first"
            )
        manifest = read_json(manifest_path)
        files = manifest.get("files") or {}
        checked: list[dict[str, Any]] = []
        ok = True
        for rel, expected in files.items():
            target = directory / rel
            if not target.is_file():
                checked.append({"file": rel, "status": "missing"})
                ok = False
                continue
            actual = sha256_file(target)
            status = "ok" if actual == expected else "mismatch"
            if status != "ok":
                ok = False
            checked.append(
                {"file": rel, "status": status, "expected": expected, "actual": actual}
            )
        known = set(files)
        extras = []
        for target in sorted(directory.rglob("*")):
            if not target.is_file():
                continue
            rel = target.relative_to(directory).as_posix()
            if rel in known or rel in {"manifest.json", "manifest.sha256"}:
                continue
            if target.suffix == ".lock":
                continue
            extras.append(rel)
        return {
            "ok": ok,
            "run_id": manifest.get("run_id"),
            "checked": checked,
            "unlisted_files": extras,
            "checked_at": utc_now(),
        }

    @staticmethod
    def _secure(path: Path) -> None:
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
