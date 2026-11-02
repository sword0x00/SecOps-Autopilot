"""Small utilities shared by the engine.

No third-party dependencies: the engine must run in a bare Python environment
and in CI with nothing more than ``requests`` installed.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

UNKNOWN = "unknown"


def utc_now() -> str:
    """Return an RFC3339 UTC timestamp with second precision."""
    return (
        datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str)


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def sha256_obj(obj: Any) -> str:
    return sha256_text(canonical_json(obj))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def truncate(text: str | None, limit: int = 8000) -> str:
    if not text:
        return ""
    if len(text) <= limit:
        return text
    return text[:limit] + f"\n...[truncated {len(text) - limit} chars]"


def first_nonempty(*values: Any) -> Any:
    for value in values:
        if value is None:
            continue
        if isinstance(value, str) and not value.strip():
            continue
        if isinstance(value, (list, dict)) and not value:
            continue
        return value
    return None


def as_float(value: Any) -> float | None:
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def as_int(value: Any) -> int | None:
    if value is None or value == "":
        return None
    try:
        return int(float(value))
    except (TypeError, ValueError):
        return None


def as_bool(value: Any) -> bool | None:
    if value is None or value == "":
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return bool(value)
    text = str(value).strip().lower()
    if text in {"true", "yes", "1", "y"}:
        return True
    if text in {"false", "no", "0", "n"}:
        return False
    return None


def dedupe(values: Iterable[Any]) -> list[Any]:
    seen: set[str] = set()
    out: list[Any] = []
    for value in values:
        if value is None:
            continue
        key = str(value)
        if key in seen:
            continue
        seen.add(key)
        out.append(value)
    return out


def safe_name(value: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]+", "-", value).strip("-")
    return cleaned[:80] or "run"


def atomic_write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, path)
    finally:
        if os.path.exists(tmp_name):
            os.unlink(tmp_name)


def write_json(path: Path, obj: Any) -> None:
    atomic_write(path, json.dumps(obj, indent=2, sort_keys=False, default=str) + "\n")


def read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


_REF_PATTERNS = {
    "kb": re.compile(r"\bKB\d{5,8}\b", re.IGNORECASE),
    "usn": re.compile(r"\bUSN-\d{4}-\d+\b", re.IGNORECASE),
    "rhsa": re.compile(r"\bRHSA-\d{4}:\d+\b", re.IGNORECASE),
    "elsa": re.compile(r"\bELSA-\d{4}-\d+\b", re.IGNORECASE),
    "suse": re.compile(r"\bSUSE-SU-\d{4}:\d+\b", re.IGNORECASE),
    "rlsa": re.compile(r"\bRLSA-\d{4}:\d+\b", re.IGNORECASE),
    "dsa": re.compile(r"\bDSA-\d{4}-\d+\b", re.IGNORECASE),
    "msrc": re.compile(r"\bMS\d{2}-\d{3}\b", re.IGNORECASE),
    "cve": re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE),
    "advisory": re.compile(r"\b(?:TNS|JSA|cisa-sa)-\d{4}[-:]\d+\b", re.IGNORECASE),
}


def extract_refs(text: str | None) -> dict[str, list[str]]:
    """Extract patch/advisory identifiers from plugin text.

    Only identifiers that literally appear in the source text are returned;
    nothing is inferred.
    """
    if not text:
        return {}
    found: dict[str, list[str]] = {}
    for kind, pattern in _REF_PATTERNS.items():
        matches = dedupe(m.group(0).upper() if kind != "advisory" else m.group(0) for m in pattern.finditer(text))
        if matches:
            found[kind] = matches
    return found


def extract_kb_refs(text: str | None) -> list[str]:
    """Extract Microsoft KB identifiers, including bare numbers in Tenable text.

    Tenable plugin names commonly render a KB as ``(4013389)`` and plugin output
    as ``- 4013429``. Requiring the literal ``KB`` prefix would drop real patch
    references, so those two contexts are handled explicitly.
    """
    if not text:
        return []
    refs: list[str] = []
    for match in re.finditer(r"\bKB\d{5,8}\b", text, re.IGNORECASE):
        refs.append(match.group(0).upper())
    for match in re.finditer(r"\((4\d{6})\)", text):
        refs.append(f"KB{match.group(1)}")
    for match in re.finditer(r"(?im)^\s*-\s*(4\d{6})\b", text):
        refs.append(f"KB{match.group(1)}")
    return dedupe(refs)


def severity_label(severity: int | None) -> str:
    return {4: "critical", 3: "high", 2: "medium", 1: "low", 0: "info"}.get(
        severity if severity is not None else -1, UNKNOWN
    )


def severity_baseline(severity: int | None) -> float:
    """Map Tenable's severity band to a 0-10 baseline when CVSS is absent."""
    return {4: 9.5, 3: 8.0, 2: 5.5, 1: 2.5, 0: 0.0}.get(
        severity if severity is not None else -1, 5.0
    )


def normalize_mac(value: str | None) -> str | None:
    if not value:
        return None
    cleaned = re.sub(r"[^0-9A-Fa-f]", "", value)
    if len(cleaned) != 12:
        return None
    return ":".join(cleaned[i : i + 2] for i in range(0, 12, 2)).lower()


def relative_age_hours(timestamp: str | None, now: datetime | None = None) -> float | None:
    parsed = parse_iso(timestamp)
    if parsed is None:
        return None
    now = now or datetime.now(timezone.utc)
    return round((now - parsed).total_seconds() / 3600.0, 1)


def redact_text(text: str, secrets: Iterable[str]) -> str:
    for secret in secrets:
        if secret and len(secret) >= 6 and secret in text:
            text = text.replace(secret, "[REDACTED]")
    # Defensive: scrub any X-ApiKeys header that might have been formatted.
    text = re.sub(
        r"(X-ApiKeys:\s*accessKey=)[^;\n]+(;\s*secretKey=)[^;\n]+(;?)",
        r"\1[REDACTED]\2[REDACTED]\3",
        text,
        flags=re.IGNORECASE,
    )
    return text
