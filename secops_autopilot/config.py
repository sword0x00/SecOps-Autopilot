"""Configuration loading and redaction.

Credentials live in a local ``.env`` (mode 0600, git-ignored) or in the process
environment. They are never written to a run record. ``Settings.redact`` is
applied to every artifact before it leaves the process.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from .errors import ConfigError
from .util import redact_text

REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_USER_AGENT = "SecOps-Autopilot/0.2.0 (SWARM Tenable Hackathon)"

PROFILES = {
    "default": ("TENABLE_ACCESS_KEY", "TENABLE_SECRET_KEY", "TENABLE_USER_AGENT"),
    "alt": ("TENABLE_ALT_ACCESS_KEY", "TENABLE_ALT_SECRET_KEY", "TENABLE_ALT_USER_AGENT"),
}
SC_PROFILE = ("TENABLE_SC_ACCESS_KEY", "TENABLE_SC_SECRET_KEY", "TENABLE_SC_USER_AGENT")


def _parse_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].strip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
            value = value[1:-1]
        values[key] = value
    return values


def load_env(extra_files: list[Path] | None = None) -> None:
    """Load ``.env`` files without overriding variables already in the process."""
    candidates = list(extra_files or [])
    candidates.extend([Path.cwd() / ".env", REPO_ROOT / ".env"])
    for path in candidates:
        for key, value in _parse_env_file(path).items():
            if key not in os.environ and value != "":
                os.environ[key] = value


def _env(key: str, default: str | None = None) -> str | None:
    value = os.environ.get(key)
    if value is None or value.strip() == "":
        return default
    return value.strip()


def _env_int(key: str, default: int) -> int:
    try:
        return int(_env(key, str(default)) or default)
    except ValueError:
        return default


def _env_float(key: str, default: float) -> float:
    try:
        return float(_env(key, str(default)) or default)
    except ValueError:
        return default


def _env_bool(key: str, default: bool) -> bool:
    value = _env(key)
    if value is None:
        return default
    return value.lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class TenableVMSettings:
    profile: str
    base_url: str
    access_key: str | None
    secret_key: str | None
    user_agent: str
    timeout: int = 60
    max_retries: int = 4

    @property
    def configured(self) -> bool:
        if not self.access_key or not self.secret_key:
            return False
        placeholders = ("replace-with", "replace_with")
        return not (
            self.access_key.startswith(placeholders)
            or self.secret_key.startswith(placeholders)
        )

    def public_snapshot(self) -> dict[str, object]:
        return {
            "product": "Tenable Vulnerability Management",
            "profile": self.profile,
            "base_url": self.base_url,
            "user_agent": self.user_agent,
            "configured": self.configured,
            "timeout_seconds": self.timeout,
            "max_retries": self.max_retries,
        }


@dataclass(frozen=True)
class TenableSCSettings:
    profile: str
    base_url: str | None
    access_key: str | None
    secret_key: str | None
    user_agent: str
    verify_tls: bool = True
    timeout: int = 60
    max_retries: int = 3

    @property
    def configured(self) -> bool:
        if not self.base_url or not self.access_key or not self.secret_key:
            return False
        placeholders = ("replace-with", "replace_with")
        return not (
            self.access_key.startswith(placeholders)
            or self.secret_key.startswith(placeholders)
        )

    def public_snapshot(self) -> dict[str, object]:
        return {
            "product": "Tenable Security Center",
            "profile": self.profile,
            "base_url": self.base_url or None,
            "user_agent": self.user_agent,
            "configured": self.configured,
            "verify_tls": self.verify_tls,
            "adapter_note": (
                "Security Center adapter is implemented against the documented "
                "/rest API but has not been exercised against a live SC appliance "
                "in this environment."
            ),
        }


@dataclass(frozen=True)
class ISESettings:
    base_url: str | None
    username: str | None
    password: str | None
    verify_tls: bool = True
    anc_action: str = "QUARANTINE"

    @property
    def configured(self) -> bool:
        return bool(self.base_url and self.username and self.password)

    def public_snapshot(self) -> dict[str, object]:
        return {
            "product": "NAC solution (Cisco ISE ERS)",
            "base_url": self.base_url or None,
            "configured": self.configured,
            "verify_tls": self.verify_tls,
            "anc_action": self.anc_action,
            "adapter_note": (
                "ERS apply/clear calls are implemented from the documented "
                "ERS API but were not exercised against a live NAC deployment here."
            ),
        }


@dataclass
class Settings:
    vm: TenableVMSettings
    sc: TenableSCSettings
    ise: ISESettings
    runs_dir: Path
    state_dir: Path
    cache_dir: Path
    date_range: int = 90
    isolate_threshold: float = 80.0
    remediation_vlan: str = "999"
    quarantine_policy: str = "SECOPS-QUARANTINE"
    verification_max_scan_age_hours: float = 72.0
    source_preference: str = "auto"
    dry_run: bool = False
    secrets: tuple[str, ...] = field(default_factory=tuple)

    @classmethod
    def load(
        cls,
        profile: str = "default",
        source: str = "auto",
        env_files: list[Path] | None = None,
        runs_dir: str | Path | None = None,
    ) -> "Settings":
        load_env(env_files)
        if profile not in PROFILES:
            raise ConfigError(
                f"unknown Tenable profile {profile!r}; expected one of {sorted(PROFILES)}"
            )
        access_key_name, secret_key_name, ua_name = PROFILES[profile]
        vm = TenableVMSettings(
            profile=profile,
            base_url=_env("TENABLE_BASE_URL", "https://cloud.tenable.com") or "https://cloud.tenable.com",
            access_key=_env(access_key_name),
            secret_key=_env(secret_key_name),
            user_agent=_env(ua_name, _env("TENABLE_USER_AGENT", DEFAULT_USER_AGENT)) or DEFAULT_USER_AGENT,
            timeout=_env_int("TENABLE_TIMEOUT", 60),
            max_retries=_env_int("TENABLE_MAX_RETRIES", 4),
        )
        sc = TenableSCSettings(
            profile="sc",
            base_url=_env("TENABLE_SC_URL"),
            access_key=_env(SC_PROFILE[0]),
            secret_key=_env(SC_PROFILE[1]),
            user_agent=_env(SC_PROFILE[2], vm.user_agent) or vm.user_agent,
            verify_tls=_env_bool("TENABLE_SC_VERIFY_TLS", True),
            timeout=_env_int("TENABLE_SC_TIMEOUT", 60),
        )
        ise = ISESettings(
            base_url=_env("ISE_URL"),
            username=_env("ISE_USERNAME"),
            password=_env("ISE_PASSWORD"),
            verify_tls=_env_bool("ISE_VERIFY_TLS", True),
            anc_action=_env("ISE_ANC_ACTION", "QUARANTINE") or "QUARANTINE",
        )
        se = str(REPO_ROOT)
        resolved_runs = Path(
            runs_dir or _env("SECOPS_RUNS_DIR", str(Path(se) / "runs")) or (Path(se) / "runs")
        ).expanduser().resolve()
        state_dir = Path(_env("SECOPS_STATE_DIR", str(Path(se) / ".state")) or (Path(se) / ".state")).resolve()
        cache_dir = Path(_env("SECOPS_CACHE_DIR", str(Path(se) / ".cache")) or (Path(se) / ".cache")).resolve()
        secrets = tuple(
            value
            for value in (
                vm.access_key,
                vm.secret_key,
                sc.access_key,
                sc.secret_key,
                _env("TENABLE_ALT_ACCESS_KEY"),
                _env("TENABLE_ALT_SECRET_KEY"),
                ise.password,
            )
            if value
        )
        return cls(
            vm=vm,
            sc=sc,
            ise=ise,
            runs_dir=resolved_runs,
            state_dir=state_dir,
            cache_dir=cache_dir,
            date_range=_env_int("SECOPS_DATE_RANGE_DAYS", 90),
            isolate_threshold=_env_float("SECOPS_ISOLATE_THRESHOLD", 80.0),
            remediation_vlan=_env("SECOPS_REMEDIATION_VLAN", "999") or "999",
            quarantine_policy=_env("SECOPS_QUARANTINE_POLICY", "SECOPS-QUARANTINE") or "SECOPS-QUARANTINE",
            verification_max_scan_age_hours=_env_float(
                "SECOPS_VERIFICATION_MAX_SCAN_AGE_HOURS", 72.0
            ),
            source_preference=source,
            secrets=secrets,
        )

    def resolve_source(self) -> str:
        if self.source_preference in {"vm", "sc"}:
            if self.source_preference == "vm" and not self.vm.configured:
                raise ConfigError(
                    "Tenable VM credentials are not configured; set TENABLE_ACCESS_KEY "
                    "and TENABLE_SECRET_KEY in .env"
                )
            if self.source_preference == "sc" and not self.sc.configured:
                raise ConfigError(
                    "Tenable Security Center is not configured; set TENABLE_SC_URL, "
                    "TENABLE_SC_ACCESS_KEY and TENABLE_SC_SECRET_KEY"
                )
            return self.source_preference
        if self.source_preference != "auto":
            raise ConfigError("source must be one of: auto, vm, sc")
        if self.vm.configured:
            return "vm"
        if self.sc.configured:
            return "sc"
        raise ConfigError(
            "no Tenable source configured. Set TENABLE_ACCESS_KEY/TENABLE_SECRET_KEY "
            "for Vulnerability Management, or the TENABLE_SC_* variables for Security Center."
        )

    def public_snapshot(self) -> dict[str, object]:
        return {
            "source_preference": self.source_preference,
            "tenable_vm": self.vm.public_snapshot(),
            "tenable_sc": self.sc.public_snapshot(),
            "ise": self.ise.public_snapshot(),
            "date_range_days": self.date_range,
            "isolate_threshold": self.isolate_threshold,
            "remediation_vlan": self.remediation_vlan,
            "quarantine_policy": self.quarantine_policy,
            "verification_max_scan_age_hours": self.verification_max_scan_age_hours,
            "runs_dir": str(self.runs_dir),
            "state_dir": str(self.state_dir),
        }

    def redact(self, text: str) -> str:
        return redact_text(text, self.secrets)
