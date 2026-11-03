from __future__ import annotations

from pathlib import Path
from typing import Any

from secops_autopilot.config import (
    ISESettings,
    Settings,
    TenableSCSettings,
    TenableVMSettings,
)
from secops_autopilot.connectors.edr import SimulatedEDR
from secops_autopilot.connectors.ticketing import SimulatedTicketingSystem
from secops_autopilot.connectors.nac import SimulatedNAC
from secops_autopilot.controls import ControlInventory, OwnerDirectory
from secops_autopilot.models import AssetRef, Finding, PluginHit
from secops_autopilot.pipeline import Pipeline
from secops_autopilot.store import RunStore

TEST_ACCESS = "TEST-ACCESS-KEY-123456"
TEST_SECRET = "TEST-SECRET-KEY-654321"
CVE = "CVE-2024-0001"
PLUGIN_ID = 900001
PLUGIN_NAME = "MS17-010 Example SMB RCE (CVE-2024-0001)"


def make_settings(root: Path) -> Settings:
    ua = "SecOps-Autopilot/test (test@example.invalid)"
    return Settings(
        vm=TenableVMSettings(
            profile="test",
            base_url="https://tenable.example.invalid",
            access_key=TEST_ACCESS,
            secret_key=TEST_SECRET,
            user_agent=ua,
        ),
        sc=TenableSCSettings(
            profile="sc",
            base_url=None,
            access_key=None,
            secret_key=None,
            user_agent=ua,
        ),
        ise=ISESettings(base_url=None, username=None, password=None),
        runs_dir=root / "runs",
        state_dir=root / "state",
        cache_dir=root / "cache",
        date_range=90,
        isolate_threshold=80.0,
        remediation_vlan="999",
        quarantine_policy="SECOPS-QUARANTINE",
        verification_max_scan_age_hours=8760.0,
        source_preference="vm",
        secrets=(TEST_ACCESS, TEST_SECRET),
    )


def make_finding(
    *,
    asset_uuid: str = "asset-1",
    hostname: str = "srv-01",
    ipv4: str = "10.0.0.10",
    mac: str | None = "00:11:22:33:44:55",
    agent_uuid: str | None = None,
    has_patch: bool = True,
    cve: str = CVE,
    plugin_name: str = PLUGIN_NAME,
    severity: int = 4,
    cvss3: float = 9.8,
    vpr: float = 9.5,
    port: int = 445,
) -> Finding:
    return Finding(
        plugin_id=PLUGIN_ID,
        plugin_name=plugin_name,
        family="Windows",
        severity=severity,
        asset=AssetRef(
            uuid=asset_uuid,
            hostname=hostname,
            ipv4=ipv4,
            mac=mac,
            os=["Microsoft Windows Server 2016"],
            agent_uuid=agent_uuid,
            last_seen="2026-11-01T10:00:00Z",
        ),
        source="test",
        cvss3_base=cvss3,
        cvss3_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        vpr=vpr,
        cve=[cve],
        cpe=["cpe:/o:microsoft:windows"],
        exploit_available=True,
        exploited_by_malware=True,
        exploit_framework_metasploit=True,
        in_the_news=True,
        has_patch=has_patch,
        solution="Apply KB5034444 or update the product.",
        synopsis="An example SMB remote code execution issue.",
        description="Synthetic finding used by the test suite.",
        see_also=["https://example.invalid/advisory"],
        port=port,
        protocol="TCP",
        service="cifs",
        output="The remote host is missing rollup KBs:\n  - 5034444",
        first_found="2026-10-01T00:00:00Z",
        last_found="2026-11-01T10:00:00Z",
        state="OPEN",
    )


def sample_findings() -> list[Finding]:
    return [
        make_finding(
            asset_uuid="asset-1",
            hostname="srv-01",
            ipv4="10.0.0.10",
            mac="00:11:22:33:44:55",
            agent_uuid=None,
        ),
        make_finding(
            asset_uuid="asset-2",
            hostname="app-01",
            ipv4="10.0.0.11",
            mac=None,
            agent_uuid=None,
        ),
    ]


DEFAULT_DETAILS: dict[str, dict[str, Any]] = {
    "asset-1": {
        "asset_uuid": "asset-1",
        "hostname": "srv-01",
        "mac": "00:11:22:33:44:55",
        "ipv4": ["10.0.0.10"],
        "fqdn": ["srv-01.example.invalid"],
        "os": ["Microsoft Windows Server 2016"],
        "has_agent": True,
        "agent_name": "agent-1",
        "acr_score": 8.0,
        "aes_score": 850.0,
        "last_seen": "2026-11-01T10:00:00Z",
        "last_scan": "2026-11-01T09:00:00Z",
        "source_ref": "GET /assets/asset-1",
    },
    "asset-2": {
        "asset_uuid": "asset-2",
        "hostname": "app-01",
        "mac": None,
        "ipv4": ["10.0.0.11"],
        "fqdn": ["app-01.example.invalid"],
        "os": ["Microsoft Windows Server 2016"],
        "has_agent": False,
        "agent_name": None,
        "acr_score": 5.0,
        "aes_score": 700.0,
        "last_seen": "2026-11-01T10:00:00Z",
        "last_scan": "2026-11-01T09:00:00Z",
        "source_ref": "GET /assets/asset-2",
    },
}


class FakeSource:
    name = "fake_tenable"
    live = True

    def __init__(
        self,
        findings: list[Finding],
        *,
        after: list[Finding] | None = None,
        details: dict[str, dict[str, Any]] | None = None,
        agents: list[dict[str, Any]] | None = None,
        agent_reason: str | None = None,
    ) -> None:
        self.findings = findings
        self.after = after if after is not None else findings
        self.details = details or DEFAULT_DETAILS
        self.agents = agents
        self.agent_reason = agent_reason or "agent inventory not available in fake source"
        self.finding_calls = 0

    def health(self) -> dict[str, Any]:
        return {"ok": True, "product": "Fake Tenable", "workbench_read": True}

    def cve_plugin_hits(self, cve: str, date_range: int = 90) -> list[PluginHit]:
        return [
            PluginHit(
                plugin_id=PLUGIN_ID,
                plugin_name=PLUGIN_NAME,
                family="Windows",
                severity=4,
                asset_count=len({finding.asset.uuid for finding in self.findings}),
                finding_count=len(self.findings),
                cvss3_base=9.8,
                vpr=9.5,
            )
        ]

    def findings_for_plugins(
        self, plugin_ids: list[int], date_range: int = 90
    ) -> list[Finding]:
        self.finding_calls += 1
        return list(self.after if self.finding_calls > 1 else self.findings)

    def asset_detail(self, asset_uuid: str) -> dict[str, Any]:
        return self.details.get(asset_uuid, {"asset_uuid": asset_uuid, "has_agent": None})

    def agent_inventory(self) -> tuple[list[dict[str, Any]] | None, str | None]:
        return self.agents, self.agent_reason if self.agents is None else None

    def public_snapshot(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "product": "Fake Tenable",
            "base_url": "https://tenable.example.invalid",
            "user_agent": "test",
            "live": True,
        }


def make_pipeline(
    settings: Settings,
    source: FakeSource,
    *,
    owners: str | Path | None = None,
    controls: str | Path | None = None,
) -> Pipeline:
    return Pipeline(
        settings,
        source,  # type: ignore[arg-type]
        RunStore(settings),
        SimulatedTicketingSystem(settings.state_dir),
        SimulatedNAC(settings.state_dir, vlan=settings.remediation_vlan),
        SimulatedEDR(settings.state_dir),
        owners=OwnerDirectory(owners),
        controls=ControlInventory(controls),
    )
