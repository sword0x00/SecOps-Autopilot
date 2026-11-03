"""Connector interfaces.

The pipeline depends on these protocols, not on a specific product. That is
what lets the same stages run against Tenable Vulnerability Management, Tenable
Security Center, or a fake source in tests.
"""

from __future__ import annotations

from typing import Any, Protocol

from ..models import Finding, PluginHit


class VulnerabilitySource(Protocol):
    """Read-only vulnerability and asset inventory."""

    name: str
    live: bool

    def health(self) -> dict[str, Any]:
        ...

    def cve_plugin_hits(self, cve: str, date_range: int = 90) -> list[PluginHit]:
        ...

    def findings_for_plugins(
        self, plugin_ids: list[int], date_range: int = 90
    ) -> list[Finding]:
        ...

    def asset_detail(self, asset_uuid: str) -> dict[str, Any]:
        ...

    def agent_inventory(self) -> tuple[list[dict[str, Any]] | None, str | None]:
        """Return (agents, unknown_reason).

        ``agents`` is ``None`` when the credential cannot read agent inventory;
        the reason is then a human-readable explanation recorded as an unknown.
        """

    def public_snapshot(self) -> dict[str, Any]:
        ...


class TicketingConnector(Protocol):
    name: str
    live: bool

    def create_ticket(self, payload: dict[str, Any]) -> dict[str, Any]:
        ...

    def approve_ticket(self, ticket_id: str, approver: str, note: str) -> dict[str, Any]:
        ...

    def reject_ticket(self, ticket_id: str, approver: str, note: str) -> dict[str, Any]:
        ...

    def update_ticket(self, ticket_id: str, fields: dict[str, Any]) -> dict[str, Any]:
        ...


class NACConnector(Protocol):
    name: str
    live: bool

    def quarantine(
        self,
        *,
        asset_uuid: str,
        hostname: str,
        mac: str | None,
        policy: str,
        vlan: str,
        reason: str,
        approver: str,
        ticket_id: str,
    ) -> dict[str, Any]:
        ...

    def restore(
        self,
        *,
        asset_uuid: str,
        hostname: str,
        mac: str | None,
        reason: str,
        approver: str,
        ticket_id: str,
    ) -> dict[str, Any]:
        ...


class EDRConnector(Protocol):
    name: str
    live: bool

    def status(self, asset_uuid: str, hostname: str) -> dict[str, Any]:
        ...
