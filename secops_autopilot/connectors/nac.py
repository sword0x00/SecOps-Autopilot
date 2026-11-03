"""NAC connectors.

The safe default is ``SimulatedNAC`` (file-backed endpoint state). When Cisco
ISE ERS credentials are configured, ``CiscoISEAdapter`` issues the documented
ERS apply/clear calls. The adapter is intentionally loud about not being
live-validated in this environment.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import requests

from ..config import ISESettings
from ..errors import AuthError, ConnectorError, NotFoundError, ScopeError
from ..util import utc_now
from .state import JsonState


class SimulatedNAC:
    name = "simulated_ise"
    live = False
    simulated = True

    def __init__(self, state_dir: Path, *, vlan: str = "999") -> None:
        self.state = JsonState(state_dir / "nac.json")
        self.vlan = vlan

    def _apply(
        self,
        *,
        action: str,
        asset_uuid: str,
        hostname: str,
        mac: str | None,
        policy: str,
        vlan: str | None,
        reason: str,
        approver: str,
        ticket_id: str,
    ) -> dict[str, Any]:
        if not mac:
            raise ConnectorError(
                "The NAC solution requires an endpoint MAC address; this asset has none. "
                "Containment must be performed manually or the asset identity enriched."
            )

        def mutate(data: dict[str, Any]) -> dict[str, Any]:
            endpoints = data.setdefault("endpoints", {})
            current = endpoints.get(mac)
            if action == "quarantine" and current and current.get("status") == "isolated":
                return {**current, "idempotent": True}
            next_id = int(data.get("next_id", 1))
            data["next_id"] = next_id + 1
            event = {
                "event_id": f"SIM-NAC-{next_id:06d}",
                "asset_uuid": asset_uuid,
                "hostname": hostname,
                "mac": mac,
                "action": action,
                "status": "isolated" if action == "quarantine" else "restored",
                "policy": policy,
                "vlan": vlan,
                "timestamp": utc_now(),
                "approver": approver,
                "ticket_id": ticket_id,
                "connector": self.name,
                "simulated": True,
                "reason": reason,
            }
            endpoints[mac] = event
            data.setdefault("events", []).append(event)
            return event

        return self.state.update(mutate, {"next_id": 1, "endpoints": {}, "events": []})

    def quarantine(self, **kwargs: Any) -> dict[str, Any]:
        kwargs.pop("action", None)
        return self._apply(action="quarantine", **kwargs)

    def restore(self, **kwargs: Any) -> dict[str, Any]:
        kwargs.pop("action", None)
        kwargs.pop("policy", None)
        kwargs.pop("vlan", None)
        return self._apply(action="restore", vlan=None, policy="", **kwargs)

    def public_snapshot(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "product": "NAC solution (simulated)",
            "live": False,
            "simulated": True,
            "note": (
                "No NAC action left this machine. Endpoint isolation events are "
                "file-backed in .state/nac.json for the demonstration run."
            ),
            "remediation_vlan": self.vlan,
        }


class CiscoISEAdapter:
    name = "cisco_ise"
    live = True
    simulated = False

    def __init__(
        self,
        settings: ISESettings,
        *,
        state_dir: Path,
        vlan: str = "999",
        timeout: int = 30,
    ) -> None:
        if not settings.configured:
            raise ConnectorError("NAC solution adapter (Cisco ISE ERS) is not configured")
        self.settings = settings
        self.base_url = (settings.base_url or "").rstrip("/")
        self.timeout = timeout
        self.vlan = vlan
        self.audit = JsonState(state_dir / "ise_audit.json")
        self.session = requests.Session()
        self.session.auth = (settings.username or "", settings.password or "")
        self.session.headers.update(
            {
                "Accept": "application/json",
                "Content-Type": "application/json",
                "User-Agent": "SecOps-Autopilot/0.2.0 (Cisco ISE ERS)",
            }
        )
        self.session.verify = settings.verify_tls

    # -- HTTP -----------------------------------------------------------

    def _request(self, method: str, path: str, body: dict[str, Any] | None = None) -> int:
        url = f"{self.base_url}{path}"
        try:
            response = self.session.request(
                method, url, json=body, timeout=(10, self.timeout)
            )
        except requests.RequestException as exc:
            raise ConnectorError(f"ISE {method} {path} failed: {exc}") from exc
        if response.status_code in {200, 201, 202, 204}:
            return response.status_code
        if response.status_code == 409:
            return response.status_code  # already applied; idempotent
        detail = (response.text or "").strip()[:400]
        if response.status_code == 404:
            raise NotFoundError(f"ISE {method} {path} returned HTTP 404: {detail}")
        if response.status_code == 401:
            raise AuthError(f"ISE rejected the ERS credentials (HTTP 401): {detail}")
        if response.status_code == 403:
            raise ScopeError(f"ISE ERS user lacks permission (HTTP 403): {detail}")
        raise ConnectorError(
            f"ISE {method} {path} returned HTTP {response.status_code}: {detail}"
        )

    def _ensure_policy(self) -> None:
        try:
            self._request("GET", f"/ers/config/ancpolicy/{self.settings.anc_action}")
        except NotFoundError:
            body = {
                "ErsAncPolicy": {
                    "name": self.settings.anc_action,
                    "actions": [self.settings.anc_action],
                }
            }
            self._request("POST", "/ers/config/ancpolicy", body)

    # -- actions --------------------------------------------------------

    def _apply(self, action: str, **kwargs: Any) -> dict[str, Any]:
        mac = kwargs.get("mac")
        if not mac:
            raise ConnectorError(
                "The NAC solution requires an endpoint MAC address; this asset has none."
            )
        # The NAC quarantine policy is a configured control-plane object; do not send
        # the run's audit label as the policy name.
        policy = self.settings.anc_action
        self._ensure_policy()
        body = {
            "OperationAdditionalData": {
                "additionalData": [
                    {"name": "macAddress", "value": mac},
                    {"name": "policyName", "value": policy},
                ]
            }
        }
        if action == "quarantine":
            self._request("PUT", "/ers/config/ancendpoint/apply", body)
            status = "isolated"
            vlan = kwargs.get("vlan") or self.vlan
        else:
            clear_body = {
                "OperationAdditionalData": {
                    "additionalData": [{"name": "macAddress", "value": mac}]
                }
            }
            self._request("PUT", "/ers/config/ancendpoint/clear", clear_body)
            status = "restored"
            vlan = None
        event = {
            "event_id": None,
            "asset_uuid": kwargs.get("asset_uuid"),
            "hostname": kwargs.get("hostname"),
            "mac": mac,
            "action": action,
            "status": status,
            "policy": policy,
            "vlan": vlan,
            "timestamp": utc_now(),
            "approver": kwargs.get("approver"),
            "ticket_id": kwargs.get("ticket_id"),
            "connector": self.name,
            "simulated": False,
            "validated": False,
            "reason": kwargs.get("reason"),
        }

        def mutate(data: dict[str, Any]) -> dict[str, Any]:
            next_id = int(data.get("next_id", 1))
            data["next_id"] = next_id + 1
            event["event_id"] = f"NAC-{next_id:06d}"
            data.setdefault("events", []).append(event)
            return event

        return self.audit.update(mutate, {"next_id": 1, "events": []})

    def quarantine(self, **kwargs: Any) -> dict[str, Any]:
        return self._apply("quarantine", **kwargs)

    def restore(self, **kwargs: Any) -> dict[str, Any]:
        return self._apply("restore", **kwargs)

    def public_snapshot(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "product": "NAC solution (Cisco ISE ERS)",
            "base_url": self.base_url,
            "live": True,
            "simulated": False,
            "validated": False,
            "note": (
                "ERS apply/clear calls follow the documented API but have not "
                "been exercised against a live NAC deployment in this environment."
            ),
            "remediation_vlan": self.vlan,
        }


def build_nac(settings: Any) -> SimulatedNAC | CiscoISEAdapter:
    if getattr(settings, "ise", None) and settings.ise.configured:
        return CiscoISEAdapter(
            settings.ise,
            state_dir=settings.state_dir,
            vlan=settings.remediation_vlan,
        )
    return SimulatedNAC(settings.state_dir, vlan=settings.remediation_vlan)
