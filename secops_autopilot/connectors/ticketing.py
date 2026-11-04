"""Ticketing-system connectors.

``SimulatedTicketingSystem`` is the safe default: it records tickets as JSON so
the approval chain is demonstrable without touching ServiceNow, Jira, or another
ticketing system. A real connector implements the same four methods from
``connectors.base.TicketingConnector``.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from ..errors import ConnectorError
from ..util import utc_now
from .state import JsonState


class SimulatedTicketingSystem:
    name = "simulated_ticketing"
    live = False
    simulated = True

    def __init__(self, state_dir: Path) -> None:
        self.state = JsonState(state_dir / "ticketing.json")

    def create_ticket(self, payload: dict[str, Any]) -> dict[str, Any]:
        def mutate(data: dict[str, Any]) -> dict[str, Any]:
            next_id = int(data.get("next_id", 1))
            ticket_id = f"SIM-TKT-{next_id:06d}"
            data["next_id"] = next_id + 1
            ticket = {
                "ticket_id": ticket_id,
                "system": self.name,
                "status": "PENDING_APPROVAL",
                "created_at": utc_now(),
                "simulated": True,
            }
            ticket.update(payload)
            data.setdefault("tickets", {})[ticket_id] = ticket
            return ticket

        return self.state.update(mutate, {"next_id": 1, "tickets": {}})

    def _transition(
        self,
        ticket_id: str,
        status: str,
        approver: str | None = None,
        note: str | None = None,
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        def mutate(data: dict[str, Any]) -> dict[str, Any]:
            ticket = (data.get("tickets") or {}).get(ticket_id)
            if not ticket:
                raise ConnectorError(f"Ticketing-system ticket {ticket_id} does not exist")
            ticket["status"] = status
            ticket["updated_at"] = utc_now()
            if approver:
                ticket["approved_by"] = approver
                ticket["approved_at"] = utc_now()
            if note is not None and str(note).strip():
                ticket.setdefault("notes", []).append(
                    {"at": utc_now(), "by": approver or "system", "note": note}
                )
            if extra:
                ticket.update(extra)
            return ticket

        return self.state.update(mutate, {"next_id": 1, "tickets": {}})

    def approve_ticket(self, ticket_id: str, approver: str, note: str) -> dict[str, Any]:
        return self._transition(ticket_id, "APPROVED", approver, note)

    def reject_ticket(self, ticket_id: str, approver: str, note: str) -> dict[str, Any]:
        return self._transition(ticket_id, "REJECTED", approver, note)

    def update_ticket(self, ticket_id: str, fields: dict[str, Any]) -> dict[str, Any]:
        return self._transition(
            ticket_id,
            str(fields.get("status") or "IN_PROGRESS"),
            note=str(fields.get("note") or ""),
            extra={key: value for key, value in fields.items() if key not in {"status", "note"}},
        )

    def get_ticket(self, ticket_id: str) -> dict[str, Any] | None:
        return ((self.state.read({"tickets": {}}).get("tickets") or {}).get(ticket_id))
