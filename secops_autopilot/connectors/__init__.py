"""Connector adapters.

Tenable is the live data source. Ticketing, NAC, and EDR default to
file-backed simulators so the full approval and containment chain can be
demonstrated and tested without changing production state.
"""

from .base import VulnerabilitySource
from .ticketing import SimulatedTicketingSystem
from .nac import SimulatedNAC
from .edr import SimulatedEDR
from .tenable_vm import TenableVMClient

__all__ = [
    "VulnerabilitySource",
    "TenableVMClient",
    "SimulatedTicketingSystem",
    "SimulatedNAC",
    "SimulatedEDR",
]
