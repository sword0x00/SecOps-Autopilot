"""SecOps Autopilot — vulnerability to verified, evidenced fix.

The package exposes a small, dependency-light engine. Tenable Vulnerability
Management and Tenable Security Center sit behind a common connector interface;
ITSM, NAC and EDR sit behind simulated adapters by default so the whole chain
can be exercised without touching a production control plane.
"""

from .models import UNKNOWN, RunState

__version__ = "0.1.0"

__all__ = ["UNKNOWN", "RunState", "__version__"]
