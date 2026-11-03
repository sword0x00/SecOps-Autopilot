"""Explicit, testable execution stages.

The orchestration layer used to be one large ``Pipeline`` method. Stages now
have a declarative contract (inputs, outputs, whether they are read-only, and
which approval gate they require) and are executed by the engine in order.

The contracts are documentation *and* runtime metadata: every stage record
written to the evidence store includes the contract identifier, order,
read-only flag, and approval gate. A reviewer can see which stage produced a
record and whether that stage was allowed to change state.
"""

from .contracts import CONTRACTS, STAGE_BY_ID, StageContract, contract_for
from .context import StageContext, Workflow
from .readonly import (
    READ_ONLY_STAGES,
    stage_control_check,
    stage_exposure,
    stage_intake,
    stage_kri_register,
    stage_planning,
    stage_risk_scoring,
)

__all__ = [
    "CONTRACTS",
    "STAGE_BY_ID",
    "StageContract",
    "contract_for",
    "StageContext",
    "Workflow",
    "READ_ONLY_STAGES",
    "stage_intake",
    "stage_exposure",
    "stage_control_check",
    "stage_kri_register",
    "stage_risk_scoring",
    "stage_planning",
]
