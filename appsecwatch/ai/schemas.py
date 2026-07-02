from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class AIFinding(BaseModel):
    type: str
    severity: Literal["info", "low", "medium", "high", "critical"]
    title: str
    description: str = ""
    evidence: dict[str, Any] = Field(default_factory=dict)


class AISuppression(BaseModel):
    """The AI's verdict that a specific deterministic finding (referenced by the
    ephemeral integer `ref` it was given in the triage payload) is a false-positive
    for this app. Applied — gated — by the analyzer; never deletes the finding
    (see AIFindingVerdict)."""
    ref: int
    suppressed: bool = True
    confidence: Literal["low", "medium", "high"] = "low"
    reason: str = ""


class AIResponse(BaseModel):
    findings: list[AIFinding] = Field(default_factory=list)
    # FP verdicts on the deterministic findings passed into the prompt (header
    # analysis only; empty for supply-chain).
    suppressions: list[AISuppression] = Field(default_factory=list)
    # Set when the call hard-failed (LLM error or unparseable after retry).
    # Mirrors AppProfile.error so callers degrade uniformly via `usable`.
    error: str | None = None

    @property
    def usable(self) -> bool:
        return self.error is None
