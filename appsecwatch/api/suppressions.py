"""Manual finding suppressions — a thin view over the unified `finding_state`.

Suppression is now one `status` on the cross-scan finding-state table (keyed by
the same `source|host|key` fingerprint, host '*' = global), so a suppression and a
finding's lifecycle share one row. This manager keeps the original CRUD surface
(used by the /suppressions routes and the JobManager fingerprint injection) but
delegates to `FindingStateManager`. Deleting a suppression un-suppresses (returns
an observed finding to 'open'; drops a manual-only row).
"""
from __future__ import annotations

from typing import Any

from appsecwatch.api.db import Database
from appsecwatch.api.finding_state import FindingStateManager


class SuppressionManager:
    def __init__(self, db: Database) -> None:
        self.db = db
        self.states = FindingStateManager(db)

    def list(self) -> list[dict[str, Any]]:
        return self.states.list_suppressed()

    def add(self, *, source: str, host: str | None, key: str,
            scope: str = "host", reason: str = "") -> dict[str, Any]:
        return self.states.add_suppression(
            source=source, host=host, key=key, scope=scope, reason=reason
        )

    def delete(self, fingerprint: str) -> bool:
        return self.states.unsuppress(fingerprint)

    def fingerprints(self) -> set[str]:
        return self.states.suppressed_fingerprints()
