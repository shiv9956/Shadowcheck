from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from .models import TriageInput


@dataclass
class AgentDeps:
    triage_input: TriageInput
    request_timeout_s: int = 12
    audit_events: list[dict[str, Any]] = field(default_factory=list)

    def record(self, event: str, details: dict[str, Any]) -> None:
        self.audit_events.append(
            {
                "ts": datetime.now(timezone.utc).isoformat(),
                "event": event,
                "details": details,
            }
        )
