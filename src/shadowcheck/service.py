from __future__ import annotations

import json
from typing import Any

try:
    import logfire
except Exception:
    logfire = None

from .agent_runtime import build_shadow_agent
from .config import model_name, request_timeout
from .deps import AgentDeps
from .intel import fetch_cve_record
from .logic import draft_simulation_command, parse_pkg_text
from .models import TriageInput
from .recon import scan_services


def configure_observability() -> None:
    if logfire is None:
        return
    try:
        logfire.configure(service_name="shadowcheck")
        logfire.instrument_pydantic()
    except Exception:
        return


async def run_shadowcheck(
    cve_id: str,
    pkg_text: str,
    host: str,
    ports: list[int],
    selected_model: str | None = None,
) -> dict[str, Any]:
    configure_observability()

    triage_input = TriageInput(
        installed_packages=parse_pkg_text(pkg_text),
        target_host=host,
        ports_to_scan=ports,
    )
    deps = AgentDeps(triage_input=triage_input, request_timeout_s=request_timeout())

    cve_data = fetch_cve_record(cve_id, deps.request_timeout_s)
    deps.record("prefetch.cve", {"cve_id": cve_id, "cvss": cve_data.cvss_score})

    fingerprints = scan_services(host, ports)
    deps.record("prefetch.recon", {"host": host, "ports": ports})

    likely_open_port = next((s.port for s in fingerprints if s.open), 80)
    simulation = draft_simulation_command(cve_id, host, likely_open_port)

    prompt = f"""
Assess exploitability for {cve_id}.

Evidence:
- CVE data: {cve_data.model_dump_json(indent=2)}
- Local service scan: {[s.model_dump() for s in fingerprints]}
- Installed packages: {triage_input.installed_packages}

Rules:
- Disprove exploitability before escalating.
- If no local evidence, reduce confidence.
- Keep remediation specific and actionable.
"""

    agent = build_shadow_agent(selected_model or model_name())
    result = await agent.run(prompt, deps=deps)

    return {
        "threat_report": result.output.model_dump(),
        "draft_simulation": simulation,
        "audit_events": deps.audit_events,
        "service_fingerprints": [s.model_dump() for s in fingerprints],
        "cve_context": cve_data.model_dump(),
    }


def to_pretty_json(data: dict[str, Any]) -> str:
    return json.dumps(data, indent=2)
