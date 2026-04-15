from __future__ import annotations

from pydantic_ai import Agent, RunContext

from .deps import AgentDeps
from .intel import fetch_cve_record
from .models import CVERecord, ServiceFingerprint, ThreatReport
from .recon import scan_services

SYSTEM_PROMPT = """
You are ShadowCheck, a Red Team Auditor specialized in defensive triage.

Mission:
1) Attempt to disprove exploitability before asserting risk.
2) Prefer evidence from local environment checks over generic CVE text.
3) Mark confidence as:
   - Verified: direct evidence confirms exploitable path
   - Likely: strong indicators but one assumption remains
   - Inferred: weak indicators or missing local evidence
4) Never fabricate package versions, ports, or config states.
5) Recommend safe, practical remediation.

Output only valid ThreatReport.
"""


def build_shadow_agent(model_name: str) -> Agent[AgentDeps, ThreatReport]:
    agent = Agent(
        model=model_name,
        deps_type=AgentDeps,
        output_type=ThreatReport,
        system_prompt=SYSTEM_PROMPT,
    )

    @agent.tool
    async def check_running_versions(ctx: RunContext[AgentDeps]) -> list[ServiceFingerprint]:
        deps = ctx.deps
        output = scan_services(deps.triage_input.target_host, deps.triage_input.ports_to_scan)
        deps.record(
            "tool.check_running_versions",
            {"host": deps.triage_input.target_host, "ports": deps.triage_input.ports_to_scan},
        )
        return output

    @agent.tool
    async def fetch_exploit_db(ctx: RunContext[AgentDeps], cve_id: str) -> CVERecord:
        deps = ctx.deps
        deps.record("tool.fetch_exploit_db.start", {"cve_id": cve_id})
        output = fetch_cve_record(cve_id, deps.request_timeout_s)
        deps.record("tool.fetch_exploit_db.done", {"cve_id": cve_id, "cvss": output.cvss_score})
        return output

    return agent
