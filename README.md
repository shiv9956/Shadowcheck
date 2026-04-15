# ShadowCheck

ShadowCheck is an autonomous vulnerability triage project that focuses on exploitability context, not just CVE presence. It combines typed outputs, read-only local recon, a disprove-first agent prompt, and a streaming analyst UI so teams can move from noisy alerts to evidence-backed triage.

## Purpose

ShadowCheck answers a practical security question: is this CVE actually exploitable in *your* environment right now? It is designed for defensive workflows only and never executes exploitation payloads.

## Core capabilities

- Produces structured output using a typed `ThreatReport` model.
- Uses read-only recon checks to evaluate local exploitability signals.
- Pulls CVE context from NVD and similar public sources.
- Applies a Red Team Auditor system prompt to reduce false positives.
- Streams triage progress in a Gradio UI.
- Captures audit events and optional Logfire traces for compliance.

## Repository structure

- `src/shadowcheck/models.py`: Typed models for reports, fingerprints, and input.
- `src/shadowcheck/agent_runtime.py`: Pydantic AI agent and tool registration.
- `src/shadowcheck/recon.py`: Read-only service fingerprint checks.
- `src/shadowcheck/intel.py`: CVE enrichment from the NVD API.
- `src/shadowcheck/logic.py`: Parsing, safe simulation drafting, and version filtering.
- `src/shadowcheck/service.py`: Orchestration and final output assembly.
- `src/shadowcheck/ui.py`: Gradio app for streaming triage.
- `src/shadowcheck/cli.py`: Command-line entry point.
- `tests/test_logic.py`: Deterministic unit tests.

## Requirements

- Python 3.10 or newer
- Internet access for CVE lookup unless you mock the intel layer
- Optional API access for your selected model provider

## Installation

Clone the repository and install it in editable mode:

```powershell
pip install -e .
```

For development and tests:

```powershell
pip install -e .[dev]
```

## Configuration

Copy [.env.example](.env.example) to `.env` and set the values for your environment.

Important variables:

- `SHADOWCHECK_MODEL`: Pydantic AI model identifier.
- `SHADOWCHECK_HOST`: Target host for local checks.
- `SHADOWCHECK_PORTS`: Comma-separated ports to scan.
- `SHADOWCHECK_REQUEST_TIMEOUT`: Timeout for CVE lookup requests.

Example:

```powershell
SHADOWCHECK_MODEL=openai:gpt-4o-mini
SHADOWCHECK_HOST=127.0.0.1
SHADOWCHECK_PORTS=22,80,443,8080,8443
SHADOWCHECK_REQUEST_TIMEOUT=12
```

## How it works

1. The user provides a CVE ID and either package metadata or a repo-derived package list.
2. ShadowCheck pulls public CVE context and associated references.
3. Read-only local recon checks whether the expected service is actually present.
4. The agent cross-checks the CVE against local evidence and tries to disprove exploitability first.
5. The final output is returned as a typed `ThreatReport` plus audit trail and a draft-only simulation command.

## Run the CLI

```powershell
shadowcheck-cli --cve CVE-2024-3094 --packages "openssl==3.0.2,nginx==1.24.0"
```

If you want to scan a different host or port list:

```powershell
shadowcheck-cli --cve CVE-2024-3094 --packages "openssl==3.0.2,nginx==1.24.0" --host 127.0.0.1 --ports 22,80,443,8080
```

## Run the UI

```powershell
shadowcheck-ui
```

The UI launches a local Gradio app and streams progress messages before rendering the structured JSON report.

## Development workflow

Run the tests:

```powershell
pytest
```

Common extension points:

- Replace the CVE source in `src/shadowcheck/intel.py` with your preferred threat intel API.
- Add repo ingestion in `src/shadowcheck/service.py` for package extraction from GitHub repositories.
- Extend the `ThreatReport` model with fields required by your SOC or SOAR pipeline.
- Wire in Logfire or another telemetry sink for immutable audit trails.

## Safety model

- No exploitation is executed.
- Draft simulation commands are generated as analyst guidance only.
- Recon is read-only and limited to port/banner checks.
- The agent is instructed to reduce confidence when local evidence is missing.

## Example output

```json
{
	"cve_id": "CVE-2024-3094",
	"severity_score": 10,
	"is_exploitable_locally": false,
	"required_remediation": "Patch the affected package and validate that the vulnerable service is not exposed.",
	"confidence_level": "Likely"
}
```

## Suggested next steps

- Add repository ingestion from GitHub URLs.
- Add export formats for CSV, JSON, and Markdown reports.
- Add CI for tests and package validation.
- Add Docker support for one-command deployment.
