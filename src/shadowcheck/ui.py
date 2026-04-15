from __future__ import annotations

import asyncio
import json

import gradio as gr

from .config import default_host, default_ports
from .service import run_shadowcheck


async def stream_shadowcheck(cve_id: str, package_text: str, host: str, ports_csv: str):
    try:
        ports = [int(p.strip()) for p in ports_csv.split(",") if p.strip()]
    except ValueError:
        yield "Invalid ports CSV. Example: 22,80,443,8080"
        return

    yield f"[1/4] Pulling CVE context for {cve_id}..."
    await asyncio.sleep(0.05)
    yield "[2/4] Performing read-only service fingerprint scan..."
    await asyncio.sleep(0.05)
    yield "[3/4] Running Red Team Auditor triage (disprove-first)..."

    result = await run_shadowcheck(cve_id=cve_id, pkg_text=package_text, host=host, ports=ports)

    yield "[4/4] Completed. Rendering structured report...\n\n" + json.dumps(result, indent=2)


def build_ui() -> gr.Blocks:
    with gr.Blocks(title="ShadowCheck SOC Console") as demo:
        gr.Markdown("# ShadowCheck SOC Console")
        gr.Markdown("Autonomous zero-day triage with typed outputs and audit trail.")

        cve_id = gr.Textbox(label="CVE ID", value="CVE-2024-3094")
        package_text = gr.Textbox(
            label="Installed Packages (pip style)",
            lines=8,
            value="openssl==3.0.2\nnginx==1.24.0",
        )
        host = gr.Textbox(label="Target Host", value=default_host())
        ports = gr.Textbox(label="Ports CSV", value=",".join(str(p) for p in default_ports()))

        run_btn = gr.Button("Run Triage", variant="primary")
        output = gr.Textbox(label="Streaming Output", lines=24)

        run_btn.click(
            fn=stream_shadowcheck,
            inputs=[cve_id, package_text, host, ports],
            outputs=[output],
        )

    return demo


def launch() -> None:
    demo = build_ui()
    demo.launch(server_name="127.0.0.1", server_port=7860)
