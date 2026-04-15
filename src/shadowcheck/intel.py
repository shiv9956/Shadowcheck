from __future__ import annotations

from typing import Any

import requests

from .models import CVERecord


def _extract_cvss(metrics_block: dict[str, Any]) -> float:
    candidates = [
        metrics_block.get("cvssMetricV31", []),
        metrics_block.get("cvssMetricV30", []),
        metrics_block.get("cvssMetricV2", []),
    ]
    for arr in candidates:
        if arr:
            cvss_data = arr[0].get("cvssData", {})
            score = cvss_data.get("baseScore")
            if isinstance(score, (int, float)):
                return float(score)
    return 0.0


def fetch_cve_record(cve_id: str, timeout_s: int) -> CVERecord:
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    response = requests.get(url, timeout=timeout_s)
    response.raise_for_status()
    payload = response.json()

    vulns = payload.get("vulnerabilities", [])
    if not vulns:
        return CVERecord(
            cve_id=cve_id,
            description="No vulnerability record found in source API.",
            cvss_score=0.0,
            references=[],
            vulnerable_version_range=None,
        )

    cve = vulns[0].get("cve", {})
    descriptions = cve.get("descriptions", [])
    description = next((d.get("value", "") for d in descriptions if d.get("lang") == "en"), "")
    refs = [r.get("url") for r in cve.get("references", []) if r.get("url")]
    metrics = cve.get("metrics", {})

    vulnerable_range = None
    configurations = cve.get("configurations", [])
    for config in configurations:
        for node in config.get("nodes", []):
            for cpe in node.get("cpeMatch", []):
                if cpe.get("vulnerable"):
                    start_inc = cpe.get("versionStartIncluding")
                    end_exc = cpe.get("versionEndExcluding")
                    start_exc = cpe.get("versionStartExcluding")
                    end_inc = cpe.get("versionEndIncluding")
                    pieces = [
                        f">={start_inc}" if start_inc else None,
                        f">{start_exc}" if start_exc else None,
                        f"<{end_exc}" if end_exc else None,
                        f"<={end_inc}" if end_inc else None,
                    ]
                    vulnerable_range = ",".join([p for p in pieces if p]) or None
                    break
            if vulnerable_range:
                break
        if vulnerable_range:
            break

    return CVERecord(
        cve_id=cve_id,
        description=description,
        cvss_score=_extract_cvss(metrics),
        references=refs[:10],
        vulnerable_version_range=vulnerable_range,
    )
