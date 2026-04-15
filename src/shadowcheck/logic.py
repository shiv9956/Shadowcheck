from __future__ import annotations

import re

from packaging import version


def parse_pkg_text(pkg_text: str) -> dict[str, str]:
    parsed: dict[str, str] = {}
    for line in pkg_text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "==" in line:
            name, ver = line.split("==", 1)
            parsed[name.strip().lower()] = ver.strip()
    return parsed


def parse_pkg_csv(packages_csv: str) -> dict[str, str]:
    # Accepts input like: openssl==3.0.2,nginx==1.24.0
    return parse_pkg_text(packages_csv.replace(",", "\n"))


def version_in_range(installed: str, range_expr: str | None) -> bool:
    if not range_expr:
        return True
    iv = version.parse(installed)
    checks = [x.strip() for x in range_expr.split(",") if x.strip()]
    for chk in checks:
        if chk.startswith(">=") and not (iv >= version.parse(chk[2:])):
            return False
        if chk.startswith(">") and not chk.startswith(">=") and not (iv > version.parse(chk[1:])):
            return False
        if chk.startswith("<=") and not (iv <= version.parse(chk[2:])):
            return False
        if chk.startswith("<") and not chk.startswith("<=") and not (iv < version.parse(chk[1:])):
            return False
    return True


def draft_simulation_command(cve_id: str, host: str, port: int) -> str:
    safe_cve = re.sub(r"[^A-Za-z0-9-]", "", cve_id)
    return (
        f"# Draft-only validation for {safe_cve}\n"
        f"curl -i --max-time 5 http://{host}:{port}/ \\\n"
        "  -H 'User-Agent: ShadowCheck-Validator/1.0'"
    )
