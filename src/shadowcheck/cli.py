from __future__ import annotations

import argparse
import asyncio
import json

from .config import default_host, default_ports
from .logic import parse_pkg_csv
from .service import run_shadowcheck


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="ShadowCheck autonomous triage CLI")
    parser.add_argument("--cve", required=True, help="CVE ID, example: CVE-2024-3094")
    parser.add_argument(
        "--packages",
        required=True,
        help="CSV entries in name==version format. Example: openssl==3.0.2,nginx==1.24.0",
    )
    parser.add_argument("--host", default=default_host(), help="Target host")
    parser.add_argument(
        "--ports",
        default=",".join(str(p) for p in default_ports()),
        help="Ports as CSV. Example: 22,80,443,8080",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    pkg_text = "\n".join(f"{k}=={v}" for k, v in parse_pkg_csv(args.packages).items())
    ports = [int(p.strip()) for p in args.ports.split(",") if p.strip()]

    result = asyncio.run(
        run_shadowcheck(
            cve_id=args.cve,
            pkg_text=pkg_text,
            host=args.host,
            ports=ports,
        )
    )
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
