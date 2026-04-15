from __future__ import annotations

import os

from dotenv import load_dotenv


load_dotenv()


def model_name() -> str:
    return os.getenv("SHADOWCHECK_MODEL", "openai:gpt-4o-mini")


def default_host() -> str:
    return os.getenv("SHADOWCHECK_HOST", "127.0.0.1")


def default_ports() -> list[int]:
    raw = os.getenv("SHADOWCHECK_PORTS", "22,80,443,8080,8443")
    out: list[int] = []
    for item in raw.split(","):
        item = item.strip()
        if not item:
            continue
        try:
            out.append(int(item))
        except ValueError:
            continue
    return out or [22, 80, 443, 8080, 8443]


def request_timeout() -> int:
    raw = os.getenv("SHADOWCHECK_REQUEST_TIMEOUT", "12")
    try:
        return max(1, int(raw))
    except ValueError:
        return 12
