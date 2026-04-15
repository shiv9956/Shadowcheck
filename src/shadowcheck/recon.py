from __future__ import annotations

import socket

from .models import ServiceFingerprint


def scan_services(host: str, ports: list[int]) -> list[ServiceFingerprint]:
    results: list[ServiceFingerprint] = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.6)
        is_open = False
        banner = None
        try:
            is_open = sock.connect_ex((host, port)) == 0
            if is_open:
                try:
                    sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                    data = sock.recv(256)
                    banner = data.decode(errors="ignore").strip() or None
                except OSError:
                    banner = None
        finally:
            sock.close()

        results.append(ServiceFingerprint(host=host, port=port, open=is_open, banner=banner))
    return results
