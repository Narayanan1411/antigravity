from __future__ import annotations
import socket

def reverse_dns(ip: str) -> str | None:
    """Perform reverse DNS lookup for an IP."""
    if not ip or ip in ("127.0.0.1", "0.0.0.0", "unknown"):
        return None
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return None
