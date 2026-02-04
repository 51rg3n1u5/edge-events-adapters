from __future__ import annotations

import ipaddress


def pick_client_ip(src_ip: str | None, xff: str | None) -> str | None:
    """Pick a best-effort client IP.

    Strategy (simple, safe):
    - If XFF exists: take the first IP that is not private/loopback/link-local.
    - Else: return src_ip.

    If everything is private, fall back to first IP in XFF or src_ip.
    """

    def _parse_ip(s: str) -> str | None:
        try:
            ip = ipaddress.ip_address(s.strip())
            return str(ip)
        except Exception:
            return None

    if xff:
        parts = [p.strip() for p in xff.split(",") if p.strip()]
        parsed = [_parse_ip(p) for p in parts]
        ips = [p for p in parsed if p]
        for s in ips:
            ip = ipaddress.ip_address(s)
            if ip.is_private or ip.is_loopback or ip.is_link_local:
                continue
            return s
        if ips:
            return ips[0]

    return src_ip
