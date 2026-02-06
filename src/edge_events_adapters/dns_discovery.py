from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class DiscoveryItem:
    path: str
    reason: str


@dataclass
class DiscoveryReport:
    found: list[DiscoveryItem]
    skipped: list[DiscoveryItem]
    errors: list[DiscoveryItem]


DEFAULT_DNS_GLOBS = [
    # BIND/named (varies by distro/config)
    "/var/log/named/*.log*",
    "/var/log/named/named.log*",
    "/var/log/named/query.log*",
    "/var/log/bind/*.log*",
    "/var/log/bind9/*.log*",

    # Unbound
    "/var/log/unbound/unbound.log*",

    # dnsmasq (often syslog, but some run dedicated files)
    "/var/log/dnsmasq*.log*",
    "/var/log/dnsmasq/*.log*",

    # Pi-hole style
    "/var/log/pihole/pihole.log*",
]


def _dedup_paths(paths: list[Path]) -> list[Path]:
    seen: set[str] = set()
    out: list[Path] = []
    for p in paths:
        s = str(p)
        if s in seen:
            continue
        seen.add(s)
        out.append(p)
    return out


def _glob_many(globs: list[str]) -> list[Path]:
    paths: list[Path] = []
    for g in globs:
        try:
            for p in Path("/").glob(g.lstrip("/")):
                paths.append(p)
        except Exception:
            continue
    return _dedup_paths(paths)


def discover_dns_logs(*, max_files: int = 25, max_total_bytes: int = 600 * 1024 * 1024) -> tuple[list[Path], DiscoveryReport]:
    report = DiscoveryReport(found=[], skipped=[], errors=[])

    candidates = [p for p in _glob_many(DEFAULT_DNS_GLOBS) if p.is_file()]

    try:
        candidates.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    except Exception:
        pass

    selected: list[Path] = []
    total = 0

    for p in candidates:
        if len(selected) >= max_files:
            report.skipped.append(DiscoveryItem(str(p), f"max_files={max_files} reached"))
            continue
        try:
            sz = p.stat().st_size
        except Exception as e:
            report.errors.append(DiscoveryItem(str(p), f"stat failed: {e}"))
            continue
        if total + sz > max_total_bytes:
            report.skipped.append(DiscoveryItem(str(p), f"max_total_bytes={max_total_bytes} reached"))
            continue

        selected.append(p)
        total += sz
        report.found.append(DiscoveryItem(str(p), "matched dns glob"))

    return selected, report
