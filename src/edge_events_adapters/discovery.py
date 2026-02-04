from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


@dataclass(frozen=True)
class DiscoveryItem:
    path: str
    reason: str


@dataclass
class DiscoveryReport:
    found: list[DiscoveryItem]
    skipped: list[DiscoveryItem]
    errors: list[DiscoveryItem]


DEFAULT_NGINX_GLOBS = [
    "/var/log/nginx/access.log*",
    "/var/log/nginx/*access*.log*",
    "/var/log/nginx/*access*",
    "/var/log/*nginx*access*.log*",
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

DEFAULT_APACHE_GLOBS = [
    "/var/log/apache2/access.log*",
    "/var/log/apache2/*access*.log*",
    "/var/log/httpd/access_log*",
    "/var/log/httpd/*access*.log*",
]


def _glob_many(globs: Iterable[str]) -> list[Path]:
    paths: list[Path] = []
    for g in globs:
        try:
            for p in Path("/").glob(g.lstrip("/")):
                paths.append(p)
        except Exception:
            continue
    return _dedup_paths(paths)


def discover_web_access_logs(
    *,
    include_apache: bool = True,
    max_files: int = 25,
    max_total_bytes: int = 500 * 1024 * 1024,
) -> tuple[list[Path], DiscoveryReport]:
    """Discover likely web access logs under /var/log.

    Safe-by-default: bounded file count and total bytes.
    """

    report = DiscoveryReport(found=[], skipped=[], errors=[])

    globs = list(DEFAULT_NGINX_GLOBS)
    if include_apache:
        globs.extend(DEFAULT_APACHE_GLOBS)

    candidates = [p for p in _glob_many(globs) if p.is_file()]

    # Prefer newer, smaller set: sort by mtime desc
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
        report.found.append(DiscoveryItem(str(p), "matched default glob"))

    return selected, report
