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


# Product-centric log roots (Linux on-prem). These are discovery targets only.
# Parsing is best-effort and handled elsewhere.
DEFAULT_APP_LOG_GLOBS = [
    # VMware vCenter Server Appliance (VCSA / Photon)
    "/var/log/vmware/**/*.log*",
    "/var/log/vmware/**/vpxd*",
    "/var/log/vmware/**/sso*",
    "/var/log/vmware/**/vsphere-ui*",
    "/var/log/vmware/**/applmgmt*",

    # GitLab Omnibus
    "/var/log/gitlab/**/*.log*",
    "/var/log/gitlab/**/current*",

    # Atlassian (common data dirs)
    "/var/atlassian/**/logs/*.log*",
    "/var/atlassian/**/logs/catalina.out*",
    "/opt/atlassian/**/logs/*.log*",
    "/opt/atlassian/**/logs/catalina.out*",

    # Zimbra
    "/opt/zimbra/log/*.log*",

    # Grafana
    "/var/log/grafana/*.log*",

    # Elastic / OpenSearch
    "/var/log/elasticsearch/*.log*",
    "/var/log/opensearch/*.log*",
    "/var/log/kibana/*.log*",
    "/var/log/opensearch-dashboards/*.log*",

    # Suricata (often present in on-prem sensor/log-host setups)
    "/var/log/suricata/eve.json*",
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


def discover_app_logs(*, max_files: int = 50, max_total_bytes: int = 800 * 1024 * 1024) -> tuple[list[Path], DiscoveryReport]:
    """Discover common product logs.

    Bounded by file count and total bytes.
    Prefers newer files.
    """

    report = DiscoveryReport(found=[], skipped=[], errors=[])

    candidates = [p for p in _glob_many(DEFAULT_APP_LOG_GLOBS) if p.is_file()]

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
        report.found.append(DiscoveryItem(str(p), "matched app log glob"))

    return selected, report
