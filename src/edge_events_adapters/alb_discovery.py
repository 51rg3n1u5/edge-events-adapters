from __future__ import annotations

from pathlib import Path
from typing import Iterable


DEFAULT_GLOBS = [
    "./AWSLogs/**/elasticloadbalancing/**/.*",
    "./AWSLogs/**/elasticloadbalancing/**/**",
    "./**/*elb*access*log*",
    "./**/*alb*access*log*",
    "./**/*loadbalancer*access*log*",
    "./**/*elasticloadbalancing*",
    "./**/*_elasticloadbalancing_*",
]


def discover_alb_logs(*, roots: list[Path] | None = None, max_files: int = 25) -> list[Path]:
    roots = roots or [Path(".")]
    found: list[Path] = []

    # Extremely conservative: only search within given roots (default cwd)
    for root in roots:
        if not root.exists():
            continue
        # common: AWSLogs structure
        awslogs = root / "AWSLogs"
        if awslogs.exists() and awslogs.is_dir():
            for p in awslogs.rglob("*"):
                if p.is_file() and ("elasticloadbalancing" in str(p).lower()):
                    found.append(p)
                    if len(found) >= max_files:
                        break
        if len(found) >= max_files:
            break

    # Prefer newest mtime
    try:
        found.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    except Exception:
        pass

    # Filter obvious non-files
    out = [p for p in found if p.is_file()]

    # De-dup
    seen: set[str] = set()
    dedup: list[Path] = []
    for p in out:
        s = str(p)
        if s in seen:
            continue
        seen.add(s)
        dedup.append(p)

    return dedup[:max_files]
