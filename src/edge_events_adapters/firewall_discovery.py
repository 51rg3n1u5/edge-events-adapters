from __future__ import annotations

from pathlib import Path


DEFAULT_GLOBS = [
    "**/*firewall*.log*",
    "**/*pan*.log*",
    "**/*paloalto*.log*",
    "**/*forti*.log*",
    "**/*checkpoint*.log*",
    "**/*netflow*.log*",
    "**/*flow*.log*",
    "**/*traffic*.log*",
    "**/*fw*.csv",
    "**/*firewall*.csv",
]


def discover_firewall_logs(*, roots: list[Path] | None = None, max_files: int = 25) -> list[Path]:
    roots = roots or [Path(".")]
    found: list[Path] = []

    for root in roots:
        if not root.exists():
            continue
        for pat in DEFAULT_GLOBS:
            for p in root.glob(pat):
                if p.is_file():
                    found.append(p)
                    if len(found) >= max_files:
                        break
            if len(found) >= max_files:
                break
        if len(found) >= max_files:
            break

    # Prefer newest mtime
    try:
        found.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    except Exception:
        pass

    # de-dup
    seen: set[str] = set()
    dedup: list[Path] = []
    for p in found:
        s = str(p)
        if s in seen:
            continue
        seen.add(s)
        dedup.append(p)

    return dedup[:max_files]
