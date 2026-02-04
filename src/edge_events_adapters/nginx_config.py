from __future__ import annotations

import re
import subprocess
from pathlib import Path


ACCESS_LOG_RE = re.compile(r"\baccess_log\s+(?P<path>[^;\s]+)")


def _run(cmd: list[str]) -> str | None:
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=False)
        if p.returncode != 0 and not p.stdout:
            return None
        return p.stdout
    except Exception:
        return None


def discover_access_logs_from_nginx_config() -> list[Path]:
    """Best-effort discovery of NGINX access_log paths.

    Preference order:
    - `nginx -T` (prints full config)
    - read /etc/nginx/nginx.conf (may have includes; not expanded here)

    Notes:
    - ignores `access_log off;`
    - if a path is relative, we do a conservative mapping to /var/log/nginx/<path>
    """

    text = _run(["nginx", "-T"])
    if text is None:
        conf = Path("/etc/nginx/nginx.conf")
        if conf.exists():
            try:
                text = conf.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                text = None

    if not text:
        return []

    paths: list[Path] = []
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if "access_log" not in line:
            continue
        if "access_log off" in line.replace("\t", " "):
            continue
        m = ACCESS_LOG_RE.search(line)
        if not m:
            continue
        p = m.group("path").strip().strip('"').strip("'")
        if not p or p == "off":
            continue
        if p.startswith("syslog:"):
            # not a file path
            continue
        # remove variables like $host (skip)
        if "$" in p:
            continue
        if p.startswith("/"):
            paths.append(Path(p))
        else:
            # Conservative fallback for relative paths
            paths.append(Path("/var/log/nginx") / p)

    # expand globs like access.log*
    expanded: list[Path] = []
    for p in paths:
        if any(ch in str(p) for ch in "*?["):
            try:
                for gp in p.parent.glob(p.name):
                    expanded.append(gp)
            except Exception:
                continue
        else:
            expanded.append(p)

    # keep only existing files
    out = [p for p in expanded if p.exists() and p.is_file()]

    # de-dup preserve order
    seen: set[str] = set()
    dedup: list[Path] = []
    for p in out:
        s = str(p)
        if s in seen:
            continue
        seen.add(s)
        dedup.append(p)
    return dedup
