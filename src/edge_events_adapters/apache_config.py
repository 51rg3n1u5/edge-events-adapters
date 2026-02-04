from __future__ import annotations

import re
import subprocess
from pathlib import Path


# Examples:
# CustomLog "/var/log/apache2/access.log" combined
# CustomLog logs/access_log combined
CUSTOMLOG_RE = re.compile(r"\bCustomLog\s+(?P<path>[^\s]+)")


def _run(cmd: list[str]) -> str | None:
    try:
        p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, check=False)
        if p.returncode != 0 and not p.stdout:
            return None
        return p.stdout
    except Exception:
        return None


def _read_if_exists(p: Path) -> str | None:
    try:
        if p.exists():
            return p.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return None
    return None


def discover_access_logs_from_apache_config() -> list[Path]:
    """Best-effort discovery of Apache access logs.

    Preference:
    - parse `apachectl -S` output? (doesn't include CustomLog usually)
    - grep common config files for CustomLog directives

    Conservative approach: read a few common config locations and extract CustomLog paths.
    """

    texts: list[str] = []

    # Try to locate config root via apachectl -V
    v = _run(["apachectl", "-V"])
    root = None
    if v:
        m = re.search(r"-D\s+HTTPD_ROOT=\"(?P<root>[^\"]+)\"", v)
        if m:
            root = Path(m.group("root"))

    # Common Debian/Ubuntu
    candidates = [
        Path("/etc/apache2/apache2.conf"),
        Path("/etc/apache2/sites-enabled/000-default.conf"),
    ]
    # Common RHEL/CentOS
    candidates += [
        Path("/etc/httpd/conf/httpd.conf"),
        Path("/etc/httpd/conf.d/ssl.conf"),
    ]

    if root:
        candidates.append(root / "conf/httpd.conf")

    for c in candidates:
        t = _read_if_exists(c)
        if t:
            texts.append(t)

    if not texts:
        return []

    paths: list[Path] = []
    for text in texts:
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "CustomLog" not in line:
                continue
            m = CUSTOMLOG_RE.search(line)
            if not m:
                continue
            p = m.group("path").strip().strip('"').strip("'")
            if not p or "$" in p:
                continue
            if p.startswith("|"):
                # piped logging
                continue
            if p.startswith("/"):
                paths.append(Path(p))
            else:
                # relative: assume under /var/log/apache2 or /var/log/httpd
                if Path("/var/log/apache2").exists():
                    paths.append(Path("/var/log/apache2") / p)
                else:
                    paths.append(Path("/var/log/httpd") / p)

    out = [p for p in paths if p.exists() and p.is_file()]
    # de-dup
    seen: set[str] = set()
    dedup: list[Path] = []
    for p in out:
        s = str(p)
        if s in seen:
            continue
        seen.add(s)
        dedup.append(p)
    return dedup
