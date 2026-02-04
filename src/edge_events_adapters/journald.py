from __future__ import annotations

import subprocess
from typing import Iterator


def iter_journal_lines(*, unit: str, since: str) -> Iterator[str]:
    """Yield journal lines in a parse-friendly format.

    Uses `-o cat` so output is just MESSAGE.
    """

    cmd = ["journalctl", "-u", unit, "--since", since, "--no-pager", "-o", "cat"]
    try:
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    except Exception:
        return

    assert p.stdout is not None
    for line in p.stdout:
        line = line.rstrip("\n")
        if line:
            yield line

    try:
        p.wait(timeout=5)
    except Exception:
        p.kill()
