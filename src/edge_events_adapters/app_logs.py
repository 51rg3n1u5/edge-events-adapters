from __future__ import annotations

import gzip
import io
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator, TextIO


# Generic text-log -> event extraction.
# This is intentionally best-effort and low-risk: we don't try to parse every vendor format.

IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")

# Very simple ISO-ish timestamp matcher
ISO_TS_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z\b")

# Log keywords
AUTH_OK = re.compile(r"\b(login|logged in|authentication succeeded|auth succeeded|successfully authenticated)\b", re.IGNORECASE)
AUTH_FAIL = re.compile(r"\b(failed login|authentication failed|invalid password|unauthorized|forbidden)\b", re.IGNORECASE)
CONFIG_CHANGE = re.compile(r"\b(created|deleted|updated|changed|configured|set|added|removed|plugin|extension|token|api key)\b", re.IGNORECASE)


@dataclass(frozen=True)
class ParsedAppEvent:
    ts: str
    event_type: str  # auth | config_change
    src_ip: str | None
    result: str | None
    object: str


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _open_text_maybe_gzip(path: Path) -> TextIO:
    if path.suffix == ".gz":
        return io.TextIOWrapper(gzip.open(path, "rb"), encoding="utf-8", errors="ignore")
    return path.open("r", encoding="utf-8", errors="ignore")


def _pick_ts(line: str) -> str:
    m = ISO_TS_RE.search(line)
    if m:
        return m.group(0)
    return _iso_now()


def _pick_ip(line: str) -> str | None:
    m = IP_RE.search(line)
    if m:
        return m.group(0)
    return None


def iter_app_events(paths: list[Path], *, max_lines_per_file: int = 20000) -> Iterator[ParsedAppEvent]:
    for p in paths:
        try:
            with _open_text_maybe_gzip(p) as f:
                for i, line in enumerate(f):
                    if i >= max_lines_per_file:
                        break
                    line = line.strip("\n")
                    if not line.strip():
                        continue

                    ts = _pick_ts(line)
                    ip = _pick_ip(line)

                    if AUTH_OK.search(line):
                        yield ParsedAppEvent(ts=ts, event_type="auth", src_ip=ip, result="success", object=f"{p.name}: {line[:200]}")
                        continue
                    if AUTH_FAIL.search(line):
                        yield ParsedAppEvent(ts=ts, event_type="auth", src_ip=ip, result="fail", object=f"{p.name}: {line[:200]}")
                        continue
                    if CONFIG_CHANGE.search(line):
                        yield ParsedAppEvent(ts=ts, event_type="config_change", src_ip=ip, result=None, object=f"{p.name}: {line[:200]}")
                        continue
        except Exception:
            continue


def write_events_jsonl(out_path: Path, *, asset_id: str, events: Iterable[ParsedAppEvent]) -> int:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with out_path.open("w", encoding="utf-8") as out:
        for e in events:
            obj = {
                "ts": e.ts,
                "asset_id": asset_id,
                "event_type": e.event_type,
                "src_ip": e.src_ip,
                "result": e.result,
                "object": e.object,
            }
            out.write(json.dumps({k: v for k, v in obj.items() if v is not None}, ensure_ascii=False) + "\n")
            n += 1
    return n
