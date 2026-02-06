from __future__ import annotations

import gzip
import io
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator, TextIO


# DNS log parsing (best-effort) for common Linux DNS stacks:
# - BIND/named query logs
# - unbound logs
# - dnsmasq logs
# - Pi-hole pihole.log

IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")

# ISO-ish timestamp
ISO_TS_RE = re.compile(r"\b\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z\b")

# BIND query: "client 1.2.3.4#1234 (example.com): query: example.com IN A +..."
BIND_RE = re.compile(
    r"client\s+(?P<ip>\d+\.\d+\.\d+\.\d+)(?:#\d+)?\s+\((?P<q1>[^)]+)\):\s+query:\s+(?P<q2>\S+)\s+IN\s+(?P<qtype>[A-Z0-9]+)",
    re.IGNORECASE,
)

# dnsmasq: "query[A] example.com from 1.2.3.4"
DNSMASQ_RE = re.compile(
    r"\bquery\[(?P<qtype>[A-Z0-9]+)\]\s+(?P<qname>\S+)\s+from\s+(?P<ip>\d+\.\d+\.\d+\.\d+)",
    re.IGNORECASE,
)

# Pi-hole: "query[A] example.com from 1.2.3.4" (similar) or "query[A] example.com from 1.2.3.4"

# Unbound: common line contains "info: 1.2.3.4 example.com. A IN"
UNBOUND_RE = re.compile(
    r"\binfo:\s+(?P<ip>\d+\.\d+\.\d+\.\d+)\s+(?P<qname>\S+)\s+(?P<qtype>[A-Z0-9]+)\s+IN\b",
    re.IGNORECASE,
)

QNAME_CLEAN_RE = re.compile(r"^[A-Za-z0-9_.-]+\.?$")


@dataclass(frozen=True)
class DnsEvent:
    ts: str
    src_ip: str
    qname: str
    qtype: str | None = None


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


def _clean_qname(q: str) -> str | None:
    q = q.strip().strip("()[]{}<>\"'")
    # drop trailing colon
    q = q.rstrip(":")
    if not q or len(q) > 255:
        return None
    # often has trailing dot
    if q.endswith("."):
        q = q[:-1]
    if not QNAME_CLEAN_RE.match(q):
        return None
    # must contain a dot to avoid tons of false positives
    if "." not in q:
        return None
    return q


def iter_dns_events(paths: list[Path], *, max_lines_per_file: int = 200000) -> Iterator[DnsEvent]:
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

                    m = BIND_RE.search(line)
                    if m:
                        ip = m.group("ip")
                        q = _clean_qname(m.group("q2") or m.group("q1"))
                        if q:
                            yield DnsEvent(ts=ts, src_ip=ip, qname=q, qtype=(m.group("qtype") or None))
                        continue

                    m = DNSMASQ_RE.search(line)
                    if m:
                        ip = m.group("ip")
                        q = _clean_qname(m.group("qname"))
                        if q:
                            yield DnsEvent(ts=ts, src_ip=ip, qname=q, qtype=(m.group("qtype") or None))
                        continue

                    m = UNBOUND_RE.search(line)
                    if m:
                        ip = m.group("ip")
                        q = _clean_qname(m.group("qname"))
                        if q:
                            yield DnsEvent(ts=ts, src_ip=ip, qname=q, qtype=(m.group("qtype") or None))
                        continue

        except Exception:
            continue


def write_events_jsonl(out_path: Path, *, asset_id: str, events: Iterable[DnsEvent]) -> int:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with out_path.open("w", encoding="utf-8") as out:
        for e in events:
            obj = {
                "ts": e.ts,
                "asset_id": asset_id,
                "event_type": "dns",
                "src_ip": e.src_ip,
                "object": e.qname,
                "qtype": e.qtype,
            }
            out.write(json.dumps({k: v for k, v in obj.items() if v is not None}, ensure_ascii=False) + "\n")
            n += 1
    return n
