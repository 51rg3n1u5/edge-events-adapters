from __future__ import annotations

import gzip
import io
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator, TextIO


# Very lightweight, vendor-agnostic syslog-ish parsing.
# Output types:
# - network_flow (if key=value contains src/dst/port/action)
# - dns (if line looks like a DNS query)
# - auth (if line looks like login success/fail)
# Otherwise, emit nothing (avoid noise).


KV_RE = re.compile(r"(?P<k>[A-Za-z0-9_.-]+)=(?P<v>\S+)")
IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")

# RFC3164-ish prefix: "Mmm dd hh:mm:ss host prog[pid]: msg"
RFC3164_RE = re.compile(r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<hms>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<rest>.*)$")

MONTHS = {"Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6, "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12}

AUTH_OK = re.compile(r"\b(accepted password|accepted publickey|authentication succeeded|logged in|login succeeded)\b", re.IGNORECASE)
AUTH_FAIL = re.compile(r"\b(failed password|invalid user|authentication failure|login failed)\b", re.IGNORECASE)

# DNS-ish
DNS_Q = re.compile(r"\b(query|query\[A\]|query\[AAAA\]|question)\b", re.IGNORECASE)
QNAME_RE = re.compile(r"\b([a-zA-Z0-9_-]{1,63}(?:\.[a-zA-Z0-9_-]{1,63}){1,10})\b")


@dataclass(frozen=True)
class ParsedEvent:
    ts: str
    event_type: str
    src_ip: str | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    action: str | None = None
    user: str | None = None
    result: str | None = None
    object: str | None = None


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _open_text_maybe_gzip(path: Path) -> TextIO:
    if path.suffix == ".gz":
        return io.TextIOWrapper(gzip.open(path, "rb"), encoding="utf-8", errors="ignore")
    return path.open("r", encoding="utf-8", errors="ignore")


def _safe_int(v: str | None) -> int | None:
    if not v:
        return None
    v = v.strip()
    if not v or v == "-":
        return None
    try:
        return int(v)
    except Exception:
        return None


def _parse_rfc3164_ts(mon: str, day: str, hms: str) -> str:
    # year is not present in RFC3164; assume current year (good enough for offline triage)
    now = datetime.now(timezone.utc)
    m = MONTHS.get(mon)
    if not m:
        return _iso_now()
    try:
        d = datetime(now.year, m, int(day), int(hms[0:2]), int(hms[3:5]), int(hms[6:8]), tzinfo=timezone.utc)
        return d.isoformat().replace("+00:00", "Z")
    except Exception:
        return _iso_now()


def _extract_kv(line: str) -> dict[str, str]:
    return {m.group("k").lower(): m.group("v").strip('"') for m in KV_RE.finditer(line)}


def _pick_first_ip(s: str) -> str | None:
    m = IP_RE.search(s)
    return m.group(0) if m else None


def iter_syslog_events(paths: list[Path], *, max_lines_per_file: int = 200000) -> Iterator[ParsedEvent]:
    for p in paths:
        try:
            with _open_text_maybe_gzip(p) as f:
                for i, line in enumerate(f):
                    if i >= max_lines_per_file:
                        break
                    line = line.strip("\n")
                    if not line.strip():
                        continue

                    ts = None
                    host = None
                    msg = line

                    m = RFC3164_RE.match(line)
                    if m:
                        ts = _parse_rfc3164_ts(m.group("mon"), m.group("day"), m.group("hms"))
                        host = m.group("host")
                        msg = m.group("rest")

                    ts = ts or _iso_now()

                    kv = _extract_kv(msg)

                    # network_flow via key=value
                    src = kv.get("src") or kv.get("src_ip") or kv.get("source") or kv.get("sourceip")
                    dst = kv.get("dst") or kv.get("dst_ip") or kv.get("destination") or kv.get("dstip") or kv.get("destinationip")
                    dpt = kv.get("dpt") or kv.get("dstport") or kv.get("dst_port") or kv.get("destinationport") or kv.get("dport")
                    act = kv.get("action") or kv.get("act") or kv.get("decision") or kv.get("rule_action")
                    if src and dst:
                        yield ParsedEvent(
                            ts=ts,
                            event_type="network_flow",
                            src_ip=str(src),
                            dst_ip=str(dst),
                            dst_port=_safe_int(dpt),
                            action=act,
                        )
                        continue

                    # DNS-ish
                    if DNS_Q.search(msg):
                        ip = _pick_first_ip(msg)
                        q = None
                        for cand in QNAME_RE.findall(msg):
                            cl = cand.lower()
                            # skip obvious non-qnames / tokens
                            if cl in {"localhost"}:
                                continue
                            # avoid matching IPs as qname
                            if IP_RE.fullmatch(cand):
                                continue
                            if "." in cand:
                                q = cand
                                break
                        if q:
                            yield ParsedEvent(ts=ts, event_type="dns", src_ip=ip, object=q)
                            continue

                    # auth-ish (ssh/authd)
                    if AUTH_OK.search(msg) or AUTH_FAIL.search(msg):
                        ip = _pick_first_ip(msg)
                        res = "success" if AUTH_OK.search(msg) else "fail"
                        yield ParsedEvent(ts=ts, event_type="auth", src_ip=ip, result=res, object=(msg[:200]))
                        continue

        except Exception:
            continue


def write_events_jsonl(out_path: Path, *, asset_id: str, events: Iterable[ParsedEvent]) -> int:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with out_path.open("w", encoding="utf-8") as out:
        for e in events:
            obj = {
                "ts": e.ts,
                "asset_id": asset_id,
                "event_type": e.event_type,
                "src_ip": e.src_ip,
                "dst_ip": e.dst_ip,
                "dst_port": e.dst_port,
                "action": e.action,
                "user": e.user,
                "result": e.result,
                "object": e.object,
            }
            out.write(json.dumps({k: v for k, v in obj.items() if v is not None}, ensure_ascii=False) + "\n")
            n += 1
    return n
