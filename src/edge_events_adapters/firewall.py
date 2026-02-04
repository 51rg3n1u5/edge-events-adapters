from __future__ import annotations

import csv
import gzip
import io
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator, TextIO


@dataclass(frozen=True)
class ParsedFlow:
    ts: str
    src_ip: str | None
    dst_ip: str | None
    dst_port: int | None
    action: str | None


IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")
KV_RE = re.compile(r"(?P<k>[A-Za-z0-9_.-]+)=(?P<v>\S+)")


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


def _iso_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def _parse_ts_guess(obj: dict) -> str | None:
    for k in ("ts", "time", "timestamp", "@timestamp", "date"):
        v = obj.get(k)
        if isinstance(v, str) and v:
            return v
    return None


def _normalize_action(s: str | None) -> str | None:
    if not s:
        return None
    sl = s.strip().lower()
    mapping = {
        "allow": "allow",
        "accept": "allow",
        "permitted": "allow",
        "permit": "allow",
        "deny": "deny",
        "drop": "deny",
        "blocked": "deny",
        "block": "deny",
        "reject": "deny",
    }
    for k, v in mapping.items():
        if sl == k:
            return v
    # if looks like allow/deny already
    if "allow" in sl or "accept" in sl:
        return "allow"
    if "deny" in sl or "drop" in sl or "block" in sl:
        return "deny"
    return s


def _from_kv(line: str) -> ParsedFlow | None:
    # Common patterns:
    # src=1.2.3.4 dst=5.6.7.8 dpt=443 action=allow
    kv = {m.group("k").lower(): m.group("v").strip('"') for m in KV_RE.finditer(line)}
    if not kv:
        return None

    src = kv.get("src") or kv.get("src_ip") or kv.get("source") or kv.get("sourceip")
    dst = kv.get("dst") or kv.get("dst_ip") or kv.get("destination") or kv.get("dstip") or kv.get("destinationip")

    dpt = kv.get("dpt") or kv.get("dstport") or kv.get("dst_port") or kv.get("destinationport") or kv.get("dport")
    act = kv.get("action") or kv.get("act") or kv.get("decision") or kv.get("rule_action")

    ts = kv.get("time") or kv.get("timestamp") or kv.get("ts")

    # If we don't have at least src+dst, ignore
    if not (src and dst):
        return None

    return ParsedFlow(ts=ts or _iso_now(), src_ip=src, dst_ip=dst, dst_port=_safe_int(dpt), action=_normalize_action(act))


def _from_cef(line: str) -> ParsedFlow | None:
    # Very loose CEF parse: look for common keys like src=, dst=, dpt=, act=
    if not line.startswith("CEF:"):
        return None
    return _from_kv(line)


def _from_json(line: str) -> ParsedFlow | None:
    try:
        obj = json.loads(line)
    except Exception:
        return None

    ts = _parse_ts_guess(obj) or _iso_now()

    # common keys
    src = obj.get("src_ip") or obj.get("src") or obj.get("source") or obj.get("client_ip")
    dst = obj.get("dst_ip") or obj.get("dst") or obj.get("destination") or obj.get("server_ip")

    dpt = obj.get("dst_port") or obj.get("dpt") or obj.get("destination_port") or obj.get("port")
    act = obj.get("action") or obj.get("act") or obj.get("result") or obj.get("decision")

    if src is None or dst is None:
        return None

    return ParsedFlow(ts=str(ts), src_ip=str(src), dst_ip=str(dst), dst_port=_safe_int(str(dpt)) if dpt is not None else None, action=_normalize_action(str(act)) if act is not None else None)


def _from_csv_row(row: dict) -> ParsedFlow | None:
    # Try common column names
    def g(*names):
        for n in names:
            if n in row and row[n]:
                return row[n]
        return None

    ts = g("ts", "time", "timestamp", "date") or _iso_now()
    src = g("src", "src_ip", "source", "source_ip")
    dst = g("dst", "dst_ip", "destination", "destination_ip")
    dpt = g("dpt", "dst_port", "destination_port", "port")
    act = g("action", "result", "decision")

    if not (src and dst):
        return None

    return ParsedFlow(ts=str(ts), src_ip=str(src), dst_ip=str(dst), dst_port=_safe_int(str(dpt)) if dpt else None, action=_normalize_action(str(act)) if act else None)


def iter_firewall_events(paths: list[Path]) -> Iterator[ParsedFlow]:
    for p in paths:
        # CSV detection by extension
        if p.suffix.lower() == ".csv":
            try:
                with p.open("r", encoding="utf-8", errors="ignore", newline="") as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        pf = _from_csv_row(row)
                        if pf:
                            yield pf
                continue
            except Exception:
                pass

        with _open_text_maybe_gzip(p) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                if line.startswith("{"):
                    pf = _from_json(line)
                    if pf:
                        yield pf
                    continue

                pf = _from_cef(line) or _from_kv(line)
                if pf:
                    yield pf
                    continue

                # last resort: if line contains 2+ IPs, we could guess, but too FP-prone
                continue


def write_events_jsonl(out_path: Path, *, asset_id: str, events: Iterable[ParsedFlow]) -> int:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with out_path.open("w", encoding="utf-8") as out:
        for e in events:
            obj = {
                "ts": e.ts,
                "asset_id": asset_id,
                "event_type": "network_flow",
                "src_ip": e.src_ip,
                "dst_ip": e.dst_ip,
                "dst_port": e.dst_port,
                "action": e.action,
            }
            out.write(json.dumps({k: v for k, v in obj.items() if v is not None}, ensure_ascii=False) + "\n")
            n += 1
    return n
