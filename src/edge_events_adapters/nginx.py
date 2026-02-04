from __future__ import annotations

import gzip
import io
import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator, TextIO


# Common NGINX/Apache combined log format:
# $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" "$http_x_forwarded_for"
# We intentionally keep this parser best-effort (many variants exist).

COMBINED_RE = re.compile(
    r"^(?P<src_ip>\S+)\s+\S+\s+(?P<user>\S+)\s+\[(?P<time>[^\]]+)\]\s+\"(?P<request>[^\"]*)\"\s+"
    r"(?P<status>\d{3}|-)\s+(?P<bytes>\d+|-)\s+\"(?P<referrer>[^\"]*)\"\s+\"(?P<ua>[^\"]*)\"(?:\s+\"(?P<xff>[^\"]*)\")?.*$"
)

# NGINX time_local example: 04/Feb/2026:17:50:01 +0100
TIMELOCAL_RE = re.compile(r"(?P<dt>\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})\s+(?P<tz>[+-]\d{4})")


@dataclass(frozen=True)
class ParsedAccess:
    ts: str
    src_ip: str | None
    method: str | None
    path: str | None
    status: int | None
    bytes: int | None
    ua: str | None
    referrer: str | None


def _parse_timelocal(s: str) -> str | None:
    m = TIMELOCAL_RE.search(s)
    if not m:
        return None
    dt = m.group("dt")
    tz = m.group("tz")
    try:
        # %z accepts +0100
        d = datetime.strptime(f"{dt} {tz}", "%d/%b/%Y:%H:%M:%S %z")
        return d.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    except Exception:
        return None


def _safe_int(v: str | None) -> int | None:
    if not v or v == "-":
        return None
    try:
        return int(v)
    except Exception:
        return None


def _parse_request(req: str) -> tuple[str | None, str | None]:
    # "GET /path?x=1 HTTP/1.1" or variants
    parts = req.split()
    if len(parts) >= 2:
        return parts[0], parts[1]
    return None, None


def _open_text_maybe_gzip(path: Path) -> TextIO:
    # Support .gz rotated logs
    if path.suffix == ".gz":
        return io.TextIOWrapper(gzip.open(path, "rb"), encoding="utf-8", errors="ignore")
    return path.open("r", encoding="utf-8", errors="ignore")


def iter_access_events(
    paths: list[Path],
) -> Iterator[ParsedAccess]:
    for p in paths:
        with _open_text_maybe_gzip(p) as f:
            for line in f:
                line = line.strip("\n")
                if not line.strip():
                    continue

                # If JSON logs, accept them directly (best-effort)
                if line.lstrip().startswith("{"):
                    try:
                        obj = json.loads(line)
                        ts = obj.get("time") or obj.get("ts") or obj.get("@timestamp")
                        if ts and isinstance(ts, str):
                            # assume already ISO-ish
                            iso = ts
                        else:
                            iso = None
                        src = obj.get("remote_addr") or obj.get("src_ip") or obj.get("client_ip")
                        status = obj.get("status")
                        req = obj.get("request") or obj.get("req")
                        method = obj.get("method")
                        path = obj.get("uri") or obj.get("path")
                        if req and (not method or not path):
                            mth, pth = _parse_request(str(req))
                            method = method or mth
                            path = path or pth
                        yield ParsedAccess(
                            ts=iso or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                            src_ip=str(src) if src else None,
                            method=str(method) if method else None,
                            path=str(path) if path else None,
                            status=int(status) if isinstance(status, int) or (isinstance(status, str) and status.isdigit()) else None,
                            bytes=_safe_int(str(obj.get("bytes") or obj.get("body_bytes_sent") or "")),
                            ua=str(obj.get("http_user_agent") or obj.get("ua") or "") or None,
                            referrer=str(obj.get("http_referer") or obj.get("referrer") or "") or None,
                        )
                        continue
                    except Exception:
                        pass

                m = COMBINED_RE.match(line)
                if not m:
                    continue

                iso = _parse_timelocal(m.group("time"))
                req = m.group("request")
                method, path = _parse_request(req)

                user = m.group("user")
                if user == "-":
                    user = None

                yield ParsedAccess(
                    ts=iso or datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                    src_ip=m.group("src_ip"),
                    method=method,
                    path=path,
                    status=_safe_int(m.group("status")),
                    bytes=_safe_int(m.group("bytes")),
                    ua=(m.group("ua") or None) if m.group("ua") != "-" else None,
                    referrer=(m.group("referrer") or None) if m.group("referrer") != "-" else None,
                )


def write_events_jsonl(
    out_path: Path,
    *,
    asset_id: str,
    events: Iterable[ParsedAccess],
    host: str | None = None,
) -> int:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    n = 0
    with out_path.open("w", encoding="utf-8") as out:
        for e in events:
            obj = {
                "ts": e.ts,
                "asset_id": asset_id,
                "event_type": "http_access",
                "src_ip": e.src_ip,
                "method": e.method,
                "object": e.path,
                "status": e.status,
                "bytes": e.bytes,
                "ua": e.ua,
                "referrer": e.referrer,
            }
            if host:
                obj["host"] = host
            out.write(json.dumps({k: v for k, v in obj.items() if v is not None}, ensure_ascii=False) + "\n")
            n += 1
    return n
