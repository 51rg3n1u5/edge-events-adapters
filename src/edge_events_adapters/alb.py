from __future__ import annotations

import gzip
import io
import json
import shlex
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable, Iterator, TextIO


# AWS ALB access log format (space-separated, some quoted fields)
# https://docs.aws.amazon.com/elasticloadbalancing/latest/application/load-balancer-access-logs.html
# Example (trimmed):
# http 2015-05-13T23:39:43.945958Z app/my-lb/50dc6c495c0c9188 192.0.2.10:2817 10.0.0.1:80 0.000 0.026 0.000 200 200 0 57 "GET http://www.example.com:80/ HTTP/1.1" "curl/7.38.0" - - - - - - - -


@dataclass(frozen=True)
class ParsedAlb:
    ts: str
    src_ip: str | None
    method: str | None
    path: str | None
    status: int | None
    bytes: int | None
    ua: str | None
    host: str | None = None


def _safe_int(v: str | None) -> int | None:
    if not v or v == "-":
        return None
    try:
        return int(v)
    except Exception:
        return None


def _open_text_maybe_gzip(path: Path) -> TextIO:
    if path.suffix == ".gz":
        return io.TextIOWrapper(gzip.open(path, "rb"), encoding="utf-8", errors="ignore")
    return path.open("r", encoding="utf-8", errors="ignore")


def _parse_request(req: str) -> tuple[str | None, str | None, str | None]:
    # "GET http://host:port/path HTTP/1.1" or "GET https://host/path HTTP/2.0" or "-"
    if not req or req == "-":
        return None, None, None
    parts = req.split()
    if len(parts) < 2:
        return None, None, None
    method = parts[0]
    url = parts[1]

    host = None
    path = url

    # Best-effort parse of absolute URL
    if url.startswith("http://") or url.startswith("https://"):
        try:
            scheme, rest = url.split("://", 1)
            if "/" in rest:
                hostpart, p = rest.split("/", 1)
                host = hostpart
                path = "/" + p
            else:
                host = rest
                path = "/"
        except Exception:
            pass

    return method, path, host


def iter_alb_events(paths: list[Path]) -> Iterator[ParsedAlb]:
    for p in paths:
        with _open_text_maybe_gzip(p) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue

                # allow pre-normalized json lines
                if line.startswith("{"):
                    try:
                        obj = json.loads(line)
                        ts = obj.get("ts") or obj.get("time") or obj.get("@timestamp")
                        yield ParsedAlb(
                            ts=str(ts),
                            src_ip=obj.get("src_ip"),
                            method=obj.get("method"),
                            path=obj.get("object") or obj.get("path"),
                            status=_safe_int(str(obj.get("status") or "")),
                            bytes=_safe_int(str(obj.get("bytes") or "")),
                            ua=obj.get("ua"),
                            host=obj.get("host"),
                        )
                        continue
                    except Exception:
                        pass

                try:
                    parts = shlex.split(line)
                except Exception:
                    continue

                if len(parts) < 12:
                    continue

                ts = parts[1]
                client = parts[3]  # ip:port
                elb_status = parts[8]
                sent_bytes = parts[10]  # received_bytes
                req = parts[12] if len(parts) > 12 else "-"
                ua = parts[13] if len(parts) > 13 else None

                src_ip = None
                if client and client != "-" and ":" in client:
                    src_ip = client.rsplit(":", 1)[0]

                method, path, host = _parse_request(req)

                # normalize ts (already UTC Z)
                try:
                    # some logs include microseconds, keep as-is but validate
                    datetime.fromisoformat(ts.replace("Z", "+00:00")).astimezone(timezone.utc)
                    iso = ts
                except Exception:
                    iso = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

                yield ParsedAlb(
                    ts=iso,
                    src_ip=src_ip,
                    method=method,
                    path=path,
                    status=_safe_int(elb_status),
                    bytes=_safe_int(sent_bytes),
                    ua=ua if ua and ua != "-" else None,
                    host=host,
                )


def write_events_jsonl(out_path: Path, *, asset_id: str, events: Iterable[ParsedAlb]) -> int:
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
            }
            if e.host:
                obj["host"] = e.host
            out.write(json.dumps({k: v for k, v in obj.items() if v is not None}, ensure_ascii=False) + "\n")
            n += 1
    return n
