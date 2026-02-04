from __future__ import annotations

import argparse
import json
from pathlib import Path

from .discovery import discover_web_access_logs
from .journald import iter_journal_lines
from .nginx import iter_access_events, iter_access_events_from_lines, write_events_jsonl
from .nginx_config import discover_access_logs_from_nginx_config


def cmd_nginx(args: argparse.Namespace) -> int:
    paths: list[Path]

    discovery_mode = "explicit" if args.input else "auto"

    report_obj: dict | None = None

    if args.input:
        paths = [Path(p) for p in args.input]
    else:
        # 1) Prefer config-derived paths (more accurate)
        cfg_paths = discover_access_logs_from_nginx_config()
        if cfg_paths:
            paths = cfg_paths
            report_obj = {"mode": "nginx_config", "paths": [str(p) for p in paths]}
        else:
            # 2) Fallback to common default globs
            paths, report = discover_web_access_logs(
                include_apache=True,
                max_files=args.max_files,
                max_total_bytes=args.max_total_bytes,
            )
            report_obj = {
                "mode": "default_globs",
                "found": [i.__dict__ for i in report.found],
                "skipped": [i.__dict__ for i in report.skipped],
                "errors": [i.__dict__ for i in report.errors],
            }

        # 3) Final fallback: journald (if file logs not present)
        if not paths and args.journal_fallback:
            # Try to parse access-log style lines out of journald output.
            journal_lines = iter_journal_lines(unit=args.journal_unit, since=args.since)
            events = iter_access_events_from_lines(journal_lines)
            n = write_events_jsonl(Path(args.out), asset_id=args.asset, events=events, host=args.host)
            if args.discovery_report and report_obj is not None:
                report_obj["journal_fallback"] = {"unit": args.journal_unit, "since": args.since, "events_written": n}
                Path(args.discovery_report).write_text(json.dumps(report_obj, indent=2) + "\n", encoding="utf-8")
            if not args.quiet:
                print(f"auto-discovery: journald fallback wrote {n} events to {args.out}")
            return 0

        if not paths:
            raise SystemExit("No access logs discovered. Provide --in explicitly, adjust limits, or enable journald fallback.")

    if args.discovery_report and report_obj is not None:
        Path(args.discovery_report).write_text(json.dumps(report_obj, indent=2) + "\n", encoding="utf-8")

    events = iter_access_events(paths)
    n = write_events_jsonl(Path(args.out), asset_id=args.asset, events=events, host=args.host)

    if not args.quiet:
        if discovery_mode == "auto":
            print(f"auto-discovered {len(paths)} files, wrote {n} events to {args.out}")
        else:
            print(f"wrote {n} events to {args.out}")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="edge-events-adapters")
    sub = p.add_subparsers(dest="cmd", required=True)

    ng = sub.add_parser("nginx", help="Parse nginx/apache access logs -> events.jsonl")
    ng.add_argument("--in", dest="input", required=False, action="append", help="input access log path (repeatable). Supports .gz. If omitted, auto-discovery is used.")
    ng.add_argument("--asset", required=True, help="asset_id")
    ng.add_argument("--out", required=True, help="output events.jsonl path")
    ng.add_argument("--host", required=False, help="optional host/vhost to stamp on events")
    ng.add_argument("--max-files", type=int, default=25, help="auto-discovery cap")
    ng.add_argument("--max-total-bytes", type=int, default=500 * 1024 * 1024, help="auto-discovery cap")
    ng.add_argument("--discovery-report", required=False, help="write discovery report JSON here")
    ng.add_argument("--no-journal-fallback", dest="journal_fallback", action="store_false", default=True, help="disable journald fallback")
    ng.add_argument("--journal-unit", default="nginx", help="journald unit name (default: nginx)")
    ng.add_argument("--since", default="24 hours ago", help="journald lookback window (default: 24 hours ago)")
    ng.add_argument("--quiet", action="store_true")
    ng.set_defaults(func=cmd_nginx)

    # TODO: implement
    alb = sub.add_parser("alb", help="Parse AWS ALB access logs -> events.jsonl (TODO)")
    alb.set_defaults(func=lambda _args: (_ for _ in ()).throw(SystemExit("alb parser not implemented yet")))

    args = p.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
