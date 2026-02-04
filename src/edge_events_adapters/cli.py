from __future__ import annotations

import argparse
import json
from pathlib import Path

from .discovery import discover_web_access_logs
from .alb import iter_alb_events as iter_alb_events, write_events_jsonl as write_alb_events_jsonl
from .alb_discovery import discover_alb_logs
from .apache_config import discover_access_logs_from_apache_config
from .firewall import iter_firewall_events, write_events_jsonl as write_firewall_events_jsonl
from .firewall_discovery import discover_firewall_logs
from .journald import iter_journal_lines
from .nginx import iter_access_events, iter_access_events_from_lines, write_events_jsonl
from .nginx_config import discover_access_logs_from_nginx_config


DEFAULT_LOOKBACK = "72 hours ago"
DEFAULT_MAX_FILES = 25
DEFAULT_MAX_TOTAL_BYTES = 500 * 1024 * 1024


def _default_report_path(out_events: Path) -> Path:
    # events.jsonl -> events.discovery.json (or add suffix)
    if out_events.name.endswith(".jsonl"):
        return out_events.with_name(out_events.name.replace(".jsonl", ".discovery.json"))
    return out_events.with_suffix(out_events.suffix + ".discovery.json")


def cmd_web(args: argparse.Namespace) -> int:
    out_events = Path(args.out)
    report_path = Path(args.report) if args.report else _default_report_path(out_events)

    paths: list[Path] = []
    report_obj: dict = {"mode": None, "selected_files": [], "journal_fallback": None}

    # 0) Explicit inputs override auto
    if args.input:
        paths = [Path(p) for p in args.input]
        report_obj["mode"] = "explicit"
        report_obj["selected_files"] = [str(p) for p in paths]
    else:
        # 1) NGINX config-derived
        cfg_paths = discover_access_logs_from_nginx_config()
        if cfg_paths:
            paths = cfg_paths
            report_obj["mode"] = "nginx_config"
            report_obj["selected_files"] = [str(p) for p in paths]
        else:
            # 2) Apache config-derived
            ap_paths = discover_access_logs_from_apache_config()
            if ap_paths:
                paths = ap_paths
                report_obj["mode"] = "apache_config"
                report_obj["selected_files"] = [str(p) for p in paths]
            else:
                # 3) default globs
                paths, rep = discover_web_access_logs(
                    include_apache=True,
                    max_files=DEFAULT_MAX_FILES,
                    max_total_bytes=DEFAULT_MAX_TOTAL_BYTES,
                )
                report_obj["mode"] = "default_globs"
                report_obj["glob_report"] = {
                    "found": [i.__dict__ for i in rep.found],
                    "skipped": [i.__dict__ for i in rep.skipped],
                    "errors": [i.__dict__ for i in rep.errors],
                }
                report_obj["selected_files"] = [str(p) for p in paths]

        # 3) journald fallback (default on)
        if not paths and not args.no_journal:
            # try common units
            units = ["nginx", "apache2", "httpd"]
            all_events = []
            used_unit = None
            for u in units:
                lines = iter_journal_lines(unit=u, since=args.since)
                evs = list(iter_access_events_from_lines(lines))
                if evs:
                    all_events = evs
                    used_unit = u
                    break
            n = write_events_jsonl(out_events, asset_id=args.asset, events=all_events, host=args.host)
            report_obj["journal_fallback"] = {"used_unit": used_unit, "since": args.since, "events_written": n}
            report_path.write_text(json.dumps(report_obj, indent=2) + "\n", encoding="utf-8")
            if not args.quiet:
                print(f"web: journald fallback wrote {n} events to {out_events}")
            return 0

        if not paths:
            report_path.write_text(json.dumps(report_obj, indent=2) + "\n", encoding="utf-8")
            raise SystemExit("web: no access logs discovered (and journald produced none). Provide --in explicitly.")

    # File-based path
    events = iter_access_events(paths)
    n = write_events_jsonl(out_events, asset_id=args.asset, events=events, host=args.host)
    report_obj["events_written"] = n
    report_path.write_text(json.dumps(report_obj, indent=2) + "\n", encoding="utf-8")

    if not args.quiet:
        print(f"web: wrote {n} events to {out_events} (report: {report_path})")
    return 0


def cmd_alb(args: argparse.Namespace) -> int:
    out_events = Path(args.out)
    report_path = Path(args.report) if args.report else _default_report_path(out_events)

    if args.input:
        paths = [Path(p) for p in args.input]
        mode = "explicit"
    else:
        # auto-discover under cwd (or given roots)
        roots = [Path(r) for r in (args.root or ["."])]
        paths = discover_alb_logs(roots=roots)
        mode = "auto"

    if not paths:
        report_path.write_text(json.dumps({"mode": mode, "selected_files": []}, indent=2) + "\n", encoding="utf-8")
        raise SystemExit("alb: no ALB logs discovered. Provide --in explicitly or set --root.")

    n = write_alb_events_jsonl(out_events, asset_id=args.asset, events=iter_alb_events(paths))
    report_path.write_text(
        json.dumps({"mode": mode, "selected_files": [str(p) for p in paths], "events_written": n}, indent=2) + "\n",
        encoding="utf-8",
    )

    if not args.quiet:
        print(f"alb: wrote {n} events to {out_events} (report: {report_path})")
    return 0


def cmd_firewall(args: argparse.Namespace) -> int:
    out_events = Path(args.out)
    report_path = Path(args.report) if args.report else _default_report_path(out_events)

    if args.input:
        paths = [Path(p) for p in args.input]
        mode = "explicit"
    else:
        roots = [Path(r) for r in (args.root or ["."])]
        paths = discover_firewall_logs(roots=roots)
        mode = "auto"

    if not paths:
        report_path.write_text(json.dumps({"mode": mode, "selected_files": []}, indent=2) + "\n", encoding="utf-8")
        raise SystemExit("firewall: no logs discovered. Provide --in explicitly or set --root.")

    n = write_firewall_events_jsonl(out_events, asset_id=args.asset, events=iter_firewall_events(paths))
    report_path.write_text(
        json.dumps({"mode": mode, "selected_files": [str(p) for p in paths], "events_written": n}, indent=2) + "\n",
        encoding="utf-8",
    )

    if not args.quiet:
        print(f"firewall: wrote {n} events to {out_events} (report: {report_path})")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="edge-events-adapters")
    sub = p.add_subparsers(dest="cmd", required=True)

    web = sub.add_parser("web", help="Collect web access events (auto-discovery by default)")
    web.add_argument("--asset", required=True, help="asset_id")
    web.add_argument("--out", required=True, help="output events.jsonl path")
    web.add_argument("--since", default=DEFAULT_LOOKBACK, help="journald lookback window (default: 72 hours ago)")
    web.add_argument("--host", required=False, help="optional host/vhost to stamp on events")
    web.add_argument("--in", dest="input", required=False, action="append", help="explicit log path (repeatable), overrides auto")
    web.add_argument("--report", required=False, help="write discovery report JSON here (default: alongside --out)")
    web.add_argument("--no-journal", action="store_true", help="disable journald fallback")
    web.add_argument("--quiet", action="store_true")
    web.set_defaults(func=cmd_web)

    alb = sub.add_parser("alb", help="Collect AWS ALB access log events (auto-discovery under cwd by default)")
    alb.add_argument("--asset", required=True, help="asset_id")
    alb.add_argument("--out", required=True, help="output events.jsonl path")
    alb.add_argument("--in", dest="input", required=False, action="append", help="explicit log path (repeatable), overrides auto")
    alb.add_argument("--root", required=False, action="append", help="auto-discovery root directory (repeatable, default: .)")
    alb.add_argument("--report", required=False, help="write discovery report JSON here (default: alongside --out)")
    alb.add_argument("--quiet", action="store_true")
    alb.set_defaults(func=cmd_alb)

    fw = sub.add_parser("firewall", help="Collect firewall/flow logs -> network_flow events (auto-discovery under cwd by default)")
    fw.add_argument("--asset", required=True, help="asset_id")
    fw.add_argument("--out", required=True, help="output events.jsonl path")
    fw.add_argument("--in", dest="input", required=False, action="append", help="explicit log path (repeatable), overrides auto")
    fw.add_argument("--root", required=False, action="append", help="auto-discovery root directory (repeatable, default: .)")
    fw.add_argument("--report", required=False, help="write discovery report JSON here (default: alongside --out)")
    fw.add_argument("--quiet", action="store_true")
    fw.set_defaults(func=cmd_firewall)

    args = p.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
