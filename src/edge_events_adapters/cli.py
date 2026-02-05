from __future__ import annotations

import argparse
import json
import tempfile
from pathlib import Path

from .discovery import discover_web_access_logs
from .alb import iter_alb_events as iter_alb_events, write_events_jsonl as write_alb_events_jsonl
from .alb_discovery import discover_alb_logs
from .apache_config import discover_access_logs_from_apache_config
from .firewall import iter_firewall_events, write_events_jsonl as write_firewall_events_jsonl
from .firewall_discovery import discover_firewall_logs
from .journald import iter_journal_lines
from .merge import merge_jsonl
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


def collect_web_events(*, asset_id: str, out_events: Path, since: str, host: str | None, explicit_inputs: list[str] | None, no_journal: bool) -> dict:
    """Collect web access events into out_events. Returns report dict."""

    report_obj: dict = {"mode": None, "selected_files": [], "journal_fallback": None}

    paths: list[Path] = []

    if explicit_inputs:
        paths = [Path(p) for p in explicit_inputs]
        report_obj["mode"] = "explicit"
        report_obj["selected_files"] = [str(p) for p in paths]
    else:
        cfg_paths = discover_access_logs_from_nginx_config()
        if cfg_paths:
            paths = cfg_paths
            report_obj["mode"] = "nginx_config"
            report_obj["selected_files"] = [str(p) for p in paths]
        else:
            ap_paths = discover_access_logs_from_apache_config()
            if ap_paths:
                paths = ap_paths
                report_obj["mode"] = "apache_config"
                report_obj["selected_files"] = [str(p) for p in paths]
            else:
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

        if not paths and not no_journal:
            units = ["nginx", "apache2", "httpd"]
            all_events = []
            used_unit = None
            for u in units:
                lines = iter_journal_lines(unit=u, since=since)
                evs = list(iter_access_events_from_lines(lines))
                if evs:
                    all_events = evs
                    used_unit = u
                    break
            n = write_events_jsonl(out_events, asset_id=asset_id, events=all_events, host=host)
            report_obj["journal_fallback"] = {"used_unit": used_unit, "since": since, "events_written": n}
            report_obj["events_written"] = n
            return report_obj

        if not paths:
            report_obj["events_written"] = 0
            return report_obj

    n = write_events_jsonl(out_events, asset_id=asset_id, events=iter_access_events(paths), host=host)
    report_obj["events_written"] = n
    return report_obj


def cmd_web(args: argparse.Namespace) -> int:
    out_events = Path(args.out)
    report_path = Path(args.report) if args.report else _default_report_path(out_events)

    rep = collect_web_events(
        asset_id=args.asset,
        out_events=out_events,
        since=args.since,
        host=args.host,
        explicit_inputs=args.input,
        no_journal=args.no_journal,
    )
    report_path.write_text(json.dumps(rep, indent=2) + "\n", encoding="utf-8")

    if not args.quiet:
        print(f"web: wrote {rep.get('events_written', 0)} events to {out_events} (report: {report_path})")
    return 0


def collect_alb_events(*, asset_id: str, out_events: Path, explicit_inputs: list[str] | None, roots: list[str] | None) -> dict:
    report: dict = {"mode": None, "selected_files": [], "events_written": 0}

    if explicit_inputs:
        paths = [Path(p) for p in explicit_inputs]
        report["mode"] = "explicit"
    else:
        rts = [Path(r) for r in (roots or ["."])]
        paths = discover_alb_logs(roots=rts)
        report["mode"] = "auto"

    if not paths:
        return report

    n = write_alb_events_jsonl(out_events, asset_id=asset_id, events=iter_alb_events(paths))
    report["selected_files"] = [str(p) for p in paths]
    report["events_written"] = n
    return report


def cmd_alb(args: argparse.Namespace) -> int:
    out_events = Path(args.out)
    report_path = Path(args.report) if args.report else _default_report_path(out_events)

    rep = collect_alb_events(asset_id=args.asset, out_events=out_events, explicit_inputs=args.input, roots=args.root)
    report_path.write_text(json.dumps(rep, indent=2) + "\n", encoding="utf-8")
    if not args.quiet:
        print(f"alb: wrote {rep.get('events_written', 0)} events to {out_events} (report: {report_path})")
    return 0


def collect_firewall_events(*, asset_id: str, out_events: Path, explicit_inputs: list[str] | None, roots: list[str] | None) -> dict:
    report: dict = {"mode": None, "selected_files": [], "events_written": 0}

    if explicit_inputs:
        paths = [Path(p) for p in explicit_inputs]
        report["mode"] = "explicit"
    else:
        rts = [Path(r) for r in (roots or ["."])]
        paths = discover_firewall_logs(roots=rts)
        report["mode"] = "auto"

    if not paths:
        return report

    n = write_firewall_events_jsonl(out_events, asset_id=asset_id, events=iter_firewall_events(paths))
    report["selected_files"] = [str(p) for p in paths]
    report["events_written"] = n
    return report


def cmd_firewall(args: argparse.Namespace) -> int:
    out_events = Path(args.out)
    report_path = Path(args.report) if args.report else _default_report_path(out_events)

    rep = collect_firewall_events(asset_id=args.asset, out_events=out_events, explicit_inputs=args.input, roots=args.root)
    report_path.write_text(json.dumps(rep, indent=2) + "\n", encoding="utf-8")

    if not args.quiet:
        print(f"firewall: wrote {rep.get('events_written', 0)} events to {out_events} (report: {report_path})")
    return 0


def cmd_bundle(args: argparse.Namespace) -> int:
    """Run a sensible default bundle: web + alb + firewall, then merge to one events.jsonl.

    Minimal knobs: asset_id, out path, optional since.
    """

    out_events = Path(args.out)
    report_path = Path(args.report) if args.report else _default_report_path(out_events)

    with tempfile.TemporaryDirectory(prefix="edge-events-") as td:
        tdir = Path(td)
        web_out = tdir / "web.jsonl"
        alb_out = tdir / "alb.jsonl"
        fw_out = tdir / "firewall.jsonl"

        web_rep = collect_web_events(
            asset_id=args.asset,
            out_events=web_out,
            since=args.since,
            host=None,
            explicit_inputs=None,
            no_journal=args.no_journal,
        )
        alb_rep = collect_alb_events(asset_id=args.asset, out_events=alb_out, explicit_inputs=None, roots=args.root)
        fw_rep = collect_firewall_events(asset_id=args.asset, out_events=fw_out, explicit_inputs=None, roots=args.root)

        # Merge in deterministic order
        merged_n = merge_jsonl(out_events, [web_out, alb_out, fw_out])

        # Simple coverage summary (for IR usability)
        bundle_items = [
            {"name": "web", **web_rep, "out": str(web_out)},
            {"name": "alb", **alb_rep, "out": str(alb_out)},
            {"name": "firewall", **fw_rep, "out": str(fw_out)},
        ]

        gaps = []
        for it in bundle_items:
            if int(it.get("events_written") or 0) == 0:
                gaps.append(it["name"])

        coverage_text = [
            f"asset: {args.asset}",
            f"merged_events: {merged_n}",
            "sources:",
        ]
        for it in bundle_items:
            coverage_text.append(f"- {it['name']}: {int(it.get('events_written') or 0)} events (mode={it.get('mode')})")
        if gaps:
            coverage_text.append("coverage_gaps:")
            coverage_text.append("- missing_or_empty: " + ", ".join(gaps))

        rep = {
            "bundle": bundle_items,
            "merged": {"out": str(out_events), "events_written": merged_n},
            "coverage": {"gaps": gaps, "summary_txt": str(out_events.with_suffix(out_events.suffix + ".coverage.txt"))},
        }
        report_path.write_text(json.dumps(rep, indent=2) + "\n", encoding="utf-8")
        out_events.with_suffix(out_events.suffix + ".coverage.txt").write_text("\n".join(coverage_text) + "\n", encoding="utf-8")

    if not args.quiet:
        print(f"bundle: wrote {merged_n} events to {out_events} (report: {report_path})")
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

    bun = sub.add_parser("bundle", help="Run web+alb+firewall collectors and merge into one events.jsonl")
    bun.add_argument("--asset", required=True, help="asset_id")
    bun.add_argument("--out", required=True, help="output merged events.jsonl path")
    bun.add_argument("--since", default=DEFAULT_LOOKBACK, help="journald lookback for web collector (default: 72 hours ago)")
    bun.add_argument("--root", required=False, action="append", help="roots for alb/firewall auto-discovery (repeatable, default: .)")
    bun.add_argument("--report", required=False, help="write bundle report JSON here (default: alongside --out)")
    bun.add_argument("--no-journal", action="store_true", help="disable journald fallback for web collector")
    bun.add_argument("--quiet", action="store_true")
    bun.set_defaults(func=cmd_bundle)

    args = p.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
