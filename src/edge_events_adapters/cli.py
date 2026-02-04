from __future__ import annotations

import argparse
from pathlib import Path

from .nginx import iter_access_events, write_events_jsonl


def cmd_nginx(args: argparse.Namespace) -> int:
    paths: list[Path] = []
    for p in args.input:
        paths.append(Path(p))

    events = iter_access_events(paths)
    n = write_events_jsonl(Path(args.out), asset_id=args.asset, events=events, host=args.host)
    if not args.quiet:
        print(f"wrote {n} events to {args.out}")
    return 0


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="edge-events-adapters")
    sub = p.add_subparsers(dest="cmd", required=True)

    ng = sub.add_parser("nginx", help="Parse nginx/apache access logs -> events.jsonl")
    ng.add_argument("--in", dest="input", required=True, action="append", help="input access log path (repeatable). Supports .gz")
    ng.add_argument("--asset", required=True, help="asset_id")
    ng.add_argument("--out", required=True, help="output events.jsonl path")
    ng.add_argument("--host", required=False, help="optional host/vhost to stamp on events")
    ng.add_argument("--quiet", action="store_true")
    ng.set_defaults(func=cmd_nginx)

    # TODO: implement
    alb = sub.add_parser("alb", help="Parse AWS ALB access logs -> events.jsonl (TODO)")
    alb.set_defaults(func=lambda _args: (_ for _ in ()).throw(SystemExit("alb parser not implemented yet")))

    args = p.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())
