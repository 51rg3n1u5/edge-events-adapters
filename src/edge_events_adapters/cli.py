from __future__ import annotations

import argparse


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="edge-events-adapters")
    sub = p.add_subparsers(dest="cmd", required=True)

    # Placeholders: implemented next
    sub.add_parser("nginx", help="Parse nginx/apache access logs -> events.jsonl")
    sub.add_parser("alb", help="Parse AWS ALB access logs -> events.jsonl")

    args = p.parse_args(argv)
    p.error("Not implemented yet. This repo is a scaffold.")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
