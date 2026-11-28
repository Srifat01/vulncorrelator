"""Run intel operations without a worker or Redis (cron-friendly):

python -m app.intel.cli sync [--sources kev,epss,nvd,cpe] [--force]
python -m app.intel.cli status
"""

import argparse
import json
import logging

from app import database
from app.intel.status import intel_status
from app.intel.sync import SOURCES, build_clients, sync_all


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="python -m app.intel.cli")
    sub = ap.add_subparsers(dest="cmd", required=True)
    sp = sub.add_parser("sync")
    sp.add_argument("--sources", default=",".join(SOURCES))
    sp.add_argument("--force", action="store_true", help="ignore freshness windows and refetch")
    sub.add_parser("status")
    args = ap.parse_args(argv)
    logging.basicConfig(level=logging.INFO)
    with database.SessionLocal() as db:
        if args.cmd == "status":
            print(json.dumps(intel_status(db), indent=2, default=str))
            return 0
        wanted = tuple(x.strip() for x in args.sources.split(",") if x.strip())
        bad = set(wanted) - set(SOURCES)
        if bad:
            ap.error(f"unknown source(s): {sorted(bad)}; choose from {list(SOURCES)}")
        clients = build_clients()
        try:
            runs = sync_all(db, clients, wanted, force=args.force)
        finally:
            clients.close()
        for r in runs:
            print(f"{r.source:5} {r.status:8} seen={r.records_seen} updated={r.records_updated} {r.error or ''}")
        return 1 if any(r.status == "failed" for r in runs) else 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
