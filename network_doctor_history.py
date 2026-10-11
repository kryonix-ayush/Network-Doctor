"""Print recent locally stored Network Doctor check results."""

from __future__ import annotations

import argparse
from collections.abc import Sequence
from pathlib import Path

from storage.repository import ResultRepository
from checks.url_validation import redact_url_query


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Display recent local diagnostic history.")
    parser.add_argument("--database", type=Path, default=Path("network_doctor.sqlite3"))
    parser.add_argument("--limit", type=int, default=30)
    parser.add_argument("--url", help="Show results for a single exact URL")
    args = parser.parse_args(argv)
    if args.limit < 1:
        parser.error("--limit must be a positive integer")

    rows = ResultRepository(args.database).get_recent(args.limit, args.url)
    if not rows:
        print("No diagnostic history found.")
        return 0
    for row in rows:
        status = "SKIPPED" if row["success"] is None else ("PASS" if row["success"] else "FAIL")
        display_url = redact_url_query(row["target_url"])
        details = f"{row['duration_ms']:.1f} ms"
        if row["status_code"] is not None:
            details += f" - HTTP {row['status_code']}"
        if row["error_code"]:
            details += f" - {row['error_code']}"
        print(
            f"{row['timestamp_utc']} {row['check_type'].upper():<6} {status:<7} "
            f"{display_url} - {details}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
