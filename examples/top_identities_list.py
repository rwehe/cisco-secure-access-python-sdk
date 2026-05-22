# Copyright 2026 Cisco Systems, Inc. and its affiliates
#
# SPDX-License-Identifier: Apache-2.0

"""
Fetch all top identities from Cisco Secure Access and write results to JSON (or CSV).

Fetches every page concurrently (max 5 workers) using TopIdentitiesApi.get_top_identities,
then optionally renders a horizontal bar chart of identities ranked by request count.

Usage:
    python top_identities_list.py [--from TIMERANGE] [--to TIMERANGE]
                                  [--identitytypes TYPES]
                                  [--top-n N]
                                  [--format json|csv] [--output FILE]
                                  [--chart TYPE] [--chart-output FILE]

Arguments:
    --from            Start of time range (default: -7days)
    --to              End of time range   (default: now)
    --identitytypes   Identity type or comma-delimited list (e.g. "roaming computers")
    --top-n           Keep only the top N records after fetching (default: all)
    --format          Output format: json or csv (default: json)
    --output          Output file path (- for stdout, default: top_identities.json)
    --chart           Chart type: none | bar | horizontal_bar | line | pie (default: none)
    --chart-output    File path to save the chart PNG (empty = display interactively)

Examples:
    python top_identities_list.py
    python top_identities_list.py --from -7days --to now --output top_identities.json
    python top_identities_list.py --from 2025-01-01 --to 2025-01-31 --format csv --output results.csv
    python top_identities_list.py --from -30days --to now --top-n 50 --chart horizontal_bar --chart-output chart.png
    python top_identities_list.py --from -7days --to now --identitytypes "roaming computers" --chart horizontal_bar
"""

import csv
import json
import logging
import argparse
import re
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from typing import List, Optional

from access_token import generate_access_token
from config import config
from secure_access.configuration import Configuration
from secure_access.api_client import ApiClient
from secure_access.api.top_identities_api import TopIdentitiesApi
from secure_access.exceptions import ApiException

try:
    import matplotlib
    matplotlib.use("Agg")  # non-interactive backend; switched to "TkAgg" for live display
    import matplotlib.pyplot as plt
    _MATPLOTLIB_AVAILABLE = True
except ImportError:
    _MATPLOTLIB_AVAILABLE = False

logging.basicConfig(
    level=logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)


# ── time helpers ──────────────────────────────────────────────────────────────

_RELATIVE_SUFFIXES = ("days", "hours", "minutes")
_ISO_FORMAT = "%Y-%m-%dT%H:%M:%SZ"
_DATE_ONLY_FORMAT = "%Y-%m-%d"

# Regex that matches relative time strings such as -7days, -30hours, -1minutes
_RELATIVE_RE = re.compile(r"^-\d+(?:days|hours|minutes)$")


def parse_time_arg(value: str) -> str:
    """
    Normalise a time argument to an API-accepted string.

    Accepted formats:
      Relative  : -1days | -7days | -30days | -90days | -365days | now
      ISO 8601  : 2025-01-01T00:00:00Z   (validated, passed through unchanged)
      Date-only : 2025-01-01             (converted to 2025-01-01T00:00:00Z)
    """
    v = value.strip()
    if v == "now":
        return v
    if v.startswith("-") and any(v.endswith(s) for s in _RELATIVE_SUFFIXES):
        return v
    try:
        datetime.strptime(v, _ISO_FORMAT)
        return v
    except ValueError:
        pass
    try:
        dt = datetime.strptime(v, _DATE_ONLY_FORMAT)
        return dt.strftime(_ISO_FORMAT)
    except ValueError:
        pass
    raise argparse.ArgumentTypeError(
        f"Unrecognised time format: '{value}'. "
        "Use a relative value (-7days, now), ISO 8601 (2025-01-01T00:00:00Z), "
        "or date-only (2025-01-01)."
    )


# ── data helpers ──────────────────────────────────────────────────────────────

def apply_top_n(records: list, top_n: Optional[int]) -> list:
    """Slice to at most top_n records (preserving API rank order). None = keep all."""
    if top_n is None:
        return records
    return records[:top_n]


def _flatten_dict(d: dict, parent_key: str = "") -> dict:
    """Flatten one level of nested dicts using dot notation for CSV output."""
    items = {}
    for k, v in d.items():
        key = f"{parent_key}.{k}" if parent_key else k
        if isinstance(v, dict):
            items.update(_flatten_dict(v, key))
        else:
            items[key] = v
    return items


def write_json(records: list, path: str) -> None:
    data = [r.to_dict() for r in records]
    if path == "-":
        print(json.dumps(data, indent=2))
    else:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        logger.info("JSON results written to %s", path)


def write_csv(records: list, path: str) -> None:
    if not records:
        logger.warning("No records to write.")
        return
    flat_rows = [_flatten_dict(r.to_dict()) for r in records]
    fieldnames = list(flat_rows[0].keys())
    dest = sys.stdout if path == "-" else open(path, "w", newline="", encoding="utf-8")
    try:
        writer = csv.DictWriter(dest, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(flat_rows)
    finally:
        if path != "-":
            dest.close()
            logger.info("CSV results written to %s", path)


# ── visualization ─────────────────────────────────────────────────────────────

def visualize(records: list, chart_type: str, chart_output: str) -> None:
    """
    Render a chart from the TopIdentity record list using matplotlib.

    chart_type   : bar | horizontal_bar | line | pie
    chart_output : file path to save PNG (e.g. chart.png), or "" to display interactively
    """
    if not _MATPLOTLIB_AVAILABLE:
        logger.error("matplotlib is not installed. Run: pip install matplotlib")
        return
    if not records:
        logger.warning("No data to visualize.")
        return

    labels: List[str] = []
    values: List[float] = []
    for i, r in enumerate(records):
        identity = getattr(r, "identity", None)
        label = (getattr(identity, "label", None) if identity else None) or str(i + 1)
        value = getattr(r, "requests", None) or 0
        labels.append(str(label))
        values.append(float(value) if value else 0.0)

    fig, ax = plt.subplots(figsize=(12, max(6, len(labels) * 0.35)))

    if chart_type == "bar":
        ax.bar(labels, values, color="steelblue")
        ax.set_xlabel("Identity")
        ax.set_ylabel("Requests")
        plt.xticks(rotation=45, ha="right")

    elif chart_type == "horizontal_bar":
        # Reverse so rank 1 appears at the top
        ax.barh(labels[::-1], values[::-1], color="steelblue")
        ax.set_xlabel("Requests")
        ax.set_ylabel("Identity")

    elif chart_type == "line":
        ax.plot(labels, values, marker="o", color="steelblue", linewidth=2)
        ax.set_xlabel("Identity")
        ax.set_ylabel("Requests")
        plt.xticks(rotation=45, ha="right")

    elif chart_type == "pie":
        ax.pie(values, labels=labels, autopct="%1.1f%%", startangle=140)

    ax.set_title("Top Identities by Requests")
    plt.tight_layout()

    if chart_output:
        plt.savefig(chart_output, dpi=150, bbox_inches="tight")
        logger.info("Chart saved to %s", chart_output)
    else:
        matplotlib.use("TkAgg")  # switch to interactive backend for live display
        plt.show()

    plt.close(fig)


# ── API client ────────────────────────────────────────────────────────────────

def build_client() -> TopIdentitiesApi:
    access_token = generate_access_token()
    configuration = Configuration(
        access_token=access_token,
        retries=config.get_retry(),
        ignore_operation_servers=True,
        server_index=1,
        server_variables={"region": "us"},
    )
    api_client = ApiClient(configuration=configuration)
    return TopIdentitiesApi(api_client=api_client)


# ── fetch (concurrent pagination) ────────────────────────────────────────────

def fetch_all(api: TopIdentitiesApi, args: argparse.Namespace) -> list:
    """
    Fetch all records using concurrent batch pagination.

    Fetches up to 5 pages in parallel per batch (max_workers=5).
    Stops as soon as any page in a batch returns fewer than 100 records,
    which indicates the last page — no reliance on meta.total.

    Use --page-delay N to sleep N seconds between batches when hitting
    429 rate limits.
    """
    limit = 100
    max_workers = 5
    page_delay: float = getattr(args, "page_delay", 0.0) or 0.0
    all_records: list = []
    offset = 0

    def fetch_page(o: int):
        return api.get_top_identities(
            var_from=args.var_from,
            to=args.to,
            limit=limit,
            offset=o,
            identitytypes=args.identitytypes,
        )

    while True:
        batch_offsets = [o for o in range(offset, offset + max_workers * limit, limit) if o <= 10000]
        if not batch_offsets:
            break  # all offsets exceed API max (10000)
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            pages = list(executor.map(fetch_page, batch_offsets))

        done = False
        for page in pages:
            all_records.extend(page.data)
            logger.info("Fetched %d records (offset=%d)", len(page.data), batch_offsets[pages.index(page)])
            if len(page.data) < limit:
                done = True
                break  # last page reached — stop processing this batch

        # truncated batch means we've hit the API offset ceiling
        if done or len(batch_offsets) < max_workers:
            break

        offset += max_workers * limit
        if page_delay > 0:
            logger.info("Sleeping %.1fs between batches (--page-delay)", page_delay)
            time.sleep(page_delay)

    return all_records


# ── main ──────────────────────────────────────────────────────────────────────

def main() -> None:
    # Pre-process argv so argparse doesn't misinterpret relative time strings
    # (e.g. -7days) as flags.  Convert --from -7days → --from=-7days.
    argv = sys.argv[1:]
    _time_flags = {"--from", "--to"}
    processed: list = []
    i = 0
    while i < len(argv):
        token = argv[i]
        if token in _time_flags and i + 1 < len(argv) and _RELATIVE_RE.match(argv[i + 1]):
            processed.append(f"{token}={argv[i + 1]}")
            i += 2
        else:
            processed.append(token)
            i += 1

    parser = argparse.ArgumentParser(
        description="Fetch all top identities from Cisco Secure Access (last 7 days by default).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Time range formats:
  Relative : -1days | -7days | -30days | -90days | now
  ISO 8601 : 2025-01-01T00:00:00Z
  Date only: 2025-01-01  (treated as midnight UTC)

Examples:
  python top_identities_list.py
  python top_identities_list.py --from -7days --to now --output top_identities.json
  python top_identities_list.py --from 2025-01-01 --to 2025-01-31 --format csv --output results.csv
  python top_identities_list.py --from -30days --to now --top-n 50 --chart horizontal_bar --chart-output chart.png
  python top_identities_list.py --from -7days --identitytypes "roaming computers" --chart horizontal_bar
        """,
    )
    parser.add_argument(
        "--from",
        dest="var_from",
        default="-7days",
        type=parse_time_arg,
        help="Start of time range (default: -7days)",
    )
    parser.add_argument(
        "--to",
        default="now",
        type=parse_time_arg,
        help="End of time range (default: now)",
    )
    parser.add_argument(
        "--identitytypes",
        default=None,
        help="Identity type or comma-delimited list (e.g. 'roaming computers,users'). Default: all types.",
    )
    parser.add_argument(
        "--top-n",
        dest="top_n",
        type=int,
        default=None,
        help="Keep only the top N records after fetching (default: all)",
    )
    parser.add_argument(
        "--format",
        dest="fmt",
        default="json",
        choices=["json", "csv"],
        help="Output format: json or csv (default: json)",
    )
    parser.add_argument(
        "--output",
        default="top_identities.json",
        help="Output file path (- for stdout, default: top_identities.json)",
    )
    parser.add_argument(
        "--chart",
        default="none",
        choices=["none", "bar", "horizontal_bar", "line", "pie"],
        help="Chart type for visualization (default: none)",
    )
    parser.add_argument(
        "--chart-output",
        dest="chart_output",
        default="top_identities_chart.png",
        help="File path to save the chart PNG (empty = display interactively, default: top_identities_chart.png)",
    )
    parser.add_argument(
        "--page-delay",
        dest="page_delay",
        type=float,
        default=0.0,
        help="Seconds to sleep between page batches (default: 0). Use e.g. 1.0 to avoid 429 rate limits.",
    )

    args = parser.parse_args(processed)

    try:
        api = build_client()

        logger.info("Fetching top identities from %s to %s", args.var_from, args.to)
        if args.identitytypes:
            logger.info("Filter — identitytypes: %s", args.identitytypes)

        records = fetch_all(api, args)
        logger.info("Retrieved %d records total", len(records))

        records = apply_top_n(records, args.top_n)
        if args.top_n is not None:
            logger.info("Limited to top %d records", len(records))

        if args.fmt == "csv":
            write_csv(records, args.output)
        else:
            write_json(records, args.output)

        if args.chart != "none":
            visualize(records, args.chart, args.chart_output)

    except ApiException as e:
        logger.error("API call failed — HTTP %s %s: %s", e.status, e.reason, e.body)
        if e.status == 401:
            logger.error("Authentication failed. Verify CLIENT_ID and CLIENT_SECRET.")
        elif e.status == 403:
            logger.error("Access forbidden. Verify the API scope permissions.")
        elif e.status == 429:
            logger.error("Rate limit exceeded. Retry configuration is active via config.get_retry().")
        elif e.status and e.status >= 500:
            logger.error("Server error. Try again later.")
        raise SystemExit(1)
    except ValueError as e:
        logger.error("Invalid parameter: %s", e)
        raise SystemExit(1)
    except Exception as e:
        logger.error("Unexpected error: %s", e)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
