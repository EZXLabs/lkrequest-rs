#!/usr/bin/env python3
import json
import re
import statistics
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

FILE_PATTERN = re.compile(
    r"^(?P<scenario>.+)-round(?P<round>\d+)-(?P<client>lkrequest|lkrequest-batch64|lkrequest-transport|lkh2|lkh2-drain64|lkh2-batch64|hyper|reqwest)\.json$"
)
CLIENT_ORDER = {
    "lkrequest": 0,
    "lkrequest-batch64": 1,
    "lkrequest-transport": 2,
    "lkh2": 3,
    "lkh2-drain64": 4,
    "lkh2-batch64": 5,
    "hyper": 6,
    "reqwest": 7,
}


def median(reports, selector):
    return statistics.median(selector(report) for report in reports)


def main():
    if len(sys.argv) != 2:
        raise SystemExit("usage: summarize.py RESULTS_DIRECTORY")

    results_dir = Path(sys.argv[1])
    grouped = defaultdict(list)
    for path in results_dir.glob("*.json"):
        match = FILE_PATTERN.match(path.name)
        if match:
            grouped[(match.group("scenario"), match.group("client"))].append(
                json.loads(path.read_text(encoding="utf-8"))
            )

    if not grouped:
        raise SystemExit(f"no benchmark result files found in {results_dir}")

    rows = []
    for (scenario, client), reports in grouped.items():
        versions = sorted({report["client_version"] for report in reports})
        if len(versions) != 1:
            raise SystemExit(f"mixed {client} versions in {scenario}: {versions}")
        rows.append(
            {
                "scenario": scenario,
                "client": client,
                "version": versions[0],
                "rounds": len(reports),
                "runtime_workers": reports[0]["runtime_workers"],
                "requests_per_second": median(
                    reports, lambda report: report["requests_per_second"]
                ),
                "mebibytes_per_second": median(
                    reports, lambda report: report["mebibytes_per_second"]
                ),
                "p50_us": median(reports, lambda report: report["latency"]["p50_us"]),
                "p95_us": median(reports, lambda report: report["latency"]["p95_us"]),
                "p99_us": median(reports, lambda report: report["latency"]["p99_us"]),
                "cpu_seconds": median(
                    reports,
                    lambda report: report["user_cpu_seconds"]
                    + report["system_cpu_seconds"],
                ),
                "peak_rss_mib": median(
                    reports, lambda report: report["peak_rss_bytes"] / 1024 / 1024
                ),
                "connections": median(
                    reports, lambda report: report["observed_connection_count"]
                ),
                "failures": sum(report["failed_requests"] for report in reports),
            }
        )

    rows.sort(key=lambda row: (row["scenario"], CLIENT_ORDER[row["client"]]))
    summary = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "aggregation": "median across rounds, failures summed",
        "rows": rows,
    }
    (results_dir / "summary.json").write_text(
        json.dumps(summary, indent=2) + "\n", encoding="utf-8"
    )

    lines = [
        "# HTTP/2 client benchmark summary",
        "",
        "Values are medians across rounds; failures are summed.",
        "",
        "| Scenario | Client | Version | Workers | Rounds | req/s | MiB/s | p50 us | p95 us | p99 us | CPU s | Peak RSS MiB | Connections | Failures |",
        "|---|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|",
    ]
    for row in rows:
        lines.append(
            "| {scenario} | {client} | {version} | {runtime_workers} | {rounds} | {requests_per_second:.1f} | "
            "{mebibytes_per_second:.1f} | {p50_us:.0f} | {p95_us:.0f} | {p99_us:.0f} | "
            "{cpu_seconds:.3f} | {peak_rss_mib:.1f} | {connections:.0f} | {failures} |".format(
                **row
            )
        )
    markdown = "\n".join(lines) + "\n"
    (results_dir / "SUMMARY.md").write_text(markdown, encoding="utf-8")
    print(markdown, end="")


if __name__ == "__main__":
    main()
