"""Summaries of a run for the page of a GitHub Actions job.

A dbt warn never turns the run red (CLAUDE.md §3, "Comprobaciones"), so it must be
visible somewhere else: each one becomes a ::warning:: annotation, shown on the
page of the run, and the job summary lists every node that did not pass.

dbt: the results of the last dbt command (run_results.json) by status, and every
node that did not pass with its failing rows and dbt's message. Nothing here
prints data values: only node names, statuses, counts and messages.

Written to $GITHUB_STEP_SUMMARY (Markdown) when it is set, and always to stdout;
annotations only inside GitHub Actions (GITHUB_ACTIONS=true).

Run from the repo root:
  uv run python -m threat_intel_pipeline.report dbt --run-results dbt/target/run_results.json
"""

from __future__ import annotations

import argparse
import collections
import json
import os
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any

from threat_intel_pipeline.storage import annotation

MESSAGE_CHARS = 300
STATUS_ORDER = ("success", "pass", "warn", "fail", "error", "skipped")

EXIT_OK = 0
EXIT_FAILED = 1  # the report could not be made


def node_name(unique_id: str) -> str:
    """'test.threat_intel_pipeline.<name>.<hash>' -> 'test <name>'; 'model.threat_intel_pipeline.<name>' -> 'model <name>'."""
    parts = unique_id.split(".")
    kind = parts[0]
    if kind == "test" and len(parts) >= 4:
        return f"test {parts[2]}"
    return f"{kind} {'.'.join(parts[2:])}"


def short(message: Any) -> str:
    text = " ".join(str(message or "").split())
    return text if len(text) <= MESSAGE_CHARS else text[: MESSAGE_CHARS - 3] + "..."


def dbt_report(run_results: Mapping[str, Any]) -> tuple[list[str], list[str]]:
    """Markdown lines of the job summary and the annotations, from a run_results.json document."""
    results = run_results["results"]
    command = run_results.get("args", {}).get("which", "dbt")
    target = run_results.get("args", {}).get("target", "?")
    counts = collections.Counter(result["status"] for result in results)
    statuses = [s for s in STATUS_ORDER if counts[s]] + sorted(s for s in counts if s not in STATUS_ORDER)
    lines = [
        f"### dbt {command} (target {target}): {len(results)} nodes",
        "",
        "| status | nodes |",
        "|---|---:|",
        *(f"| {status} | {counts[status]} |" for status in statuses),
    ]
    not_passed = [result for result in results if result["status"] not in ("success", "pass")]
    if not_passed:
        lines += ["", "| node | status | failing rows | message |", "|---|---|---:|---|"]
        for result in sorted(not_passed, key=lambda r: (r["status"], r["unique_id"])):
            failures = "" if result.get("failures") is None else str(result["failures"])
            message = short(result.get("message")).replace("|", "\\|")
            lines.append(f"| {node_name(result['unique_id'])} | {result['status']} | {failures} | {message} |")
    annotations = [
        annotation(
            "warning",
            "dbt warn",
            f"{node_name(result['unique_id'])}: {result.get('failures')} rows; {short(result.get('message'))}",
        )
        for result in results
        if result["status"] == "warn"
    ]
    return lines, annotations


def main(argv: Sequence[str] | None = None, *, environ: Mapping[str, str] = os.environ) -> int:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(errors="backslashreplace")
    args = _parse_args(argv)
    try:
        document = json.loads(args.run_results.read_text(encoding="utf-8"))
        lines, annotations = dbt_report(document)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"Result: FAILED, exit code {EXIT_FAILED} (cannot read {args.run_results.as_posix()}: {exc})", flush=True)
        return EXIT_FAILED
    print("\n".join(lines), flush=True)
    if environ.get("GITHUB_ACTIONS") == "true":
        print("\n".join(annotations), flush=True)
    summary = environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as file:
            file.write("\n".join(lines) + "\n\n")
    return EXIT_OK


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m threat_intel_pipeline.report",
        description="Summaries of a run for the page of a GitHub Actions job.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    dbt = commands.add_parser("dbt", help="statuses of the last dbt command and every node that did not pass")
    dbt.add_argument("--run-results", required=True, type=Path, help="dbt's run_results.json")
    return parser.parse_args(argv)


if __name__ == "__main__":
    sys.exit(main())
