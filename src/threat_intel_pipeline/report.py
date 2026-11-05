"""Summaries of a run for the page of a GitHub Actions job.

A dbt warn never turns the run red (CLAUDE.md §3, "Comprobaciones"), so it must be
visible somewhere else: each one becomes a ::warning:: annotation, shown on the
page of the run, and the job summary lists every node that did not pass.

dbt: the results of the last dbt command (run_results.json) by status, and every
node that did not pass with its failing rows and dbt's message.

ingest: the manifest written by the run, its warnings as ::warning:: annotations,
and two rules that are errors only in Actions (session 4): a source whose 1% drop
check was skipped (no reference manifest), and a source recorded ok with two
different sha256 values on the same snapshot_date. The ingest command keeps them
as warnings (CLAUDE.md §4) and its files are already saved; the report turns the
job red so that they are looked at that same day. A drop reference older than the
day before means days without an ok manifest of that source, a gap that cannot be
filled (no backfill): it is a ::warning:: annotation and never turns the job red.

Nothing here prints data values: only names, statuses, counts and messages.
Written to $GITHUB_STEP_SUMMARY (Markdown) when it is set, and always to stdout;
annotations only inside GitHub Actions (GITHUB_ACTIONS=true).

Run from the repo root:
  uv run python -m threat_intel_pipeline.report dbt --run-results dbt/target/run_results.json
  uv run python -m threat_intel_pipeline.report ingest --raw-dir data/raw [--new-manifest NAME]
"""

from __future__ import annotations

import argparse
import collections
import json
import os
import sys
from collections.abc import Mapping, Sequence
from datetime import date, timedelta
from pathlib import Path
from typing import Any

from threat_intel_pipeline.manifest import load_manifests
from threat_intel_pipeline.storage import annotation

MESSAGE_CHARS = 300
STATUS_ORDER = ("success", "pass", "warn", "fail", "error", "skipped")
SOURCES = ("kev", "epss")

EXIT_OK = 0
EXIT_FAILED = 1  # the report could not be made, or an Actions rule failed


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


def ingest_report(raw_dir: Path, new_manifest: str | None) -> tuple[list[str], list[str], list[str]]:
    """Markdown lines, annotations and errors of the Actions rules, for the manifest written by the run."""
    if not new_manifest:
        lines = [
            "### Ingest: no manifest written by this run",
            "",
            (
                "Nothing to do (every source already on disk and ok in the day's latest manifest), "
                "or the ingest stopped before writing it: see its log."
            ),
        ]
        return lines, [], []
    data = json.loads((raw_dir / new_manifest).read_text(encoding="ascii"))
    lines = [
        f"### Ingest: {new_manifest} (status {data['status']})",
        "",
        "| source | status | action | rows | bytes | 1% drop check | error |",
        "|---|---|---|---:|---:|---|---|",
    ]
    errors = []
    old_references = []
    day = date.fromisoformat(data["snapshot_date"])
    for source, entry in data["sources"].items():
        drop = entry.get("drop_check") or {}
        checked = short(drop.get("summary")) or "-"
        age = drop.get("reference_age_days")
        if type(age) is int and age > 1:
            checked += f" (reference {age} days old)"
            old_references.append(_old_reference(source, age, day))
        cells = [
            source, entry["status"], entry.get("action") or "-", _number(entry.get("rows")), _number(entry.get("bytes")),
            checked, short(entry.get("error")) or "-",
        ]
        lines.append("| " + " | ".join(cell.replace("|", "\\|") for cell in cells) + " |")
        if drop.get("status") == "skipped":
            errors.append(f"{source}: the 1% drop check was skipped ({drop.get('reason')}); in Actions every source needs a reference manifest")
    index = load_manifests(raw_dir, day, SOURCES)
    for source in SOURCES:
        recorded: dict[str, str] = {}
        for manifest in index.readable:
            entry = manifest.entry(source)
            if manifest.snapshot_date == day and entry["status"] == "ok":
                recorded.setdefault(entry["sha256"], manifest.name)
        if len(recorded) > 1:
            found = ", ".join(f"{sha256} in {name}" for sha256, name in sorted(recorded.items()))
            errors.append(f"{source}: the ok manifests of {day.isoformat()} record different sha256 values ({found})")
    warnings = [str(warning) for warning in data.get("warnings") or []]
    lines += ["", f"Warnings of the manifest ({len(warnings)}):" if warnings else "Warnings of the manifest: none"]
    lines += [f"- {short(warning)}" for warning in warnings]
    lines += [
        "",
        f"Drop references older than one day ({len(old_references)}):" if old_references
        else "Drop references older than one day: none",
    ]
    lines += [f"- {reference}" for reference in old_references]
    lines += ["", f"Actions rules: {len(errors)} errors" if errors else "Actions rules: ok"]
    lines += [f"- {error}" for error in errors]
    annotations = [annotation("warning", "ingest warning", short(warning)) for warning in warnings]
    annotations += [annotation("warning", "ingest gap", reference) for reference in old_references]
    annotations += [annotation("error", "ingest rule", error) for error in errors]
    return lines, annotations, errors


def _old_reference(source: str, age: int, day: date) -> str:
    """The days between a drop reference ``age`` days old and ``day``, which have no ok manifest of the source."""
    first, last = day - timedelta(days=age - 1), day - timedelta(days=1)
    missing = f"on {first}" if first == last else f"from {first} to {last}"
    count = age - 1
    return (
        f"{source}: the 1% drop reference is {age} days old ({day - timedelta(days=age)}): "
        f"no readable manifest with {source} ok {missing} ({count} day{'s' if count > 1 else ''})"
    )


def _number(value: Any) -> str:
    return f"{value:,}" if type(value) is int else "-"


def main(argv: Sequence[str] | None = None, *, environ: Mapping[str, str] = os.environ) -> int:
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(errors="backslashreplace")
    args = _parse_args(argv)
    errors: list[str] = []
    try:
        if args.command == "dbt":
            lines, annotations = dbt_report(json.loads(args.run_results.read_text(encoding="utf-8")))
        else:
            lines, annotations, errors = ingest_report(args.raw_dir, args.new_manifest)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"Result: FAILED, exit code {EXIT_FAILED} (cannot make the {args.command} report: {exc})", flush=True)
        return EXIT_FAILED
    print("\n".join(lines), flush=True)
    if environ.get("GITHUB_ACTIONS") == "true" and annotations:
        print("\n".join(annotations), flush=True)
    summary = environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as file:
            file.write("\n".join(lines) + "\n\n")
    if errors:
        print(f"Result: FAILED, exit code {EXIT_FAILED} ({len(errors)} Actions rule errors)", flush=True)
        return EXIT_FAILED
    return EXIT_OK


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m threat_intel_pipeline.report",
        description="Summaries of a run for the page of a GitHub Actions job.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    dbt = commands.add_parser("dbt", help="statuses of the last dbt command and every node that did not pass")
    dbt.add_argument("--run-results", required=True, type=Path, help="dbt's run_results.json")
    ingest = commands.add_parser("ingest", help="the manifest written by the run and the Actions rules")
    ingest.add_argument("--raw-dir", required=True, type=Path, help="the raw folder, for example data/raw")
    ingest.add_argument("--new-manifest", default="", help="file name of the manifest written by the run, if any")
    return parser.parse_args(argv)


if __name__ == "__main__":
    sys.exit(main())
