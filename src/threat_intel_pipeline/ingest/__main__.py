"""Entry point: ``uv run python -m threat_intel_pipeline.ingest [--accept-drop SOURCE]``.

Gets the day's raw file of every source into data/raw/, each source isolated
from the others; writes the attempt's manifest, also when a source fails; runs
final checks; prints a summary; and exits with a code that says what happened.
Run it from the root of the repository.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import sys
import time
import tomllib
from collections.abc import Callable, Sequence
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

from threat_intel_pipeline import manifest
from threat_intel_pipeline.fileio import orphan_temp_files
from threat_intel_pipeline.ingest import epss, kev
from threat_intel_pipeline.ingest.common import (
    DropCheck,
    SourceResult,
    SourceSpec,
    describe_os_error,
    run_source,
)
from threat_intel_pipeline.ingest.download import FetchResult, fetch

log = logging.getLogger("threat_intel_pipeline.ingest")

PROJECT_NAME = "threat-intel-pipeline"
SOURCES: tuple[SourceSpec, ...] = (kev.SOURCE, epss.SOURCE)
RAW_DIR = Path("data", "raw")
QUARANTINE_DIR = Path("data", "quarantine")

EXIT_OK = 0  # every source ok, or nothing to do
EXIT_SOURCE_FAILED = 1  # manifest written
EXIT_USAGE = 2  # invalid argument (argparse), before doing anything
EXIT_WRONG_FOLDER = 3  # not run from the repository root, before creating anything
EXIT_MANIFEST_NOT_WRITTEN = 4
EXIT_FINAL_CHECKS_FAILED = 5
EXIT_INTERNAL_ERROR = 6  # unexpected error outside the sources


def main(
    argv: Sequence[str] | None = None,
    *,
    fetcher: Callable[[str], FetchResult] = fetch,
    now: Callable[[], datetime] = lambda: datetime.now(UTC),
) -> int:
    _make_output_safe()
    _configure_logging()
    args = _parse_args(argv)
    if not _in_project_root():
        return EXIT_WRONG_FOLDER
    # snapshot_date comes from this single instant, shared by every source.
    started_at = now().astimezone(UTC).replace(microsecond=0)
    try:
        return _run(started_at, frozenset(args.accept_drop or ()), fetcher)
    except Exception:
        log.exception("internal error: the run stopped before finishing")
        print(f"Result: FAILED, exit code {EXIT_INTERNAL_ERROR} (internal error, see above)", flush=True)
        return EXIT_INTERNAL_ERROR


def _make_output_safe() -> None:
    """Never stop on a character the console cannot encode: print it escaped."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(errors="backslashreplace")


def _configure_logging() -> None:
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter("%(asctime)sZ %(levelname)s %(message)s", datefmt="%Y-%m-%dT%H:%M:%S")
    formatter.converter = time.gmtime
    handler.setFormatter(formatter)
    logging.basicConfig(level=logging.INFO, handlers=[handler], force=True)


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m threat_intel_pipeline.ingest",
        description="Download the day's raw file of every source into data/raw/ and write the attempt's manifest.",
    )
    parser.add_argument(
        "--accept-drop",
        action="append",
        choices=[spec.name for spec in SOURCES],
        metavar="SOURCE",
        help=(
            "accept, for this run, a drop in rows above the maximum for SOURCE (kev or epss), "
            "after reviewing it by hand; can be repeated"
        ),
    )
    return parser.parse_args(argv)


def _in_project_root() -> bool:
    """True if the current folder holds this project's pyproject.toml."""
    path = Path("pyproject.toml")
    try:
        with path.open("rb") as file:
            project = tomllib.load(file).get("project")
    except FileNotFoundError:
        log.error("no pyproject.toml in %s: run this command from the root of the %s repository", Path.cwd(), PROJECT_NAME)
        return False
    except (OSError, tomllib.TOMLDecodeError) as exc:
        log.error("cannot read %s: %s", path.resolve(), exc)
        return False
    name = project.get("name") if isinstance(project, dict) else None
    if name != PROJECT_NAME:
        log.error(
            "%s is for project %r, not %r: run this command from the root of the %s repository",
            path.resolve(), name, PROJECT_NAME, PROJECT_NAME,
        )
        return False
    return True


def _run(started_at: datetime, accept_drop: frozenset[str], fetcher: Callable[[str], FetchResult]) -> int:
    snapshot_date = started_at.date()
    names = [spec.name for spec in SOURCES]
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    log.info(
        "snapshot_date %s, run_started_at %s, raw dir %s",
        snapshot_date.isoformat(), manifest.format_timestamp(started_at), RAW_DIR.resolve(),
    )
    if accept_drop:
        log.warning("WARNING: --accept-drop given for: %s", ", ".join(sorted(accept_drop)))

    index = manifest.load_manifests(RAW_DIR, snapshot_date, names)
    warnings = index.warnings()
    for directory in (RAW_DIR, QUARANTINE_DIR):
        warnings += [
            f"orphan temporary file left by an interrupted write: {path.as_posix()}"
            for path in orphan_temp_files(directory)
        ]
    _log_warnings(warnings)

    results = [
        _run_isolated(spec, snapshot_date, started_at, index, spec.name in accept_drop, fetcher)
        for spec in SOURCES
    ]

    # Drop notes are already in each source's log lines; they go to the manifest and the summary.
    sha256_warnings = manifest.sha256_warnings(index, results, snapshot_date)
    _log_warnings(sha256_warnings)
    warnings += _drop_warnings(results, accept_drop) + sha256_warnings

    if manifest.nothing_to_do(index, results, snapshot_date):
        _print_summary(
            snapshot_date, started_at, results, warnings,
            "nothing to do: every source is already on disk and ok in the day's latest manifest; no manifest written",
        )
        return _finish(EXIT_OK, results, [])

    results, download_warnings = manifest.complete_already_present(index, results, snapshot_date)
    _log_warnings(download_warnings)
    warnings += download_warnings

    document = manifest.build_manifest(snapshot_date, started_at, results, warnings)
    try:
        path = manifest.write_manifest(RAW_DIR, document)
    except OSError as exc:
        log.error("manifest NOT written: %s", exc)
        _print_summary(snapshot_date, started_at, results, warnings, f"NOT WRITTEN ({describe_os_error(exc)})")
        return _finish(EXIT_MANIFEST_NOT_WRITTEN, results, [])
    log.info("manifest written: %s", path.name)

    problems = _final_checks(path, document, results, snapshot_date, names)
    _print_summary(snapshot_date, started_at, results, warnings, path.name)
    if problems:
        return _finish(EXIT_FINAL_CHECKS_FAILED, results, problems)
    failed = any(result.status != "ok" for result in results)
    return _finish(EXIT_SOURCE_FAILED if failed else EXIT_OK, results, [])


def _run_isolated(
    spec: SourceSpec,
    snapshot_date: date,
    started_at: datetime,
    index: manifest.ManifestIndex,
    accept_drop: bool,
    fetcher: Callable[[str], FetchResult],
) -> SourceResult:
    """Run one source. Any exception, even a bug, becomes a failed result: the next source still runs."""
    try:
        return run_source(
            spec,
            snapshot_date,
            RAW_DIR,
            manifest.find_reference(index, spec.name, snapshot_date),
            started_at=started_at,
            quarantine_dir=QUARANTINE_DIR,
            fetcher=fetcher,
            accept_drop=accept_drop,
            accepted_earlier=manifest.accepted_earlier(index, spec.name, snapshot_date),
        )
    except Exception as exc:
        log.exception("%s: unexpected error", spec.name)
        reason = describe_os_error(exc) if isinstance(exc, OSError) else f"{type(exc).__name__}: {exc}"
        return SourceResult(
            source=spec.name,
            status="failed",
            file=spec.filename(snapshot_date),
            url=spec.url,
            metadata=dict.fromkeys(spec.metadata_keys),
            error=f"unexpected error: {reason}",
        )


def _drop_warnings(results: Sequence[SourceResult], accept_drop: frozenset[str]) -> list[str]:
    warnings = []
    for result in results:
        drop_check = result.drop_check
        requested = result.source in accept_drop
        if drop_check is not None and drop_check.status == "skipped":
            warnings.append(f"{result.source}: 1% drop check skipped: {drop_check.reason}")
        if drop_check is not None and drop_check.status == "accepted_by_operator":
            warnings.append(
                f"{result.source}: DROP ABOVE THE MAXIMUM ACCEPTED BY OPERATOR: "
                f"{drop_check.describe()} ({drop_check.reason})"
            )
        elif requested and result.status != "ok":
            warnings.append(f"--accept-drop {result.source} had no effect: the source failed")
        elif requested:
            checked = drop_check.describe() if drop_check else "no drop check"
            warnings.append(f"--accept-drop {result.source} was not needed: {checked}")
    return warnings


def _final_checks(
    path: Path,
    document: dict[str, Any],
    results: Sequence[SourceResult],
    snapshot_date: date,
    names: Sequence[str],
) -> list[str]:
    """Check that what the manifest says is what is on disk."""
    problems = []
    try:
        if json.loads(path.read_text(encoding="ascii")) != document:
            problems.append(f"{path.name} does not read back as written")
    except (OSError, ValueError) as exc:
        problems.append(f"{path.name} cannot be read back: {exc}")
    readable = {m.name for m in manifest.load_manifests(RAW_DIR, snapshot_date, names).readable}
    if path.name not in readable:
        problems.append(f"{path.name} is not readable as a manifest")
    for result in results:
        if result.status == "ok":
            raw_path = RAW_DIR / result.file
            try:
                content = raw_path.read_bytes()
            except OSError as exc:
                problems.append(f"{result.source}: {result.file} cannot be read: {describe_os_error(exc)}")
                continue
            if len(content) != result.bytes or hashlib.sha256(content).hexdigest() != result.sha256:
                problems.append(f"{result.source}: {result.file} on disk does not match the manifest (size or sha256)")
        if result.quarantine_file and not (QUARANTINE_DIR / result.quarantine_file).is_file():
            problems.append(f"{result.source}: quarantine file {result.quarantine_file} is missing")
    for problem in problems:
        log.error("final check FAILED: %s", problem)
    if not problems:
        log.info("final checks passed: manifest reads back, raw files and quarantine files match it")
    return problems


def _log_warnings(warnings: Sequence[str]) -> None:
    for warning in warnings:
        log.warning("WARNING: %s", warning)


def _drop_text(drop_check: DropCheck | None) -> str:
    if drop_check is None:
        return "-"
    if drop_check.status == "accepted_by_operator":
        return f"ACCEPTED BY OPERATOR: {drop_check.describe()}"
    if drop_check.status == "failed":
        return f"FAILED: {drop_check.describe()}"
    return drop_check.describe()


def _print_summary(
    snapshot_date: date,
    started_at: datetime,
    results: Sequence[SourceResult],
    warnings: Sequence[str],
    manifest_line: str,
) -> None:
    header = ("source", "status", "action", "rows", "bytes", "drop check")
    rows = [
        (
            r.source,
            "ok" if r.status == "ok" else "FAILED",
            r.action or "-",
            f"{r.rows:,}" if r.rows is not None else "-",
            f"{r.bytes:,}" if r.bytes is not None else "-",
            _drop_text(r.drop_check),
        )
        for r in results
    ]
    widths = [max(len(row[i]) for row in (header, *rows)) for i in range(len(header) - 1)]
    numeric = {3, 4}

    def line(cells: Sequence[str]) -> str:
        padded = [
            cell.rjust(widths[i]) if i in numeric else cell.ljust(widths[i])
            for i, cell in enumerate(cells[:-1])
        ]
        return "  ".join([*padded, cells[-1]])

    out = [
        "",
        f"==== Summary: snapshot_date {snapshot_date.isoformat()}, "
        f"run_started_at {manifest.format_timestamp(started_at)} ====",
        line(header),
        *(line(row) for row in rows),
    ]
    for r in results:
        if r.status != "ok":
            out.append(f"  {r.source} error: {r.error}")
        if r.quarantine_file:
            out.append(f"  {r.source} quarantine: {(QUARANTINE_DIR / r.quarantine_file).as_posix()}")
        for number, excerpt_line in enumerate(r.excerpt or (), start=1):
            out.append(f"  {r.source} first line {number}: {excerpt_line}")
    out.append(f"Warnings ({len(warnings)}):" if warnings else "Warnings: none")
    out += [f"  - {warning}" for warning in warnings]
    out.append(f"Manifest: {manifest_line}")
    print("\n".join(out), flush=True)


def _finish(code: int, results: Sequence[SourceResult], problems: Sequence[str]) -> int:
    failed = [r.source for r in results if r.status != "ok"]
    reasons = []
    if failed:
        reasons.append(f"sources failed: {', '.join(failed)}")
    if code == EXIT_MANIFEST_NOT_WRITTEN:
        reasons.append("manifest not written")
    if problems:
        reasons.append(f"final checks failed: {len(problems)}")
    status = "OK" if code == EXIT_OK else "FAILED"
    detail = f" ({'; '.join(reasons)})" if reasons else ""
    print(f"Result: {status}, exit code {code}{detail}", flush=True)
    return code


if __name__ == "__main__":
    sys.exit(main())
