"""Fill and check a raw folder from the permanent stores, and plan the dbt run (CLAUDE.md §4).

The permanent stores of the default path, while FIRST has not given permission:
KEV raw files and manifests are in GitHub Releases (storage.py), and EPSS raw
files in the official archive (github.com/empiricalsec/epss_scores). For every
source and snapshot_date, the latest readable manifest of that day with the
source ok says which file is the raw file of that day and its sha256, the same
rule as the dbt test assert_staging_rows_match_manifests. A file is written only
if it has that sha256; nothing is ever overwritten, and nothing a manifest does
not vouch for is accepted.

Run from the repo root:
  uv run python -m threat_intel_pipeline.rebuild sync-releases --raw-dir DIR (--repo OWNER/NAME --release-prefix PREFIX | --from-dir DIR)
  uv run python -m threat_intel_pipeline.rebuild sync-epss --raw-dir DIR --archive URL_OR_DIR
  uv run python -m threat_intel_pipeline.rebuild verify --raw-dir DIR
  uv run python -m threat_intel_pipeline.rebuild plan --raw-dir DIR --database FILE [--full-refresh]

A full rebuild is: an empty raw folder, sync-releases, sync-epss, verify, then
dbt build --full-refresh.
"""

from __future__ import annotations

import argparse
import logging
import os
import re
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from pathlib import Path

import duckdb

from threat_intel_pipeline import storage
from threat_intel_pipeline.fileio import write_new_file
from threat_intel_pipeline.ingest.download import DownloadError, FetchResult, fetch
from threat_intel_pipeline.manifest import ManifestIndex, load_manifests
from threat_intel_pipeline.storage import (
    KEV_NAME,
    MANIFEST_NAME,
    GitHub,
    StorageError,
    file_sha256,
    sha256_of,
)

log = logging.getLogger("threat_intel_pipeline.rebuild")

SOURCES = ("kev", "epss")
EXTENSIONS = {"kev": "json", "epss": "csv.gz"}
RAW_NAME = re.compile(r"(?P<source>kev|epss)_(?P<date>\d{4}-\d{2}-\d{2})\.(?P<extension>json|csv\.gz)")
OFFICIAL_ARCHIVE = "https://raw.githubusercontent.com/empiricalsec/epss_scores/main"  # CLAUDE.md §4
ARCHIVE_NAME = re.compile(r"epss_scores-(?P<date>\d{4}-\d{2}-\d{2})\.csv\.gz")
SCORE_DATE = re.compile(r"(?P<date>\d{4}-\d{2}-\d{2})T\d{2}:\d{2}:\d{2}Z")
MARTS_SCHEMA = "main_marts"

EXIT_OK = 0
EXIT_FAILED = 1


class RebuildError(Exception):
    """The raw folder cannot be filled or planned; the message says why."""


@dataclass(frozen=True)
class Recorded:
    """What the latest readable manifest of a day with a source ok records for it."""

    source: str
    snapshot_date: date
    manifest: str
    file: str
    sha256: str
    bytes: int | None
    score_date: str | None  # EPSS only, as written in its '#' line
    final_url: str | None


def raw_name(source: str, day: date) -> str:
    return f"{source}_{day.isoformat()}.{EXTENSIONS[source]}"


def recorded_ok(index: ManifestIndex) -> dict[tuple[str, date], Recorded]:
    """(source, snapshot_date) -> what the latest readable manifest of that day with the source ok records."""
    recorded: dict[tuple[str, date], Recorded] = {}
    for manifest in index.readable:  # oldest first, so a later manifest of the same day wins
        for source in SOURCES:
            entry = manifest.entry(source)
            if entry["status"] != "ok":
                continue
            size = entry.get("bytes")
            recorded[(source, manifest.snapshot_date)] = Recorded(
                source=source,
                snapshot_date=manifest.snapshot_date,
                manifest=manifest.name,
                file=entry.get("file"),
                sha256=entry["sha256"],
                bytes=size if type(size) is int else None,
                score_date=entry.get("score_date"),
                final_url=entry.get("final_url"),
            )
    return recorded


def utc_today() -> date:
    return datetime.now(UTC).date()


@dataclass
class Report:
    written: list[str] = field(default_factory=list)
    present: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)


# --- KEV raw files and manifests: from GitHub Releases or from a local folder ---


class ReleaseFiles:
    """KEV raw files and manifests of the ``<prefix>YYYY-MM`` releases, checked against size and digest."""

    def __init__(self, github: GitHub, prefix: str) -> None:
        storage.check_prefix(prefix)
        self.github = github
        self.prefix = prefix
        self.warnings: list[str] = []
        self._assets: dict[str, tuple[storage.Release, storage.Asset]] | None = None

    def _index(self) -> dict[str, tuple[storage.Release, storage.Asset]]:
        if self._assets is None:
            self._assets = {}
            for release in self.github.releases(self.prefix):
                for name, asset in self.github.assets(release).items():
                    where = f"{release.tag}/{name}"
                    if not storage.is_publishable(name):
                        self.warnings.append(f"{where}: not a KEV raw file or a manifest; ignored")
                    elif storage.release_tag(self.prefix, storage.day_of(name)) != release.tag:
                        raise RebuildError(f"{where}: belongs to another release")
                    elif asset.state != "uploaded":
                        self.warnings.append(f"{where}: incomplete upload (state {asset.state!r}); ignored")
                    else:
                        self._assets[name] = (release, asset)
        return self._assets

    def names(self) -> list[str]:
        return sorted(self._index())

    def sha256(self, name: str) -> str:
        release, asset = self._index()[name]
        return self.github.published_sha256(release, asset)

    def fetch(self, name: str) -> bytes:
        release, asset = self._index()[name]
        content = self.github.download(release.tag, name)
        if len(content) != asset.size:
            raise RebuildError(f"{release.tag}/{name}: downloaded {len(content):,} bytes, the asset has {asset.size:,}")
        if asset.sha256 is not None and sha256_of(content) != asset.sha256:
            raise RebuildError(f"{release.tag}/{name}: downloaded content does not match the asset digest")
        return content


class FolderFiles:
    """KEV raw files and manifests in the top level of a local folder (only read)."""

    def __init__(self, folder: Path) -> None:
        if not folder.is_dir():
            raise RebuildError(f"{folder} is not a directory")
        self.folder = folder
        self.warnings: list[str] = []

    def names(self) -> list[str]:
        return sorted(path.name for path in self.folder.iterdir() if path.is_file() and storage.is_publishable(path.name))

    def sha256(self, name: str) -> str:
        return file_sha256(self.folder / name)[0]

    def fetch(self, name: str) -> bytes:
        return (self.folder / name).read_bytes()


def sync_releases(files: ReleaseFiles | FolderFiles, raw_dir: Path, today: date) -> Report:
    """Write into ``raw_dir`` the manifests and KEV raw files it lacks.

    Manifests first; then each KEV raw file, only if the latest readable manifest
    of its day with KEV ok records it with the same sha256. A local file that
    differs from the source is a conflict and is left as it is.
    """
    raw_dir.mkdir(parents=True, exist_ok=True)
    report = Report()
    names = files.names()
    report.warnings += files.warnings
    for name in (n for n in names if MANIFEST_NAME.fullmatch(n)):
        _bring(files, name, raw_dir, report, expected=None)
    index = load_manifests(raw_dir, today, SOURCES)
    report.warnings += index.warnings()
    recorded = recorded_ok(index)
    for name in (n for n in names if KEV_NAME.fullmatch(n)):
        entry = recorded.get(("kev", storage.day_of(name)))
        if entry is None or entry.file != name:
            report.errors.append(f"{name}: no readable manifest of its day records it ok; not written")
            continue
        _bring(files, name, raw_dir, report, expected=entry)
    return report


def _bring(files: ReleaseFiles | FolderFiles, name: str, raw_dir: Path, report: Report, expected: Recorded | None) -> None:
    path = raw_dir / name
    if path.exists():
        local = file_sha256(path)[0]
        source = files.sha256(name)
        if local != source:
            report.errors.append(f"{name}: the local file (sha256 {local}) differs from the source ({source}); left as it is")
        elif expected is not None and local != expected.sha256:
            report.errors.append(f"{name}: sha256 {local}, but {expected.manifest} records {expected.sha256}")
        else:
            report.present.append(name)
        return
    content = files.fetch(name)
    if expected is not None and sha256_of(content) != expected.sha256:
        report.errors.append(
            f"{name}: sha256 {sha256_of(content)}, but {expected.manifest} records {expected.sha256}; not written"
        )
        return
    write_new_file(path, content)
    report.written.append(name)


# --- EPSS raw files: from the official archive or a local copy of it ---


class ArchiveError(Exception):
    """The archive does not have the file, or it could not be read."""


class UrlArchive:
    """The official archive: <base>/<year>/epss_scores-<date>.csv.gz, downloaded with the pipeline's fetch."""

    def __init__(self, base: str = OFFICIAL_ARCHIVE, fetcher: Callable[[str], FetchResult] = fetch) -> None:
        self.base = base.rstrip("/")
        self.fetcher = fetcher

    def describe(self, day: date) -> str:
        return f"{self.base}/{day.year}/epss_scores-{day.isoformat()}.csv.gz"

    def fetch(self, day: date) -> bytes:
        try:
            return self.fetcher(self.describe(day)).content
        except DownloadError as exc:
            raise ArchiveError(str(exc)) from exc


class FolderArchive:
    """A local copy of the archive: a folder of epss_scores-<date>.csv.gz files (only read)."""

    def __init__(self, folder: Path) -> None:
        if not folder.is_dir():
            raise RebuildError(f"{folder} is not a directory")
        self.folder = folder

    def describe(self, day: date) -> str:
        return (self.folder / f"epss_scores-{day.isoformat()}.csv.gz").as_posix()

    def fetch(self, day: date) -> bytes:
        path = self.folder / f"epss_scores-{day.isoformat()}.csv.gz"
        if not path.is_file():
            raise ArchiveError(f"{path.name} is not in {self.folder.as_posix()}")
        return path.read_bytes()


def archive_from(value: str) -> UrlArchive | FolderArchive:
    if value.startswith("https://"):
        return UrlArchive(value)
    return FolderArchive(Path(value))


def sync_epss(archive: UrlArchive | FolderArchive, raw_dir: Path, today: date) -> Report:
    """Write into ``raw_dir`` the EPSS raw files that a manifest records ok and that are missing.

    The archive file is the one of the EPSS score date (the date of ``score_date``
    in the manifest), not of the snapshot_date: when EPSS publishes late, the raw
    file of a day is the archive file of the day before. It is written only if
    its sha256 (and size) are the ones the manifest records. One day at a time.
    """
    index = load_manifests(raw_dir, today, SOURCES)
    report = Report(warnings=index.warnings())
    for (source, day), entry in sorted(recorded_ok(index).items()):
        if source != "epss":
            continue
        name = raw_name("epss", day)
        if entry.file != name:
            report.errors.append(f"{entry.manifest} records epss file {entry.file!r}, expected {name}")
            continue
        path = raw_dir / name
        if path.exists():
            report.present.append(name)  # its content is checked by verify
            continue
        score = SCORE_DATE.fullmatch(entry.score_date or "")
        if score is None:
            report.errors.append(f"{name}: {entry.manifest} has no valid score_date ({entry.score_date!r})")
            continue
        score_day = date.fromisoformat(score["date"])
        final = ARCHIVE_NAME.search(entry.final_url or "")
        if entry.final_url and (final is None or final["date"] != score_day.isoformat()):
            report.errors.append(
                f"{name}: {entry.manifest} has final_url {entry.final_url!r} and score_date {entry.score_date}; they disagree"
            )
            continue
        source_file = archive.describe(score_day)
        try:
            content = archive.fetch(score_day)
        except ArchiveError as exc:
            report.errors.append(f"{name}: {source_file} could not be read: {exc}")
            continue
        got = sha256_of(content)
        if got != entry.sha256 or (entry.bytes is not None and len(content) != entry.bytes):
            recorded_size = f" ({entry.bytes:,} bytes)" if entry.bytes is not None else ""
            report.errors.append(
                f"{name}: {source_file} has sha256 {got} ({len(content):,} bytes), but {entry.manifest} "
                f"records {entry.sha256}{recorded_size}; not written"
            )
            continue
        write_new_file(path, content)
        log.info("%s written from %s (sha256 %s)", name, source_file, got)
        report.written.append(f"{name} <- {source_file}")
    return report


# --- verify ---


def verify(raw_dir: Path, today: date) -> Report:
    """Every raw file that the latest ok manifest of its day records is on disk with that sha256 and size.

    Errors: a recorded file that is missing or differs. Warnings: unreadable
    manifests, raw files that no manifest records ok, and days whose ok manifests
    record two different sha256 values for a source.
    """
    if not raw_dir.is_dir():
        raise RebuildError(f"{raw_dir} is not a directory")
    index = load_manifests(raw_dir, today, SOURCES)
    report = Report(warnings=index.warnings())
    recorded = recorded_ok(index)
    for (source, day), entry in sorted(recorded.items()):
        name = raw_name(source, day)
        path = raw_dir / name
        if entry.file != name:
            report.errors.append(f"{entry.manifest} records {source} file {entry.file!r}, expected {name}")
        elif not path.is_file():
            report.errors.append(f"{name}: {entry.manifest} records it ok, but it is not in {raw_dir.as_posix()}")
        else:
            sha256, size = file_sha256(path)
            if sha256 != entry.sha256 or (entry.bytes is not None and size != entry.bytes):
                report.errors.append(
                    f"{name}: sha256 {sha256} ({size:,} bytes), but {entry.manifest} records {entry.sha256}"
                )
            else:
                report.present.append(name)
    for path in sorted(raw_dir.iterdir()):
        match = RAW_NAME.fullmatch(path.name)
        if match and path.is_file() and (match["source"], date.fromisoformat(match["date"])) not in recorded:
            report.warnings.append(f"{path.name}: no readable manifest of its day records it ok")
    seen: dict[tuple[str, date], set[str]] = {}
    for manifest in index.readable:
        for source in SOURCES:
            entry = manifest.entry(source)
            if entry["status"] == "ok":
                seen.setdefault((source, manifest.snapshot_date), set()).add(entry["sha256"])
    for (source, day), values in sorted(seen.items()):
        if len(values) > 1:
            report.warnings.append(
                f"{source} {day.isoformat()}: ok manifests record {len(values)} different sha256 values "
                f"({', '.join(sorted(values))}); the latest manifest decides"
            )
    return report


# --- plan ---


@dataclass(frozen=True)
class Plan:
    mode: str  # "incremental" or "full"
    reason: str
    test_since: date | None  # incremental only
    new_days: bool


def plan(raw_dir: Path, database: Path, *, full_refresh: bool = False) -> Plan:
    """How the daily job runs dbt build.

    Full refresh if asked, or if the database is missing, cannot be opened or has
    no days in mart_source_days. Otherwise incremental, with test_since the
    earliest day the run will load: for each source, its first raw day after its
    last day in mart_source_days or, if it has none (its download failed), its
    last raw day, so every source has rows from test_since on and every new day
    is tested.
    """
    if full_refresh:
        return Plan("full", "full refresh requested", None, True)
    watermarks, problem = _watermarks(database)
    if problem is not None:
        return Plan("full", problem, None, True)
    raw_days: dict[str, list[date]] = {source: [] for source in SOURCES}
    for path in raw_dir.iterdir():
        match = RAW_NAME.fullmatch(path.name)
        if match and path.is_file():
            raw_days[match["source"]].append(date.fromisoformat(match["date"]))
    starts: list[date] = []
    new_days = False
    details = []
    for source in SOURCES:
        days = sorted(raw_days[source])
        if not days:
            continue
        mark = watermarks.get(source)
        newer = [day for day in days if mark is None or day > mark]
        new_days = new_days or bool(newer)
        starts.append(newer[0] if newer else days[-1])
        details.append(f"{source}: last loaded {mark.isoformat() if mark else 'none'}, {len(newer)} new days")
    if not starts:
        raise RebuildError(f"no raw files in {raw_dir.as_posix()}")
    return Plan("incremental", "; ".join(details), min(starts), new_days)


def _watermarks(database: Path) -> tuple[dict[str, date], str | None]:
    if not database.is_file():
        return {}, f"no database at {database.as_posix()}"
    try:
        with duckdb.connect(str(database), read_only=True) as con:
            rows = con.execute(
                f"select source, max(snapshot_date) from {MARTS_SCHEMA}.mart_source_days group by source"
            ).fetchall()
    except duckdb.Error as exc:
        return {}, f"the database cannot be used: {type(exc).__name__}: {str(exc).splitlines()[0]}"
    if not rows:
        return {}, "mart_source_days has no days"
    return dict(rows), None


# --- command line ---


def main(argv: Sequence[str] | None = None, *, environ: Mapping[str, str] = os.environ) -> int:
    _make_output_safe()
    _configure_logging()
    args = _parse_args(argv)
    try:
        if args.command == "plan":
            return _run_plan(args, environ)
        today = utc_today()
        if args.command == "sync-releases":
            if args.from_dir is not None:
                files: ReleaseFiles | FolderFiles = FolderFiles(args.from_dir)
                source = args.from_dir.as_posix()
            else:
                files = ReleaseFiles(GitHub(args.repo, storage.run_gh), args.release_prefix)
                source = f"{args.release_prefix}YYYY-MM releases of {args.repo}"
            report = sync_releases(files, args.raw_dir, today)
            title = f"sync-releases: KEV raw files and manifests from {source}"
        elif args.command == "sync-epss":
            archive = archive_from(args.archive)
            report = sync_epss(archive, args.raw_dir, today)
            title = f"sync-epss: EPSS raw files from {args.archive}"
        else:
            report = verify(args.raw_dir, today)
            title = "verify: every raw file recorded ok by its manifest is on disk and identical"
    except (RebuildError, StorageError) as exc:
        log.error("%s", exc)
        print(f"Result: FAILED, exit code {EXIT_FAILED} ({exc})", flush=True)
        return EXIT_FAILED
    where = "in" if args.command == "verify" else "into"
    return _print_report(report, f"{title}, {where} {args.raw_dir.as_posix()}")


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m threat_intel_pipeline.rebuild",
        description="Fill and check a raw folder from GitHub Releases and the EPSS archive, and plan the dbt run.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    releases = commands.add_parser("sync-releases", help="KEV raw files and manifests that --raw-dir lacks")
    releases.add_argument("--raw-dir", required=True, type=Path)
    origin = releases.add_mutually_exclusive_group(required=True)
    origin.add_argument("--repo", help="OWNER/NAME: read the releases of this repository (needs --release-prefix)")
    origin.add_argument("--from-dir", type=Path, help="read a local folder instead of the releases")
    releases.add_argument("--release-prefix", help="data- for the real history; test-data-, test2-data-... for tests")
    epss = commands.add_parser("sync-epss", help="EPSS raw files that --raw-dir lacks and a manifest records ok")
    epss.add_argument("--raw-dir", required=True, type=Path)
    epss.add_argument("--archive", required=True, help=f"{OFFICIAL_ARCHIVE} or a local folder of epss_scores-*.csv.gz")
    check = commands.add_parser("verify", help="every raw file recorded ok is on disk and identical")
    check.add_argument("--raw-dir", required=True, type=Path)
    planner = commands.add_parser("plan", help="incremental dbt build with test_since, or --full-refresh")
    planner.add_argument("--raw-dir", required=True, type=Path)
    planner.add_argument("--database", required=True, type=Path)
    planner.add_argument("--full-refresh", action="store_true", help="plan a full refresh whatever the database")
    args = parser.parse_args(argv)
    if args.command == "sync-releases" and (args.repo is None) != (args.release_prefix is None):
        parser.error("--repo and --release-prefix go together")
    return args


def _run_plan(args: argparse.Namespace, environ: Mapping[str, str]) -> int:
    result = plan(args.raw_dir, args.database, full_refresh=args.full_refresh)
    since = result.test_since.isoformat() if result.test_since else ""
    outputs = f"mode={result.mode}\ntest_since={since}\nnew_days={'true' if result.new_days else 'false'}\n"
    print(f"\n==== plan: {args.database.as_posix()} and {args.raw_dir.as_posix()} ====\n{outputs}reason: {result.reason}")
    github_output = environ.get("GITHUB_OUTPUT")
    if github_output:
        with open(github_output, "a", encoding="utf-8") as file:
            file.write(outputs)
    print(f"Result: OK, exit code {EXIT_OK}", flush=True)
    return EXIT_OK


def _print_report(report: Report, title: str) -> int:
    lines = [
        "",
        f"==== {title} ====",
        *_section("written", report.written),
        *_section("already present", report.present, show=False),
        *_section("warnings", report.warnings),
        *_section("ERRORS", report.errors),
    ]
    code = EXIT_FAILED if report.errors else EXIT_OK
    reasons = f" ({len(report.errors)} errors)" if report.errors else ""
    lines.append(f"Result: {'OK' if code == EXIT_OK else 'FAILED'}, exit code {code}{reasons}")
    print("\n".join(lines), flush=True)
    return code


def _section(title: str, items: Sequence[str], *, show: bool = True) -> list[str]:
    if not items:
        return [f"{title}: none"]
    if not show:
        return [f"{title}: {len(items)}"]
    return [f"{title} ({len(items)}):", *(f"  - {item}" for item in items)]


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


if __name__ == "__main__":
    sys.exit(main())
