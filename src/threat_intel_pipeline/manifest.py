"""Per-attempt manifests: build, write and read them, and the rules of CLAUDE.md §4.

One ``manifest_<snapshot_date>_<HHMMSS>Z.json`` per attempt, in the top level
of the raw directory. Each manifest records every source, so the latest one of
a day describes that day. Manifests are never modified or deleted; one that
cannot be read is ignored and reported, never touched.
"""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from dataclasses import dataclass, replace
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

from threat_intel_pipeline.fileio import write_new_file
from threat_intel_pipeline.ingest.common import DropCheck, Reference, SourceResult

MANIFEST_VERSION = 1
TIMESTAMP_FORMAT = "%Y-%m-%dT%H:%M:%SZ"  # ISO 8601 UTC, to the second
MAX_MANIFEST_BYTES = 1_000_000
NAME_PATTERN = re.compile(r"manifest_(?P<date>\d{4}-\d{2}-\d{2})_(?P<time>\d{6})Z\.json")
SHA256_PATTERN = re.compile(r"[0-9a-f]{64}")


def format_timestamp(moment: datetime) -> str:
    if moment.tzinfo is None:
        raise ValueError("timestamps must be timezone-aware (UTC)")
    return moment.astimezone(UTC).strftime(TIMESTAMP_FORMAT)


def parse_timestamp(text: str) -> datetime:
    return datetime.strptime(text, TIMESTAMP_FORMAT).replace(tzinfo=UTC)


def manifest_name(started_at: datetime) -> str:
    started = started_at.astimezone(UTC)
    return f"manifest_{started.date().isoformat()}_{started:%H%M%S}Z.json"


def build_manifest(
    snapshot_date: date,
    started_at: datetime,
    results: Sequence[SourceResult],
    warnings: Sequence[str],
) -> dict[str, Any]:
    if started_at.astimezone(UTC).date() != snapshot_date:
        raise ValueError("snapshot_date must be the UTC date of started_at")
    sources = {result.source: source_entry(result) for result in results}
    if len(sources) != len(results):
        raise ValueError("each source must appear once")
    return {
        "manifest_version": MANIFEST_VERSION,
        "snapshot_date": snapshot_date.isoformat(),
        "run_started_at": format_timestamp(started_at),
        "status": "ok" if all(result.status == "ok" for result in results) else "failed",
        "warnings": list(warnings),
        "sources": sources,
    }


def source_entry(result: SourceResult) -> dict[str, Any]:
    """Manifest entry of one source: same keys always, null when not applicable."""
    return {
        "status": result.status,
        "action": result.action,
        "file": result.file,
        "url": result.url,
        "final_url": result.final_url,
        "downloaded_at": format_timestamp(result.downloaded_at) if result.downloaded_at else None,
        "bytes": result.bytes,
        "rows": result.rows,
        "sha256": result.sha256,
        **result.metadata,
        "drop_check": _drop_check_entry(result.drop_check) if result.drop_check else None,
        "error": result.error,
        "quarantine_file": result.quarantine_file,
        "excerpt": result.excerpt,
    }


def _drop_check_entry(drop_check: DropCheck) -> dict[str, Any]:
    reference_date = drop_check.reference_snapshot_date
    return {
        "status": drop_check.status,
        "rows": drop_check.rows,
        "max_drop_percent": drop_check.max_drop_percent,
        "reference_manifest": drop_check.reference_manifest,
        "reference_snapshot_date": reference_date.isoformat() if reference_date else None,
        "reference_rows": drop_check.reference_rows,
        "reference_age_days": drop_check.reference_age_days,
        "reason": drop_check.reason,
        "summary": drop_check.describe(),
    }


def write_manifest(raw_dir: Path, manifest: dict[str, Any]) -> Path:
    """Write atomically as ASCII JSON with LF endings; never overwrites.

    Two attempts in the same second share the name: the second one raises
    ``FileExistsError`` and nothing is overwritten.
    """
    path = raw_dir / manifest_name(parse_timestamp(manifest["run_started_at"]))
    text = json.dumps(manifest, indent=2, ensure_ascii=True) + "\n"
    write_new_file(path, text.encode("ascii"))
    return path



@dataclass(frozen=True)
class LoadedManifest:
    name: str
    snapshot_date: date
    started_at: datetime
    data: dict[str, Any]

    def entry(self, source: str) -> dict[str, Any]:
        return self.data["sources"][source]


@dataclass(frozen=True)
class UnreadableManifest:
    name: str
    reason: str
    snapshot_date: date | None  # from the file name, when it parses
    started_at: datetime | None


@dataclass(frozen=True)
class ManifestIndex:
    readable: tuple[LoadedManifest, ...]  # oldest first
    unreadable: tuple[UnreadableManifest, ...]

    def warnings(self) -> list[str]:
        return [f"unreadable manifest ignored: {m.name}: {m.reason}" for m in self.unreadable]


class _Unreadable(Exception):
    pass


def load_manifests(raw_dir: Path, today: date, sources: Sequence[str]) -> ManifestIndex:
    """Read every ``manifest_*.json`` in the top level of ``raw_dir`` (not recursive).

    A manifest is readable if its name parses, its JSON has the expected
    structure for ``sources``, its dates match its name and it is not from
    after ``today``. Anything else is listed as unreadable, with the reason.
    """
    readable: list[LoadedManifest] = []
    unreadable: list[UnreadableManifest] = []
    if not raw_dir.is_dir():
        return ManifestIndex((), ())
    for path in sorted(raw_dir.iterdir()):
        name = path.name
        if not (name.startswith("manifest_") and name.endswith(".json")):
            continue
        started_at = _started_at_from_name(name)
        if started_at is None:
            unreadable.append(UnreadableManifest(name, "unexpected file name", None, None))
            continue
        try:
            data = _read_manifest(path, started_at, today, sources)
        except _Unreadable as exc:
            unreadable.append(UnreadableManifest(name, str(exc), started_at.date(), started_at))
            continue
        readable.append(LoadedManifest(name, started_at.date(), started_at, data))
    readable.sort(key=lambda manifest: manifest.started_at)
    return ManifestIndex(tuple(readable), tuple(unreadable))


def _started_at_from_name(name: str) -> datetime | None:
    match = NAME_PATTERN.fullmatch(name)
    if match is None:
        return None
    try:
        return datetime.strptime(f"{match['date']}T{match['time']}", "%Y-%m-%dT%H%M%S").replace(tzinfo=UTC)
    except ValueError:
        return None


def _read_manifest(path: Path, started_at: datetime, today: date, sources: Sequence[str]) -> dict[str, Any]:
    try:
        if not path.is_file():
            raise _Unreadable("not a regular file")
        if path.stat().st_size > MAX_MANIFEST_BYTES:
            raise _Unreadable(f"larger than {MAX_MANIFEST_BYTES:,} bytes")
        raw = path.read_bytes()
    except OSError as exc:
        raise _Unreadable(f"{type(exc).__name__}: {exc.strerror}") from exc
    try:
        data = json.loads(raw)
    except ValueError as exc:
        raise _Unreadable(f"invalid JSON: {exc}") from exc

    if not isinstance(data, dict):
        raise _Unreadable("not a JSON object")
    version = data.get("manifest_version")
    if type(version) is not int or version != MANIFEST_VERSION:
        raise _Unreadable(f"manifest_version is {version!r}, expected {MANIFEST_VERSION}")
    if data.get("snapshot_date") != started_at.date().isoformat():
        raise _Unreadable("snapshot_date does not match the file name")
    if data.get("run_started_at") != format_timestamp(started_at):
        raise _Unreadable("run_started_at does not match the file name")
    if started_at.date() > today:
        raise _Unreadable(f"snapshot_date is after today ({today.isoformat()})")
    entries = data.get("sources")
    if not isinstance(entries, dict):
        raise _Unreadable("sources is not a JSON object")
    for source in sources:
        _check_entry(source, entries.get(source))
    return data


def _check_entry(source: str, entry: Any) -> None:
    if not isinstance(entry, dict):
        raise _Unreadable(f"sources.{source} is missing or not an object")
    status = entry.get("status")
    if status not in ("ok", "failed"):
        raise _Unreadable(f"sources.{source}.status is {status!r}")
    if status == "ok":
        rows = entry.get("rows")
        if type(rows) is not int or rows < 0:
            raise _Unreadable(f"sources.{source}.rows is {rows!r}")
        sha256 = entry.get("sha256")
        if not (isinstance(sha256, str) and SHA256_PATTERN.fullmatch(sha256)):
            raise _Unreadable(f"sources.{source}.sha256 is not a sha256")
    downloaded_at = entry.get("downloaded_at")
    if downloaded_at is not None:
        try:
            parse_timestamp(downloaded_at)
        except (TypeError, ValueError) as exc:
            raise _Unreadable(f"sources.{source}.downloaded_at is {downloaded_at!r}") from exc


def find_reference(index: ManifestIndex, source: str, snapshot_date: date) -> Reference | None:
    """Rows of ``source`` in the latest readable manifest of an earlier day with it ok."""
    for manifest in reversed(index.readable):
        if manifest.snapshot_date >= snapshot_date:
            continue
        entry = manifest.entry(source)
        if entry["status"] == "ok":
            return Reference(manifest.snapshot_date, entry["rows"], manifest.name)
    return None


def latest_of_day(index: ManifestIndex, snapshot_date: date) -> LoadedManifest | UnreadableManifest | None:
    """The day's manifest with the latest start time, readable or not."""
    candidates: list[LoadedManifest | UnreadableManifest] = [
        m for m in index.readable if m.snapshot_date == snapshot_date
    ]
    candidates += [m for m in index.unreadable if m.snapshot_date == snapshot_date]
    if not candidates:
        return None
    return max(candidates, key=lambda m: m.started_at)


def nothing_to_do(index: ManifestIndex, results: Sequence[SourceResult], snapshot_date: date) -> bool:
    """True if every source was already on disk and ok, and the day's latest manifest says so."""
    if not results or any(r.status != "ok" or r.action != "already_present" for r in results):
        return False
    latest = latest_of_day(index, snapshot_date)
    if not isinstance(latest, LoadedManifest):
        return False
    return all(
        latest.entry(r.source)["status"] == "ok" and latest.entry(r.source)["sha256"] == r.sha256
        for r in results
    )


def accepted_earlier(index: ManifestIndex, source: str, snapshot_date: date) -> dict[str, str]:
    """sha256 -> manifest name, for contents of ``source`` whose drop an operator accepted that day."""
    accepted: dict[str, str] = {}
    for manifest in index.readable:
        if manifest.snapshot_date != snapshot_date:
            continue
        entry = manifest.entry(source)
        drop_check = entry.get("drop_check")
        if (
            entry["status"] == "ok"
            and isinstance(drop_check, dict)
            and drop_check.get("status") == "accepted_by_operator"
        ):
            accepted.setdefault(entry["sha256"], manifest.name)
    return accepted


def sha256_warnings(index: ManifestIndex, results: Sequence[SourceResult], snapshot_date: date) -> list[str]:
    """Warn when an earlier manifest of the same day recorded a source ok with another sha256."""
    warnings = []
    for result in results:
        if result.sha256 is None:
            continue
        for manifest in index.readable:
            if manifest.snapshot_date != snapshot_date:
                continue
            entry = manifest.entry(result.source)
            if entry["status"] == "ok" and entry["sha256"] != result.sha256:
                warnings.append(
                    f"{result.source}: sha256 is now {result.sha256} but {manifest.name} "
                    f"recorded {entry['sha256']} for the same snapshot_date"
                )
    return warnings


def complete_already_present(
    index: ManifestIndex, results: Sequence[SourceResult], snapshot_date: date
) -> tuple[list[SourceResult], list[str]]:
    """Copy ``downloaded_at`` and ``final_url`` for sources that were already on disk.

    They come from the latest earlier manifest of the same day with that source
    ok, the same sha256 and a known download time. Without one, they stay
    null and a warning says so.
    """
    completed: list[SourceResult] = []
    warnings: list[str] = []
    for result in results:
        if result.status != "ok" or result.action != "already_present":
            completed.append(result)
            continue
        previous = _previous_download(index, result, snapshot_date)
        if previous is None:
            warnings.append(
                f"{result.source}: download time unknown: no earlier manifest of "
                f"{snapshot_date.isoformat()} records {result.file} with sha256 {result.sha256}"
            )
            completed.append(result)
            continue
        completed.append(
            replace(
                result,
                downloaded_at=parse_timestamp(previous["downloaded_at"]),
                final_url=previous.get("final_url"),
            )
        )
    return completed, warnings


def _previous_download(index: ManifestIndex, result: SourceResult, snapshot_date: date) -> dict[str, Any] | None:
    for manifest in reversed(index.readable):
        if manifest.snapshot_date != snapshot_date:
            continue
        entry = manifest.entry(result.source)
        if entry["status"] == "ok" and entry["sha256"] == result.sha256 and entry.get("downloaded_at"):
            return entry
    return None
