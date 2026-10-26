"""Flow shared by every source: skip if present, download, validate in memory, save.

Also the row checks common to all sources (minimum rows and maximum drop
against the reference, the rows of the latest earlier ok manifest), and the
handling of rejected downloads: quarantine file and diagnostic excerpt.
"""

from __future__ import annotations

import hashlib
import logging
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

from threat_intel_pipeline.fileio import write_new_file
from threat_intel_pipeline.ingest.download import DownloadError, FetchResult, fetch

log = logging.getLogger(__name__)

MAX_DROP_PERCENT = 1  # CLAUDE.md §6: at most a 1% drop against the reference

EXCERPT_LINES = 2
EXCERPT_CHARS = 200  # per line, before escaping
EXCERPT_SCAN_BYTES = 64 * 1024
EXCERPT_TRUNCATED = "...[truncated]"
EXCERPT_REDACTED = "[redacted: line contains a CVE id, possibly a data row]"


class RawValidationError(Exception):
    """The content fails a raw test (CLAUDE.md §6) and must not be saved."""

    def __init__(self, message: str, drop_check: DropCheck | None = None) -> None:
        super().__init__(message)
        self.drop_check = drop_check


@dataclass(frozen=True)
class Reference:
    """Rows of a source in the latest earlier ok manifest."""

    snapshot_date: date
    rows: int
    manifest: str | None = None  # file name of that manifest


@dataclass(frozen=True)
class DropCheck:
    status: str  # "ok", "failed", "skipped" or "accepted_by_operator"
    rows: int
    max_drop_percent: int
    reference_manifest: str | None = None
    reference_snapshot_date: date | None = None
    reference_rows: int | None = None
    reference_age_days: int | None = None
    reason: str | None = None

    def describe(self) -> str:
        if self.reference_rows is None or self.reference_snapshot_date is None:
            return f"skipped ({self.reason})"
        drop = self.reference_rows - self.rows
        ref_date = self.reference_snapshot_date.isoformat()
        if drop <= 0:
            return f"no drop: {self.rows:,} rows vs {self.reference_rows:,} on {ref_date} ({-drop:+,})"
        return (
            f"drop {100 * drop / self.reference_rows:.2f}% = "
            f"{drop:,} / {self.reference_rows:,} vs {ref_date}"
        )


@dataclass(frozen=True)
class Validated:
    rows: int
    metadata: dict[str, Any]  # source-specific manifest fields, as found in the file
    drop_check: DropCheck


# validate(content, snapshot_date, reference, *, accept_reason=None) -> Validated
Validator = Callable[..., Validated]


@dataclass(frozen=True)
class SourceSpec:
    name: str
    url: str
    extension: str
    validate: Validator
    excerpt: Callable[[bytes], list[str]]  # diagnostic excerpt of rejected content
    metadata_keys: tuple[str, ...]  # source-specific manifest fields, null when unknown

    def filename(self, snapshot_date: date) -> str:
        return f"{self.name}_{snapshot_date.isoformat()}.{self.extension}"


@dataclass(frozen=True)
class SourceResult:
    """Outcome of one source in one run; becomes its manifest entry."""

    source: str
    status: str  # "ok" or "failed"
    file: str
    url: str
    action: str | None = None  # "downloaded" or "already_present"; None if no content
    final_url: str | None = None
    downloaded_at: datetime | None = None
    bytes: int | None = None  # of the content handled (saved, present or rejected)
    rows: int | None = None
    sha256: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)
    drop_check: DropCheck | None = None
    error: str | None = None
    quarantine_file: str | None = None  # rejected download kept in the quarantine directory
    excerpt: list[str] | None = None  # first lines of a rejected download


def diagnostic_excerpt(data: bytes, redact: re.Pattern[str] | None = None) -> list[str]:
    """First lines of rejected content, safe to print and to publish in the manifest.

    Each line is cut to ``EXCERPT_CHARS`` characters and non-printable
    characters are escaped, so a CRLF ending shows as ``\\r``. Lines matching
    ``redact`` are replaced by a marker instead of being kept.
    """
    text = data[:EXCERPT_SCAN_BYTES].decode("utf-8", errors="backslashreplace")
    excerpt = []
    for line in text.split("\n")[:EXCERPT_LINES]:
        if redact is not None and redact.search(line):
            excerpt.append(EXCERPT_REDACTED)
            continue
        shown = _escape(line[:EXCERPT_CHARS])
        if len(line) > EXCERPT_CHARS:
            shown += EXCERPT_TRUNCATED
        excerpt.append(shown)
    return excerpt


def _escape(text: str) -> str:
    return "".join(
        char if char.isprintable() else char.encode("unicode_escape").decode("ascii")
        for char in text
    )


def check_row_count(
    rows: int,
    snapshot_date: date,
    reference: Reference | None,
    *,
    min_rows: int,
    max_drop_percent: int = MAX_DROP_PERCENT,
    accept_reason: str | None = None,
) -> DropCheck:
    """Raise ``RawValidationError`` if ``rows`` is below ``min_rows`` or dropped too much.

    The drop is ``(reference - rows) / reference`` in exact integer arithmetic;
    exactly ``max_drop_percent`` passes. Without a reference the drop check is
    skipped and the returned ``DropCheck`` says so. With ``accept_reason`` a
    larger drop is accepted (status ``accepted_by_operator``); the minimum rows
    are always enforced.
    """
    if reference is None:
        drop_check = DropCheck(
            status="skipped",
            rows=rows,
            max_drop_percent=max_drop_percent,
            reason="no previous ok manifest",
        )
    else:
        if reference.snapshot_date >= snapshot_date:
            raise ValueError("the reference must be from an earlier snapshot_date")
        drop = reference.rows - rows
        failed = drop * 100 > reference.rows * max_drop_percent
        drop_check = DropCheck(
            status="failed" if failed else "ok",
            rows=rows,
            max_drop_percent=max_drop_percent,
            reference_manifest=reference.manifest,
            reference_snapshot_date=reference.snapshot_date,
            reference_rows=reference.rows,
            reference_age_days=(snapshot_date - reference.snapshot_date).days,
        )
    if rows < min_rows:
        raise RawValidationError(f"{rows:,} rows, minimum is {min_rows:,}", drop_check)
    if drop_check.status == "failed" and accept_reason is not None:
        return replace(drop_check, status="accepted_by_operator", reason=accept_reason)
    if drop_check.status == "failed":
        raise RawValidationError(
            f"{drop_check.describe()}, maximum drop is {max_drop_percent}%", drop_check
        )
    return drop_check


def run_source(
    spec: SourceSpec,
    snapshot_date: date,
    raw_dir: Path,
    reference: Reference | None,
    *,
    started_at: datetime,
    quarantine_dir: Path,
    fetcher: Callable[[str], FetchResult] = fetch,
    accept_drop: bool = False,
    accepted_earlier: Mapping[str, str] | None = None,
) -> SourceResult:
    """Get one source's raw file for ``snapshot_date`` and save it if it passes.

    If the raw file already exists no HTTP request is made: the file is read
    and validated again to report its metadata. Downloaded content is validated
    in memory and written atomically only if every raw test passes; if it
    fails, it goes to ``quarantine_dir`` (named after ``started_at``, the UTC
    start of the run) and the result carries a diagnostic excerpt. Download,
    validation and write failures become a ``failed`` result.

    ``accept_drop`` accepts a drop above the maximum for this run (operator
    option). ``accepted_earlier`` maps the sha256 of contents whose drop was
    accepted earlier the same day to that manifest: a file already on disk
    with one of those hashes keeps its acceptance.
    """
    if started_at.tzinfo is None:
        raise ValueError("started_at must be timezone-aware (UTC)")
    name = spec.name
    path = raw_dir / spec.filename(snapshot_date)
    base = {"source": name, "file": path.name, "url": spec.url}
    unknown_metadata = dict.fromkeys(spec.metadata_keys)

    fetched: FetchResult | None = None
    if path.exists():
        log.info("%s: %s already present; validating it again, no HTTP request", name, path.name)
        content = path.read_bytes()
        action = "already_present"
    else:
        try:
            fetched = fetcher(spec.url)
        except DownloadError as exc:
            log.error("%s: download failed: %s", name, exc)
            return SourceResult(
                status="failed", metadata=unknown_metadata, error=f"DownloadError: {exc}", **base
            )
        content = fetched.content
        action = "downloaded"

    handled = {
        **base,
        "action": action,
        "final_url": fetched.final_url if fetched else None,
        "downloaded_at": fetched.downloaded_at if fetched else None,
        "bytes": len(content),
        "sha256": hashlib.sha256(content).hexdigest(),
    }

    sha256 = handled["sha256"]
    if accept_drop:
        accept_reason = f"--accept-drop {name}"
    elif action == "already_present" and accepted_earlier and sha256 in accepted_earlier:
        accept_reason = f"accepted earlier today in {accepted_earlier[sha256]} (same sha256)"
    else:
        accept_reason = None

    try:
        validated = spec.validate(content, snapshot_date, reference, accept_reason=accept_reason)
    except RawValidationError as exc:
        if action == "already_present":
            # data/raw/ is append-only: the file stays where it is, only reported.
            message = f"existing raw file no longer passes the raw tests: {exc}"
            log.error("%s: %s", name, message)
            return SourceResult(
                status="failed",
                metadata=unknown_metadata,
                drop_check=exc.drop_check,
                error=f"RawValidationError: {message}",
                **handled,
            )
        message = f"rejected, not saved: {exc}"
        log.error("%s: %s", name, message)
        quarantine_file = excerpt = None
        if content:
            excerpt = spec.excerpt(content)
            log.error("%s: first lines of the rejected content: %s", name, " | ".join(excerpt))
            quarantine_file, quarantine_error = _quarantine(
                spec, snapshot_date, started_at, quarantine_dir, content
            )
            if quarantine_error:
                message = f"{message}; {quarantine_error}"
        return SourceResult(
            status="failed",
            metadata=unknown_metadata,
            drop_check=exc.drop_check,
            error=f"RawValidationError: {message}",
            quarantine_file=quarantine_file,
            excerpt=excerpt,
            **handled,
        )

    if set(validated.metadata) != set(spec.metadata_keys):
        raise ValueError(f"{name}: validate() returned metadata keys other than {spec.metadata_keys}")
    _log_drop_check(name, validated.drop_check)

    if action == "downloaded":
        try:
            write_new_file(path, content)
        except OSError as exc:
            log.error("%s: could not save %s: %s", name, path.name, exc)
            return SourceResult(
                status="failed",
                rows=validated.rows,
                metadata=validated.metadata,
                drop_check=validated.drop_check,
                error=f"could not save {path.name}: {describe_os_error(exc)}",
                **handled,
            )
        log.info("%s: saved %s (%s rows, %s bytes)", name, path.name, f"{validated.rows:,}", f"{len(content):,}")

    return SourceResult(
        status="ok",
        rows=validated.rows,
        metadata=validated.metadata,
        drop_check=validated.drop_check,
        **handled,
    )


def _quarantine(
    spec: SourceSpec, snapshot_date: date, started_at: datetime, quarantine_dir: Path, content: bytes
) -> tuple[str | None, str | None]:
    """Keep rejected content as ``<source>_<snapshot_date>_<HHMMSS>Z.<ext>``.

    Returns the file name, or an error message if it could not be written.
    Quarantine files are never read by any model and never overwritten.
    """
    file_name = (
        f"{spec.name}_{snapshot_date.isoformat()}_"
        f"{started_at.astimezone(UTC):%H%M%S}Z.{spec.extension}"
    )
    try:
        write_new_file(quarantine_dir / file_name, content)
    except OSError as exc:
        log.error("%s: could not write quarantine file %s: %s", spec.name, file_name, exc)
        return None, f"quarantine failed: {describe_os_error(exc)}"
    log.warning("%s: rejected content kept in quarantine: %s", spec.name, quarantine_dir / file_name)
    return file_name, None


def describe_os_error(exc: OSError) -> str:
    """Error type and reason without file paths, for the published manifest."""
    return f"{type(exc).__name__}: {exc.strerror or 'no reason given'}"


def _log_drop_check(name: str, drop_check: DropCheck) -> None:
    if drop_check.status == "accepted_by_operator":
        log.warning(
            "%s: WARNING: DROP ABOVE THE MAXIMUM ACCEPTED BY OPERATOR: %s (%s)",
            name, drop_check.describe(), drop_check.reason,
        )
    elif drop_check.status == "skipped":
        log.warning("%s: WARNING: 1%% drop check skipped: %s", name, drop_check.reason)
    elif drop_check.reference_age_days and drop_check.reference_age_days > 1:
        log.warning(
            "%s: WARNING: reference is %d days old; %s",
            name, drop_check.reference_age_days, drop_check.describe(),
        )
    else:
        log.info("%s: %s", name, drop_check.describe())
