"""FIRST EPSS: daily gzipped CSV of scores and its raw tests (CLAUDE.md §4 and §6)."""

from __future__ import annotations

import gzip
import io
import re
import zlib
from datetime import date, datetime, timedelta

from threat_intel_pipeline.ingest.common import (
    MAX_DROP_PERCENT,
    RawValidationError,
    Reference,
    SourceSpec,
    EXCERPT_REDACTED,
    EXCERPT_SCAN_BYTES,
    Validated,
    check_row_count,
    diagnostic_excerpt,
)

URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
MIN_ROWS = 350_000
METADATA_KEYS = ("model_version", "score_date")  # as written in the '#' line
MAX_DECOMPRESSED_BYTES = 200_000_000  # 200 MB; 12,024,990 in session 0

HEADER = "cve,epss,percentile"
COMMENT_LINE = re.compile(
    r"#model_version:(?P<model_version>[^,]+),"
    r"score_date:(?P<score_date>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z)"
)
SHOWN_CHARS = 100  # of a malformed first line or header in error messages
CVE_ID = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)


def validate(
    content: bytes,
    snapshot_date: date,
    reference: Reference | None,
    *,
    min_rows: int = MIN_ROWS,
    max_drop_percent: int = MAX_DROP_PERCENT,
    accept_reason: str | None = None,
) -> Validated:
    """Raw tests for EPSS. Raises ``RawValidationError`` at the first failure.

    ``accept_reason`` accepts a drop above ``max_drop_percent`` (operator decision).
    """
    if not content:
        raise RawValidationError("empty file")
    try:
        text = _decompress(content).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise RawValidationError(f"not valid UTF-8: {exc}") from exc

    lines = text.split("\n")
    if lines[-1] == "":  # the file ends with LF
        lines.pop()
    if len(lines) < 2:
        raise RawValidationError("missing the '#' line or the header")

    comment = COMMENT_LINE.fullmatch(lines[0])
    if comment is None:
        raise RawValidationError(
            "first line does not match "
            f"'#model_version:<version>,score_date:<YYYY-MM-DDTHH:MM:SSZ>': {_quoted(lines[0])}"
        )
    try:
        score_date = datetime.strptime(comment["score_date"], "%Y-%m-%dT%H:%M:%SZ")
    except ValueError as exc:
        raise RawValidationError(f"score_date is not a valid timestamp: {comment['score_date']!r}") from exc

    if lines[1] != HEADER:
        raise RawValidationError(f"header is {_quoted(lines[1])}, expected {HEADER!r}")

    data_lines = lines[2:]
    for line_number, line in enumerate(data_lines, start=3):
        if line.count(",") != 2:
            raise RawValidationError(
                f"line {line_number:,} has {line.count(',') + 1} fields, expected 3"
            )

    drop_check = check_row_count(
        len(data_lines),
        snapshot_date,
        reference,
        min_rows=min_rows,
        max_drop_percent=max_drop_percent,
        accept_reason=accept_reason,
    )

    # CLAUDE.md §5: epss_score_date must be snapshot_date or the day before.
    epss_score_date = score_date.date()
    allowed = (snapshot_date, snapshot_date - timedelta(days=1))
    if epss_score_date not in allowed:
        raise RawValidationError(
            f"epss_score_date is {epss_score_date.isoformat()}, expected "
            f"{allowed[0].isoformat()} or {allowed[1].isoformat()}",
            drop_check,
        )

    metadata = {key: comment[key] for key in METADATA_KEYS}
    return Validated(rows=len(data_lines), metadata=metadata, drop_check=drop_check)


def _quoted(line: str) -> str:
    """A line for an error message; redacted if it may be a data row (the manifest is public)."""
    if CVE_ID.search(line):
        return EXCERPT_REDACTED
    return repr(line[:SHOWN_CHARS])


def _decompress(content: bytes) -> bytes:
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(content)) as archive:
            data = archive.read(MAX_DECOMPRESSED_BYTES + 1)
    except (OSError, EOFError, zlib.error) as exc:  # BadGzipFile is an OSError
        raise RawValidationError(f"not a valid gzip file: {type(exc).__name__}: {exc}") from exc
    if len(data) > MAX_DECOMPRESSED_BYTES:
        raise RawValidationError(f"decompressed size exceeds {MAX_DECOMPRESSED_BYTES:,} bytes")
    return data


def excerpt(content: bytes) -> list[str]:
    """Diagnostic excerpt of rejected content: decompressed if possible, else raw bytes.

    Lines containing a CVE id are redacted, so the published manifest never
    carries EPSS scores even if a format change puts data rows first. The '#'
    line, the header and the text of an error page stay visible.
    """
    decompressor = zlib.decompressobj(wbits=16 + zlib.MAX_WBITS)  # expect a gzip header
    try:
        data = decompressor.decompress(content, EXCERPT_SCAN_BYTES)
    except zlib.error:
        data = b""
    return diagnostic_excerpt(data or content, redact=CVE_ID)


SOURCE = SourceSpec(
    name="epss",
    url=URL,
    extension="csv.gz",
    validate=validate,
    excerpt=excerpt,
    metadata_keys=METADATA_KEYS,
)
