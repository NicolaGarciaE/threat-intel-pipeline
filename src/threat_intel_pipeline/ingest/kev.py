"""CISA KEV: daily JSON catalog and its raw tests (CLAUDE.md §4 and §6)."""

from __future__ import annotations

import json
from datetime import date

from threat_intel_pipeline.ingest.common import (
    MAX_DROP_PERCENT,
    RawValidationError,
    Reference,
    SourceSpec,
    Validated,
    check_row_count,
    diagnostic_excerpt,
)

URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
MIN_ROWS = 1_700
METADATA_KEYS = ("catalogVersion", "dateReleased", "count")  # copied to the manifest as is

TOP_LEVEL_KEYS = frozenset({"title", "catalogVersion", "dateReleased", "count", "vulnerabilities"})
# Strict on purpose: all 12 fields required, although the schema makes 4 optional.
RECORD_KEYS = frozenset({
    "cveID",
    "vendorProject",
    "product",
    "vulnerabilityName",
    "dateAdded",
    "shortDescription",
    "requiredAction",
    "dueDate",
    "knownRansomwareCampaignUse",
    "forensicTriage",
    "notes",
    "cwes",
})


def validate(
    content: bytes,
    snapshot_date: date,
    reference: Reference | None,
    *,
    min_rows: int = MIN_ROWS,
    max_drop_percent: int = MAX_DROP_PERCENT,
    accept_reason: str | None = None,
) -> Validated:
    """Raw tests for KEV. Raises ``RawValidationError`` at the first failure.

    ``accept_reason`` accepts a drop above ``max_drop_percent`` (operator decision).
    """
    if not content:
        raise RawValidationError("empty file")
    try:
        catalog = json.loads(content)
    except ValueError as exc:  # JSONDecodeError and UnicodeDecodeError
        raise RawValidationError(f"invalid JSON: {exc}") from exc

    if not isinstance(catalog, dict):
        raise RawValidationError(f"top level is a JSON {type(catalog).__name__}, expected an object")
    _check_keys("top level", set(catalog), TOP_LEVEL_KEYS)

    records = catalog["vulnerabilities"]
    if not isinstance(records, list):
        raise RawValidationError(f"vulnerabilities is a JSON {type(records).__name__}, expected an array")
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            raise RawValidationError(f"vulnerabilities[{index}] is not a JSON object")
        cve = record.get("cveID")
        _check_keys(f"vulnerabilities[{index}] ({cve})", set(record), RECORD_KEYS)

    count = catalog["count"]
    if type(count) is not int:  # isinstance() would accept true/false
        raise RawValidationError(f"count is a {type(count).__name__}, expected an integer")
    if count != len(records):
        raise RawValidationError(f"count is {count:,} but vulnerabilities has {len(records):,} records")

    drop_check = check_row_count(
        len(records),
        snapshot_date,
        reference,
        min_rows=min_rows,
        max_drop_percent=max_drop_percent,
        accept_reason=accept_reason,
    )
    metadata = {key: catalog[key] for key in METADATA_KEYS}
    return Validated(rows=len(records), metadata=metadata, drop_check=drop_check)


def _check_keys(where: str, found: set[str], expected: frozenset[str]) -> None:
    missing = sorted(expected - found)
    extra = sorted(found - expected)
    if missing or extra:
        raise RawValidationError(f"{where}: missing keys {missing}, unexpected keys {extra}")


# KEV is CC0 (CLAUDE.md §4): the excerpt of a rejected file needs no redaction.
SOURCE = SourceSpec(
    name="kev",
    url=URL,
    extension="json",
    validate=validate,
    excerpt=diagnostic_excerpt,
    metadata_keys=METADATA_KEYS,
)
