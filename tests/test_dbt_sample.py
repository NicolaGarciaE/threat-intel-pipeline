"""The dbt sample in tests/fixtures/dbt/ (see its README.md).

Every raw file passes the session 1 structure checks (not the row thresholds),
manifests are the only other files, and they match the files they describe.
"""

import hashlib
import re
from datetime import UTC, date, datetime
from pathlib import Path

import pytest

from threat_intel_pipeline.ingest import epss, kev
from threat_intel_pipeline.manifest import NAME_PATTERN, latest_of_day, load_manifests

SAMPLE = Path(__file__).parent / "fixtures" / "dbt"
FOLDERS = ("raw", "invalid")
SOURCES = {"kev": kev, "epss": epss}
RAW_NAME = re.compile(r"(?P<source>kev|epss)_(?P<date>\d{4}-\d{2}-\d{2})\..+")
SYNTHETIC_WARNING = "synthetic test manifest (tests/fixtures/dbt): not a real download"
EXPECTED_ROWS = {"kev": 49, "epss": 96}  # raw/, see README.md


def raw_files(folder: str) -> list[Path]:
    return sorted(p for p in (SAMPLE / folder).iterdir() if not NAME_PATTERN.fullmatch(p.name))


def parse_raw_name(path: Path) -> tuple[str, date]:
    """Source and snapshot_date of a raw file; fails unless the name is exactly the canonical one."""
    match = RAW_NAME.fullmatch(path.name)
    assert match is not None, f"unexpected file {path.name}"
    source, snapshot = match["source"], date.fromisoformat(match["date"])
    assert path.name == SOURCES[source].SOURCE.filename(snapshot), f"unexpected file {path.name}"
    return source, snapshot


def rows_of(path: Path) -> int:
    source, snapshot = parse_raw_name(path)
    return SOURCES[source].validate(path.read_bytes(), snapshot, None, min_rows=1).rows


@pytest.mark.parametrize("folder", FOLDERS)
def test_only_raw_files_of_both_sources_and_manifests(folder):
    entries = sorted((SAMPLE / folder).iterdir())
    assert all(entry.is_file() for entry in entries), "no subfolders (the dbt glob would ignore them)"
    assert any(NAME_PATTERN.fullmatch(entry.name) for entry in entries), "no manifest"
    sources = {parse_raw_name(path)[0] for path in raw_files(folder)}
    assert sources == set(SOURCES)


@pytest.mark.parametrize(
    "path", [p for folder in FOLDERS for p in raw_files(folder)], ids=lambda p: f"{p.parent.name}/{p.name}"
)
def test_raw_file_passes_the_session_1_structure_checks(path):
    assert rows_of(path) > 0


@pytest.mark.parametrize("folder", FOLDERS)
def test_manifests_are_synthetic_readable_and_match_the_files(folder):
    index = load_manifests(SAMPLE / folder, datetime.now(UTC).date(), list(SOURCES))
    assert index.unreadable == ()
    for manifest in index.readable:
        assert SYNTHETIC_WARNING in manifest.data["warnings"]
        for entry in manifest.data["sources"].values():
            assert entry["url"] is None and entry["final_url"] is None and entry["downloaded_at"] is None
            if entry["status"] == "failed":
                assert (entry["bytes"], entry["rows"], entry["sha256"]) == (None, None, None)

    # Every raw file is described by the latest manifest of its day, with the source ok.
    for path in raw_files(folder):
        source, snapshot = parse_raw_name(path)
        latest = latest_of_day(index, snapshot)
        assert latest is not None, f"no manifest for {path.name}"
        entry = latest.data["sources"][source]
        content = path.read_bytes()
        assert entry["status"] == "ok"
        assert entry["file"] == path.name
        assert entry["bytes"] == len(content)
        assert entry["sha256"] == hashlib.sha256(content).hexdigest()
        assert entry["rows"] == rows_of(path)


def test_rows_per_source_are_the_expected_ones():
    totals = dict.fromkeys(SOURCES, 0)
    for path in raw_files("raw"):
        totals[parse_raw_name(path)[0]] += rows_of(path)
    assert totals == EXPECTED_ROWS
