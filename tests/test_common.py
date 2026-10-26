"""Flow shared by the sources: row checks, excerpt, run_source and quarantine. No network."""

import hashlib
from datetime import date, datetime

import pytest
from helpers import SNAPSHOT, big_kev, fetch_result, fixture_bytes, kev_bytes, kev_catalog, utc

from threat_intel_pipeline.ingest import common, kev
from threat_intel_pipeline.ingest.common import (
    RawValidationError,
    Reference,
    check_row_count,
    diagnostic_excerpt,
    run_source,
)
from threat_intel_pipeline.ingest.download import DownloadError

YESTERDAY = date(2026, 10, 25)
STARTED = utc(26)  # 2026-10-26T15:17:03Z


# check_row_count


def test_exactly_one_percent_drop_passes():
    assert check_row_count(99, SNAPSHOT, Reference(YESTERDAY, 100), min_rows=0).status == "ok"


def test_drop_above_one_percent_fails_with_numerator_and_denominator():
    with pytest.raises(RawValidationError, match=r"drop 2\.00% = 2 / 100 vs 2026-10-25, maximum drop is 1%") as error:
        check_row_count(98, SNAPSHOT, Reference(YESTERDAY, 100), min_rows=0)
    assert error.value.drop_check.status == "failed"


def test_without_reference_the_drop_check_is_skipped_not_silent():
    drop_check = check_row_count(10, SNAPSHOT, None, min_rows=0)
    assert (drop_check.status, drop_check.reason) == ("skipped", "no previous ok manifest")
    assert drop_check.describe() == "skipped (no previous ok manifest)"


def test_old_reference_is_compared_and_its_age_recorded():
    drop_check = check_row_count(100, SNAPSHOT, Reference(date(2026, 10, 20), 100), min_rows=0)
    assert (drop_check.status, drop_check.reference_age_days) == ("ok", 6)


@pytest.mark.parametrize("reference_date", [SNAPSHOT, date(2026, 10, 27)], ids=["same-day", "later"])
def test_reference_must_be_from_an_earlier_day(reference_date):
    with pytest.raises(ValueError, match="earlier snapshot_date"):
        check_row_count(100, SNAPSHOT, Reference(reference_date, 100), min_rows=0)


def test_accepted_drop_is_recorded_with_its_reason():
    drop_check = check_row_count(98, SNAPSHOT, Reference(YESTERDAY, 100), min_rows=0, accept_reason="--accept-drop kev")
    assert (drop_check.status, drop_check.reason) == ("accepted_by_operator", "--accept-drop kev")
    assert drop_check.describe() == "drop 2.00% = 2 / 100 vs 2026-10-25"


def test_accepting_a_drop_never_lifts_the_minimum_rows():
    with pytest.raises(RawValidationError, match="98 rows, minimum is 99"):
        check_row_count(98, SNAPSHOT, Reference(YESTERDAY, 100), min_rows=99, accept_reason="--accept-drop kev")


# diagnostic_excerpt


def test_excerpt_escapes_non_printable_characters():
    assert diagnostic_excerpt(b"\x00\x01garbage\tvalue\r\nsecond\x1b[31m") == [
        "\\x00\\x01garbage\\tvalue\\r",
        "second\\x1b[31m",
    ]


def test_excerpt_cuts_long_lines_to_200_characters():
    assert diagnostic_excerpt(b"x" * 300) == ["x" * 200 + "...[truncated]"]


def test_excerpt_escapes_invalid_utf8_and_invisible_characters():
    content = '{\n  "title": "café ​"'.encode() + b"\xff\nthird line"
    assert diagnostic_excerpt(content) == ["{", '  "title": "café \\u200b"\\xff']


# run_source


def fetcher(content=None, error=None, calls=None):
    def _fetch(url):
        if calls is not None:
            calls.append(url)
        if error is not None:
            raise error
        return fetch_result(url, content, utc(26, 15, 17, 5))

    return _fetch


def must_not_fetch(url):
    raise AssertionError(f"unexpected HTTP request to {url}")


def run(tmp_path, content=None, *, error=None, fetch=None, snapshot=SNAPSHOT, reference=None, **kwargs):
    raw = tmp_path / "raw"
    raw.mkdir(exist_ok=True)
    return run_source(
        kev.SOURCE,
        snapshot,
        raw,
        reference,
        started_at=kwargs.pop("started_at", STARTED),
        quarantine_dir=tmp_path / "quarantine",
        fetcher=fetch or fetcher(content, error),
        **kwargs,
    )


def test_download_is_validated_and_saved_byte_identical(tmp_path):
    content = big_kev()
    result = run(tmp_path, content)
    saved = tmp_path / "raw" / "kev_2026-10-26.json"
    assert (result.status, result.action, result.rows) == ("ok", "downloaded", 1_800)
    assert saved.read_bytes() == content
    assert result.sha256 == hashlib.sha256(content).hexdigest()
    assert list((tmp_path / "raw" / ".tmp").iterdir()) == []


def test_existing_raw_is_validated_again_without_any_request(tmp_path):
    first = run(tmp_path, big_kev())
    second = run(tmp_path, fetch=must_not_fetch)
    assert (second.status, second.action, second.sha256) == ("ok", "already_present", first.sha256)


def test_rejected_download_goes_to_quarantine_with_an_excerpt(tmp_path):
    content = fixture_bytes("kev_bad_top_level.json")
    result = run(tmp_path, content)
    quarantined = tmp_path / "quarantine" / "kev_2026-10-26_151703Z.json"
    assert result.status == "failed"
    assert result.error.startswith("RawValidationError: rejected, not saved: top level: missing keys ['catalogVersion']")
    assert result.quarantine_file == "kev_2026-10-26_151703Z.json"
    assert quarantined.read_bytes() == content
    assert result.sha256 == hashlib.sha256(content).hexdigest()
    assert result.excerpt == ["{", '    "title": "Synthetic test catalog (not real KEV data)",']
    assert not (tmp_path / "raw" / "kev_2026-10-26.json").exists()
    assert list((tmp_path / "quarantine" / ".tmp").iterdir()) == []
    assert result.metadata == dict.fromkeys(kev.METADATA_KEYS)


def test_quarantine_collision_is_reported_without_local_paths(tmp_path):
    run(tmp_path, b"first rejected content")
    before = (tmp_path / "quarantine" / "kev_2026-10-26_151703Z.json").read_bytes()
    result = run(tmp_path, b"second rejected content")
    assert result.status == "failed"
    assert result.quarantine_file is None
    assert "quarantine failed: FileExistsError:" in result.error
    assert str(tmp_path) not in result.error and "\\" not in result.error
    assert (tmp_path / "quarantine" / "kev_2026-10-26_151703Z.json").read_bytes() == before


def test_empty_download_has_no_quarantine_and_no_excerpt(tmp_path):
    result = run(tmp_path, fixture_bytes("kev_empty.json"))
    assert (result.status, result.quarantine_file, result.excerpt) == ("failed", None, None)
    assert "empty file" in result.error
    assert not (tmp_path / "quarantine").exists()


def test_download_error_gives_a_failed_result_with_null_metadata(tmp_path):
    result = run(tmp_path, error=DownloadError("GET x failed after 4 attempts; last error: HTTP 503"))
    assert (result.status, result.action, result.sha256) == ("failed", None, None)
    assert result.error == "DownloadError: GET x failed after 4 attempts; last error: HTTP 503"
    assert result.metadata == dict.fromkeys(kev.METADATA_KEYS)


def test_existing_raw_that_no_longer_passes_is_reported_and_not_moved(tmp_path):
    (tmp_path / "raw").mkdir()
    existing = tmp_path / "raw" / "kev_2026-10-26.json"
    existing.write_bytes(b"not json")
    result = run(tmp_path, fetch=must_not_fetch)
    assert (result.status, result.action, result.quarantine_file, result.excerpt) == ("failed", "already_present", None, None)
    assert "existing raw file no longer passes the raw tests: invalid JSON" in result.error
    assert existing.read_bytes() == b"not json"


def test_accept_drop_accepts_a_large_drop_for_this_run(tmp_path):
    result = run(tmp_path, big_kev(1_770), reference=Reference(YESTERDAY, 1_800), accept_drop=True)
    assert result.status == "ok"
    assert (result.drop_check.status, result.drop_check.reason) == ("accepted_by_operator", "--accept-drop kev")
    assert result.drop_check.describe() == "drop 1.67% = 30 / 1,800 vs 2026-10-25"


def test_earlier_acceptance_is_kept_only_for_the_same_file(tmp_path):
    accepted = run(tmp_path, big_kev(1_770), reference=Reference(YESTERDAY, 1_800), accept_drop=True)
    same_file = run(
        tmp_path,
        fetch=must_not_fetch,
        reference=Reference(YESTERDAY, 1_800),
        accepted_earlier={accepted.sha256: "manifest_2026-10-26_151703Z.json"},
    )
    assert same_file.drop_check.status == "accepted_by_operator"
    assert same_file.drop_check.reason == "accepted earlier today in manifest_2026-10-26_151703Z.json (same sha256)"

    other = tmp_path / "other"
    (other / "raw").mkdir(parents=True)
    (other / "raw" / "kev_2026-10-26.json").write_bytes(kev_bytes(kev_catalog(1_770)) + b"\n")  # other bytes
    other_file = run(
        other,
        fetch=must_not_fetch,
        reference=Reference(YESTERDAY, 1_800),
        accepted_earlier={accepted.sha256: "manifest_2026-10-26_151703Z.json"},
    )
    assert (other_file.status, other_file.action) == ("failed", "already_present")
    assert "maximum drop is 1%" in other_file.error


def test_started_at_must_be_timezone_aware(tmp_path):
    with pytest.raises(ValueError, match="timezone-aware"):
        run(tmp_path, big_kev(), started_at=datetime(2026, 10, 26, 15, 17, 3))


def test_max_drop_constant_is_shared():
    assert common.MAX_DROP_PERCENT == 1
