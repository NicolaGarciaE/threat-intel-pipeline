"""Raw tests of EPSS (CLAUDE.md §5 and §6) and its diagnostic excerpt, on synthetic data."""

import re
from datetime import date

import pytest
from helpers import SNAPSHOT, epss_gz, fixture_bytes, fixture_text, gz

from threat_intel_pipeline.ingest import epss
from threat_intel_pipeline.ingest.common import EXCERPT_REDACTED, RawValidationError, Reference

CVE = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)
VALID = fixture_text("epss_valid.csv")
COMMENT = "#model_version:v2099.01.01,score_date:2026-10-26T12:03:22Z"


def validate(content: bytes, snapshot: date = SNAPSHOT, reference: Reference | None = None, **kwargs):
    kwargs.setdefault("min_rows", 1)
    return epss.validate(content, snapshot, reference, **kwargs)


def test_minimum_rows_is_the_one_in_claude_md():
    assert epss.MIN_ROWS == 350_000


def test_valid_fixture_passes_with_its_metadata():
    validated = validate(gz(VALID))
    assert validated.rows == 3
    assert validated.metadata == {"model_version": "v2099.01.01", "score_date": "2026-10-26T12:03:22Z"}
    assert tuple(validated.metadata) == epss.METADATA_KEYS == epss.SOURCE.metadata_keys


def test_default_minimum_rows():
    assert epss.validate(epss_gz(350_000), SNAPSHOT, None).rows == 350_000
    with pytest.raises(RawValidationError, match="349,999 rows, minimum is 350,000"):
        epss.validate(epss_gz(349_999), SNAPSHOT, None)


def test_empty_fixture_fails():
    with pytest.raises(RawValidationError, match="empty file"):
        validate(fixture_bytes("epss_empty.csv.gz"))


def test_not_gzip_fails():
    with pytest.raises(RawValidationError, match="not a valid gzip file: BadGzipFile"):
        validate(VALID.encode())


def test_truncated_gzip_fails():
    with pytest.raises(RawValidationError, match="not a valid gzip file: EOFError"):
        validate(epss_gz()[:5000])


def test_bad_header_fixture_fails():
    with pytest.raises(RawValidationError, match="header is 'cve,epss,percentil', expected 'cve,epss,percentile'"):
        validate(gz(fixture_text("epss_bad_header.csv")))


def test_old_score_date_fixture_fails():
    with pytest.raises(RawValidationError, match="epss_score_date is 2026-10-20, expected 2026-10-26 or 2026-10-25") as error:
        validate(gz(fixture_text("epss_old_score_date.csv")))
    assert error.value.drop_check.status == "skipped"  # the drop check already done is kept for the manifest


def test_score_date_of_the_day_before_passes():
    assert validate(gz(VALID), date(2026, 10, 27)).rows == 3


@pytest.mark.parametrize("snapshot", [date(2026, 10, 28), date(2026, 10, 25)], ids=["two-days-old", "future"])
def test_score_date_outside_the_two_allowed_days_fails(snapshot):
    with pytest.raises(RawValidationError, match="epss_score_date is 2026-10-26, expected"):
        validate(gz(VALID), snapshot)


@pytest.mark.parametrize(
    ("text", "message"),
    [
        (VALID.replace("\n", "\r\n"), "first line does not match"),
        (VALID.replace("#model_version:", "#model:"), "first line does not match"),
        (VALID.replace("2026-10-26T12", "2026-13-26T12"), "score_date is not a valid timestamp: '2026-13-26T12:03:22Z'"),
        (VALID.replace("CVE-2099-0002,0.00012,0.1", "CVE-2099-0002,0.00012,0.1,extra"), "line 4 has 4 fields, expected 3"),
        (VALID.replace("\nCVE-2099-0002", "\n\nCVE-2099-0002"), "line 4 has 1 fields, expected 3"),
        (COMMENT + "\n", "missing the '#' line or the header"),
    ],
    ids=["crlf", "bad-comment-line", "invalid-timestamp", "four-fields", "blank-line", "no-header"],
)
def test_structure_must_be_exact(text, message):
    with pytest.raises(RawValidationError, match=re.escape(message)):
        validate(gz(text))


def test_no_drop_against_the_reference_is_reported_with_figures():
    validated = validate(gz(VALID), reference=Reference(date(2026, 10, 25), 2))
    assert validated.drop_check.status == "ok"
    assert validated.drop_check.describe() == "no drop: 3 rows vs 2 on 2026-10-25 (+1)"


@pytest.mark.parametrize(
    "text",
    [
        "CVE-2099-0001,0.5,0.9\nCVE-2099-0002,0.1,0.2\n",  # no '#' line, no header
        f"{COMMENT}\nCVE-2099-0001,0.5,0.9\n",  # no header
    ],
    ids=["data-row-as-comment-line", "data-row-as-header"],
)
def test_error_messages_never_carry_a_data_row(text):
    with pytest.raises(RawValidationError) as error:
        validate(gz(text))
    assert EXCERPT_REDACTED in str(error.value)
    assert not CVE.search(str(error.value))


@pytest.mark.parametrize(
    ("content", "expected"),
    [
        (gz(fixture_text("epss_bad_header.csv")), [COMMENT, "cve,epss,percentil"]),
        (b"<!DOCTYPE html>\n<html><title>503</title></html>\n", ["<!DOCTYPE html>", "<html><title>503</title></html>"]),
        (gz("cve,epss,percentile\nCVE-2099-0001,0.5,0.9\n"), ["cve,epss,percentile", EXCERPT_REDACTED]),
        (gz(VALID.replace("\n", "\r\n")), [COMMENT + "\\r", "cve,epss,percentile\\r"]),
        (epss_gz()[:5000], ["#model_version:v2099.01.01,score_date:2026-10-26T12:03:22Z", "cve,epss,percentile"]),
    ],
    ids=["bad-header", "html-error-page", "format-change-redacted", "crlf-visible", "truncated-gzip"],
)
def test_excerpt(content, expected):
    assert epss.excerpt(content) == expected


@pytest.mark.parametrize(
    "content",
    [
        gz("CVE-2099-1,0.1,0.2\nCVE-2099-2,0.3,0.4\n"),
        b"cve-2099-1234;0.5;0.9\n",
        gz(VALID.split("\n", 1)[1]),
    ],
    ids=["only-data-rows", "lowercase-other-separator", "header-then-rows"],
)
def test_excerpt_never_carries_a_cve_id(content):
    assert not any(CVE.search(line) for line in epss.excerpt(content))
