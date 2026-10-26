"""Raw tests of KEV (CLAUDE.md §6), on synthetic fixtures."""

import json
from datetime import date

import pytest
from helpers import SNAPSHOT, fixture_bytes, kev_bytes

from threat_intel_pipeline.ingest import common, kev
from threat_intel_pipeline.ingest.common import RawValidationError, Reference

YESTERDAY = date(2026, 10, 25)


def valid_catalog() -> dict:
    return json.loads(fixture_bytes("kev_valid.json"))


def validate(content: bytes, reference: Reference | None = None, **kwargs):
    kwargs.setdefault("min_rows", 1)
    return kev.validate(content, SNAPSHOT, reference, **kwargs)


def mutated(mutate) -> bytes:
    catalog = valid_catalog()
    mutate(catalog)
    return kev_bytes(catalog)


def test_thresholds_are_the_ones_in_claude_md():
    assert kev.MIN_ROWS == 1_700
    assert common.MAX_DROP_PERCENT == 1


def test_valid_fixture_passes_with_its_metadata():
    validated = validate(fixture_bytes("kev_valid.json"))
    assert validated.rows == 3
    assert validated.metadata == {"catalogVersion": "2099.01.01", "dateReleased": "2099-01-01T00:00:00.0000Z", "count": 3}
    assert validated.drop_check.status == "skipped"


def test_empty_file_fails():
    with pytest.raises(RawValidationError, match="empty file"):
        validate(fixture_bytes("kev_empty.json"))


def test_invalid_json_fails():
    with pytest.raises(RawValidationError, match="invalid JSON"):
        validate(fixture_bytes("kev_valid.json")[:-10])


def test_bad_top_level_fixture_fails():
    with pytest.raises(RawValidationError, match=r"top level: missing keys \['catalogVersion'\], unexpected keys \['version'\]"):
        validate(fixture_bytes("kev_bad_top_level.json"))


@pytest.mark.parametrize(
    ("mutate", "message"),
    [
        (lambda c: c.update(extra=1), r"top level: missing keys \[\], unexpected keys \['extra'\]"),
        (lambda c: c.pop("title"), r"top level: missing keys \['title'\], unexpected keys \[\]"),
        (lambda c: c["vulnerabilities"][1].pop("notes"), r"vulnerabilities\[1\] \(CVE-2099-0002\): missing keys \['notes'\]"),
        (lambda c: c["vulnerabilities"][2].update(newField="x"), r"vulnerabilities\[2\] \(CVE-2099-0003\): .*unexpected keys \['newField'\]"),
        (lambda c: c.update(vulnerabilities={}), "vulnerabilities is a JSON dict, expected an array"),
    ],
    ids=["extra-top-level-key", "missing-top-level-key", "record-missing-field", "record-new-field", "vulnerabilities-not-array"],
)
def test_structure_must_be_exact(mutate, message):
    with pytest.raises(RawValidationError, match=message):
        validate(mutated(mutate))


@pytest.mark.parametrize(
    ("count", "message"),
    [
        (True, "count is a bool, expected an integer"),  # isinstance(True, int) is True
        ("3", "count is a str, expected an integer"),
        (2, "count is 2 but vulnerabilities has 3 records"),
    ],
    ids=["bool", "string", "mismatch"],
)
def test_count_must_be_an_integer_equal_to_the_records(count, message):
    with pytest.raises(RawValidationError, match=message):
        validate(mutated(lambda c: c.update(count=count)))


def test_below_minimum_rows_fails():
    with pytest.raises(RawValidationError, match="3 rows, minimum is 4"):
        validate(fixture_bytes("kev_valid.json"), min_rows=4)


def test_drop_above_one_percent_fails():
    # 300 -> 3 records is far above 1%; the message shows numerator and denominator.
    with pytest.raises(RawValidationError, match=r"drop 99\.00% = 297 / 300 vs 2026-10-25, maximum drop is 1%"):
        validate(fixture_bytes("kev_valid.json"), Reference(YESTERDAY, 300))


def test_drop_within_one_percent_passes_and_records_the_reference():
    validated = validate(fixture_bytes("kev_valid.json"), Reference(YESTERDAY, 3, "manifest_2026-10-25_151703Z.json"))
    assert validated.drop_check.status == "ok"
    assert validated.drop_check.reference_manifest == "manifest_2026-10-25_151703Z.json"
    assert validated.drop_check.describe() == "no drop: 3 rows vs 3 on 2026-10-25 (+0)"


def test_metadata_keys_are_the_declared_ones():
    validated = validate(fixture_bytes("kev_valid.json"))
    assert tuple(validated.metadata) == kev.METADATA_KEYS == kev.SOURCE.metadata_keys
