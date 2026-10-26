"""Per-attempt manifests and the rules of CLAUDE.md §4, on synthetic results."""

import json
import re
import shutil
from dataclasses import replace
from datetime import date

import pytest
from helpers import utc

from threat_intel_pipeline import manifest as mf
from threat_intel_pipeline.ingest.common import DropCheck, SourceResult

SOURCES = ["kev", "epss"]
DAY = date(2026, 10, 26)
SHA_A = "a" * 64
SHA_B = "b" * 64
ISO_Z = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")


def ok(source, sha=SHA_A, rows=10, action="downloaded", downloaded_at=utc(26, 15, 17, 5), drop_status="skipped"):
    return SourceResult(
        source=source,
        status="ok",
        file=f"{source}_file",
        url=f"https://example.test/{source}",
        action=action,
        final_url=f"https://example.test/{source}-final" if downloaded_at else None,
        downloaded_at=downloaded_at,
        bytes=100,
        rows=rows,
        sha256=sha,
        drop_check=DropCheck(drop_status, rows, 1, reason="no previous ok manifest" if drop_status == "skipped" else None),
    )


def failed(source):
    return SourceResult(source=source, status="failed", file=f"{source}_file", url=f"https://example.test/{source}", error="DownloadError: x")


def write(raw, started_at, results, warnings=()):
    return mf.write_manifest(raw, mf.build_manifest(started_at.date(), started_at, results, list(warnings)))


def load(raw, today=DAY):
    return mf.load_manifests(raw, today, SOURCES)


def test_format_iso_times_ascii_lf_and_name(tmp_path):
    results = [replace(ok("kev"), metadata={"catalogVersion": "café"}), ok("epss")]
    path = write(tmp_path, utc(26, 15, 17, 3), results, ["note →"])
    data = json.loads(path.read_text(encoding="ascii"))
    raw_bytes = path.read_bytes()
    assert path.name == "manifest_2026-10-26_151703Z.json"
    assert data["run_started_at"] == "2026-10-26T15:17:03Z"
    assert all(ISO_Z.fullmatch(data["sources"][s]["downloaded_at"]) for s in SOURCES)
    assert raw_bytes.isascii() and b"\r" not in raw_bytes and raw_bytes.endswith(b"}\n")
    assert b"caf\\u00e9" in raw_bytes and data["sources"]["kev"]["catalogVersion"] == "café"
    assert data["status"] == "ok"
    assert list(data) == ["manifest_version", "snapshot_date", "run_started_at", "status", "warnings", "sources"]


def test_status_is_failed_if_any_source_failed(tmp_path):
    data = json.loads(write(tmp_path, utc(26), [ok("kev"), failed("epss")]).read_text())
    assert data["status"] == "failed"
    assert data["sources"]["epss"]["sha256"] is None and data["sources"]["epss"]["drop_check"] is None


def test_two_attempts_in_the_same_second_never_overwrite(tmp_path):
    first = write(tmp_path, utc(26), [ok("kev"), failed("epss")])
    before = first.read_bytes()
    with pytest.raises(FileExistsError):
        write(tmp_path, utc(26), [ok("kev"), ok("epss")])
    assert first.read_bytes() == before


def test_snapshot_date_must_be_the_utc_date_of_the_start():
    with pytest.raises(ValueError, match="UTC date of started_at"):
        mf.build_manifest(date(2026, 10, 25), utc(26), [ok("kev"), ok("epss")], [])


def test_loading_is_not_recursive(tmp_path):
    path = write(tmp_path, utc(26), [ok("kev"), ok("epss")])
    for sub in ("_probe", ".tmp"):
        (tmp_path / sub).mkdir(exist_ok=True)
        shutil.copy(path, tmp_path / sub / "manifest_2026-10-26_210000Z.json")
    index = load(tmp_path)
    assert [m.name for m in index.readable] == [path.name]
    assert index.unreadable == ()


def write_text(raw, name, text):
    (raw / name).write_text(text, encoding="ascii")


@pytest.mark.parametrize(
    ("name", "make", "reason"),
    [
        ("manifest_2026-10-26_190000Z.json", lambda good: "{ not json", "invalid JSON"),
        ("manifest_2026-10-26_200000Z.json", lambda good: good, "run_started_at does not match the file name"),
        ("manifest_2026-10-25.json", lambda good: "{}", "unexpected file name"),
        ("manifest_2026-10-26_190000Z.json", lambda good: good.replace('"manifest_version": 1', '"manifest_version": true'), "manifest_version is True"),
        ("manifest_2026-10-26_151703Z.json", lambda good: json.dumps({**json.loads(good), "sources": {"kev": json.loads(good)["sources"]["kev"]}}), "sources.epss is missing"),
        ("manifest_2026-10-26_151703Z.json", lambda good: good.replace(SHA_A, "not-a-hash"), "sources.kev.sha256 is not a sha256"),
    ],
    ids=["invalid-json", "name-content-mismatch", "old-naming", "version-bool", "missing-source", "bad-sha256"],
)
def test_unreadable_manifests_are_reported_and_untouched(tmp_path, name, make, reason):
    good_dir = tmp_path / "good"
    good_dir.mkdir()
    good = write(good_dir, utc(26), [ok("kev"), ok("epss", SHA_B)]).read_text(encoding="ascii")
    raw = tmp_path / "raw"
    raw.mkdir()
    write_text(raw, name, make(good))
    before = (raw / name).read_bytes()
    index = load(raw)
    assert index.readable == ()
    assert len(index.unreadable) == 1
    assert index.unreadable[0].name == name
    assert reason in index.unreadable[0].reason
    assert index.warnings() == [f"unreadable manifest ignored: {name}: {index.unreadable[0].reason}"]
    assert (raw / name).read_bytes() == before


def test_manifest_from_a_future_date_is_reported(tmp_path):
    write(tmp_path, utc(30), [failed("kev"), failed("epss")])
    index = load(tmp_path, today=date(2026, 10, 27))
    assert index.readable == ()
    assert "snapshot_date is after today (2026-10-27)" in index.unreadable[0].reason
    assert [m.name for m in load(tmp_path, today=date(2026, 10, 30)).readable] == ["manifest_2026-10-30_151703Z.json"]


def test_reference_is_the_latest_earlier_ok_and_skips_failed_and_unreadable(tmp_path):
    write(tmp_path, utc(24), [ok("kev", rows=7), ok("epss", rows=70)])
    write(tmp_path, utc(25, 10), [ok("kev", rows=8), failed("epss")])
    write_text(tmp_path, "manifest_2026-10-25_200000Z.json", "{ broken")
    write(tmp_path, utc(26, 9), [ok("kev", rows=99), ok("epss", rows=99)])  # today: never a reference
    index = load(tmp_path)
    kev_ref = mf.find_reference(index, "kev", DAY)
    epss_ref = mf.find_reference(index, "epss", DAY)
    assert (kev_ref.snapshot_date, kev_ref.rows, kev_ref.manifest) == (date(2026, 10, 25), 8, "manifest_2026-10-25_101703Z.json")
    assert (epss_ref.snapshot_date, epss_ref.rows, epss_ref.manifest) == (date(2026, 10, 24), 70, "manifest_2026-10-24_151703Z.json")
    assert mf.find_reference(index, "kev", date(2026, 10, 24)) is None


def test_nothing_to_do_only_when_the_latest_of_the_day_matches(tmp_path):
    write(tmp_path, utc(26, 15), [ok("kev"), ok("epss", SHA_B)])
    present = [ok("kev", action="already_present"), ok("epss", SHA_B, action="already_present")]
    assert mf.nothing_to_do(load(tmp_path), present, DAY)
    assert not mf.nothing_to_do(load(tmp_path), [ok("kev", action="already_present"), ok("epss", SHA_A, action="already_present")], DAY)
    assert not mf.nothing_to_do(load(tmp_path), [ok("kev"), ok("epss", SHA_B, action="already_present")], DAY)
    assert not mf.nothing_to_do(load(tmp_path), present, date(2026, 10, 27))  # no manifest that day


def test_latest_manifest_of_the_day_unreadable_means_something_to_do(tmp_path):
    write(tmp_path, utc(26, 15), [ok("kev"), ok("epss", SHA_B)])
    write_text(tmp_path, "manifest_2026-10-26_160000Z.json", "truncated {")
    index = load(tmp_path)
    assert mf.latest_of_day(index, DAY).name == "manifest_2026-10-26_160000Z.json"
    present = [ok("kev", action="already_present"), ok("epss", SHA_B, action="already_present")]
    assert not mf.nothing_to_do(index, present, DAY)


def test_latest_failed_entry_means_something_to_do(tmp_path):
    write(tmp_path, utc(26, 15), [ok("kev"), failed("epss")])
    present = [ok("kev", action="already_present"), ok("epss", SHA_B, action="already_present")]
    assert not mf.nothing_to_do(load(tmp_path), present, DAY)


def test_sha256_differing_from_an_earlier_manifest_of_the_same_day_warns(tmp_path):
    write(tmp_path, utc(26, 15), [ok("kev"), ok("epss", SHA_A)])
    write(tmp_path, utc(25), [ok("kev"), ok("epss", SHA_B)])  # another day: never compared
    warnings = mf.sha256_warnings(load(tmp_path), [ok("kev"), ok("epss", SHA_B)], DAY)
    assert warnings == [
        f"epss: sha256 is now {SHA_B} but manifest_2026-10-26_151703Z.json recorded {SHA_A} for the same snapshot_date"
    ]


def test_already_present_copies_download_time_and_final_url_from_the_same_day(tmp_path):
    write(tmp_path, utc(26, 15), [ok("kev", downloaded_at=utc(26, 15, 17, 5)), failed("epss")])
    results, warnings = mf.complete_already_present(
        load(tmp_path),
        [ok("kev", action="already_present", downloaded_at=None), ok("epss", SHA_B, action="downloaded")],
        DAY,
    )
    assert results[0].downloaded_at == utc(26, 15, 17, 5)
    assert results[0].final_url == "https://example.test/kev-final"
    assert warnings == []


def test_already_present_without_an_earlier_record_warns(tmp_path):
    results, warnings = mf.complete_already_present(
        load(tmp_path), [ok("kev", action="already_present", downloaded_at=None)], DAY
    )
    assert results[0].downloaded_at is None
    assert warnings == [f"kev: download time unknown: no earlier manifest of 2026-10-26 records kev_file with sha256 {SHA_A}"]


def test_accepted_earlier_lists_accepted_contents_of_the_same_day(tmp_path):
    write(tmp_path, utc(26, 15), [ok("kev", drop_status="accepted_by_operator"), ok("epss")])
    write(tmp_path, utc(25), [ok("kev", SHA_B, drop_status="accepted_by_operator"), ok("epss")])
    index = load(tmp_path)
    assert mf.accepted_earlier(index, "kev", DAY) == {SHA_A: "manifest_2026-10-26_151703Z.json"}
    assert mf.accepted_earlier(index, "epss", DAY) == {}
