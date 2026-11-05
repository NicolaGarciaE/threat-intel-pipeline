"""Rebuilding and checking a raw folder, and planning the dbt run. No network.

The dbt sample (tests/fixtures/dbt/raw) plays the permanent stores: its KEV
raw files and manifests are the releases (a folder, or FakeGh), and its EPSS
files, renamed epss_scores-<date>.csv.gz, are the EPSS archive. The sample is
only read; everything is written to pytest's temporary folders.
"""

import shutil
from datetime import UTC, date, datetime
from pathlib import Path

import duckdb
import pytest
from helpers import REPO, FakeGh, fetch_result, sha256

from threat_intel_pipeline import manifest, rebuild, storage
from threat_intel_pipeline.ingest.common import SourceResult
from threat_intel_pipeline.ingest.download import DownloadError
from threat_intel_pipeline.storage import GitHub

SAMPLE = Path(__file__).resolve().parent / "fixtures" / "dbt" / "raw"
TODAY = date(2026, 10, 28)
SAMPLE_EPSS_DAYS = ["2026-09-20", "2026-09-23", "2026-10-13", "2026-10-14", "2026-10-20", "2026-10-23", "2026-10-24", "2026-10-27"]


def sample_names() -> list[str]:
    return sorted(path.name for path in SAMPLE.iterdir() if path.is_file())


def make_archive(folder, days=SAMPLE_EPSS_DAYS):
    """The sample's EPSS files as an archive folder (their score_date is their snapshot_date)."""
    folder.mkdir(parents=True, exist_ok=True)
    for day in days:
        shutil.copyfile(SAMPLE / f"epss_{day}.csv.gz", folder / f"epss_scores-{day}.csv.gz")
    return folder


def files_in(folder) -> list[str]:
    return sorted(path.name for path in folder.iterdir() if path.is_file())


def rebuild_from_folders(tmp_path, archive=None):
    raw = tmp_path / "raw"
    releases = rebuild.sync_releases(rebuild.FolderFiles(SAMPLE), raw, TODAY)
    epss = rebuild.sync_epss(rebuild.FolderArchive(archive or make_archive(tmp_path / "archive")), raw, TODAY)
    return raw, releases, epss


def write_attempt(folder, started, *, kev=None, epss=None, score_date=None, final_url=None):
    """A real manifest (the functions of session 1) for one attempt; None means the source failed."""
    day = started.date().isoformat()
    results = [
        SourceResult(
            source=name, status="ok" if content is not None else "failed", file=f"{name}_{day}.{extension}",
            url=f"https://example.invalid/{name}", action="downloaded" if content is not None else None,
            final_url=final_url if name == "epss" else None,
            bytes=len(content) if content is not None else None, rows=1 if content is not None else None,
            sha256=sha256(content) if content is not None else None, metadata=metadata,
        )
        for name, extension, content, metadata in (
            ("kev", "json", kev, {"catalogVersion": None, "dateReleased": None, "count": None}),
            ("epss", "csv.gz", epss, {"model_version": "v2099.01.01", "score_date": score_date}),
        )
    ]
    return manifest.write_manifest(folder, manifest.build_manifest(started.date(), started, results, []))


# --- sync-releases and sync-epss ---


def test_a_full_rebuild_from_folders_gives_the_sample_back(tmp_path):
    raw, releases, epss = rebuild_from_folders(tmp_path)
    check = rebuild.verify(raw, TODAY)

    assert releases.errors == epss.errors == check.errors == []
    assert releases.warnings == epss.warnings == check.warnings == []
    assert len(releases.written) == 18  # 11 manifests and 7 KEV raw files
    assert len(epss.written) == 8
    assert files_in(raw) == sample_names()
    for name in sample_names():
        assert (raw / name).read_bytes() == (SAMPLE / name).read_bytes(), name
    assert not (SAMPLE / ".tmp").exists()


def test_a_second_pass_writes_nothing(tmp_path):
    raw, _, _ = rebuild_from_folders(tmp_path)

    releases = rebuild.sync_releases(rebuild.FolderFiles(SAMPLE), raw, TODAY)
    epss = rebuild.sync_epss(rebuild.FolderArchive(tmp_path / "archive"), raw, TODAY)

    assert releases.written == epss.written == []
    assert len(releases.present) == 18 and len(epss.present) == 8
    assert releases.errors == epss.errors == []


def test_kev_files_and_manifests_come_from_the_releases(tmp_path):
    gh = FakeGh()
    storage.publish(GitHub(REPO, gh), "data-", SAMPLE, environ={})
    writes = len(gh.writes())

    raw = tmp_path / "raw"
    report = rebuild.sync_releases(rebuild.ReleaseFiles(GitHub(REPO, gh), "data-"), raw, TODAY)

    assert report.errors == [] and len(report.written) == 18
    assert len(gh.writes()) == writes  # reading the releases writes nothing
    for name in files_in(raw):
        assert (raw / name).read_bytes() == (SAMPLE / name).read_bytes(), name


def test_a_published_kev_file_without_an_ok_manifest_is_not_written(tmp_path):
    gh = FakeGh()
    storage.publish(GitHub(REPO, gh), "data-", SAMPLE, environ={})
    gh.store("data-2026-10", "kev_2026-10-14.json", b"{}")  # its manifest marks kev failed

    raw = tmp_path / "raw"
    report = rebuild.sync_releases(rebuild.ReleaseFiles(GitHub(REPO, gh), "data-"), raw, TODAY)

    assert report.errors == ["kev_2026-10-14.json: no readable manifest of its day records it ok; not written"]
    assert not (raw / "kev_2026-10-14.json").exists()


def test_a_local_file_that_differs_is_never_overwritten(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "kev_2026-10-13.json").write_bytes(b"local")

    report = rebuild.sync_releases(rebuild.FolderFiles(SAMPLE), raw, TODAY)

    assert len(report.errors) == 1
    assert report.errors[0].startswith("kev_2026-10-13.json: the local file (sha256 ")
    assert (raw / "kev_2026-10-13.json").read_bytes() == b"local"
    assert len(report.written) == 17


def test_a_kev_file_that_differs_from_its_manifest_is_not_written(tmp_path):
    source = tmp_path / "source"
    shutil.copytree(SAMPLE, source)
    (source / "kev_2026-10-13.json").write_bytes(b"tampered")

    raw = tmp_path / "raw"
    report = rebuild.sync_releases(rebuild.FolderFiles(source), raw, TODAY)

    assert report.errors == [
        (
            f"kev_2026-10-13.json: sha256 {sha256(b'tampered')}, but manifest_2026-10-13_151705Z.json records "
            f"{sha256((SAMPLE / 'kev_2026-10-13.json').read_bytes())}; not written"
        )
    ]
    assert not (raw / "kev_2026-10-13.json").exists()


def test_a_day_missing_from_the_archive_is_an_error_and_the_other_days_are_written(tmp_path):
    archive = make_archive(tmp_path / "archive", [day for day in SAMPLE_EPSS_DAYS if day != "2026-10-13"])

    raw, _, epss = rebuild_from_folders(tmp_path, archive)

    assert epss.errors == [
        (
            f"epss_2026-10-13.csv.gz: {archive.as_posix()}/epss_scores-2026-10-13.csv.gz could not be read: "
            f"epss_scores-2026-10-13.csv.gz is not in {archive.as_posix()}"
        )
    ]
    assert len(epss.written) == 7
    assert not (raw / "epss_2026-10-13.csv.gz").exists()
    assert rebuild.verify(raw, TODAY).errors == [
        f"epss_2026-10-13.csv.gz: manifest_2026-10-13_151705Z.json records it ok, but it is not in {raw.as_posix()}"
    ]


def test_an_archive_file_with_another_sha256_is_never_accepted(tmp_path):
    archive = make_archive(tmp_path / "archive")
    other = (SAMPLE / "epss_2026-10-14.csv.gz").read_bytes()
    (archive / "epss_scores-2026-10-13.csv.gz").write_bytes(other)

    raw, _, epss = rebuild_from_folders(tmp_path, archive)

    recorded = (SAMPLE / "epss_2026-10-13.csv.gz").read_bytes()
    assert epss.errors == [
        (
            f"epss_2026-10-13.csv.gz: {archive.as_posix()}/epss_scores-2026-10-13.csv.gz has sha256 {sha256(other)} "
            f"({len(other):,} bytes), but manifest_2026-10-13_151705Z.json records {sha256(recorded)} "
            f"({len(recorded):,} bytes); not written"
        )
    ]
    assert not (raw / "epss_2026-10-13.csv.gz").exists()


def test_the_epss_file_is_the_archive_file_of_its_score_date(tmp_path):
    # EPSS published late: the raw file of 2026-10-29 holds the scores of 2026-10-28.
    source, archive, raw = tmp_path / "source", tmp_path / "archive", tmp_path / "raw"
    for folder in (source, archive, raw):
        folder.mkdir()
    (archive / "epss_scores-2026-10-28.csv.gz").write_bytes(b"scores of the 28th")
    (archive / "epss_scores-2026-10-29.csv.gz").write_bytes(b"scores of the 29th")
    write_attempt(source, datetime(2026, 10, 29, 15, 17, 3, tzinfo=UTC), epss=b"scores of the 28th",
                  score_date="2026-10-28T12:03:13Z", final_url="https://example.invalid/epss_scores-2026-10-28.csv.gz")

    rebuild.sync_releases(rebuild.FolderFiles(source), raw, date(2026, 10, 29))
    report = rebuild.sync_epss(rebuild.FolderArchive(archive), raw, date(2026, 10, 29))

    assert report.errors == []
    assert (raw / "epss_2026-10-29.csv.gz").read_bytes() == b"scores of the 28th"


def test_a_final_url_that_disagrees_with_the_score_date_is_an_error(tmp_path):
    raw, archive = tmp_path / "raw", tmp_path / "archive"
    raw.mkdir()
    archive.mkdir()
    (archive / "epss_scores-2026-10-28.csv.gz").write_bytes(b"x")
    write_attempt(raw, datetime(2026, 10, 28, 15, 17, 3, tzinfo=UTC), epss=b"x",
                  score_date="2026-10-28T12:03:13Z", final_url="https://example.invalid/epss_scores-2026-10-27.csv.gz")

    report = rebuild.sync_epss(rebuild.FolderArchive(archive), raw, TODAY)

    assert len(report.errors) == 1 and "they disagree" in report.errors[0]
    assert not (raw / "epss_2026-10-28.csv.gz").exists()


def test_the_official_archive_url_and_a_missing_file(tmp_path):
    raw = tmp_path / "raw"
    raw.mkdir()
    for day in (27, 28):
        write_attempt(raw, datetime(2026, 10, day, 15, 17, 3, tzinfo=UTC), epss=f"day {day}".encode(),
                      score_date=f"2026-10-{day}T12:03:13Z")
    requested = []

    def fetcher(url):
        requested.append(url)
        if url.endswith("2026-10-27.csv.gz"):
            raise DownloadError(f"GET {url} failed: HTTP 404")
        return fetch_result(url, b"day 28", datetime(2026, 10, 28, 15, 17, tzinfo=UTC))

    report = rebuild.sync_epss(rebuild.UrlArchive(fetcher=fetcher), raw, TODAY)

    base = "https://raw.githubusercontent.com/empiricalsec/epss_scores/main/2026"
    assert requested == [f"{base}/epss_scores-2026-10-27.csv.gz", f"{base}/epss_scores-2026-10-28.csv.gz"]
    assert report.written == [f"epss_2026-10-28.csv.gz <- {base}/epss_scores-2026-10-28.csv.gz"]
    assert report.errors == [
        (
            f"epss_2026-10-27.csv.gz: {base}/epss_scores-2026-10-27.csv.gz could not be read: "
            f"GET {base}/epss_scores-2026-10-27.csv.gz failed: HTTP 404"
        )
    ]


# --- verify ---


def test_verify_finds_missing_and_changed_files_and_warns_about_the_rest(tmp_path):
    raw, _, _ = rebuild_from_folders(tmp_path)
    (raw / "epss_2026-09-23.csv.gz").unlink()
    (raw / "kev_2026-10-20.json").write_bytes(b"changed")
    (raw / "kev_2026-10-14.json").write_bytes(b"{}")  # its manifest marks kev failed
    later = write_attempt(raw, datetime(2026, 10, 27, 18, 0, 0, tzinfo=UTC), kev=b"another catalog",
                          epss=(raw / "epss_2026-10-27.csv.gz").read_bytes(), score_date="2026-10-27T12:03:22Z")

    report = rebuild.verify(raw, TODAY)

    assert report.errors == [
        f"epss_2026-09-23.csv.gz: manifest_2026-09-23_151705Z.json records it ok, but it is not in {raw.as_posix()}",
        (
            f"kev_2026-10-20.json: sha256 {sha256(b'changed')} (7 bytes), but manifest_2026-10-20_163005Z.json records "
            f"{sha256((SAMPLE / 'kev_2026-10-20.json').read_bytes())}"
        ),
        (
            f"kev_2026-10-27.json: sha256 {sha256((SAMPLE / 'kev_2026-10-27.json').read_bytes())} "
            f"({(SAMPLE / 'kev_2026-10-27.json').stat().st_size:,} bytes), but {later.name} records {sha256(b'another catalog')}"
        ),
    ]
    assert report.warnings == [
        "kev_2026-10-14.json: no readable manifest of its day records it ok",
        (
            f"kev 2026-10-27: ok manifests record 2 different sha256 values "
            f"({', '.join(sorted([sha256(b'another catalog'), sha256((SAMPLE / 'kev_2026-10-27.json').read_bytes())]))}); "
            "the latest manifest decides"
        ),
    ]


# --- plan ---


def make_database(path, days):
    with duckdb.connect(str(path)) as con:
        con.execute("create schema main_marts")
        con.execute("create table main_marts.mart_source_days (source varchar, snapshot_date date, rows bigint)")
        for source, day in days:
            con.execute("insert into main_marts.mart_source_days values (?, ?, 1)", [source, date.fromisoformat(day)])
    return path


def make_raw(folder, kev_days, epss_days):
    folder.mkdir(parents=True, exist_ok=True)
    for day in kev_days:
        (folder / f"kev_{day}.json").write_bytes(b"")
    for day in epss_days:
        (folder / f"epss_{day}.csv.gz").write_bytes(b"")
    return folder


DAYS = ["2026-10-26", "2026-10-27", "2026-10-28"]


@pytest.mark.parametrize(
    ("loaded", "kev_days", "epss_days", "test_since", "new_days"),
    [
        pytest.param("2026-10-27", DAYS, DAYS, "2026-10-28", True, id="one new day"),
        pytest.param("2026-10-27", DAYS, DAYS[:2], "2026-10-27", True, id="EPSS failed today: its last day"),
        pytest.param("2026-10-26", DAYS, DAYS, "2026-10-27", True, id="a day without a build: both new days"),
        pytest.param("2026-10-28", DAYS, DAYS, "2026-10-28", False, id="nothing new: the last day"),
    ],
)
def test_plan_incremental_tests_every_new_day_and_never_an_empty_source(tmp_path, loaded, kev_days, epss_days, test_since, new_days):
    loaded_days = [(source, day) for source in ("kev", "epss") for day in DAYS if day <= loaded]
    database = make_database(tmp_path / "real.duckdb", loaded_days)
    raw = make_raw(tmp_path / "raw", kev_days, epss_days)

    result = rebuild.plan(raw, database)

    assert (result.mode, result.test_since, result.new_days) == ("incremental", date.fromisoformat(test_since), new_days)


def test_plan_is_a_full_refresh_without_a_usable_database(tmp_path):
    raw = make_raw(tmp_path / "raw", DAYS, DAYS)
    no_table = tmp_path / "no_table.duckdb"
    duckdb.connect(str(no_table)).close()
    garbage = tmp_path / "garbage.duckdb"
    garbage.write_bytes(b"not a database")
    empty = make_database(tmp_path / "empty.duckdb", [])
    good = make_database(tmp_path / "good.duckdb", [("kev", "2026-10-28"), ("epss", "2026-10-28")])

    reasons = {
        name: rebuild.plan(raw, database)
        for name, database in (("missing", tmp_path / "missing.duckdb"), ("no_table", no_table),
                               ("garbage", garbage), ("empty", empty))
    }
    asked = rebuild.plan(raw, good, full_refresh=True)

    assert all(result.mode == "full" and result.test_since is None for result in [*reasons.values(), asked])
    assert reasons["missing"].reason.startswith("no database at ")
    assert reasons["no_table"].reason.startswith("the database cannot be used: CatalogException")
    assert reasons["garbage"].reason.startswith("the database cannot be used: ")
    assert reasons["empty"].reason == "mart_source_days has no days"
    assert asked.reason == "full refresh requested"


# --- command line ---


def test_cli_plan_writes_the_step_outputs(tmp_path, capsys):
    raw = make_raw(tmp_path / "raw", DAYS, DAYS[:2])
    database = make_database(tmp_path / "real.duckdb", [("kev", "2026-10-27"), ("epss", "2026-10-27")])
    output = tmp_path / "github_output"

    code = rebuild.main(["plan", "--raw-dir", str(raw), "--database", str(database)], environ={"GITHUB_OUTPUT": str(output)})

    assert code == 0
    assert output.read_text(encoding="utf-8") == "mode=incremental\ntest_since=2026-10-27\nnew_days=true\n"
    assert "Result: OK, exit code 0" in capsys.readouterr().out


def test_cli_sync_commands_and_exit_codes(tmp_path, capsys):
    raw = tmp_path / "raw"
    archive = make_archive(tmp_path / "archive", SAMPLE_EPSS_DAYS[1:])

    assert rebuild.main(["sync-releases", "--raw-dir", str(raw), "--from-dir", str(SAMPLE)]) == 0
    assert "written (18):" in capsys.readouterr().out
    assert rebuild.main(["sync-epss", "--raw-dir", str(raw), "--archive", str(archive)]) == 1
    assert "Result: FAILED, exit code 1 (1 errors)" in capsys.readouterr().out
    assert rebuild.main(["verify", "--raw-dir", str(raw)]) == 1
    assert "epss_2026-09-20.csv.gz: manifest_2026-09-20_151705Z.json records it ok, but it is not in" in capsys.readouterr().out
    with pytest.raises(SystemExit) as usage:
        rebuild.main(["sync-releases", "--raw-dir", str(raw), "--repo", REPO])
    assert usage.value.code == 2
