"""GitHub Releases storage, against a fake gh in memory (FakeGh in helpers.py). No network.

FakeGh fails the test on any destructive gh command (--clobber or delete), so
every test also checks that nothing published is ever replaced or deleted.
"""

import fnmatch
import json
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
from helpers import REPO, FakeGh, sha256

from threat_intel_pipeline import manifest, storage
from threat_intel_pipeline.storage import GitHub, StorageError

ROOT = Path(__file__).resolve().parents[1]
OUTSIDE_ACTIONS: dict[str, str] = {}


@pytest.fixture
def gh() -> FakeGh:
    return FakeGh()


def write_day(raw: Path, day: str, kev: bytes | None = b'{"day": "%s"}', time: str = "151705", ok: bool = True) -> Path:
    """A KEV raw file of ``day`` and a manifest that records it (ok or failed)."""
    raw.mkdir(parents=True, exist_ok=True)
    entry: dict = {"status": "failed", "file": f"kev_{day}.json", "sha256": None}
    if kev is not None:
        content = kev.replace(b"%s", day.encode()) if b"%s" in kev else kev
        (raw / f"kev_{day}.json").write_bytes(content)
        if ok:
            entry = {"status": "ok", "file": f"kev_{day}.json", "sha256": sha256(content)}
    path = raw / f"manifest_{day}_{time}Z.json"
    path.write_text(json.dumps({"snapshot_date": day, "sources": {"kev": entry}}), encoding="ascii")
    return path


def publish(gh: FakeGh, raw: Path, prefix: str = "data-", **kwargs) -> storage.PublishReport:
    return storage.publish(GitHub(REPO, gh), prefix, raw, environ=kwargs.pop("environ", OUTSIDE_ACTIONS), **kwargs)


def test_storage_imports_only_the_standard_library_and_fileio():
    # The write job of the daily workflow runs it with no package installed.
    code = (
        "import sys; before = set(sys.modules); import threat_intel_pipeline.storage; "
        "print('\\n'.join(sorted(set(sys.modules) - before)))"
    )
    env = {**os.environ, "PYTHONPATH": str(ROOT / "src")}
    result = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True, check=True, env=env)
    loaded = result.stdout.split()
    ours = {name for name in loaded if name.split(".")[0] == "threat_intel_pipeline"}
    assert ours == {"threat_intel_pipeline", "threat_intel_pipeline.fileio", "threat_intel_pipeline.storage"}
    others = {name.split(".")[0] for name in loaded} - {"threat_intel_pipeline"}
    assert others <= set(sys.stdlib_module_names), others - set(sys.stdlib_module_names)


def test_publishable_names_are_the_raw_names_of_dbt_and_of_the_manifests():
    project = (ROOT / "dbt" / "dbt_project.yml").read_text(encoding="utf-8")
    globs = dict(re.findall(r'^\s+(kev_glob|manifest_glob): "([^"]+)"', project, re.MULTILINE))
    names = [
        "kev_2026-10-26.json", "kev_2026-10-26.json.bak", "kev_20261026.json", "epss_2026-10-26.csv.gz",
        "manifest_2026-10-26_151705Z.json", "manifest_2026-10-26_1517Z.json", "manifest_2026-10-26.json",
    ]
    for name in names:
        assert bool(storage.KEV_NAME.fullmatch(name)) == fnmatch.fnmatchcase(name, globs["kev_glob"]), name
        assert bool(storage.MANIFEST_NAME.fullmatch(name)) == fnmatch.fnmatchcase(name, globs["manifest_glob"]), name
        assert bool(storage.MANIFEST_NAME.fullmatch(name)) == bool(manifest.NAME_PATTERN.fullmatch(name)), name


def test_publish_uploads_kev_files_first_then_manifests_and_never_epss(gh, tmp_path):
    raw = tmp_path / "raw"
    write_day(raw, "2026-10-26")
    write_day(raw, "2026-10-27")
    (raw / "epss_2026-10-26.csv.gz").write_bytes(b"epss")
    (raw / "_probe").mkdir()
    (raw / "_probe" / "kev_2026-10-25.json").write_bytes(b"probe")

    report = publish(gh, raw)

    uploaded = [Path(command[3]).name for command in gh.writes() if command[1] == "upload"]
    assert uploaded == [
        "kev_2026-10-26.json", "kev_2026-10-27.json",
        "manifest_2026-10-26_151705Z.json", "manifest_2026-10-27_151705Z.json",
    ]
    assert gh.published("data-2026-10") == {name: (raw / name).read_bytes() for name in uploaded}
    assert report.uploaded == [f"data-2026-10/{name}" for name in uploaded]
    assert report.conflicts == [] and report.not_published == []


def test_publish_creates_one_real_release_per_month_marked_not_latest(gh, tmp_path):
    raw = tmp_path / "raw"
    write_day(raw, "2026-10-31")
    write_day(raw, "2026-11-01")

    publish(gh, raw)

    creates = [command for command in gh.writes() if command[1] == "create"]
    assert [command[2] for command in creates] == ["data-2026-10", "data-2026-11"]
    assert all("--prerelease" not in command for command in creates)
    assert set(gh.published("data-2026-10")) == {"kev_2026-10-31.json", "manifest_2026-10-31_151705Z.json"}
    assert set(gh.published("data-2026-11")) == {"kev_2026-11-01.json", "manifest_2026-11-01_151705Z.json"}
    release = gh.releases["data-2026-10"]
    assert release["title"] == "data-2026-10"
    assert "EPSS raw files are not published" in release["notes"]


def test_test_prefix_creates_prereleases_marked_as_tests(gh, tmp_path):
    raw = tmp_path / "raw"
    write_day(raw, "2026-10-29")

    publish(gh, raw, prefix="test2-data-")

    release = gh.releases["test2-data-2026-10"]
    assert release["prerelease"] is True
    assert release["title"] == "TEST test2-data-2026-10"
    assert "not part of the real history" in release["notes"]
    assert "data-2026-10" not in gh.releases


def test_a_second_publish_uploads_nothing(gh, tmp_path):
    raw = tmp_path / "raw"
    write_day(raw, "2026-10-26")
    publish(gh, raw)
    gh.commands.clear()

    report = publish(gh, raw)

    assert gh.writes() == []
    assert report.uploaded == []
    assert report.already_published == ["data-2026-10/kev_2026-10-26.json", "data-2026-10/manifest_2026-10-26_151705Z.json"]


def test_a_different_published_file_is_a_conflict_and_is_never_replaced(gh, tmp_path):
    raw = tmp_path / "raw"
    write_day(raw, "2026-10-26")
    gh.add_release("data-2026-10", {"kev_2026-10-26.json": b"other content"})

    report = publish(gh, raw)

    local = (raw / "kev_2026-10-26.json").read_bytes()
    assert gh.published("data-2026-10")["kev_2026-10-26.json"] == b"other content"
    assert report.conflicts == [
        (
            f"data-2026-10/kev_2026-10-26.json: published 13 bytes with sha256 {sha256(b'other content')}, "
            f"local {len(local)} bytes with sha256 {sha256(local)}; nothing was replaced"
        )
    ]
    assert report.uploaded == []
    assert report.withheld == [
        "data-2026-10/manifest_2026-10-26_151705Z.json: not uploaded because kev_2026-10-26.json is in conflict"
    ]


def test_a_kev_conflict_withholds_every_manifest_of_that_day_but_not_other_days(gh, tmp_path, capsys):
    raw = tmp_path / "raw"
    write_day(raw, "2026-10-26")
    write_day(raw, "2026-10-26", time="163005")  # a retry of the same day
    write_day(raw, "2026-10-27")
    gh.add_release("data-2026-10", {"kev_2026-10-26.json": b"other content"})
    args = ["publish", "--repo", REPO, "--release-prefix", "data-", "--raw-dir", str(raw)]

    assert storage.main(args, runner=gh, environ={}) == 1

    assert set(gh.published("data-2026-10")) == {
        "kev_2026-10-26.json", "kev_2026-10-27.json", "manifest_2026-10-27_151705Z.json"
    }
    assert gh.published("data-2026-10")["kev_2026-10-26.json"] == b"other content"
    out = capsys.readouterr().out
    assert "NOT UPLOADED because of an error with the KEV file of that day (2):" in out
    assert "manifest_2026-10-26_151705Z.json: not uploaded" in out
    assert "manifest_2026-10-26_163005Z.json: not uploaded" in out
    assert "Result: FAILED, exit code 1 (1 conflicts)" in out


def test_an_incomplete_published_file_is_a_conflict(gh, tmp_path):
    raw = tmp_path / "raw"
    write_day(raw, "2026-10-26")
    gh.add_release("data-2026-10")
    gh.store("data-2026-10", "kev_2026-10-26.json", b"", state="starter")

    report = publish(gh, raw)

    assert "incomplete (state 'starter')" in report.conflicts[0]
    assert gh.writes() == []
    assert report.withheld == [
        "data-2026-10/manifest_2026-10-26_151705Z.json: not uploaded because kev_2026-10-26.json is in conflict"
    ]


def test_a_kev_file_that_no_manifest_records_ok_is_not_published_but_its_manifests_are(gh, tmp_path):
    raw = tmp_path / "raw"
    write_day(raw, "2026-10-26", ok=False)  # the manifest marks kev failed
    raw.joinpath("kev_2026-10-27.json").write_bytes(b"no manifest was written")  # ingest exit code 4

    report = publish(gh, raw)

    assert set(gh.published("data-2026-10")) == {"manifest_2026-10-26_151705Z.json"}
    assert [line.split(":")[0] for line in report.not_published] == ["kev_2026-10-26.json", "kev_2026-10-27.json"]
    assert not report.failed


def test_a_kev_file_that_differs_from_its_manifests_withholds_its_day_and_fails(gh, tmp_path, capsys):
    raw = tmp_path / "raw"
    write_day(raw, "2026-10-26")
    write_day(raw, "2026-10-26", time="163005")
    recorded = sha256((raw / "kev_2026-10-26.json").read_bytes())
    (raw / "kev_2026-10-26.json").write_bytes(b"changed after the manifests")
    write_day(raw, "2026-10-27")
    write_day(raw, "2026-10-28")
    (raw / "kev_2026-10-28.json").unlink()  # recorded ok, then missing
    args = ["publish", "--repo", REPO, "--release-prefix", "data-", "--raw-dir", str(raw)]

    assert storage.main(args, runner=gh, environ={}) == 1

    assert set(gh.published("data-2026-10")) == {"kev_2026-10-27.json", "manifest_2026-10-27_151705Z.json"}
    out = capsys.readouterr().out
    assert "KEV FILES THAT DIFFER FROM THEIR MANIFESTS (2):" in out
    assert f"kev_2026-10-26.json: manifests record it ok with sha256 {recorded}, but the local file has sha256" in out
    assert "kev_2026-10-28.json: manifests record it ok with sha256" in out and "but there is no local file" in out
    for name in ("manifest_2026-10-26_151705Z.json", "manifest_2026-10-26_163005Z.json"):
        assert f"data-2026-10/{name}: not uploaded because kev_2026-10-26.json differs from its manifests" in out
    assert "data-2026-10/manifest_2026-10-28_151705Z.json: not uploaded because kev_2026-10-28.json differs" in out
    assert "not published (warning): none" in out
    assert "Result: FAILED, exit code 1 (2 KEV files differ from their manifests)" in out


def test_in_actions_a_kev_file_not_published_is_also_a_warning_annotation(gh, tmp_path, capsys):
    raw = tmp_path / "raw"
    write_day(raw, "2026-10-26", ok=False)
    args = ["publish", "--repo", REPO, "--release-prefix", "test-data-", "--raw-dir", str(raw)]

    assert storage.main(args, runner=gh, environ={}) == 0
    assert "::warning" not in capsys.readouterr().out

    in_actions = {"GITHUB_ACTIONS": "true", "GITHUB_REF": "refs/heads/main"}
    assert storage.main(args, runner=gh, environ=in_actions) == 0
    annotations = [line for line in capsys.readouterr().out.splitlines() if line.startswith("::")]
    assert annotations == [
        (
            f"::warning title=KEV file not published::kev_2026-10-26.json: no manifest in {raw} records it ok "
            f"with sha256 {sha256((raw / 'kev_2026-10-26.json').read_bytes())}"
        )
    ]


def test_annotations_are_escaped_like_actions_toolkit():
    assert storage.annotation("warning", "a:b,c%", "50%\r\nnext: line") == "::warning title=a%3Ab%2Cc%25::50%25%0D%0Anext: line"


def test_without_a_digest_the_published_file_is_downloaded_to_compare(gh, tmp_path):
    gh.with_digests = False
    raw = tmp_path / "raw"
    write_day(raw, "2026-10-26")
    publish(gh, raw)  # the uploads are verified by downloading them
    gh.commands.clear()

    report = publish(gh, raw)

    assert gh.writes() == []
    assert [command[1] for command in gh.commands if command[0] == "release"] == ["download", "download"]
    assert len(report.already_published) == 2


def test_an_upload_that_does_not_match_stops_before_the_manifests(gh, tmp_path):
    gh.corrupt_uploads = True
    raw = tmp_path / "raw"
    write_day(raw, "2026-10-26")

    with pytest.raises(StorageError, match="kev_2026-10-26.json differs after uploading it"):
        publish(gh, raw)

    assert set(gh.published("data-2026-10")) == {"kev_2026-10-26.json"}


def test_the_real_history_is_written_only_from_main_in_actions(gh, tmp_path):
    raw = tmp_path / "raw"
    write_day(raw, "2026-10-26")
    branch = {"GITHUB_ACTIONS": "true", "GITHUB_REF": "refs/heads/session-4-ci"}

    with pytest.raises(StorageError, match="refusing to write to data-YYYY-MM releases from 'refs/heads/session-4-ci'"):
        publish(gh, raw, environ=branch)
    with pytest.raises(StorageError, match="refusing"):
        publish(gh, raw, environ=branch, dry_run=True)
    assert gh.commands == []

    publish(gh, raw, prefix="test-data-", environ=branch)
    publish(gh, raw, environ={"GITHUB_ACTIONS": "true", "GITHUB_REF": "refs/heads/main"})
    assert set(gh.releases) == {"test-data-2026-10", "data-2026-10"}


@pytest.mark.parametrize("prefix", ["", "data", "real-data-", "test-", "Data-", "test-data-2026-"])
def test_unknown_release_prefixes_are_refused(gh, tmp_path, prefix):
    write_day(tmp_path, "2026-10-26")
    with pytest.raises(StorageError, match="--release-prefix must be"):
        publish(gh, tmp_path, prefix=prefix)
    assert gh.commands == []


def test_a_malformed_repo_is_refused():
    with pytest.raises(StorageError, match="--repo must be OWNER/NAME"):
        GitHub("owner/repo/extra", FakeGh())


def test_dry_run_only_reads(gh, tmp_path):
    raw = tmp_path / "raw"
    write_day(raw, "2026-10-26")
    gh.add_release("data-2026-10", {"kev_2026-10-26.json": (raw / "kev_2026-10-26.json").read_bytes()})

    report = publish(gh, raw, dry_run=True)

    assert gh.writes() == []
    assert report.planned == ["data-2026-10/manifest_2026-10-26_151705Z.json"]
    assert report.already_published == ["data-2026-10/kev_2026-10-26.json"]


def test_a_release_created_meanwhile_by_another_run_is_used(gh, tmp_path):
    gh.create_race = True
    raw = tmp_path / "raw"
    write_day(raw, "2026-10-26")

    report = publish(gh, raw)

    assert len(report.uploaded) == 2
    assert set(gh.published("data-2026-10")) == {"kev_2026-10-26.json", "manifest_2026-10-26_151705Z.json"}


def test_download_missing_writes_verified_files_and_never_overwrites(gh, tmp_path):
    source = tmp_path / "source"
    write_day(source, "2026-10-26")
    write_day(source, "2026-10-27")
    publish(gh, source)
    raw = tmp_path / "raw"
    raw.mkdir()
    (raw / "kev_2026-10-26.json").write_bytes((source / "kev_2026-10-26.json").read_bytes())
    (raw / "kev_2026-10-27.json").write_bytes(b"local and different")

    report = storage.download_missing(GitHub(REPO, gh), "data-", raw)

    assert report.already_present == ["data-2026-10/kev_2026-10-26.json"]
    assert report.downloaded == [
        "data-2026-10/manifest_2026-10-26_151705Z.json", "data-2026-10/manifest_2026-10-27_151705Z.json"
    ]
    assert [line.split(":")[0] for line in report.conflicts] == ["data-2026-10/kev_2026-10-27.json"]
    assert (raw / "kev_2026-10-27.json").read_bytes() == b"local and different"
    for name in ("manifest_2026-10-26_151705Z.json", "manifest_2026-10-27_151705Z.json"):
        assert (raw / name).read_bytes() == (source / name).read_bytes()
    assert not any((raw / ".tmp").iterdir())


def test_download_rejects_content_that_does_not_match_the_digest(gh, tmp_path):
    gh.add_release("data-2026-10", {"kev_2026-10-26.json": b"published"})
    gh.releases["data-2026-10"]["assets"]["kev_2026-10-26.json"]["content"] = b"tampered"  # same size

    report = storage.download_missing(GitHub(REPO, gh), "data-", tmp_path)

    assert "the asset digest is" in report.conflicts[0]
    assert not (tmp_path / "kev_2026-10-26.json").exists()


def test_download_skips_other_files_incomplete_uploads_and_other_prefixes(gh, tmp_path):
    gh.add_release("data-2026-10", {"notes.txt": b"x", "epss_2026-10-26.csv.gz": b"y"})
    gh.store("data-2026-10", "kev_2026-10-26.json", b"", state="starter")
    gh.add_release("test-data-2026-10", {"kev_2026-10-27.json": b"test"})
    gh.add_release("data-2026-11", {"kev_2026-10-28.json": b"misplaced"})

    report = storage.download_missing(GitHub(REPO, gh), "data-", tmp_path)

    assert report.downloaded == []
    assert len(report.skipped) == 3
    assert report.conflicts == ["data-2026-11/kev_2026-10-28.json: belongs to release data-2026-10"]
    assert list(tmp_path.glob("*.json")) == []


def test_cli_publish_dry_run_publish_and_list(gh, tmp_path, capsys):
    raw = tmp_path / "raw"
    write_day(raw, "2026-10-26")
    base = ["--repo", REPO, "--release-prefix", "data-"]

    assert storage.main(["publish", *base, "--raw-dir", str(raw), "--dry-run"], runner=gh, environ={}) == 0
    assert "would upload (2):" in capsys.readouterr().out
    assert gh.writes() == []

    assert storage.main(["publish", *base, "--raw-dir", str(raw)], runner=gh, environ={}) == 0
    assert "Result: OK, exit code 0" in capsys.readouterr().out

    assert storage.main(["list", *base], runner=gh, environ={}) == 0
    listed = capsys.readouterr().out
    assert "data-2026-10: 2 files" in listed
    assert f"sha256:{sha256((raw / 'kev_2026-10-26.json').read_bytes())}" in listed


def test_cli_fails_on_a_conflict_or_a_gh_error(gh, tmp_path, capsys):
    raw = tmp_path / "raw"
    write_day(raw, "2026-10-26")
    gh.add_release("data-2026-10", {"kev_2026-10-26.json": b"other content"})
    args = ["publish", "--repo", REPO, "--release-prefix", "data-", "--raw-dir", str(raw)]

    assert storage.main(args, runner=gh, environ={}) == 1
    assert "CONFLICTS (never replaced) (1):" in capsys.readouterr().out

    def broken(argv):
        return subprocess.CompletedProcess(["gh", *argv], 1, b"", b"HTTP 503: Service Unavailable")

    assert storage.main(args, runner=broken, environ={}) == 1
    assert "Result: FAILED, exit code 1 (gh api repos/owner/repo/releases/tags/data-2026-10 failed" in capsys.readouterr().out
