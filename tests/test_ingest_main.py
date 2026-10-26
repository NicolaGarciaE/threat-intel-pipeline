"""End-to-end runs of the entry point in temporary project folders. No network.

Each run uses a fake fetcher and a fixed clock; the inputs are synthetic and
large enough for the real minimum-row thresholds.
"""

import hashlib
import io
import json
import logging
import shutil
import sys

import pytest
from helpers import EPSS_ROWS, big_kev, epss_gz, epss_text, fetch_result, gz, kev_bytes, kev_catalog, utc

from threat_intel_pipeline import manifest
from threat_intel_pipeline.ingest import __main__ as cli
from threat_intel_pipeline.ingest import kev
from threat_intel_pipeline.ingest.download import DownloadError

PYPROJECT = '[project]\nname = "threat-intel-pipeline"\n'
NO_HTTP = {"kev": None, "epss": None}


def all_ok(day=26):
    return {"kev": big_kev(), "epss": epss_gz(EPSS_ROWS, day)}


class Cli:
    """Runs main() inside one project folder and keeps what it printed."""

    def __init__(self, monkeypatch: pytest.MonkeyPatch, folder):
        self.monkeypatch = monkeypatch
        self.folder = folder
        self.raw = folder / "data" / "raw"
        self.calls: list[str] = []

    def run(self, at, plan, argv=(), encoding="utf-8"):
        self.calls.clear()

        def fetch(url):
            source = "kev" if url == kev.URL else "epss"
            self.calls.append(source)
            item = plan[source]
            if item is None:
                raise AssertionError(f"unexpected HTTP request for {source}")
            if isinstance(item, BaseException):
                raise item
            final_url = url.replace("current", at.date().isoformat()) if source == "epss" else url
            return fetch_result(url, item, at, final_url)

        out = io.BytesIO()
        stream = io.TextIOWrapper(out, encoding=encoding, errors="strict", newline="\n")
        self.monkeypatch.setattr(sys, "stdout", stream)
        self.monkeypatch.setattr(sys, "stderr", stream)
        self.monkeypatch.chdir(self.folder)
        root = logging.getLogger()
        saved_handlers, saved_level = root.handlers[:], root.level
        try:
            code = cli.main(list(argv), fetcher=fetch, now=lambda: at)
        except SystemExit as exc:
            code = exc.code
        finally:
            root.handlers[:] = saved_handlers  # main() reconfigures the root logger
            root.setLevel(saved_level)
        stream.flush()
        return code, out.getvalue().decode(encoding)

    def manifests(self):
        return sorted(p.name for p in self.raw.glob("manifest_*.json")) if self.raw.exists() else []

    def manifest(self, name=None):
        return json.loads((self.raw / (name or self.manifests()[-1])).read_text(encoding="ascii"))


@pytest.fixture
def cli_in(tmp_path, monkeypatch):
    def make(name="project", pyproject=PYPROJECT):
        folder = tmp_path / name
        folder.mkdir()
        if pyproject is not None:
            (folder / "pyproject.toml").write_text(pyproject, encoding="utf-8")
        return Cli(monkeypatch, folder)

    return make


def tree(folder):
    return {
        p.relative_to(folder).as_posix(): hashlib.sha256(p.read_bytes()).hexdigest()
        for p in sorted(folder.rglob("*"))
        if p.is_file()
    }


def test_first_run_saves_both_sources_and_writes_the_manifest(cli_in):
    c = cli_in()
    code, out = c.run(utc(26), all_ok())
    assert code == 0
    assert c.manifests() == ["manifest_2026-10-26_151703Z.json"]
    assert (c.raw / "kev_2026-10-26.json").read_bytes() == big_kev()
    assert (c.raw / "epss_2026-10-26.csv.gz").read_bytes() == epss_gz(EPSS_ROWS, 26)
    assert "final checks passed" in out
    assert "source  status  action" in out
    assert "Result: OK, exit code 0" in out


def test_skipped_drop_check_is_listed_as_a_warning(cli_in):
    c = cli_in()
    code, out = c.run(utc(26), all_ok())  # first day: no reference
    expected = [
        "kev: 1% drop check skipped: no previous ok manifest",
        "epss: 1% drop check skipped: no previous ok manifest",
    ]
    assert code == 0
    assert c.manifest()["warnings"] == expected
    assert "Warnings (2):\n  - " + "\n  - ".join(expected) in out

    c.run(utc(27), all_ok(27))  # next day: compared, nothing skipped
    assert c.manifest("manifest_2026-10-27_151703Z.json")["warnings"] == []


def test_case_a_second_run_the_same_day_changes_nothing(cli_in):
    c = cli_in()
    c.run(utc(26), all_ok())
    before = tree(c.folder)
    code, out = c.run(utc(26, 15, 40, 0), NO_HTTP)
    assert code == 0
    assert "nothing to do" in out
    assert c.calls == []
    assert tree(c.folder) == before


def test_case_b_retry_after_epss_failed(cli_in):
    c = cli_in()
    code, _ = c.run(utc(26), {"kev": big_kev(), "epss": DownloadError("GET x failed after 4 attempts; last error: HTTP 503")})
    first = c.manifest()
    assert code == 1
    assert first["status"] == "failed"
    assert first["sources"]["epss"]["error"].startswith("DownloadError")

    code, _ = c.run(utc(26, 17, 2, 11), {"kev": None, "epss": epss_gz()})
    second = c.manifest("manifest_2026-10-26_170211Z.json")
    assert code == 0
    assert c.calls == ["epss"]
    assert second["status"] == "ok"
    assert second["sources"]["kev"]["action"] == "already_present"
    assert second["sources"]["kev"]["downloaded_at"] == "2026-10-26T15:17:03Z"  # copied from the 1st attempt

    code, out = c.run(utc(26, 18, 0, 0), NO_HTTP)
    assert code == 0
    assert "nothing to do" in out


def test_case_c_crash_just_before_the_manifest(cli_in):
    c = cli_in()
    c.raw.mkdir(parents=True)
    (c.raw / "kev_2026-10-26.json").write_bytes(big_kev())
    (c.raw / "epss_2026-10-26.csv.gz").write_bytes(epss_gz())
    (c.raw / ".tmp").mkdir()
    orphan = c.raw / ".tmp" / "manifest_2026-10-26_151703Z.json.k3x9.part"
    orphan.write_text('{"manifest_ver')

    code, _ = c.run(utc(26, 15, 30, 0), NO_HTTP)
    data = c.manifest()
    assert code == 0
    assert c.calls == []
    assert data["status"] == "ok"
    assert [data["sources"][s]["downloaded_at"] for s in ("kev", "epss")] == [None, None]
    assert sum("download time unknown" in w for w in data["warnings"]) == 2
    assert any("orphan temporary file" in w for w in data["warnings"])
    assert orphan.exists()

    code, _ = c.run(utc(26, 15, 45, 0), NO_HTTP)
    assert code == 0
    assert len(c.manifests()) == 1


def test_kev_failure_does_not_stop_epss(cli_in):
    c = cli_in()
    code, out = c.run(utc(26), {"kev": DownloadError("GET x failed after 4 attempts; last error: HTTP 503"), "epss": epss_gz()})
    data = c.manifest()
    assert code == 1
    assert (data["sources"]["kev"]["status"], data["sources"]["epss"]["status"]) == ("failed", "ok")
    assert (c.raw / "epss_2026-10-26.csv.gz").exists()
    assert not (c.raw / "kev_2026-10-26.json").exists()
    assert "Result: FAILED, exit code 1 (sources failed: kev)" in out


def test_epss_failure_does_not_stop_kev(cli_in):
    c = cli_in()
    code, out = c.run(utc(26), {"kev": big_kev(), "epss": b"<!DOCTYPE html>\n<html><title>503</title></html>\n"})
    epss_entry = c.manifest()["sources"]["epss"]
    assert code == 1
    assert (c.raw / "kev_2026-10-26.json").exists()
    assert not (c.raw / "epss_2026-10-26.csv.gz").exists()
    assert epss_entry["quarantine_file"] == "epss_2026-10-26_151703Z.csv.gz"
    assert (c.folder / "data" / "quarantine" / "epss_2026-10-26_151703Z.csv.gz").exists()
    assert epss_entry["excerpt"] == ["<!DOCTYPE html>", "<html><title>503</title></html>"]
    assert "epss first line 1: <!DOCTYPE html>" in out


def test_unexpected_bug_in_one_source_is_isolated(cli_in):
    c = cli_in()
    code, _ = c.run(utc(26), {"kev": RuntimeError("simulated bug"), "epss": epss_gz()})
    data = c.manifest()
    assert code == 1
    assert data["sources"]["kev"]["error"] == "unexpected error: RuntimeError: simulated bug"
    assert data["sources"]["kev"]["catalogVersion"] is None
    assert data["sources"]["epss"]["status"] == "ok"


def test_accept_drop_and_recovery_the_next_day(cli_in):
    c = cli_in()
    c.run(utc(26), all_ok())  # 1,800 KEV records
    smaller = big_kev(1_770)  # 30 / 1,800 = 1.67% drop

    code, _ = c.run(utc(27), {"kev": smaller, "epss": epss_gz(EPSS_ROWS, 27)})
    rejected = c.manifest("manifest_2026-10-27_151703Z.json")["sources"]["kev"]
    assert code == 1
    assert rejected["drop_check"]["status"] == "failed"
    assert rejected["quarantine_file"] == "kev_2026-10-27_151703Z.json"

    code, out = c.run(utc(27, 16, 0, 0), {"kev": smaller, "epss": None}, ["--accept-drop", "kev"])
    accepted = c.manifest("manifest_2026-10-27_160000Z.json")
    drop = accepted["sources"]["kev"]["drop_check"]
    assert code == 0
    assert accepted["sources"]["kev"]["status"] == "ok"
    assert (drop["status"], drop["rows"], drop["reference_rows"], drop["reason"]) == (
        "accepted_by_operator", 1_770, 1_800, "--accept-drop kev"
    )
    assert drop["summary"] == "drop 1.67% = 30 / 1,800 vs 2026-10-26"
    assert out.count("DROP ABOVE THE MAXIMUM ACCEPTED BY OPERATOR") == 2  # the run's log line and the summary
    assert any("ACCEPTED BY OPERATOR" in w for w in accepted["warnings"])

    code, out = c.run(utc(27, 17, 0, 0), NO_HTTP)  # same file, no flag: acceptance kept
    assert code == 0
    assert "nothing to do" in out
    assert c.calls == []

    code, _ = c.run(utc(28), {"kev": smaller, "epss": epss_gz(EPSS_ROWS, 28)})
    next_day = c.manifest("manifest_2026-10-28_151703Z.json")["sources"]["kev"]["drop_check"]
    assert code == 0
    assert (next_day["status"], next_day["reference_manifest"], next_day["reference_rows"]) == (
        "ok", "manifest_2026-10-27_160000Z.json", 1_770
    )


def test_accept_drop_when_not_needed_only_warns(cli_in):
    c = cli_in()
    c.run(utc(26), all_ok())
    code, _ = c.run(utc(27), {"kev": big_kev(), "epss": epss_gz(EPSS_ROWS, 27)}, ["--accept-drop", "epss"])
    data = c.manifest()
    assert code == 0
    assert data["sources"]["epss"]["drop_check"]["status"] == "ok"
    assert any(w.startswith("--accept-drop epss was not needed: no drop") for w in data["warnings"])


def test_accept_drop_never_lifts_the_minimum_rows(cli_in):
    c = cli_in()
    c.run(utc(26), all_ok())
    code, _ = c.run(utc(27), {"kev": big_kev(1_650), "epss": epss_gz(EPSS_ROWS, 27)}, ["--accept-drop", "kev"])
    data = c.manifest()
    assert code == 1
    assert "1,650 rows, minimum is 1,700" in data["sources"]["kev"]["error"]
    assert "--accept-drop kev had no effect: the source failed" in data["warnings"]


def test_unknown_source_exits_2_before_doing_anything(cli_in):
    c = cli_in()
    code, out = c.run(utc(26), all_ok(), ["--accept-drop", "foo"])
    assert code == 2
    assert "invalid choice: 'foo' (choose from 'kev', 'epss')" in out
    assert not (c.folder / "data").exists()
    assert c.calls == []


@pytest.mark.parametrize(
    "pyproject",
    [None, '[project]\nname = "other-project"\n', "not [valid toml"],
    ids=["no-pyproject", "other-project", "invalid-toml"],
)
def test_wrong_folder_exits_3_before_creating_anything(cli_in, pyproject):
    c = cli_in(pyproject=pyproject)
    code, out = c.run(utc(26), all_ok())
    assert code == 3
    assert "pyproject.toml" in out
    assert not (c.folder / "data").exists()
    assert c.calls == []


def test_manifest_not_written_exits_4(cli_in):
    c = cli_in()
    c.run(utc(26), {"kev": big_kev(), "epss": DownloadError("HTTP 503")})
    before = c.manifest()
    code, out = c.run(utc(26), {"kev": None, "epss": epss_gz()})  # same second
    assert code == 4
    assert "Manifest: NOT WRITTEN (FileExistsError" in out
    assert c.manifests() == ["manifest_2026-10-26_151703Z.json"]
    assert c.manifest() == before


def test_most_severe_exit_code_wins(cli_in):
    c = cli_in()
    c.run(utc(26), {"kev": big_kev(), "epss": DownloadError("HTTP 503")})
    code, out = c.run(utc(26), {"kev": None, "epss": DownloadError("HTTP 503")})  # epss fails again, same second
    assert code == 4
    assert "Result: FAILED, exit code 4 (sources failed: epss; manifest not written)" in out


def test_final_checks_failure_exits_5(cli_in, monkeypatch):
    original = manifest.write_manifest

    def write_then_tamper(raw_dir, document):
        path = original(raw_dir, document)
        (raw_dir / "kev_2026-10-26.json").write_bytes(b"tampered after validation")
        return path

    monkeypatch.setattr(manifest, "write_manifest", write_then_tamper)
    c = cli_in()
    code, out = c.run(utc(26), all_ok())
    assert code == 5
    assert "final check FAILED: kev: kev_2026-10-26.json on disk does not match the manifest" in out
    assert "Result: FAILED, exit code 5 (final checks failed: 1)" in out


def test_internal_error_outside_the_sources_exits_6(cli_in, monkeypatch):
    def broken(*args, **kwargs):
        raise PermissionError(13, "simulated: cannot list data/raw")

    monkeypatch.setattr(manifest, "load_manifests", broken)
    c = cli_in()
    code, out = c.run(utc(26), all_ok())
    assert code == 6
    assert "internal error" in out
    assert c.calls == []


def test_unencodable_characters_never_break_a_cp1252_output(cli_in):
    catalog = kev_catalog(1_800)
    catalog["title"] = "Synthetic catalog 中"  # printable, kept in the excerpt
    catalog["vulnerabilities"][0]["cveID"] = "CVE-2099-00000→"  # not in cp1252
    del catalog["vulnerabilities"][0]["notes"]
    c = cli_in()
    code, out = c.run(utc(26), {"kev": kev_bytes(catalog), "epss": epss_gz()}, encoding="cp1252")
    assert code == 1
    assert (c.raw / "epss_2026-10-26.csv.gz").exists()
    assert "CVE-2099-00000\\u2192" in out
    assert "\\u4e2d" in out
    manifest_bytes = (c.raw / c.manifests()[0]).read_bytes()
    assert manifest_bytes.isascii()
    assert b"CVE-2099-00000\\u2192" in manifest_bytes


def test_sha256_differing_from_an_earlier_manifest_of_the_day_warns(cli_in):
    first = cli_in("runner1")
    first.run(utc(26), all_ok())
    # Actions-like retry on a new runner: the manifests and the KEV raw come back, the EPSS raw does not.
    second = cli_in("runner2")
    second.raw.mkdir(parents=True)
    for name in [*first.manifests(), "kev_2026-10-26.json"]:
        shutil.copy(first.raw / name, second.raw / name)
    other_bytes = gz(epss_text(EPSS_ROWS, 26), level=6)  # same data, other bytes

    code, out = second.run(utc(26, 17, 2, 11), {"kev": None, "epss": other_bytes})
    data = second.manifest("manifest_2026-10-26_170211Z.json")
    old = hashlib.sha256(epss_gz()).hexdigest()
    new = hashlib.sha256(other_bytes).hexdigest()
    expected = f"epss: sha256 is now {new} but manifest_2026-10-26_151703Z.json recorded {old} for the same snapshot_date"
    assert code == 0
    assert data["status"] == "ok"
    assert [w for w in data["warnings"] if " is now " in w] == [expected]
    assert expected in out
