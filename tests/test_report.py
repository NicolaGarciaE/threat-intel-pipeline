"""Job summaries of a run, from synthetic dbt results and manifests. No network."""

import json
from datetime import date, timedelta

from helpers import sha256, utc

from threat_intel_pipeline import manifest, report
from threat_intel_pipeline.ingest.common import DropCheck, SourceResult

RUN_RESULTS = {
    "args": {"which": "build", "target": "real"},
    "results": [
        {"unique_id": "model.threat_intel_pipeline.stg_kev", "status": "success", "failures": None, "message": "OK"},
        {"unique_id": "test.threat_intel_pipeline.not_null_stg_kev_cve_id.1a2b", "status": "pass", "failures": 0, "message": None},
        {
            "unique_id": "test.threat_intel_pipeline.assert_manifest_bookkeeping",
            "status": "warn", "failures": 2, "message": "Got 2 results, configured to warn if != 0",
        },
        {
            "unique_id": "test.threat_intel_pipeline.source_max_decimal_places_raw_epss_epss__5.95bd3a2831",
            "status": "fail", "failures": 1, "message": "Got 1 result, configured to fail if != 0",
        },
        {"unique_id": "model.threat_intel_pipeline.stg_epss", "status": "skipped", "failures": None, "message": None},
    ],
}


def write(tmp_path, document=RUN_RESULTS):
    path = tmp_path / "run_results.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def test_the_dbt_summary_counts_statuses_and_lists_every_node_that_did_not_pass(tmp_path, capsys):
    summary = tmp_path / "summary.md"
    environ = {"GITHUB_STEP_SUMMARY": str(summary)}

    assert report.main(["dbt", "--run-results", str(write(tmp_path))], environ=environ) == 0

    written = summary.read_text(encoding="utf-8")
    assert written == capsys.readouterr().out.replace("\r\n", "\n").rstrip("\n") + "\n\n"
    assert "### dbt build (target real): 5 nodes" in written
    for status in ("success", "pass", "warn", "fail", "skipped"):
        assert f"| {status} | 1 |" in written
    assert "| test assert_manifest_bookkeeping | warn | 2 | Got 2 results, configured to warn if != 0 |" in written
    assert "| test source_max_decimal_places_raw_epss_epss__5 | fail | 1 |" in written
    assert "| model stg_epss | skipped |  |" in written
    assert "stg_kev" not in written and "not_null" not in written  # only what did not pass


def test_each_warn_is_an_annotation_inside_actions_only(tmp_path, capsys):
    path = write(tmp_path)

    report.main(["dbt", "--run-results", str(path)], environ={})
    assert "::warning" not in capsys.readouterr().out

    report.main(["dbt", "--run-results", str(path)], environ={"GITHUB_ACTIONS": "true"})
    annotations = [line for line in capsys.readouterr().out.splitlines() if line.startswith("::")]
    assert annotations == [
        "::warning title=dbt warn::test assert_manifest_bookkeeping: 2 rows; Got 2 results, configured to warn if != 0"
    ]


def test_long_messages_are_cut_and_pipes_escaped(tmp_path, capsys):
    document = {
        "args": {},
        "results": [{"unique_id": "model.threat_intel_pipeline.x", "status": "error", "failures": None, "message": "a|b\n" + "c" * 400}],
    }
    report.main(["dbt", "--run-results", str(write(tmp_path, document))], environ={})
    line = next(line for line in capsys.readouterr().out.splitlines() if line.startswith("| model x"))
    assert "a\\|b c" in line and line.endswith("... |")
    assert len(line) < report.MESSAGE_CHARS + 50


def test_a_missing_or_broken_file_fails(tmp_path, capsys):
    assert report.main(["dbt", "--run-results", str(tmp_path / "missing.json")], environ={}) == 1
    assert "Result: FAILED, exit code 1 (cannot make the dbt report:" in capsys.readouterr().out
    broken = tmp_path / "broken.json"
    broken.write_text("{", encoding="utf-8")
    assert report.main(["dbt", "--run-results", str(broken)], environ={}) == 1


# --- ingest ---

DAY = date(2026, 10, 29)


def write_manifest(raw, hour, *, kev=b"kev", epss=b"epss", drop="ok", warnings=(), age=1):
    """A manifest of DAY written with the functions of session 1; a None source failed."""
    results = []
    for name, extension, content in (("kev", "json", kev), ("epss", "csv.gz", epss)):
        check = DropCheck(
            status=drop, rows=1, max_drop_percent=1,
            reference_snapshot_date=None if drop == "skipped" else DAY - timedelta(days=age),
            reference_rows=None if drop == "skipped" else 1,
            reference_age_days=None if drop == "skipped" else age,
            reason="no previous ok manifest" if drop == "skipped" else None,
        )
        results.append(SourceResult(
            source=name, status="ok" if content is not None else "failed", file=f"{name}_{DAY}.{extension}",
            url=f"https://example.invalid/{name}", action="downloaded" if content is not None else None,
            bytes=len(content) if content is not None else None, rows=1 if content is not None else None,
            sha256=sha256(content) if content is not None else None, metadata={},
            drop_check=check if content is not None else None,
            error=None if content is not None else "DownloadError: GET https://example.invalid/epss failed",
        ))
    document = manifest.build_manifest(DAY, utc(29, hour, 17, 3), results, list(warnings))
    return manifest.write_manifest(raw, document).name


def ingest(raw, name, environ=None):
    return report.main(["ingest", "--raw-dir", str(raw), "--new-manifest", name], environ=environ or {})


def test_ingest_report_without_a_new_manifest(tmp_path, capsys):
    assert ingest(tmp_path, "") == 0
    assert "### Ingest: no manifest written by this run" in capsys.readouterr().out


def test_ingest_report_lists_the_sources_and_annotates_the_warnings(tmp_path, capsys):
    name = write_manifest(tmp_path, 15, epss=None, warnings=["orphan temporary file left by an interrupted write: x"])

    assert ingest(tmp_path, name, {"GITHUB_ACTIONS": "true"}) == 0

    out = capsys.readouterr().out
    assert f"### Ingest: {name} (status failed)" in out
    assert "| kev | ok | downloaded | 1 | 3 | no drop: 1 rows vs 1 on 2026-10-28 (+0) | - |" in out
    assert "| epss | failed | - | - | - | - | DownloadError: GET https://example.invalid/epss failed |" in out
    assert "Actions rules: ok" in out
    assert "::warning title=ingest warning::orphan temporary file left by an interrupted write: x" in out
    assert "Drop references older than one day: none" in out and "ingest gap" not in out


def test_a_drop_reference_older_than_one_day_is_a_warning_in_actions(tmp_path, capsys):
    name = write_manifest(tmp_path, 15, age=5)

    assert ingest(tmp_path, name, {"GITHUB_ACTIONS": "true"}) == 0  # a gap cannot be filled: never red

    out = capsys.readouterr().out
    assert "| kev | ok | downloaded | 1 | 3 | no drop: 1 rows vs 1 on 2026-10-24 (+0) (reference 5 days old) | - |" in out
    assert "Drop references older than one day (2):" in out
    # In an annotation % is written %25 (actions/toolkit escaping).
    assert (
        "::warning title=ingest gap::kev: the 1%25 drop reference is 5 days old (2026-10-24): "
        "no readable manifest with kev ok from 2026-10-25 to 2026-10-28 (4 days)"
    ) in out
    assert "::warning title=ingest gap::epss: the 1%25 drop reference is 5 days old" in out
    assert "Actions rules: ok" in out and "::error" not in out


def test_a_drop_reference_two_days_old_names_the_one_missing_day(tmp_path, capsys):
    name = write_manifest(tmp_path, 15, age=2)

    assert ingest(tmp_path, name) == 0

    out = capsys.readouterr().out
    assert "- kev: the 1% drop reference is 2 days old (2026-10-27): no readable manifest with kev ok on 2026-10-28 (1 day)" in out
    assert "::warning" not in out  # annotations only inside Actions


def test_a_skipped_drop_check_is_an_error_in_actions(tmp_path, capsys):
    name = write_manifest(tmp_path, 15, drop="skipped")

    assert ingest(tmp_path, name, {"GITHUB_ACTIONS": "true"}) == 1

    out = capsys.readouterr().out
    assert "Actions rules: 2 errors" in out
    # In an annotation % is written %25 (actions/toolkit escaping).
    assert "::error title=ingest rule::kev: the 1%25 drop check was skipped (no previous ok manifest)" in out
    assert "Result: FAILED, exit code 1 (2 Actions rule errors)" in out


def test_two_sha256_values_of_a_source_on_the_same_day_are_an_error_in_actions(tmp_path, capsys):
    write_manifest(tmp_path, 15, epss=b"first download")
    name = write_manifest(tmp_path, 16, epss=b"second download")

    assert ingest(tmp_path, name) == 1

    out = capsys.readouterr().out
    assert "- epss: the ok manifests of 2026-10-29 record different sha256 values" in out
    assert sha256(b"first download") in out and sha256(b"second download") in out
    assert "kev:" not in out.split("Actions rules")[1]  # the same kev in both manifests
