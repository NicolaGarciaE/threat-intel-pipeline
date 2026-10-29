"""Job summaries of a run, from synthetic dbt results. No network."""

import json

from threat_intel_pipeline import report

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
    assert "Result: FAILED, exit code 1 (cannot read" in capsys.readouterr().out
    broken = tmp_path / "broken.json"
    broken.write_text("{", encoding="utf-8")
    assert report.main(["dbt", "--run-results", str(broken)], environ={}) == 1
