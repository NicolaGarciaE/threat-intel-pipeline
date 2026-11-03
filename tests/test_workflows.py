"""Security and consistency rules of the GitHub Actions workflows (session 4). No network.

Read with PyYAML (a dependency of dbt) and, for the pinned actions, as text,
because YAML drops the comments that hold their versions. TIP_WORKFLOWS_DIR
points the tests to another folder, to check that each rule fails on a broken copy.
"""

import os
import re
from pathlib import Path

import pytest
import yaml

WORKFLOWS = Path(os.environ.get("TIP_WORKFLOWS_DIR", Path(__file__).resolve().parents[1] / ".github" / "workflows"))
FILES = ("ci.yml", "daily.yml")
PINNED_USES = re.compile(r"^\s*(- )?uses: [A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}  # v\d+(\.\d+)*$")
SIMULATE_CHECK = (  # the only lines of the target check that only the ingest job has
    'if [ "$TARGET" = real ] && [ "$SIMULATE_EPSS_FAILURE" = true ]; then\n'
    '  echo "::error::simulate_epss_failure is only for test targets"; exit 1\n'
    "fi\n"
)


def load(name: str) -> dict:
    return yaml.safe_load((WORKFLOWS / name).read_text(encoding="utf-8"))


def triggers(workflow: dict) -> dict:
    return workflow[True]  # PyYAML reads the key "on" as the boolean True


def steps(workflow: dict):
    for job_name, job in workflow["jobs"].items():
        for step in job["steps"]:
            yield job_name, step


def test_the_target_check_is_the_first_step_and_the_same_in_every_daily_job():
    jobs = load("daily.yml")["jobs"]
    assert set(jobs) == {"ingest", "publish", "build"}
    checks = {}
    for name, job in jobs.items():
        first = job["steps"][0]
        assert first["name"] == "Check the target", f"{name}: the first step is {first['name']!r}"
        checks[name] = first["run"]
    assert checks["ingest"].count(SIMULATE_CHECK) == 1, "ingest must also refuse simulate_epss_failure with target real"
    without_simulate = checks["ingest"].replace(SIMULATE_CHECK, "")
    assert checks["publish"] == without_simulate, "the target check of publish differs from the one of ingest"
    assert checks["build"] == without_simulate, "the target check of build differs from the one of ingest"


@pytest.mark.parametrize("name", FILES)
def test_every_action_is_pinned_to_a_commit_sha_with_its_version(name):
    text = (WORKFLOWS / name).read_text(encoding="utf-8")
    lines = [line for line in text.splitlines() if re.match(r"^\s*(- )?uses:", line)]
    assert lines, f"{name} uses no action"
    for line in lines:
        assert PINNED_USES.fullmatch(line), f"{name}: not pinned to a full commit SHA with '# vX.Y.Z': {line.strip()}"
    assert len(lines) == sum(1 for _, step in steps(load(name)) if "uses" in step)


@pytest.mark.parametrize("name", FILES)
def test_no_run_script_interpolates_an_expression(name):
    for job_name, step in steps(load(name)):
        assert "${{" not in step.get("run", ""), f"{name}, job {job_name}, step {step['name']!r}: use env, not ${{{{ }}}}"


@pytest.mark.parametrize("name", FILES)
def test_no_pull_request_target_and_no_schedule_yet(name):
    events = set(triggers(load(name)))
    assert "pull_request_target" not in events, f"{name}: pull_request_target"
    assert "schedule" not in events, f"{name}: schedule comes in a later pull request, after the first real run"


def test_publish_and_build_restore_the_exact_mirror_key_saved_by_the_ingest():
    jobs = load("daily.yml")["jobs"]
    ingest = {step.get("id"): step for step in jobs["ingest"]["steps"]}
    save, saved = ingest["save"], ingest["saved"]
    assert save["uses"].startswith("actions/cache/save@") and save["with"]["path"] == "data/raw"
    assert "steps.save.outcome == 'success'" in saved["if"], "raw_key only after the save step succeeded"
    assert saved["env"]["RAW_KEY"] == save["with"]["key"], "raw_key must be the key that was saved"
    assert jobs["ingest"]["outputs"] == {"raw_key": "${{ steps.saved.outputs.raw_key }}"}
    for name in ("publish", "build"):
        restores = [
            step for step in jobs[name]["steps"]
            if step.get("uses", "").startswith("actions/cache/restore@") and step["with"]["path"] == "data/raw"
        ]
        exact = [step for step in restores if step["with"].get("fail-on-cache-miss")]
        latest = [step for step in restores if not step["with"].get("fail-on-cache-miss")]
        assert len(exact) == 1 and len(latest) == 1, f"{name}: one exact and one latest restore of data/raw"
        assert exact[0]["if"] == "needs.ingest.outputs.raw_key != ''", f"{name}: exact restore only with a raw_key"
        assert exact[0]["with"]["key"] == "${{ needs.ingest.outputs.raw_key }}", f"{name}: not the saved key"
        assert latest[0]["if"] == "needs.ingest.outputs.raw_key == ''", f"{name}: latest restore only without one"
        assert latest[0]["with"]["restore-keys"] == "raw-${{ env.TARGET }}-", f"{name}: latest of its own target"


def test_only_the_publish_job_can_write():
    for name in FILES:
        workflow = load(name)
        assert workflow["permissions"] == {"contents": "read"}, f"{name}: default permissions"
        for job_name, job in workflow["jobs"].items():
            expected = {"contents": "write"} if (name, job_name) == ("daily.yml", "publish") else None
            assert job.get("permissions") == expected, f"{name}, job {job_name}: permissions {job.get('permissions')}"
