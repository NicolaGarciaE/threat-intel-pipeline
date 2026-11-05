"""The invalid dbt sample must fail exactly as expected (CLAUDE.md §8, invalid/).

dbt build --target fixtures_invalid reads tests/fixtures/dbt/invalid/, whose EPSS
file of 2026-10-20 has an epss with 6 decimals and a percentile with 7. The build
must end with exit code 1 and exactly 100 nodes:
- 2 failed tests: max_decimal_places of raw.epss on epss and on percentile, with
  1 failing row each;
- 84 skipped: stg_epss, its tests, the tests that compare staging with the
  manifests, and every mart with its tests;
- 14 passed (models that succeed and tests that pass), and nothing else.

The build uses a temporary database (a copy of profiles.yml where only the
database of the fixtures_invalid target changes) and its own --target-path and
--log-path, so it touches nothing in data/warehouse/ or dbt/target/. Exit code 0
only if the result is exactly the expected one.

Run from the repo root: uv run python tests/dbt_invalid_check.py
"""

from __future__ import annotations

import collections
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
TARGET = "fixtures_invalid"
PROFILE_DATABASE = "path: data/warehouse/fixtures_invalid.duckdb"  # the only line of profiles.yml that changes
EXPECTED_EXIT_CODE = 1
EXPECTED_STATUSES = {"pass": 14, "fail": 2, "skipped": 84}  # "pass" counts models that succeed and tests that pass
EXPECTED_FAILURES = {  # unique_id without its hash -> failing rows
    "test.threat_intel_pipeline.source_max_decimal_places_raw_epss_epss__5": 1,
    "test.threat_intel_pipeline.source_max_decimal_places_raw_epss_percentile__5": 1,
}


def main() -> int:
    dbt = shutil.which("dbt")
    if dbt is None:
        print("error: dbt not found; run it with: uv run python tests/dbt_invalid_check.py", file=sys.stderr)
        return 1
    profile = (REPO_ROOT / "dbt" / "profiles.yml").read_text(encoding="utf-8")
    if profile.count(PROFILE_DATABASE) != 1:
        print(f"error: dbt/profiles.yml must contain '{PROFILE_DATABASE}' exactly once", file=sys.stderr)
        return 1
    with tempfile.TemporaryDirectory(prefix="tip-invalid-") as tmp:
        home = Path(tmp)
        (home / "profiles").mkdir()
        database = (home / "invalid.duckdb").as_posix()
        (home / "profiles" / "profiles.yml").write_text(
            profile.replace(PROFILE_DATABASE, f"path: '{database}'"), encoding="utf-8")
        command = [
            dbt, "build", "--project-dir", str(REPO_ROOT / "dbt"), "--profiles-dir", str(home / "profiles"),
            "--target", TARGET, "--target-path", str(home / "target"), "--log-path", str(home / "logs"),
        ]
        result = subprocess.run(  # exit code 1 is the expected result, checked below
            command, cwd=REPO_ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace",
            env={**os.environ, "DBT_USE_COLORS": "false"}, check=False,
        )
        output = result.stdout + result.stderr
        run_results = home / "target" / "run_results.json"
        if not run_results.is_file():
            print("\n".join(output.splitlines()[-30:]))
            print(f"\nResult: FAILED: dbt wrote no run_results.json (exit code {result.returncode})")
            return 1
        results = json.loads(run_results.read_text(encoding="utf-8"))["results"]

    statuses = collections.Counter("pass" if r["status"] == "success" else r["status"] for r in results)
    failed = {r["unique_id"].rsplit(".", 1)[0]: r["failures"] for r in results if r["status"] == "fail"}
    done = next((line.split("Done. ", 1)[1] for line in reversed(output.splitlines()) if "Done. " in line), "no summary")
    print(f"dbt build --target {TARGET}: exit code {result.returncode}; {done}")
    print(f"statuses: {dict(sorted(statuses.items()))}")
    for unique_id, failures in sorted(failed.items()):
        print(f"  fail: {unique_id.split('.')[-1]} ({failures} failing rows)")

    problems = []
    if result.returncode != EXPECTED_EXIT_CODE:
        problems.append(f"exit code {result.returncode}, expected {EXPECTED_EXIT_CODE}")
    if dict(statuses) != EXPECTED_STATUSES:
        problems.append(f"statuses {dict(sorted(statuses.items()))}, expected {dict(sorted(EXPECTED_STATUSES.items()))}")
    if failed != EXPECTED_FAILURES:
        problems.append(f"failed tests {failed}, expected {EXPECTED_FAILURES}")
    if problems:
        print("\n".join(["", "Result: FAILED", *(f"  - {problem}" for problem in problems)]))
        return 1
    print("\nResult: ok, the invalid sample fails exactly as expected")
    return 0


if __name__ == "__main__":
    sys.exit(main())
