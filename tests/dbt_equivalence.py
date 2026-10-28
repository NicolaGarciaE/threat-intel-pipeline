"""Equivalence test of the incremental marts (CLAUDE.md §6, "Equivalencia").

The files of the dbt sample (tests/fixtures/dbt/raw) arrive into a temporary raw
folder as its manifests say, and dbt builds the marts incrementally. Every table
of the marts schema must then be identical (EXCEPT ALL both ways) to a reference
database built at once with --full-refresh. Scenarios:

- A: one build per attempt (one per manifest, with the same-day retries), then
  one more with nothing new;
- B: attempt by attempt up to CATCH_UP_AFTER, then every later attempt in a
  single build, as on the day after a day stopped by the guard;
- C: every attempt in one build, then every marts table emptied and one more
  build (the tables exist but are empty);
- late raw file: every attempt but those of LATE_DAY in one build. Adding them
  must stop the build with the guard's error and leave the marts unchanged, and
  --full-refresh must then match the reference.

No network. Each scenario has its own raw folder, database and profile: a copy
of profiles.yml where only the database of the fixtures target changes, so the
target keeps its name, settings and vars; the raw folder is passed with --vars.
Every dbt run has its own --target-path and --log-path. Everything lives in a
temporary folder, deleted at the end unless --keep-temp (to inspect the
databases after a failure). Exit code 0 only if every scenario behaved as
expected and no table differs.

Run from the repo root: uv run python tests/dbt_equivalence.py [--project-dir DIR] [--keep-temp]
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import duckdb

from threat_intel_pipeline.manifest import NAME_PATTERN

REPO_ROOT = Path(__file__).resolve().parents[1]
SAMPLE = REPO_ROOT / "tests" / "fixtures" / "dbt" / "raw"
TARGET = "fixtures"
PROFILE_DATABASE = "path: data/warehouse/fixtures.duckdb"  # the only line of profiles.yml that changes
MARTS_SCHEMA = "main_marts"
CATCH_UP_AFTER = "2026-10-14"  # scenario B: one attempt at a time up to this day, then the rest at once
LATE_DAY = "2026-09-23"  # late raw file scenario: EPSS only, before later days of EPSS
GUARD_MESSAGE = "raw files of days already passed were never loaded"

Attempt = tuple[str, list[str]]  # manifest name, raw files it brought


class ScenarioError(Exception):
    """A scenario did not behave as expected; the message says how."""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Equivalence test of the incremental marts on the dbt sample.")
    parser.add_argument("--project-dir", type=Path, default=REPO_ROOT / "dbt", help="dbt project (default: %(default)s)")
    parser.add_argument("--keep-temp", action="store_true", help="keep the temporary folder and print its path")
    args = parser.parse_args(argv)
    dbt = shutil.which("dbt")
    if dbt is None:
        print("error: dbt not found; run it with: uv run python tests/dbt_equivalence.py", file=sys.stderr)
        return 1

    started = time.monotonic()
    attempts = load_attempts(SAMPLE)
    print(f"dbt equivalence test: {len(attempts)} attempts of {SAMPLE.relative_to(REPO_ROOT).as_posix()}, "
          f"project {args.project_dir}")
    problems: list[str] = []
    comparisons: dict[str, list[tuple[str, int, int, int, int]]] = {}
    with tempfile.TemporaryDirectory(prefix="tip-equivalence-", delete=not args.keep_temp) as tmp:
        harness = Harness(Path(tmp), args.project_dir.resolve(), dbt)
        try:
            reference = harness.scenario("reference")
            reference.arrive(attempts)
            harness.build(reference, "every attempt at once, --full-refresh", full_refresh=True)
        except ScenarioError as exc:
            problems.append(f"reference: {exc}")
            print(f"  reference: FAILED: {exc}")
        else:
            for name, run in (("A", scenario_a), ("B", scenario_b), ("C", scenario_c), ("late", scenario_late)):
                try:
                    database = run(harness, attempts)
                    comparisons[name] = compare(reference.database, database)
                except ScenarioError as exc:
                    problems.append(f"{name}: {exc}")
                    print(f"  {name}: FAILED: {exc}")
    if args.keep_temp:
        print(f"\nTemporary folder kept: {tmp}")

    print("\nTables of the marts schema against the reference (EXCEPT ALL both ways):")
    print(f"  {'scenario':8} {'table':24} {'reference':>9} {'scenario':>9} {'missing':>8} {'extra':>8}")
    for name, rows in comparisons.items():
        for table, reference_rows, scenario_rows, missing, extra in rows:
            print(f"  {name:8} {table:24} {reference_rows:>9} {scenario_rows:>9} {missing:>8} {extra:>8}")
            if missing or extra:
                problems.append(f"{name}: {table} differs ({missing} rows missing, {extra} extra)")
    seconds = time.monotonic() - started
    if problems:
        print(f"\nResult: FAILED in {seconds:.0f} s")
        for problem in problems:
            print(f"  - {problem.splitlines()[0]}")
        return 1
    tables = len(next(iter(comparisons.values())))
    print(f"\nResult: ok, 0 differences in {tables} tables x {len(comparisons)} scenarios ({seconds:.0f} s)")
    return 0


def load_attempts(sample: Path) -> list[Attempt]:
    """The manifests of the sample in chronological order, each with the raw files
    it brought: its sources that are ok and were downloaded in that attempt."""
    attempts = []
    for path in sorted(p for p in sample.iterdir() if NAME_PATTERN.fullmatch(p.name)):
        manifest = json.loads(path.read_text(encoding="utf-8"))
        files = [entry["file"] for entry in manifest["sources"].values()
                 if entry["status"] == "ok" and entry["action"] == "downloaded"]
        attempts.append((path.name, sorted(files)))
    raw_files = {p.name for p in sample.iterdir() if not NAME_PATTERN.fullmatch(p.name)}
    brought = [name for _, files in attempts for name in files]
    if sorted(brought) != sorted(raw_files):
        raise SystemExit(f"error: the manifests of {sample} do not bring every raw file exactly once")
    return attempts


def day_of(attempt: Attempt) -> str:
    return NAME_PATTERN.fullmatch(attempt[0])["date"]


class Scenario:
    """The raw folder, database and profile of one scenario."""

    def __init__(self, home: Path, raw: Path, profile: str):
        self.name = home.name
        self.home = home
        self.raw = raw
        self.database = home / "marts.duckdb"
        self.profiles = home / "profiles"
        self.profiles.mkdir(parents=True)
        self.raw.mkdir(parents=True, exist_ok=True)
        (self.profiles / "profiles.yml").write_text(
            profile.replace(PROFILE_DATABASE, f"path: '{self.database.as_posix()}'"), encoding="utf-8")

    def arrive(self, attempts: list[Attempt]) -> None:
        """Copy the manifests and raw files of these attempts, never overwriting."""
        for manifest, files in attempts:
            for name in [*files, manifest]:
                target = self.raw / name
                if target.exists():
                    raise ScenarioError(f"{target} already exists")
                shutil.copy2(SAMPLE / name, target)


class Harness:
    """Runs dbt for the scenarios, each run with its own target and log paths."""

    def __init__(self, root: Path, project_dir: Path, dbt: str):
        self.root = root
        self.project_dir = project_dir
        self.dbt = dbt
        self.profile = (project_dir / "profiles.yml").read_text(encoding="utf-8")
        if self.profile.count(PROFILE_DATABASE) != 1:
            raise SystemExit(f"error: {project_dir / 'profiles.yml'} must contain '{PROFILE_DATABASE}' exactly once")
        self.runs = 0

    def scenario(self, name: str, raw: Path | None = None) -> Scenario:
        home = self.root / name
        return Scenario(home, raw if raw is not None else home / "raw", self.profile)

    def build(self, scenario: Scenario, label: str, *, full_refresh: bool = False, expect_error: bool = False) -> str:
        """dbt build on the scenario; raises ScenarioError unless it ends as expected."""
        self.runs += 1
        run = scenario.home / f"run-{self.runs:02d}"
        command = [
            self.dbt, "build",
            "--project-dir", str(self.project_dir),
            "--profiles-dir", str(scenario.profiles),
            "--target", TARGET,
            "--vars", json.dumps({f"raw_dir_{TARGET}": scenario.raw.as_posix()}),
            "--target-path", str(run / "target"),
            "--log-path", str(run / "logs"),
        ]
        if full_refresh:
            command.append("--full-refresh")
        started = time.monotonic()
        result = subprocess.run(
            command, cwd=REPO_ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace",
            env={**os.environ, "DBT_USE_COLORS": "false"},
        )
        output = result.stdout + result.stderr
        done = next((line.split("Done. ", 1)[1] for line in reversed(output.splitlines()) if "Done. " in line), "")
        print(f"  {scenario.name}: {label}: exit {result.returncode}, {done or 'no summary'} "
              f"({time.monotonic() - started:.1f} s)")
        if (result.returncode != 0) != expect_error:
            tail = "\n".join(output.splitlines()[-20:])
            expected = "an error" if expect_error else "exit 0"
            raise ScenarioError(f"'{label}' ended with exit {result.returncode}, expected {expected}\n{tail}")
        return output


def scenario_a(harness: Harness, attempts: list[Attempt]) -> Path:
    """One build per attempt, then one with nothing new."""
    scenario = harness.scenario("A")
    for attempt in attempts:
        scenario.arrive([attempt])
        harness.build(scenario, f"{attempt[0]} brings {', '.join(attempt[1]) or 'nothing'}")
    harness.build(scenario, "nothing new")
    return scenario.database


def scenario_b(harness: Harness, attempts: list[Attempt]) -> Path:
    """Attempt by attempt up to CATCH_UP_AFTER, then the rest in one build."""
    scenario = harness.scenario("B")
    first = [attempt for attempt in attempts if day_of(attempt) <= CATCH_UP_AFTER]
    rest = [attempt for attempt in attempts if day_of(attempt) > CATCH_UP_AFTER]
    days = sorted({day_of(attempt) for attempt in rest})
    if len(days) < 2:
        raise ScenarioError(f"catching up needs 2 or more days after {CATCH_UP_AFTER}, the sample has {days}")
    for attempt in first:
        scenario.arrive([attempt])
        harness.build(scenario, f"{attempt[0]} brings {', '.join(attempt[1]) or 'nothing'}")
    scenario.arrive(rest)
    harness.build(scenario, f"{len(rest)} attempts at once, {len(days)} days ({days[0]} to {days[-1]})")
    return scenario.database


def scenario_c(harness: Harness, attempts: list[Attempt]) -> Path:
    """Every attempt in one build, then every marts table emptied and one more
    build: the tables exist, so the run is incremental, but without a watermark."""
    scenario = harness.scenario("C")
    scenario.arrive(attempts)
    harness.build(scenario, "every attempt at once")
    with duckdb.connect(str(scenario.database)) as con:
        tables = [row[0] for row in con.execute(
            "select table_name from duckdb_tables() where schema_name = ? order by 1", [MARTS_SCHEMA]).fetchall()]
        for table in tables:
            con.execute(f'delete from {MARTS_SCHEMA}."{table}"')
    harness.build(scenario, f"{len(tables)} tables emptied")
    return scenario.database


def scenario_late(harness: Harness, attempts: list[Attempt]) -> Path:
    """A raw file of a day before the last one loaded arrives late: the build must
    stop with the guard's error without changing the marts; --full-refresh then loads it."""
    scenario = harness.scenario("late")
    late = [attempt for attempt in attempts if day_of(attempt) == LATE_DAY]
    files = [name for _, names in late for name in names]
    if not files or LATE_DAY >= max(day_of(attempt) for attempt in attempts):
        raise ScenarioError(f"{LATE_DAY} must bring raw files and come before the last day of the sample")
    scenario.arrive([attempt for attempt in attempts if day_of(attempt) != LATE_DAY])
    harness.build(scenario, f"every attempt but those of {LATE_DAY}")
    before = scenario.home / "before_late.duckdb"
    copy_database(scenario.database, before)
    scenario.arrive(late)
    output = harness.build(scenario, f"{', '.join(files)} arrives late", expect_error=True)
    message = next((line.strip() for line in output.splitlines() if GUARD_MESSAGE in line), "")
    if LATE_DAY not in message:
        raise ScenarioError(f"the late build did not fail with the guard's error ('{GUARD_MESSAGE}' ... {LATE_DAY})")
    changed = [row for row in compare(before, scenario.database) if row[3] or row[4]]
    if changed:
        raise ScenarioError(f"the failed build changed the marts: {[row[0] for row in changed]}")
    print(f"  {scenario.name}: the guard stopped the build and the marts did not change: {message}")
    harness.build(scenario, "--full-refresh", full_refresh=True)
    return scenario.database


def copy_database(source: Path, target: Path) -> None:
    """Copy a closed DuckDB file; a leftover write-ahead log means it was not closed cleanly."""
    if not source.is_file():
        raise ScenarioError(f"{source} does not exist")
    if source.with_name(source.name + ".wal").exists():
        raise ScenarioError(f"{source} has a write-ahead log: it was not closed cleanly")
    shutil.copy2(source, target)


def compare(reference: Path, candidate: Path) -> list[tuple[str, int, int, int, int]]:
    """Every table of the marts schema in both databases, found automatically: the
    tables and their columns must be the same, then EXCEPT ALL both ways per table.
    Returns (table, reference rows, candidate rows, missing rows, extra rows)."""
    with duckdb.connect() as con:
        con.execute(f"attach '{reference.as_posix()}' as reference_db (read_only)")
        con.execute(f"attach '{candidate.as_posix()}' as candidate_db (read_only)")
        columns = {
            database: dict(con.execute(
                "select table_name, list(column_name || ' ' || data_type order by column_index) "
                "from duckdb_columns() where database_name = ? and schema_name = ? group by table_name",
                [database, MARTS_SCHEMA]).fetchall())
            for database in ("reference_db", "candidate_db")
        }
        reference_tables, candidate_tables = columns["reference_db"], columns["candidate_db"]
        if not reference_tables:
            raise ScenarioError(f"the reference has no tables in {MARTS_SCHEMA}")
        if reference_tables.keys() != candidate_tables.keys():
            only_reference = sorted(reference_tables.keys() - candidate_tables.keys())
            only_candidate = sorted(candidate_tables.keys() - reference_tables.keys())
            raise ScenarioError(f"the tables differ: only in the reference {only_reference}, only here {only_candidate}")
        rows = []
        for table in sorted(reference_tables):
            if reference_tables[table] != candidate_tables[table]:
                raise ScenarioError(f"{table}: the columns differ")
            counts = [con.execute(f'select count(*) from {db}.{MARTS_SCHEMA}."{table}"').fetchone()[0]
                      for db in ("reference_db", "candidate_db")]
            missing, extra = (
                con.execute(f'select count(*) from (select * from {a}.{MARTS_SCHEMA}."{table}" '
                            f'except all select * from {b}.{MARTS_SCHEMA}."{table}")').fetchone()[0]
                for a, b in (("reference_db", "candidate_db"), ("candidate_db", "reference_db"))
            )
            rows.append((table, counts[0], counts[1], missing, extra))
    return rows


if __name__ == "__main__":
    sys.exit(main())
