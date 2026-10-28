"""Generate the dbt sample in tests/fixtures/dbt/ (see README.md there).

- KEV: 8 records copied verbatim from the real KEV raw of 2026-10-26 (CC0). Which
  records each daily file holds, and its count, catalogVersion and dateReleased,
  are fabricated. Two more records are entirely synthetic: CVE-2099-0101, the only
  one whose fields change, so the KEV history has changes to track, and
  CVE-2099-0102, added on the start date but first in a later catalog.
- EPSS: synthetic, with the exact structure of the real files.
- Manifests: synthetic, built with the session 1 functions; url, final_url and
  downloaded_at are null because nothing was downloaded.

Deterministic: the same input gives the same bytes (gzip with mtime=0). It never
overwrites: raw/ and invalid/ must be missing or empty.

Run from the repo root: uv run python tests/fixtures/dbt/make_sample.py [--out DIR]
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import sys
from datetime import UTC, date, datetime
from pathlib import Path

from threat_intel_pipeline.fileio import TMP_DIR_NAME, write_new_file
from threat_intel_pipeline.ingest import epss, kev
from threat_intel_pipeline.ingest.common import RawValidationError, SourceResult
from threat_intel_pipeline.manifest import build_manifest, find_reference, latest_of_day, load_manifests, write_manifest

HERE = Path(__file__).resolve().parent
REPO_ROOT = HERE.parents[2]
REAL_KEV = REPO_ROOT / "data" / "raw" / "kev_2026-10-26.json"
REAL_KEV_SHA256 = "97a6e54bc74c651ab3c55657191db9adec6c63b05ca54e4205327cfd97a8fb70"  # manifest_2026-10-26_221051Z.json

# Verbatim KEV records: label -> (cveID, its dateAdded in the real file).
KEV_RECORDS = {
    "A": ("CVE-2026-96656", "2026-10-20"),
    "B": ("CVE-2026-110447", "2026-10-23"),
    "C": ("CVE-2026-105133", "2026-10-14"),
    "D": ("CVE-2026-53362", "2026-08-27"),
    "E1": ("CVE-2021-41773", "2021-11-03"),
    "E2": ("CVE-2026-59310", "2026-08-18"),
    "E3": ("CVE-2015-3246", "2026-08-26"),
    "E4": ("CVE-2024-57728", "2026-04-24"),
}
BASE = ("E1", "E2", "E3", "E4")
# Fabricated: the real records of each KEV file. C is left out on 10-16 (dateAdded
# before its first snapshot), D is removed from 10-23 on (disappears) and E2 is
# left out on 10-20 only (disappears and returns). 10-24 repeats 10-23: a day
# without changes, followed by one with a change (10-27, in the synthetic record).
KEV_DAYS = {
    "2026-09-20": BASE + ("D",),
    "2026-10-13": BASE + ("D",),
    "2026-10-16": BASE + ("D",),
    "2026-10-20": ("E1", "E3", "E4", "D", "A", "C"),
    "2026-10-23": BASE + ("A", "B", "C"),
    "2026-10-24": BASE + ("A", "B", "C"),
    "2026-10-27": BASE + ("A", "B", "C"),
}

# Synthetic KEV record (not CISA data), in every KEV file after the real ones.
# v2 turns notes from "" into a JSON null: real KEV has no nulls, but the raw tests
# allow them, so the history must compare NULL safely. v3 changes cwes and
# knownRansomwareCampaignUse; v4 only reorders cwes, which is a change as published.
SYNTHETIC_V1 = {
    "cveID": "CVE-2099-0101",
    "vendorProject": "Synthetic Vendor",
    "product": "Synthetic Product",
    "vulnerabilityName": "Synthetic Vendor Synthetic Product Test Record",
    "dateAdded": "2026-09-01",
    "shortDescription": "Synthetic record of the dbt sample (tests/fixtures/dbt); not CISA data.",
    "requiredAction": "None: synthetic test record.",
    "dueDate": "2026-09-22",
    "knownRansomwareCampaignUse": "Unknown",
    "forensicTriage": "No",
    "notes": "",
    "cwes": [],
}
SYNTHETIC_V2 = SYNTHETIC_V1 | {"notes": None}
SYNTHETIC_V3 = SYNTHETIC_V2 | {"knownRansomwareCampaignUse": "Known", "cwes": ["CWE-79", "CWE-89"]}
SYNTHETIC_V4 = SYNTHETIC_V3 | {"cwes": ["CWE-89", "CWE-79"]}
# A second synthetic record, added on the start date (2026-09-20) but first in the
# catalog of 10-13 (question 1 counts dateAdded >= start date). Its vendorProject
# has a trailing space, so question 3 groups it with CVE-2099-0101 once trimmed.
SYNTHETIC_ADDED_ON_START = SYNTHETIC_V1 | {
    "cveID": "CVE-2099-0102",
    "vendorProject": "Synthetic Vendor ",
    "product": "Synthetic Product 2",
    "vulnerabilityName": "Synthetic Vendor Synthetic Product 2 Test Record",
    "dateAdded": "2026-09-20",
    "dueDate": "2026-10-11",
}
SYNTHETIC_KEV_DAYS = {
    "2026-09-20": (SYNTHETIC_V1,),
    "2026-10-13": (SYNTHETIC_V1, SYNTHETIC_ADDED_ON_START),
    "2026-10-16": (SYNTHETIC_V2, SYNTHETIC_ADDED_ON_START),
    "2026-10-20": (SYNTHETIC_V2, SYNTHETIC_ADDED_ON_START),
    "2026-10-23": (SYNTHETIC_V3, SYNTHETIC_ADDED_ON_START),
    "2026-10-24": (SYNTHETIC_V3, SYNTHETIC_ADDED_ON_START),
    "2026-10-27": (SYNTHETIC_V4, SYNTHETIC_ADDED_ON_START),
}

EPSS_DAYS = (
    "2026-09-20", "2026-09-23", "2026-10-13", "2026-10-14", "2026-10-20", "2026-10-23", "2026-10-24", "2026-10-27",
)
# Synthetic (epss, percentile) texts, one per EPSS day; None: absent that day.
# Keys are KEV labels or synthetic CVE ids. 10-24 repeats every epss of 10-23 (a
# day without changes) and A and C change on 10-27. B is not scored yet on 09-20
# and 09-23 (question 1: not_scored at -30 days), and C rises exactly 0.1 from 10-20
# to 10-27 (question 2: a rise equal to the threshold counts).
EPSS_VALUES = {
    "A": [("0.0121", "0.61"), ("0.0121", "0.612"), ("0.0457", "0.83"), ("0.0457", "0.831"),
          ("0.3105", "0.97"), ("0.3105", "0.971"), ("0.3105", "0.972"), ("0.4", "0.98")],
    "B": [None, None, ("0.0021", "0.33"), ("0.0021", "0.331"),
          ("0.09", "0.9"), ("0.2", "0.95"), ("0.2", "0.951"), ("0.2", "0.952")],
    "C": [("0.0008", "0.2"), ("0.0008", "0.21"), ("0.0011", "0.25"), ("0.003", "0.4"),
          ("0.003", "0.41"), ("0.003", "0.42"), ("0.003", "0.42"), ("0.103", "0.8")],
    "D": [("0.0091", "0.74")] * 8,
    "E1": [("0.92", "0.99")] * 8,
    "E2": [("0.71", "0.97")] * 8,
    "E3": [("0.0042", "0.6")] * 8,
    "E4": [("0.38", "0.95")] * 8,
    "CVE-2099-0001": [("0.5", "1.0")] * 8,
    # The same epss written two ways (CLAUDE.md §5): the SCD2 must see one value.
    "CVE-2099-0002": [("3e-05", "1e-05"), ("0.00003", "1e-05")] * 4,
    "CVE-2099-0003": [("0.00012", "0.0")] * 4 + [None] * 4,
    # 0004 appears on the first day 0005 is absent and 0005 returns on the day 0003
    # leaves: every day has 12 rows, so no manifest fails the 1% drop check.
    "CVE-2099-0004": [None] * 2 + [("0.04", "0.5")] * 6,
    "CVE-2099-0005": [("0.0007", "0.15")] * 2 + [None] * 2 + [("0.0007", "0.15")] * 4,
    # The second synthetic KEV record, scored every day.
    "CVE-2099-0102": [("0.0015", "0.3")] * 8,
}
# invalid/: the files of this day, with two EPSS values of more than 5 decimals.
INVALID_DAY = "2026-10-20"
INVALID_VALUES = {"CVE-2099-0001": ("0.123456", "1.0"), "CVE-2099-0002": ("3e-05", "1.5e-06")}

# Synthetic runs: (snapshot_date, start time UTC, sources forced to fail). A
# source without its file that day is failed too. Two days have a same-day retry,
# so the latest manifest of the day is the one to use: EPSS failed in the first
# attempt of 2026-10-20, and KEV in the first attempt of 2026-10-23.
RUNS = [
    ("2026-09-20", "151705", ()),
    ("2026-09-23", "151705", ()),
    ("2026-10-13", "151705", ()),
    ("2026-10-14", "151705", ()),
    ("2026-10-16", "151705", ()),
    ("2026-10-20", "151705", ("epss",)),
    ("2026-10-20", "163005", ()),
    ("2026-10-23", "151705", ("kev",)),
    ("2026-10-23", "163005", ()),
    ("2026-10-24", "151705", ()),
    ("2026-10-27", "151705", ()),
]
INVALID_RUNS = [(INVALID_DAY, "151705", ())]
WARNING = "synthetic test manifest (tests/fixtures/dbt): not a real download"
EXPECTED_ROWS = {"kev": 55, "epss": 102}
SOURCES = {"kev": kev, "epss": epss}


class SampleError(Exception):
    """The sample cannot be generated; the message says why."""


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate the dbt sample (see tests/fixtures/dbt/README.md).")
    parser.add_argument("--out", type=Path, default=HERE, help="folder for raw/ and invalid/ (default: %(default)s)")
    args = parser.parse_args(argv)
    try:
        records, title, real_order = load_real_kev()
        raw_dir, invalid_dir = args.out / "raw", args.out / "invalid"
        for folder in (raw_dir, invalid_dir):
            prepare_empty(folder)

        files = {f"kev_{day}.json": kev_file(records, title, real_order, day, labels) for day, labels in KEV_DAYS.items()}
        files |= {f"epss_{day}.csv.gz": epss_file(day, {}) for day in EPSS_DAYS}
        invalid = {
            f"kev_{INVALID_DAY}.json": files[f"kev_{INVALID_DAY}.json"],
            f"epss_{INVALID_DAY}.csv.gz": epss_file(INVALID_DAY, INVALID_VALUES),
        }
        for folder, folder_files, runs in ((raw_dir, files, RUNS), (invalid_dir, invalid, INVALID_RUNS)):
            for name, content in folder_files.items():
                write_new_file(folder / name, content)
            write_manifests(folder, folder_files, runs)
            (folder / TMP_DIR_NAME).rmdir()  # fails if a temporary file was left behind

        check(raw_dir, EXPECTED_ROWS)
        check(invalid_dir, None)
    except (SampleError, RawValidationError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    return 0


def load_real_kev() -> tuple[dict[str, dict], str, dict[str, int]]:
    """The selected records of the real KEV raw, its title and the position of each CVE in it."""
    if not REAL_KEV.is_file():
        raise SampleError(
            f"{REAL_KEV.relative_to(REPO_ROOT).as_posix()} not found. Regenerating the sample needs the real "
            "KEV raw of 2026-10-26 (CLAUDE.md section 4); the generated sample is already in the repo."
        )
    content = REAL_KEV.read_bytes()
    digest = hashlib.sha256(content).hexdigest()
    if digest != REAL_KEV_SHA256:
        raise SampleError(
            f"{REAL_KEV.name} has sha256 {digest}, expected {REAL_KEV_SHA256} "
            "(manifest_2026-10-26_221051Z.json); refusing to build the sample from a different file."
        )
    catalog = json.loads(content)
    if serialize_kev(catalog) != content:
        raise SampleError("serializing the real catalog does not reproduce its bytes: the KEV format changed")
    real_order = {record["cveID"]: position for position, record in enumerate(catalog["vulnerabilities"])}
    by_cve = {record["cveID"]: record for record in catalog["vulnerabilities"]}
    records = {}
    for label, (cve, date_added) in KEV_RECORDS.items():
        record = by_cve.get(cve)
        if record is None or record["dateAdded"] != date_added:
            raise SampleError(f"{cve} is missing from the real KEV or its dateAdded is not {date_added}")
        records[label] = record
    return records, catalog["title"], real_order


def serialize_kev(catalog: dict) -> bytes:
    """The real KEV format: 4-space indent, ASCII with \\uXXXX escapes, '/' as '\\/', no final newline."""
    return json.dumps(catalog, indent=4, ensure_ascii=True).replace("/", "\\/").encode("ascii")


def prepare_empty(folder: Path) -> None:
    if folder.exists() and any(folder.iterdir()):
        raise SampleError(f"{folder} is not empty: delete it first to regenerate (this script never overwrites)")
    folder.mkdir(parents=True, exist_ok=True)


def kev_file(records: dict[str, dict], title: str, real_order: dict[str, int], day: str, labels: tuple[str, ...]) -> bytes:
    """A KEV file of the sample: verbatim records in the order of the real file, then the synthetic ones."""
    selected = sorted((records[label] for label in labels), key=lambda record: real_order[record["cveID"]])
    selected.extend(SYNTHETIC_KEV_DAYS[day])
    for record in selected:
        if record["dateAdded"] > day:
            raise SampleError(f"{record['cveID']} cannot be in the catalog of {day}, before its dateAdded")
    catalog = {
        "title": title,
        "catalogVersion": day.replace("-", "."),
        "dateReleased": f"{day}T00:00:00.0000Z",
        "count": len(selected),
        "vulnerabilities": selected,
    }
    return serialize_kev(catalog)


def epss_file(day: str, overrides: dict[str, tuple[str, str]]) -> bytes:
    """A synthetic EPSS file: the '#' line, the header and one row per CVE present, sorted by CVE."""
    index = EPSS_DAYS.index(day)
    rows = {}
    for key, values in EPSS_VALUES.items():
        cve = KEV_RECORDS[key][0] if key in KEV_RECORDS else key
        if values[index] is not None:
            rows[cve] = overrides.get(cve, values[index])
    lines = [f"#model_version:v2099.01.01,score_date:{day}T12:03:22Z", "cve,epss,percentile"]
    lines += [f"{cve},{value},{percentile}" for cve, (value, percentile) in sorted(rows.items())]
    return gzip.compress(("\n".join(lines) + "\n").encode("ascii"), compresslevel=9, mtime=0)


def write_manifests(folder: Path, files: dict[str, bytes], runs: list[tuple[str, str, tuple[str, ...]]]) -> None:
    """One synthetic manifest per run, built and written with the session 1 functions."""
    ok_before: set[tuple[str, str]] = set()  # (day, source) ok in an earlier run of the same day
    for day, time, forced_failures in runs:
        snapshot = date.fromisoformat(day)
        started_at = datetime.strptime(f"{day}T{time}", "%Y-%m-%dT%H%M%S").replace(tzinfo=UTC)
        index = load_manifests(folder, snapshot, list(SOURCES))
        results = []
        for source, module in SOURCES.items():
            name = module.SOURCE.filename(snapshot)
            content = files.get(name)
            base = {"source": source, "file": name, "url": None}
            if content is None or source in forced_failures:
                error = "synthetic sample: no file on this day" if content is None else "synthetic sample: failed attempt"
                results.append(SourceResult(status="failed", metadata=dict.fromkeys(module.SOURCE.metadata_keys), error=error, **base))
                continue
            # The 1% drop check against the latest ok manifest of an earlier day, as in session 1.
            validated = module.validate(content, snapshot, find_reference(index, source, snapshot), min_rows=1)
            results.append(SourceResult(
                status="ok",
                action="already_present" if (day, source) in ok_before else "downloaded",
                bytes=len(content),
                rows=validated.rows,
                sha256=hashlib.sha256(content).hexdigest(),
                metadata=validated.metadata,
                drop_check=validated.drop_check,
                **base,
            ))
        write_manifest(folder, build_manifest(snapshot, started_at, results, [WARNING]))
        ok_before |= {(day, result.source) for result in results if result.status == "ok"}


def check(folder: Path, expected_rows: dict[str, int] | None) -> None:
    """Final checks: manifests readable, every file matching the latest manifest of its day."""
    index = load_manifests(folder, datetime.now(UTC).date(), list(SOURCES))
    if index.unreadable:
        raise SampleError(f"unreadable manifests in {folder}: {index.unreadable}")
    totals = dict.fromkeys(SOURCES, 0)
    print(f"\n{folder}:")
    for path in sorted(p for p in folder.iterdir() if not p.name.startswith("manifest_")):
        source, rest = path.name.split("_", 1)
        snapshot = date.fromisoformat(rest[:10])
        content = path.read_bytes()
        digest = hashlib.sha256(content).hexdigest()
        rows = SOURCES[source].validate(content, snapshot, None, min_rows=1).rows
        latest = latest_of_day(index, snapshot)
        entry = latest.data["sources"][source] if latest is not None else None
        if entry is None or entry["status"] != "ok" or (entry["bytes"], entry["sha256"], entry["rows"]) != (len(content), digest, rows):
            raise SampleError(f"{path.name} does not match the latest manifest of its day")
        totals[source] += rows
        print(f"  {path.name:30} {len(content):>6,} bytes {rows:>3} rows  sha256 {digest}")
    for manifest in index.readable:
        states = ", ".join(f"{source}={entry['status']}" for source, entry in manifest.data["sources"].items())
        print(f"  {manifest.name:30} {states}")
    if expected_rows is not None and totals != expected_rows:
        raise SampleError(f"rows per source are {totals}, expected {expected_rows}")
    print(f"  rows: {totals}")


if __name__ == "__main__":
    sys.exit(main())
