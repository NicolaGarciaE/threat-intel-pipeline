"""Helpers shared by the tests. All data here is synthetic (see fixtures/README.md).

Tests only read ``tests/fixtures/`` and write to pytest's temporary folders.
"""

from __future__ import annotations

import copy
import gzip
import json
from datetime import UTC, date, datetime
from functools import lru_cache
from pathlib import Path
from typing import Any

from threat_intel_pipeline.ingest.download import FetchResult

FIXTURES = Path(__file__).parent / "fixtures" / "raw"
SNAPSHOT = date(2026, 10, 26)  # the score_date of epss_valid.csv
EPSS_ROWS = 360_000  # above the 350,000 minimum


class NetworkAccessBlocked(RuntimeError):
    """Raised by any attempt to open a network connection during the tests."""


def fixture_bytes(name: str) -> bytes:
    return (FIXTURES / name).read_bytes()


def fixture_text(name: str) -> str:
    return (FIXTURES / name).read_text(encoding="utf-8")


def gz(data: str | bytes, level: int = 1) -> bytes:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return gzip.compress(data, compresslevel=level, mtime=0)


def utc(day: int, hour: int = 15, minute: int = 17, second: int = 3) -> datetime:
    return datetime(2026, 10, day, hour, minute, second, tzinfo=UTC)


@lru_cache(maxsize=8)
def epss_text(rows: int, day: int = 26) -> str:
    """Synthetic EPSS file with ``rows`` data rows and score_date on 2026-10-<day>."""
    lines = [f"#model_version:v2099.01.01,score_date:2026-10-{day:02d}T12:03:22Z", "cve,epss,percentile"]
    lines += [f"CVE-2099-{i:06d},0.00001,0.00001" for i in range(rows)]
    return "\n".join(lines) + "\n"


@lru_cache(maxsize=8)
def epss_gz(rows: int = EPSS_ROWS, day: int = 26) -> bytes:
    return gz(epss_text(rows, day))


def kev_catalog(records: int) -> dict[str, Any]:
    """Synthetic KEV catalog: ``records`` copies of the first record of kev_valid.json."""
    catalog = json.loads(fixture_bytes("kev_valid.json"))
    template = catalog["vulnerabilities"][0]
    catalog["vulnerabilities"] = [
        {**copy.deepcopy(template), "cveID": f"CVE-2099-{i:05d}"} for i in range(records)
    ]
    catalog["count"] = records
    return catalog


def kev_bytes(catalog: dict[str, Any]) -> bytes:
    return json.dumps(catalog, indent=4, ensure_ascii=False).encode("utf-8")


@lru_cache(maxsize=8)
def big_kev(records: int = 1_800) -> bytes:
    """Synthetic KEV file above the 1,700 minimum."""
    return kev_bytes(kev_catalog(records))


def fetch_result(url: str, content: bytes, at: datetime, final_url: str | None = None) -> FetchResult:
    return FetchResult(url=url, final_url=final_url or url, content=content, downloaded_at=at, attempts=1)
