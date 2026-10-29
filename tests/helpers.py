"""Helpers shared by the tests. All data here is synthetic (see fixtures/README.md).

Tests only read ``tests/fixtures/`` and write to pytest's temporary folders.
"""

from __future__ import annotations

import copy
import gzip
import hashlib
import json
import subprocess
from datetime import UTC, date, datetime
from functools import lru_cache
from pathlib import Path
from typing import Any

from threat_intel_pipeline import storage
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


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


REPO = "owner/repo"  # the repository of FakeGh


class GhFailure(Exception):
    """A gh command that fails, with the text gh would print on stderr."""


class FakeGh:
    """In-memory releases of one repository, behind the gh commands of storage.py.

    It answers only those commands and fails the test on any destructive one
    (--clobber or delete), so every test that uses it also checks that nothing
    published is ever replaced or deleted.
    """

    def __init__(self) -> None:
        self.releases: dict[str, dict] = {}
        self.commands: list[list[str]] = []
        self.with_digests = True
        self.corrupt_uploads = False
        self.create_race = False  # another run creates the release just before us

    def add_release(self, tag: str, files: dict[str, bytes] | None = None, prerelease: bool = False) -> dict:
        release = {"id": 100 + len(self.releases), "prerelease": prerelease, "title": None, "notes": None, "assets": {}}
        self.releases[tag] = release
        for name, content in (files or {}).items():
            self.store(tag, name, content)
        return release

    def store(self, tag: str, name: str, content: bytes, state: str = "uploaded") -> None:
        digest = f"sha256:{sha256(content)}" if self.with_digests else None
        self.releases[tag]["assets"][name] = {"content": content, "digest": digest, "state": state}

    def published(self, tag: str) -> dict[str, bytes]:
        return {name: asset["content"] for name, asset in self.releases[tag]["assets"].items()}

    def writes(self) -> list[list[str]]:
        return [command for command in self.commands if command[0] == "release" and command[1] in ("create", "upload")]

    def __call__(self, args):
        args = list(args)
        self.commands.append(args)
        assert "--clobber" not in args and "delete" not in args, f"destructive gh command: {args}"
        try:
            stdout = self._answer(args)
        except GhFailure as exc:
            return subprocess.CompletedProcess(["gh", *args], 1, b"", str(exc).encode())
        return subprocess.CompletedProcess(["gh", *args], 0, stdout, b"")

    def _answer(self, args: list[str]) -> bytes:
        releases = f"repos/{REPO}/releases"
        if args[:3] == ["api", "--paginate", "--slurp"]:
            path = args[3].removesuffix(f"?per_page={storage.PER_PAGE}")
            if path == releases:
                items = [
                    {"tag_name": tag, "id": release["id"], "prerelease": release["prerelease"], "draft": False}
                    for tag, release in self.releases.items()
                ]
            else:
                release_id = int(path.removeprefix(f"{releases}/").removesuffix("/assets"))
                release = next(r for r in self.releases.values() if r["id"] == release_id)
                items = [
                    {"name": name, "size": len(a["content"]), "digest": a["digest"], "state": a["state"]}
                    for name, a in release["assets"].items()
                ]
            pages = [items[i : i + 2] for i in range(0, len(items), 2)] or [[]]  # two per page: pages are joined
            return json.dumps(pages).encode()
        if args[0] == "api" and args[1].startswith(f"{releases}/tags/"):
            tag = args[1].removeprefix(f"{releases}/tags/")
            if tag not in self.releases:
                raise GhFailure("gh: Not Found (HTTP 404)")
            release = self.releases[tag]
            return json.dumps({"tag_name": tag, "id": release["id"], "prerelease": release["prerelease"]}).encode()
        if args[:2] == ["release", "create"]:
            tag = args[2]
            assert args[3:9] == ["--repo", REPO, "--title", args[6], "--notes", args[8]]
            assert "--latest=false" in args and "--target" not in args
            if self.create_race:
                self.add_release(tag)
                raise GhFailure("HTTP 422: Validation Failed (already_exists)")
            release = self.add_release(tag, prerelease="--prerelease" in args)
            release["title"], release["notes"] = args[6], args[8]
            return b""
        if args[:2] == ["release", "upload"]:
            tag, path = args[2], Path(args[3])
            assert args[4:] == ["--repo", REPO]
            if path.name in self.releases[tag]["assets"]:
                raise GhFailure("HTTP 422: Validation Failed (already_exists)")
            content = path.read_bytes()
            self.store(tag, path.name, content + b"corrupted" if self.corrupt_uploads else content)
            return b""
        if args[:2] == ["release", "download"]:
            tag, name = args[2], args[6]
            assert args[3:] == ["--repo", REPO, "--pattern", name, "--output", "-"]
            return self.releases[tag]["assets"][name]["content"]
        raise AssertionError(f"unexpected gh command: {args}")
