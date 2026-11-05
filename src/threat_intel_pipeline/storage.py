"""GitHub Releases as the permanent store of the raw history (CLAUDE.md §4).

One release per month, ``<prefix>YYYY-MM``: prefix ``data-`` holds the real
history, ``test-data-`` and ``test2-data-`` hold the test runs. Only KEV raw
files and manifests are published: EPSS raw files never are, while FIRST has not
given permission (CLAUDE.md §4). A published file is never replaced or deleted;
a local file that differs from the published one is reported as a conflict.

Every call to GitHub goes through the GitHub CLI (``gh``), which reads its token
from the environment (``GH_TOKEN`` in Actions): nothing here reads, stores or
prints a token. Only the standard library and ``fileio`` are imported, so the
write job of the daily workflow runs this module without installing any package.

Run from the repo root:
  uv run python -m threat_intel_pipeline.storage publish  --repo OWNER/NAME --release-prefix PREFIX --raw-dir DIR [--dry-run]
  uv run python -m threat_intel_pipeline.storage download --repo OWNER/NAME --release-prefix PREFIX --raw-dir DIR
  uv run python -m threat_intel_pipeline.storage list     --repo OWNER/NAME --release-prefix PREFIX
"""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import re
import subprocess
import sys
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any

from threat_intel_pipeline.fileio import write_new_file

log = logging.getLogger("threat_intel_pipeline.storage")

REAL_PREFIX = "data-"
PREFIX_PATTERN = re.compile(r"(test[0-9]*-)?data-")
REPO_PATTERN = re.compile(r"[A-Za-z0-9-]+/[A-Za-z0-9._-]+")
MAIN_REF = "refs/heads/main"
# The only publishable names: the same raw file names as the kev_glob and
# manifest_glob vars of dbt/dbt_project.yml and manifest.NAME_PATTERN.
KEV_NAME = re.compile(r"kev_(?P<date>\d{4}-\d{2}-\d{2})\.json")
MANIFEST_NAME = re.compile(r"manifest_(?P<date>\d{4}-\d{2}-\d{2})_\d{6}Z\.json")
DIGEST_PATTERN = re.compile(r"sha256:(?P<hex>[0-9a-f]{64})")
PER_PAGE = 100

EXIT_OK = 0
EXIT_FAILED = 1  # conflicts, failed uploads or downloads, gh errors

GhRunner = Callable[[Sequence[str]], subprocess.CompletedProcess[bytes]]


class StorageError(Exception):
    """A release operation failed or was refused; nothing published was replaced or deleted."""


@dataclass(frozen=True)
class Release:
    tag: str
    id: int
    prerelease: bool


@dataclass(frozen=True)
class Asset:
    name: str
    size: int
    digest: str | None  # as the API gives it, for example "sha256:<hex>", or null
    state: str  # "uploaded" once the upload is complete

    @property
    def sha256(self) -> str | None:
        match = DIGEST_PATTERN.fullmatch(self.digest or "")
        return match["hex"] if match else None


def run_gh(args: Sequence[str]) -> subprocess.CompletedProcess[bytes]:
    """Run the GitHub CLI without prompts or update notices; its token comes from the environment."""
    env = {**os.environ, "GH_PROMPT_DISABLED": "1", "GH_NO_UPDATE_NOTIFIER": "1"}
    try:
        return subprocess.run(["gh", *args], capture_output=True, check=False, env=env)
    except FileNotFoundError as exc:
        raise StorageError("gh (GitHub CLI) not found on PATH") from exc


class GitHub:
    """The release operations of one repository, through gh. ``runner`` is injectable for tests."""

    def __init__(self, repo: str, runner: GhRunner = run_gh) -> None:
        if not REPO_PATTERN.fullmatch(repo):
            raise StorageError(f"--repo must be OWNER/NAME, got {repo!r}")
        self.repo = repo
        self.runner = runner

    def _run(self, args: Sequence[str], *, allow_not_found: bool = False) -> bytes | None:
        result = self.runner(list(args))
        if result.returncode == 0:
            return result.stdout
        stderr = result.stderr.decode("utf-8", errors="replace").strip()
        if allow_not_found and "HTTP 404" in stderr:
            return None
        raise StorageError(f"gh {' '.join(args[:2])} failed (exit {result.returncode}): {stderr}")

    def _pages(self, path: str) -> list[dict[str, Any]]:
        output = self._run(["api", "--paginate", "--slurp", f"{path}?per_page={PER_PAGE}"])
        return [item for page in json.loads(output) for item in page]

    def releases(self, prefix: str) -> list[Release]:
        """The published releases named ``<prefix>YYYY-MM``, oldest month first."""
        tag = re.compile(re.escape(prefix) + r"\d{4}-\d{2}")
        found = [
            Release(item["tag_name"], item["id"], item["prerelease"])
            for item in self._pages(f"repos/{self.repo}/releases")
            if tag.fullmatch(item["tag_name"]) and not item.get("draft")
        ]
        return sorted(found, key=lambda release: release.tag)

    def release(self, tag: str) -> Release | None:
        output = self._run(["api", f"repos/{self.repo}/releases/tags/{tag}"], allow_not_found=True)
        if output is None:
            return None
        item = json.loads(output)
        return Release(item["tag_name"], item["id"], item["prerelease"])

    def assets(self, release: Release) -> dict[str, Asset]:
        return {
            item["name"]: Asset(item["name"], item["size"], item.get("digest"), item["state"])
            for item in self._pages(f"repos/{self.repo}/releases/{release.id}/assets")
        }

    def create_release(self, tag: str, *, title: str, notes: str, prerelease: bool) -> None:
        # No --target: the tag goes on the latest commit of the default branch, so
        # the token never needs the workflows permission (docs.github.com, "Create a release").
        args = ["release", "create", tag, "--repo", self.repo, "--title", title, "--notes", notes, "--latest=false"]
        if prerelease:
            args.append("--prerelease")
        self._run(args)

    def upload(self, tag: str, path: Path) -> None:
        # Never --clobber: an existing asset is never deleted to upload another one.
        self._run(["release", "upload", tag, str(path), "--repo", self.repo])

    def download(self, tag: str, name: str) -> bytes:
        output = self._run(["release", "download", tag, "--repo", self.repo, "--pattern", name, "--output", "-"])
        return output or b""

    def published_sha256(self, release: Release, asset: Asset) -> str:
        """sha256 of a published asset: its digest, or the hash of the downloaded asset if the API gives none."""
        if asset.sha256 is not None:
            return asset.sha256
        log.warning("%s/%s: no sha256 digest from the API; downloading it to compare", release.tag, asset.name)
        return hashlib.sha256(self.download(release.tag, asset.name)).hexdigest()


def check_prefix(prefix: str) -> None:
    if not PREFIX_PATTERN.fullmatch(prefix):
        raise StorageError(f"--release-prefix must be {REAL_PREFIX!r} or a test prefix like 'test-data-', got {prefix!r}")


def check_may_write(prefix: str, environ: Mapping[str, str]) -> None:
    """In GitHub Actions, only the main branch may write the real history."""
    ref = environ.get("GITHUB_REF")
    if prefix == REAL_PREFIX and environ.get("GITHUB_ACTIONS") == "true" and ref != MAIN_REF:
        raise StorageError(
            f"refusing to write to {REAL_PREFIX}YYYY-MM releases from {ref!r}: "
            f"in GitHub Actions only {MAIN_REF} may write the real history"
        )


def is_publishable(name: str) -> bool:
    return bool(KEV_NAME.fullmatch(name) or MANIFEST_NAME.fullmatch(name))


def day_of(name: str) -> date:
    match = KEV_NAME.fullmatch(name) or MANIFEST_NAME.fullmatch(name)
    if match is None:
        raise StorageError(f"{name} is not a KEV raw file or a manifest")
    try:
        return date.fromisoformat(match["date"])
    except ValueError as exc:
        raise StorageError(f"{name} has an impossible date") from exc


def release_tag(prefix: str, day: date) -> str:
    return f"{prefix}{day:%Y-%m}"


def release_text(tag: str, prefix: str) -> tuple[str, str]:
    """Title and notes of a new release."""
    if prefix == REAL_PREFIX:
        return tag, (
            f"Raw history of {tag.removeprefix(prefix)}: the daily CISA KEV catalog (CC0 1.0) and the manifest "
            "of every ingest attempt of threat-intel-pipeline. EPSS raw files are not published. "
            "Published files are never replaced or deleted."
        )
    return f"TEST {tag}", "Test release of the daily workflow, not part of the real history; it is deleted after the tests."


def sha256_of(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def publishable_files(raw_dir: Path) -> list[Path]:
    """KEV raw files and manifests in the top level of ``raw_dir``: every KEV first, then every manifest."""
    if not raw_dir.is_dir():
        raise StorageError(f"{raw_dir} is not a directory")
    files = sorted(path for path in raw_dir.iterdir() if path.is_file())
    return [p for p in files if KEV_NAME.fullmatch(p.name)] + [p for p in files if MANIFEST_NAME.fullmatch(p.name)]


def file_sha256(path: Path) -> tuple[str, int]:
    """sha256 and size of a file, read in chunks."""
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as file:
        for chunk in iter(lambda: file.read(1024 * 1024), b""):
            digest.update(chunk)
            size += len(chunk)
    return digest.hexdigest(), size


def kev_recorded_ok(manifests: Sequence[Path]) -> dict[str, set[str]]:
    """KEV file name -> the sha256 values that some readable manifest records as ok."""
    recorded: dict[str, set[str]] = {}
    for path in manifests:
        try:
            entry = json.loads(path.read_bytes())["sources"]["kev"]
            if entry["status"] == "ok" and KEV_NAME.fullmatch(entry["file"]):
                recorded.setdefault(entry["file"], set()).add(entry["sha256"])
        except (OSError, ValueError, KeyError, TypeError):
            continue  # an unreadable manifest is never used (CLAUDE.md §4)
    return recorded


@dataclass
class PublishReport:
    uploaded: list[str] = field(default_factory=list)
    planned: list[str] = field(default_factory=list)  # --dry-run: what would be uploaded
    already_published: list[str] = field(default_factory=list)
    not_published: list[str] = field(default_factory=list)  # warnings
    conflicts: list[str] = field(default_factory=list)  # errors: never replaced
    kev_mismatches: list[str] = field(default_factory=list)  # errors: a KEV file differs from its manifests
    withheld: list[str] = field(default_factory=list)  # manifests of a day with one of the two errors above

    @property
    def failed(self) -> bool:
        return bool(self.conflicts or self.kev_mismatches)


@dataclass(frozen=True)
class _Upload:
    tag: str
    path: Path
    sha256: str
    size: int


def publish(
    github: GitHub,
    prefix: str,
    raw_dir: Path,
    *,
    dry_run: bool = False,
    environ: Mapping[str, str] = os.environ,
) -> PublishReport:
    """Upload every KEV raw file and manifest of ``raw_dir`` that its month release lacks.

    Rules, per ``snapshot_date``:
    - KEV file that no manifest records ok (the manifest was not written, or it
      marks KEV failed): the KEV file is not uploaded, a warning; the manifests are.
    - KEV file that differs from what a manifest records ok, or is missing although
      a manifest records it ok: data/raw changed, an error; neither the KEV file nor
      any manifest of that day is uploaded.
    - KEV file published with other content: a conflict, an error; nothing is
      replaced, and no manifest of that day is uploaded, since it records the
      sha256 of the local file and the release would contradict itself.
    A name already published with the same content is skipped. The other days are
    uploaded. Uploads stop at the first failure, so a manifest is never uploaded
    before the KEV file of an earlier step; the next run uploads what is missing.
    """
    check_prefix(prefix)
    check_may_write(prefix, environ)
    files = publishable_files(raw_dir)  # every KEV file comes before every manifest
    hashes = {path: file_sha256(path) for path in files}
    recorded = kev_recorded_ok([path for path in files if MANIFEST_NAME.fullmatch(path.name)])
    local_kev = {path.name: hashes[path][0] for path in files if KEV_NAME.fullmatch(path.name)}
    report = PublishReport()
    held: dict[date, str] = {}  # day -> why none of its manifests is uploaded
    for name, shas in sorted(recorded.items()):
        local = local_kev.get(name)
        if shas - {local}:
            found = f"the local file has sha256 {local}" if local else "there is no local file"
            report.kev_mismatches.append(
                f"{name}: manifests record it ok with sha256 {', '.join(sorted(shas - {local}))}, "
                f"but {found}; data/raw changed and nothing of that day is uploaded"
            )
            held[day_of(name)] = f"{name} differs from its manifests"
    releases: dict[str, Release | None] = {}
    published: dict[str, dict[str, Asset]] = {}
    uploads: list[_Upload] = []

    for path in files:
        sha256, size = hashes[path]
        is_kev = KEV_NAME.fullmatch(path.name) is not None
        day = day_of(path.name)
        if is_kev and day in held:
            continue  # reported in kev_mismatches
        if is_kev and sha256 not in recorded.get(path.name, set()):
            report.not_published.append(f"{path.name}: no manifest in {raw_dir} records it ok with sha256 {sha256}")
            continue
        tag = release_tag(prefix, day)
        if tag not in releases:
            releases[tag] = github.release(tag)
            published[tag] = github.assets(releases[tag]) if releases[tag] else {}
        asset = published[tag].get(path.name)
        if asset is None and not is_kev and day in held:
            report.withheld.append(f"{tag}/{path.name}: not uploaded because {held[day]}")
            continue
        if asset is None:
            uploads.append(_Upload(tag, path, sha256, size))
            continue
        problem = _difference(github, releases[tag], asset, sha256, size)
        if problem:
            report.conflicts.append(f"{tag}/{path.name}: {problem}; nothing was replaced")
            if is_kev:
                held[day] = f"{path.name} is in conflict"
        else:
            report.already_published.append(f"{tag}/{path.name}")

    if dry_run:
        report.planned = [f"{upload.tag}/{upload.path.name}" for upload in uploads]
        return report
    for upload in uploads:
        if releases[upload.tag] is None:
            releases[upload.tag] = ensure_release(github, upload.tag, prefix)
        github.upload(upload.tag, upload.path)
        verify_upload(github, releases[upload.tag], upload)
        log.info("uploaded %s/%s (%s bytes, sha256 %s)", upload.tag, upload.path.name, f"{upload.size:,}", upload.sha256)
        report.uploaded.append(f"{upload.tag}/{upload.path.name}")
    return report


def _difference(github: GitHub, release: Release | None, asset: Asset, sha256: str, size: int) -> str | None:
    """Why a published asset differs from local content of that sha256 and size, or None if identical."""
    if asset.state != "uploaded":
        return f"published asset is incomplete (state {asset.state!r}) and can only be fixed by hand"
    published = github.published_sha256(release, asset)
    if asset.size != size or published != sha256:
        return f"published {asset.size:,} bytes with sha256 {published}, local {size:,} bytes with sha256 {sha256}"
    return None


def ensure_release(github: GitHub, tag: str, prefix: str) -> Release:
    """The month release, created if it does not exist yet (test releases as prereleases)."""
    release = github.release(tag)
    if release is not None:
        return release
    title, notes = release_text(tag, prefix)
    try:
        github.create_release(tag, title=title, notes=notes, prerelease=prefix != REAL_PREFIX)
        log.info("created release %s", tag)
    except StorageError:
        # Another run may have created it in the meantime; if not, it fails below.
        log.warning("could not create release %s; checking whether it exists now", tag)
    release = github.release(tag)
    if release is None:
        raise StorageError(f"release {tag} does not exist and could not be created")
    return release


def verify_upload(github: GitHub, release: Release, upload: _Upload) -> None:
    """The asset just uploaded must be listed complete, with the local size and sha256."""
    asset = github.assets(release).get(upload.path.name)
    if asset is None:
        raise StorageError(f"{release.tag}/{upload.path.name} is not listed after uploading it")
    problem = _difference(github, release, asset, upload.sha256, upload.size)
    if problem:
        raise StorageError(f"{release.tag}/{upload.path.name} differs after uploading it: {problem}; check it by hand")


@dataclass
class DownloadReport:
    downloaded: list[str] = field(default_factory=list)
    already_present: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)  # warnings
    conflicts: list[str] = field(default_factory=list)  # errors: nothing written


def download_missing(github: GitHub, prefix: str, raw_dir: Path) -> DownloadReport:
    """Download the KEV raw files and manifests of every ``<prefix>YYYY-MM`` release that ``raw_dir`` lacks.

    Each download is checked against the asset's size and sha256 digest before
    it is written, atomically and never over an existing file. A local file that
    differs from the published one is a conflict and is left as it is.
    """
    check_prefix(prefix)
    raw_dir.mkdir(parents=True, exist_ok=True)
    report = DownloadReport()
    for release in github.releases(prefix):
        for name, asset in sorted(github.assets(release).items()):
            where = f"{release.tag}/{name}"
            if not is_publishable(name):
                report.skipped.append(f"{where}: not a KEV raw file or a manifest")
                continue
            if release_tag(prefix, day_of(name)) != release.tag:
                report.conflicts.append(f"{where}: belongs to release {release_tag(prefix, day_of(name))}")
                continue
            if asset.state != "uploaded":
                report.skipped.append(f"{where}: incomplete upload (state {asset.state!r})")
                continue
            path = raw_dir / name
            if path.exists():
                local = path.read_bytes()
                problem = _difference(github, release, asset, sha256_of(local), len(local))
                if problem:
                    report.conflicts.append(f"{where}: {problem}; the local file was left as it is")
                else:
                    report.already_present.append(where)
                continue
            content = github.download(release.tag, name)
            problem = _content_problem(asset, content)
            if problem:
                report.conflicts.append(f"{where}: {problem}; not written")
                continue
            if asset.sha256 is None:
                report.skipped.append(f"{where}: no sha256 digest from the API; only its size was checked")
            write_new_file(path, content)
            report.downloaded.append(where)
    return report


def _content_problem(asset: Asset, content: bytes) -> str | None:
    if len(content) != asset.size:
        return f"downloaded {len(content):,} bytes, the asset has {asset.size:,}"
    if asset.sha256 is not None and sha256_of(content) != asset.sha256:
        return f"downloaded content has sha256 {sha256_of(content)}, the asset digest is {asset.sha256}"
    return None


def main(
    argv: Sequence[str] | None = None,
    *,
    runner: GhRunner = run_gh,
    environ: Mapping[str, str] = os.environ,
) -> int:
    _make_output_safe()
    _configure_logging()
    args = _parse_args(argv)
    try:
        github = GitHub(args.repo, runner)
        check_prefix(args.release_prefix)
        if args.command == "publish":
            report = publish(github, args.release_prefix, args.raw_dir, dry_run=args.dry_run, environ=environ)
            return _print_publish(report, args, in_actions=environ.get("GITHUB_ACTIONS") == "true")
        if args.command == "download":
            return _print_download(download_missing(github, args.release_prefix, args.raw_dir), args)
        return _print_list(github, args.release_prefix)
    except StorageError as exc:
        log.error("%s", exc)
        print(f"Result: FAILED, exit code {EXIT_FAILED} ({exc})", flush=True)
        return EXIT_FAILED


def _parse_args(argv: Sequence[str] | None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="python -m threat_intel_pipeline.storage",
        description="Publish and download the raw history (KEV raw files and manifests) in GitHub Releases.",
    )
    commands = parser.add_subparsers(dest="command", required=True)
    for name, text in (
        ("publish", "upload the KEV raw files and manifests of --raw-dir that their month release lacks"),
        ("download", "download into --raw-dir the KEV raw files and manifests it lacks"),
        ("list", "list the releases of --release-prefix and their files"),
    ):
        command = commands.add_parser(name, help=text, description=text)
        command.add_argument("--repo", required=True, help="OWNER/NAME of the GitHub repository")
        command.add_argument(
            "--release-prefix", required=True, help="data- for the real history; test-data-, test2-data-... for tests"
        )
        if name != "list":
            command.add_argument("--raw-dir", required=True, type=Path, help="local raw folder, for example data/raw")
        if name == "publish":
            command.add_argument("--dry-run", action="store_true", help="only show what would be uploaded")
    return parser.parse_args(argv)


def _print_publish(report: PublishReport, args: argparse.Namespace, *, in_actions: bool) -> int:
    action = "would upload" if args.dry_run else "uploaded"
    lines = [
        "",
        f"==== storage publish: {args.release_prefix}YYYY-MM releases of {args.repo}, from {args.raw_dir.as_posix()} ====",
        *_section(action, report.planned if args.dry_run else report.uploaded),
        *_section("already published, identical", report.already_published),
        *_section("not published (warning)", report.not_published),
        *_section("CONFLICTS (never replaced)", report.conflicts),
        *_section("KEV FILES THAT DIFFER FROM THEIR MANIFESTS", report.kev_mismatches),
        *_section("NOT UPLOADED because of an error with the KEV file of that day", report.withheld),
    ]
    if in_actions:  # shown on the page of the job, which a warning would not turn red
        lines += [annotation("warning", "KEV file not published", item) for item in report.not_published]
    reasons = [f"{len(report.conflicts)} conflicts"] if report.conflicts else []
    if report.kev_mismatches:
        reasons.append(f"{len(report.kev_mismatches)} KEV files differ from their manifests")
    code = EXIT_FAILED if report.failed else EXIT_OK
    lines.append(_result(code, reasons))
    print("\n".join(lines), flush=True)
    return code


def annotation(level: str, title: str, message: str) -> str:
    """A GitHub Actions workflow command (``::warning title=...::message``), escaped as
    actions/toolkit does it (packages/core/src/command.ts, escapeProperty and escapeData)."""

    def data(text: str) -> str:
        return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")

    return f"::{level} title={data(title).replace(':', '%3A').replace(',', '%2C')}::{data(message)}"


def _print_download(report: DownloadReport, args: argparse.Namespace) -> int:
    lines = [
        "",
        f"==== storage download: {args.release_prefix}YYYY-MM releases of {args.repo}, into {args.raw_dir.as_posix()} ====",
        *_section("downloaded", report.downloaded),
        *_section("already present, identical", report.already_present),
        *_section("skipped (warning)", report.skipped),
        *_section("CONFLICTS (nothing written)", report.conflicts),
    ]
    code = EXIT_FAILED if report.conflicts else EXIT_OK
    lines.append(_result(code, [f"{len(report.conflicts)} conflicts"] if report.conflicts else []))
    print("\n".join(lines), flush=True)
    return code


def _print_list(github: GitHub, prefix: str) -> int:
    releases = github.releases(prefix)
    lines = [f"{len(releases)} {prefix}YYYY-MM releases"]
    for release in releases:
        assets = github.assets(release)
        kind = " (prerelease)" if release.prerelease else ""
        lines.append(f"{release.tag}{kind}: {len(assets)} files")
        for asset in sorted(assets.values(), key=lambda a: a.name):
            lines.append(f"  {asset.name:36} {asset.size:>12,}  {asset.digest or 'no digest'}  {asset.state}")
    lines.append(_result(EXIT_OK, []))
    print("\n".join(lines), flush=True)
    return EXIT_OK


def _section(title: str, items: Sequence[str]) -> list[str]:
    if not items:
        return [f"{title}: none"]
    return [f"{title} ({len(items)}):", *(f"  - {item}" for item in items)]


def _result(code: int, reasons: Sequence[str]) -> str:
    status = "OK" if code == EXIT_OK else "FAILED"
    detail = f" ({'; '.join(reasons)})" if reasons else ""
    return f"Result: {status}, exit code {code}{detail}"


def _make_output_safe() -> None:
    """Never stop on a character the console cannot encode: print it escaped."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(errors="backslashreplace")


def _configure_logging() -> None:
    handler = logging.StreamHandler(sys.stdout)
    formatter = logging.Formatter("%(asctime)sZ %(levelname)s %(message)s", datefmt="%Y-%m-%dT%H:%M:%S")
    formatter.converter = time.gmtime
    handler.setFormatter(formatter)
    logging.basicConfig(level=logging.INFO, handlers=[handler], force=True)


if __name__ == "__main__":
    sys.exit(main())
