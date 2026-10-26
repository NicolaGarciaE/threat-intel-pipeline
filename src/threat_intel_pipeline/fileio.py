"""Atomic, no-overwrite file writes for raw files and manifests."""

from __future__ import annotations

import os
import tempfile
from pathlib import Path

TMP_DIR_NAME = ".tmp"


def write_new_file(path: Path, data: bytes) -> None:
    """Write ``data`` to ``path`` atomically and never replace an existing file.

    The bytes go first to a temporary file in ``<path.parent>/.tmp/`` (same
    disk), are flushed and fsynced, and only then are published under the
    final name with ``os.link``, which raises ``FileExistsError`` if that name
    already exists. An interrupted write can leave an orphan in ``.tmp/`` but
    never a partial file under the final name.
    """
    tmp_dir = path.parent / TMP_DIR_NAME
    tmp_dir.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=tmp_dir, prefix=f"{path.name}.", suffix=".part")
    tmp_path = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as tmp:
            tmp.write(data)
            tmp.flush()
            os.fsync(tmp.fileno())
        os.link(tmp_path, path)
    finally:
        tmp_path.unlink(missing_ok=True)


def orphan_temp_files(directory: Path) -> list[Path]:
    """Temporary files left in ``<directory>/.tmp/`` by an interrupted write."""
    tmp_dir = directory / TMP_DIR_NAME
    if not tmp_dir.is_dir():
        return []
    return sorted(p for p in tmp_dir.iterdir() if p.is_file())
