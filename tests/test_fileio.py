"""Atomic, no-overwrite writes."""

import pytest

from threat_intel_pipeline.fileio import orphan_temp_files, write_new_file


def test_write_new_file_writes_and_leaves_no_temp_file(tmp_path):
    path = tmp_path / "kev_2026-10-26.json"
    write_new_file(path, b"content")
    assert path.read_bytes() == b"content"
    assert orphan_temp_files(tmp_path) == []


def test_write_new_file_never_overwrites(tmp_path):
    path = tmp_path / "kev_2026-10-26.json"
    write_new_file(path, b"first")
    with pytest.raises(FileExistsError):
        write_new_file(path, b"second")
    assert path.read_bytes() == b"first"
    assert orphan_temp_files(tmp_path) == []


def test_orphan_temp_files_are_listed(tmp_path):
    (tmp_path / ".tmp").mkdir()
    orphan = tmp_path / ".tmp" / "kev_2026-10-26.json.abc.part"
    orphan.write_bytes(b"half")
    assert orphan_temp_files(tmp_path) == [orphan]
    assert orphan_temp_files(tmp_path / "missing") == []
