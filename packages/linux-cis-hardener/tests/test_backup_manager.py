"""Unit tests for the BackupManager ensuring deterministic snapshots and rollbacks."""

import os
import stat
import pytest

from cis.backup_manager import BackupManager, compute_sha256
from cis.rules.base import safe_read_file, safe_write_file


@pytest.fixture
def backup_env(tmp_path):
    root = tmp_path / "env_root"
    root.mkdir()
    backup_dir = tmp_path / "backups"
    backup_dir.mkdir()
    return str(root), str(backup_dir)


def test_backup_and_rollback_existing_file(backup_env):
    root, backup_dir = backup_env
    bm = BackupManager(backup_dir=backup_dir, root_prefix=root)

    test_file = os.path.join(root, "config.conf")
    safe_write_file(test_file, "original_content=true\n", mode=0o640)

    # 1. Take backup
    session_id = bm.start_session("session_test_01")
    assert session_id == "session_test_01"

    entry = bm.backup_file(test_file)
    assert entry.file_existed is True
    assert entry.stat_mode == 0o640
    assert entry.sha256_original == compute_sha256(test_file)
    assert os.path.exists(entry.backup_path)

    # 2. Mutate file
    safe_write_file(test_file, "mutated_content=true\n", mode=0o600)
    assert "mutated_content=true" in safe_read_file(test_file)

    # 3. Rollback
    rb_res = bm.rollback_session("session_test_01")
    assert rb_res["success"] is True
    assert rb_res["restored_count"] == 1
    assert "original_content=true" in safe_read_file(test_file)
    st = os.stat(test_file)
    assert stat.S_IMODE(st.st_mode) == 0o640


def test_backup_and_rollback_non_existent_file(backup_env):
    root, backup_dir = backup_env
    bm = BackupManager(backup_dir=backup_dir, root_prefix=root)

    new_file = os.path.join(root, "new_created.conf")
    assert not os.path.exists(new_file)

    bm.start_session("session_new_01")
    entry = bm.backup_file(new_file)
    assert entry.file_existed is False

    # Simulate creation
    safe_write_file(new_file, "newly_created=true\n")
    assert os.path.exists(new_file)

    # Rollback should delete the newly created file
    rb_res = bm.rollback_session("session_new_01")
    assert rb_res["success"] is True
    assert not os.path.exists(new_file)


def test_backup_list_sessions(backup_env):
    root, backup_dir = backup_env
    bm = BackupManager(backup_dir=backup_dir, root_prefix=root)

    bm.start_session("session_A")
    bm.start_session("session_B")

    sessions = bm.list_sessions()
    assert len(sessions) == 2
    session_ids = [s["session_id"] for s in sessions]
    assert "session_A" in session_ids
    assert "session_B" in session_ids


def test_backup_tampered_integrity_check(backup_env):
    root, backup_dir = backup_env
    bm = BackupManager(backup_dir=backup_dir, root_prefix=root)

    target_file = os.path.join(root, "tamper_test.conf")
    safe_write_file(target_file, "data=initial\n")

    bm.start_session("session_tamper")
    entry = bm.backup_file(target_file)

    # Tamper with the backup file directly
    with open(entry.backup_path, "w") as f:
        f.write("corrupted_data\n")

    # Rollback should detect checksum mismatch and fail gracefully
    rb_res = bm.rollback_session("session_tamper")
    assert rb_res["success"] is False
    assert len(rb_res["errors"]) == 1


def test_backup_manager_empty_and_corrupt_manifests(tmp_path):
    root = str(tmp_path / "root")
    os.makedirs(root)
    b_dir = str(tmp_path / "backups")
    os.makedirs(b_dir)

    bm = BackupManager(backup_dir=b_dir, root_prefix=root)
    assert bm.get_latest_session_id() is None
    assert bm.list_sessions() == []

    # Non-existent backup dir list_sessions
    bm_non = BackupManager(backup_dir="/non/existent/dir", root_prefix=root)
    assert bm_non.list_sessions() == []

    # Restore non-existent file
    assert bm.restore_file("/non/existent/file.conf") is False

    # Rollback non-existent session
    rb = bm.rollback_session("fake_session_123")
    assert rb["success"] is False
