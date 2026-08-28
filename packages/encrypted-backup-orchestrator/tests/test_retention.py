"""Tests for Grandfather-Father-Son (GFS) retention manager and pruning engine."""

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import pytest

from backup.retention import (
    GFSRetentionManager,
    RetentionPolicy,
    BackupRecord,
)


def test_gfs_empty_backups():
    """Test evaluation when no backups exist."""
    manager = GFSRetentionManager()
    decision = manager.evaluate([])

    assert decision.total_evaluated == 0
    assert decision.total_kept == 0
    assert decision.total_pruned == 0
    assert len(decision.kept_backups) == 0
    assert len(decision.pruned_backups) == 0


def test_gfs_evaluation_timeline():
    """Test GFS retention classification across 60 days of daily backups."""
    base_time = datetime(2026, 8, 27, 12, 0, 0, tzinfo=timezone.utc)
    policy = RetentionPolicy(daily_count=7, weekly_count=4, monthly_count=3)
    manager = GFSRetentionManager(policy=policy)

    backups: list[BackupRecord] = []
    for days_ago in range(60):
        ts = base_time - timedelta(days=days_ago)
        bid = f"bkp_{ts.strftime('%Y%m%d_%H%M%S')}"
        backups.append(
            BackupRecord(
                backup_id=bid,
                timestamp=ts,
                manifest_path=f"/repo/manifests/{bid}.json",
                source_path="/data",
                total_bytes=1000,
                total_files=5,
                chunks=[f"chunk_{days_ago}"],
            )
        )

    decision = manager.evaluate(backups)
    assert decision.total_evaluated == 60
    assert decision.total_kept > 0
    assert decision.total_pruned > 0
    assert decision.total_kept + decision.total_pruned == 60

    # Verify the most recent 7 days are kept
    kept_ids = {k.backup_id for k in decision.kept_backups}
    for days_ago in range(7):
        recent_bid = f"bkp_{(base_time - timedelta(days=days_ago)).strftime('%Y%m%d_%H%M%S')}"
        assert recent_bid in kept_ids


def test_gfs_naive_datetime_handling():
    """Test handling of naive datetimes without explicit tzinfo."""
    naive_ts = datetime(2026, 8, 27, 10, 0, 0)  # No tzinfo
    record = BackupRecord(
        backup_id="naive_bkp",
        timestamp=naive_ts,
        manifest_path="/repo/naive.json",
        source_path="/data",
        total_bytes=100,
        total_files=1,
        chunks=["c1"],
    )
    manager = GFSRetentionManager()
    decision = manager.evaluate([record])
    assert decision.total_kept == 1
    assert decision.kept_backups[0].tier in ("monthly", "weekly", "daily")


def test_gfs_custom_policy_counts():
    """Test GFS retention with small custom counts."""
    base_time = datetime(2026, 8, 27, 10, 0, 0, tzinfo=timezone.utc)
    policy = RetentionPolicy(daily_count=3, weekly_count=2, monthly_count=2)
    manager = GFSRetentionManager(policy=policy)

    # 10 backups 1 day apart
    backups = [
        BackupRecord(
            backup_id=f"b_{i}",
            timestamp=base_time - timedelta(days=i),
            manifest_path=f"/repo/b_{i}.json",
            source_path="/data",
            total_bytes=500,
            total_files=2,
            chunks=[f"c_{i}"],
        )
        for i in range(10)
    ]

    decision = manager.evaluate(backups)
    assert decision.total_evaluated == 10
    # At least 3 daily kept + weekly/monthly representatives
    assert decision.total_kept >= 3
    assert decision.total_pruned <= 7


def test_gfs_prune_dry_run_and_execution(tmp_path: Path):
    """Test dry_run simulation vs actual disk pruning and orphan chunk cleanup."""
    repo_dir = tmp_path / "repo"
    manifests_dir = repo_dir / "manifests"
    chunks_dir = repo_dir / "chunks"

    manifests_dir.mkdir(parents=True)
    chunks_dir.mkdir(parents=True)

    # Setup 4 chunk files (2 in subdir, 2 flat)
    sub_chunk_dir = chunks_dir / "or"
    sub_chunk_dir.mkdir()
    (sub_chunk_dir / "orphan_sub").write_bytes(b"SUB_ORPHAN")

    (chunks_dir / "chunk_keep_1").write_bytes(b"DATA1111")
    (chunks_dir / "chunk_keep_2").write_bytes(b"DATA2222")
    (chunks_dir / "chunk_orphan_1").write_bytes(b"ORPHAN11")
    (chunks_dir / "chunk_orphan_2").write_bytes(b"ORPHAN22")

    # Setup 2 manifest files (1 kept, 1 pruned)
    m1 = manifests_dir / "bkp_keep.json"
    m1.write_text('{"backup_id": "bkp_keep"}')
    m2 = manifests_dir / "bkp_prune.json"
    m2.write_text('{"backup_id": "bkp_prune"}')

    base_time = datetime(2026, 8, 27, 0, 0, 0, tzinfo=timezone.utc)
    kept_rec = BackupRecord(
        backup_id="bkp_keep",
        timestamp=base_time,
        manifest_path=str(m1),
        source_path="/data",
        total_bytes=200,
        total_files=1,
        chunks=["chunk_keep_1", "chunk_keep_2"],
    )
    pruned_rec = BackupRecord(
        backup_id="bkp_prune",
        timestamp=base_time - timedelta(days=20),
        manifest_path=str(m2),
        source_path="/data",
        total_bytes=200,
        total_files=1,
        chunks=["chunk_orphan_1", "chunk_orphan_2"],
    )

    manager = GFSRetentionManager(policy=RetentionPolicy(daily_count=1, weekly_count=1, monthly_count=1))
    decision = manager.evaluate([kept_rec, pruned_rec])

    # 1. Test Dry Run
    dry_result = manager.prune_repository(repo_dir, decision, dry_run=True)
    assert dry_result.dry_run is True
    assert len(dry_result.deleted_manifests) == 1
    assert dry_result.deleted_chunks_count >= 2
    assert dry_result.reclaimed_bytes > 0
    # Files must still exist on disk after dry run
    assert m2.exists()
    assert (chunks_dir / "chunk_orphan_1").exists()

    # 2. Test Actual Execution
    exec_result = manager.prune_repository(repo_dir, decision, dry_run=False)
    assert exec_result.dry_run is False
    assert not m2.exists()
    assert m1.exists()
    assert not (chunks_dir / "chunk_orphan_1").exists()
    assert not (chunks_dir / "chunk_orphan_2").exists()
    assert not (sub_chunk_dir / "orphan_sub").exists()
    assert (chunks_dir / "chunk_keep_1").exists()
    assert (chunks_dir / "chunk_keep_2").exists()


def test_gfs_load_records_from_repo(tmp_path: Path):
    """Test loading backup records from JSON manifests in repo."""
    repo_dir = tmp_path / "repo"
    manifests_dir = repo_dir / "manifests"
    manifests_dir.mkdir(parents=True)

    # Valid manifest
    manifest_data = {
        "backup_id": "bkp_load_test",
        "timestamp": "2026-08-27T15:30:00+00:00",
        "source_path": "/var/data",
        "total_files": 3,
        "total_bytes": 1024,
        "chunk_hashes": ["hash_a", "hash_b"],
        "tier": "daily",
    }
    (manifests_dir / "bkp_load_test.json").write_text(json.dumps(manifest_data))

    # Manifest with invalid timestamp format to test fallback
    manifest_bad_ts = {
        "backup_id": "bkp_bad_ts",
        "timestamp": "invalid_timestamp_str",
        "source_path": "/var/data2",
        "total_files": 1,
        "total_bytes": 50,
        "chunk_hashes": ["hash_c"],
    }
    (manifests_dir / "bkp_bad_ts.json").write_text(json.dumps(manifest_bad_ts))

    # Invalid JSON file to test graceful ignore
    (manifests_dir / "corrupted.json").write_text("INVALID NOT JSON {{{{")

    records = GFSRetentionManager.load_records_from_repo(repo_dir)
    assert len(records) == 2
    b_ids = {r.backup_id for r in records}
    assert "bkp_load_test" in b_ids
    assert "bkp_bad_ts" in b_ids

    # Non-existent manifests dir
    assert GFSRetentionManager.load_records_from_repo(tmp_path / "non_existent") == []
