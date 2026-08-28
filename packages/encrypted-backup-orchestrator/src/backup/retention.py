"""
Grandfather-Father-Son (GFS) Backup Retention and Rotation Manager.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple

from pydantic import BaseModel, Field


class RetentionPolicy(BaseModel):
    """Configuration for Grandfather-Father-Son retention scheme."""

    daily_count: int = Field(default=7, ge=1, description="Son: number of daily backups to keep")
    weekly_count: int = Field(default=4, ge=1, description="Father: number of weekly backups to keep")
    monthly_count: int = Field(default=12, ge=1, description="Grandfather: number of monthly backups to keep")


class BackupRecord(BaseModel):
    """Metadata representing an existing backup archive."""

    backup_id: str = Field(description="Unique identifier of backup")
    timestamp: datetime = Field(description="Backup creation timestamp (UTC)")
    manifest_path: str = Field(description="Absolute path to backup manifest JSON")
    source_path: str = Field(description="Original source path")
    total_bytes: int = Field(ge=0, description="Logical total bytes")
    total_files: int = Field(ge=0, description="Total files backed up")
    chunks: List[str] = Field(default_factory=list, description="List of chunk SHA-256 hashes")
    tier: Optional[str] = Field(default=None, description="GFS tier: monthly, weekly, daily")


class RetentionDecision(BaseModel):
    """Outcome of retention evaluation showing kept vs pruned backups."""

    kept_backups: List[BackupRecord]
    pruned_backups: List[BackupRecord]
    tier_map: Dict[str, str] = Field(description="Mapping of backup_id to assigned GFS tier")
    total_evaluated: int
    total_kept: int
    total_pruned: int


class RetentionResult(BaseModel):
    """Result of executing a retention prune operation."""

    decision: RetentionDecision
    deleted_manifests: List[str]
    deleted_chunks_count: int
    reclaimed_bytes: int
    dry_run: bool


class GFSRetentionManager:
    """Manages backup lifecycle and rotation using the Grandfather-Father-Son policy."""

    def __init__(self, policy: Optional[RetentionPolicy] = None) -> None:
        """
        Initialize GFS retention manager.

        Args:
            policy: Retention configuration (defaults to 7 daily, 4 weekly, 12 monthly).
        """
        self.policy = policy or RetentionPolicy()

    def evaluate(self, backups: List[BackupRecord]) -> RetentionDecision:
        """
        Evaluate backups against the GFS retention policy.

        Args:
            backups: List of existing BackupRecord items.

        Returns:
            RetentionDecision containing kept backups, pruned backups, and tier tags.
        """
        if not backups:
            return RetentionDecision(
                kept_backups=[],
                pruned_backups=[],
                tier_map={},
                total_evaluated=0,
                total_kept=0,
                total_pruned=0,
            )

        # Ensure timestamps are in UTC and sort in descending order (latest first)
        def _get_utc(record: BackupRecord) -> datetime:
            ts = record.timestamp
            if ts.tzinfo is None:
                return ts.replace(tzinfo=timezone.utc)
            return ts.astimezone(timezone.utc)

        sorted_backups = sorted(backups, key=_get_utc, reverse=True)

        tier_map: Dict[str, str] = {}
        kept_set: Set[str] = set()

        # 1. Grandfather (Monthly): Latest backup for each of the last N calendar months
        monthly_buckets: Dict[Tuple[int, int], BackupRecord] = {}
        for record in sorted_backups:
            ts = _get_utc(record)
            month_key = (ts.year, ts.month)
            if month_key not in monthly_buckets:
                monthly_buckets[month_key] = record

        # Select the most recent monthly_count distinct months
        sorted_month_keys = sorted(monthly_buckets.keys(), reverse=True)[: self.policy.monthly_count]
        for m_key in sorted_month_keys:
            rec_m = monthly_buckets[m_key]
            kept_set.add(rec_m.backup_id)
            tier_map[rec_m.backup_id] = "monthly"

        # 2. Father (Weekly): Latest backup for each of the last N ISO weeks
        weekly_buckets: Dict[Tuple[int, int], BackupRecord] = {}
        for record in sorted_backups:
            ts = _get_utc(record)
            iso_year, iso_week, _ = ts.isocalendar()
            week_key = (iso_year, iso_week)
            if week_key not in weekly_buckets:
                weekly_buckets[week_key] = record

        sorted_week_keys = sorted(weekly_buckets.keys(), reverse=True)[: self.policy.weekly_count]
        for w_key in sorted_week_keys:
            rec_w = weekly_buckets[w_key]
            if rec_w.backup_id not in kept_set:
                kept_set.add(rec_w.backup_id)
                tier_map[rec_w.backup_id] = "weekly"
            elif tier_map.get(rec_w.backup_id) is None:
                tier_map[rec_w.backup_id] = "weekly"

        # 3. Son (Daily): Latest backup for each of the last N calendar days
        daily_buckets: Dict[Tuple[int, int, int], BackupRecord] = {}
        for record in sorted_backups:
            ts = _get_utc(record)
            day_key = (ts.year, ts.month, ts.day)
            if day_key not in daily_buckets:
                daily_buckets[day_key] = record

        sorted_day_keys = sorted(daily_buckets.keys(), reverse=True)[: self.policy.daily_count]
        for d_key in sorted_day_keys:
            rec_d = daily_buckets[d_key]
            if rec_d.backup_id not in kept_set:
                kept_set.add(rec_d.backup_id)
                tier_map[rec_d.backup_id] = "daily"
            elif tier_map.get(rec_d.backup_id) is None:
                tier_map[rec_d.backup_id] = "daily"

        kept_backups: List[BackupRecord] = []
        pruned_backups: List[BackupRecord] = []

        for record in sorted_backups:
            if record.backup_id in kept_set:
                record_copy = record.model_copy(update={"tier": tier_map.get(record.backup_id)})
                kept_backups.append(record_copy)
            else:
                pruned_backups.append(record)

        return RetentionDecision(
            kept_backups=kept_backups,
            pruned_backups=pruned_backups,
            tier_map=tier_map,
            total_evaluated=len(sorted_backups),
            total_kept=len(kept_backups),
            total_pruned=len(pruned_backups),
        )

    def prune_repository(
        self,
        repo_dir: str | Path,
        decision: RetentionDecision,
        dry_run: bool = False,
    ) -> RetentionResult:
        """
        Execute pruning on repository, removing pruned manifests and orphaned chunks.

        Args:
            repo_dir: Root repository directory.
            decision: Evaluated retention decision.
            dry_run: If True, simulate actions without modifying disk.

        Returns:
            RetentionResult with operation details and space reclaimed.
        """
        repo_path = Path(repo_dir).resolve()
        manifests_dir = repo_path / "manifests"
        chunks_dir = repo_path / "chunks"

        deleted_manifests: List[str] = []
        reclaimed_bytes = 0

        # Collect all active chunks referenced across kept backups
        active_chunks: Set[str] = set()
        for kept in decision.kept_backups:
            for chunk_hash in kept.chunks:
                active_chunks.add(chunk_hash)

        # 1. Prune manifests of discarded backups
        for pruned in decision.pruned_backups:
            m_path = Path(pruned.manifest_path)
            if not m_path.is_absolute():
                m_path = repo_path / m_path

            if m_path.exists():
                reclaimed_bytes += m_path.stat().st_size
                deleted_manifests.append(str(m_path))
                if not dry_run:
                    m_path.unlink()

        # 2. Garbage-collect orphaned chunks
        deleted_chunks_count = 0
        if chunks_dir.exists():
            for root, _, files in os.walk(chunks_dir):
                for filename in files:
                    chunk_file = Path(root) / filename
                    # Chunk filename is the SHA-256 hash or hash.ext
                    chunk_hash = filename.split(".")[0]
                    if chunk_hash not in active_chunks:
                        chunk_size = chunk_file.stat().st_size
                        reclaimed_bytes += chunk_size
                        deleted_chunks_count += 1
                        if not dry_run:
                            chunk_file.unlink()

            # Clean empty chunk subdirectories if not dry_run
            if not dry_run:
                for root, dirs, _ in os.walk(chunks_dir, topdown=False):
                    for d in dirs:
                        dir_path = Path(root) / d
                        try:
                            dir_path.rmdir()
                        except OSError:
                            pass

        return RetentionResult(
            decision=decision,
            deleted_manifests=deleted_manifests,
            deleted_chunks_count=deleted_chunks_count,
            reclaimed_bytes=reclaimed_bytes,
            dry_run=dry_run,
        )

    @classmethod
    def load_records_from_repo(cls, repo_dir: str | Path) -> List[BackupRecord]:
        """
        Load all BackupRecords from repository manifests directory.

        Args:
            repo_dir: Root repository path.

        Returns:
            List of BackupRecord instances.
        """
        repo_path = Path(repo_dir).resolve()
        manifests_dir = repo_path / "manifests"
        records: List[BackupRecord] = []

        if not manifests_dir.exists():
            return records

        for m_file in sorted(manifests_dir.glob("*.json")):
            try:
                with open(m_file, "r", encoding="utf-8") as f:
                    data = json.load(f)

                ts_str = data.get("timestamp")
                if ts_str:
                    try:
                        ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                    except Exception:
                        ts = datetime.fromtimestamp(m_file.stat().st_mtime, tz=timezone.utc)
                else:
                    ts = datetime.fromtimestamp(m_file.stat().st_mtime, tz=timezone.utc)

                record = BackupRecord(
                    backup_id=data.get("backup_id", m_file.stem),
                    timestamp=ts,
                    manifest_path=str(m_file),
                    source_path=data.get("source_path", ""),
                    total_bytes=data.get("total_bytes", 0),
                    total_files=data.get("total_files", 0),
                    chunks=data.get("chunk_hashes", []),
                    tier=data.get("tier"),
                )
                records.append(record)
            except Exception:
                continue

        return records
