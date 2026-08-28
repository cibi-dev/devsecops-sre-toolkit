"""Deterministic backup manager creating timestamped .bak files with integrity verification."""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import shutil
import stat
from typing import Any, Optional

from pydantic import BaseModel, Field

from cis.rules.base import resolve_target_path

DEFAULT_BACKUP_ROOT = "/var/backups/cis-hardener"


def compute_sha256(file_path: str) -> str:
    """Compute SHA-256 hash of a file safely."""
    hasher = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            hasher.update(chunk)
    return hasher.hexdigest()


class BackupEntry(BaseModel):
    """Metadata record for a backed-up file."""

    model_config = {"extra": "forbid"}

    original_path: str = Field(..., description="Absolute path of original configuration file")
    backup_path: str = Field(..., description="Absolute path of stored .bak copy")
    sha256_original: str = Field(..., description="SHA-256 checksum of original content")
    stat_mode: int = Field(..., description="File permission mode integer")
    stat_uid: int = Field(..., description="Owner User ID")
    stat_gid: int = Field(..., description="Owner Group ID")
    file_existed: bool = Field(..., description="Whether file existed prior to remediation")
    timestamp: str = Field(..., description="ISO 8601 timestamp of snapshot")


class BackupSessionManifest(BaseModel):
    """Manifest file stored in each backup session directory."""

    model_config = {"extra": "forbid"}

    session_id: str
    created_at: str
    entries: list[BackupEntry] = Field(default_factory=list)


class BackupManager:
    """Manages timestamped backups and deterministic rollbacks for CIS remediation."""

    def __init__(self, backup_dir: Optional[str] = None, root_prefix: str = ""):
        self.root_prefix = root_prefix
        if backup_dir:
            self.base_dir = resolve_target_path(root_prefix, backup_dir)
        elif root_prefix:
            self.base_dir = os.path.join(os.path.abspath(root_prefix), "var/backups/cis-hardener")
        else:
            self.base_dir = DEFAULT_BACKUP_ROOT

        self.current_session_id: Optional[str] = None
        self.current_session_dir: Optional[str] = None
        self._manifest: Optional[BackupSessionManifest] = None

    def start_session(self, session_id: Optional[str] = None) -> str:
        """Initialize a new atomic backup session."""
        now = datetime.datetime.now(datetime.timezone.utc)
        if not session_id:
            time_str = now.strftime("%Y%m%d_%H%M%S_%f")
            session_id = f"cis_session_{time_str}"

        self.current_session_id = session_id
        self.current_session_dir = os.path.join(self.base_dir, session_id)
        os.makedirs(self.current_session_dir, mode=0o700, exist_ok=True)

        self._manifest = BackupSessionManifest(
            session_id=session_id,
            created_at=now.isoformat(),
            entries=[],
        )
        self._save_manifest()
        return session_id

    def _save_manifest(self) -> None:
        """Persist session manifest to JSON."""
        if not self.current_session_dir or not self._manifest:
            return
        manifest_path = os.path.join(self.current_session_dir, "manifest.json")
        data = self._manifest.model_dump_json(indent=2)
        with open(manifest_path, "w", encoding="utf-8") as f:
            f.write(data)
        os.chmod(manifest_path, 0o600)

    def backup_file(self, target_path: str) -> BackupEntry:
        """Create a timestamped .bak copy of target file before mutation.

        If target file does not exist, an entry recording file_existed=False is tracked.
        """
        if not self.current_session_id:
            self.start_session()

        target_abs = os.path.abspath(target_path)
        # Defense against path traversal
        if self.root_prefix:
            base_abs = os.path.abspath(self.root_prefix)
            if os.path.commonpath([base_abs, target_abs]) != base_abs:
                raise ValueError(f"Path traversal detected in backup target: {target_path!r}")

        # Check if already backed up in this session to prevent overwriting initial snapshot
        assert self._manifest is not None
        for entry in self._manifest.entries:
            if entry.original_path == target_abs:
                return entry

        now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()

        # Sanitize filename for backup store
        safe_rel_name = target_abs.lstrip("/").replace("/", "__")
        bak_filename = f"{safe_rel_name}.bak"
        assert self.current_session_dir is not None
        bak_dest = os.path.join(self.current_session_dir, bak_filename)

        if not os.path.exists(target_abs):
            entry = BackupEntry(
                original_path=target_abs,
                backup_path=bak_dest,
                sha256_original="NONE",
                stat_mode=0,
                stat_uid=0,
                stat_gid=0,
                file_existed=False,
                timestamp=now_iso,
            )
        else:
            st = os.stat(target_abs)
            sha = compute_sha256(target_abs)
            shutil.copy2(target_abs, bak_dest)
            os.chmod(bak_dest, 0o600)

            entry = BackupEntry(
                original_path=target_abs,
                backup_path=bak_dest,
                sha256_original=sha,
                stat_mode=stat.S_IMODE(st.st_mode),
                stat_uid=st.st_uid,
                stat_gid=st.st_gid,
                file_existed=True,
                timestamp=now_iso,
            )

        self._manifest.entries.append(entry)
        self._save_manifest()
        return entry

    def restore_file(self, target_path: str, session_id: Optional[str] = None) -> bool:
        """Restore a single file from the specified or active backup session."""
        target_abs = os.path.abspath(target_path)
        manifest = self._load_manifest(session_id)
        if not manifest:
            return False

        target_entry = None
        for entry in manifest.entries:
            if entry.original_path == target_abs:
                target_entry = entry
                break

        if not target_entry:
            return False

        return self._restore_entry(target_entry)

    def _restore_entry(self, entry: BackupEntry) -> bool:
        """Restore a specific BackupEntry to original location with integrity checks."""
        try:
            if not entry.file_existed:
                # File was created during remediation; remove it to rollback
                if os.path.exists(entry.original_path):
                    os.unlink(entry.original_path)
                return True

            if not os.path.exists(entry.backup_path):
                return False

            # Verify backup integrity
            current_bak_sha = compute_sha256(entry.backup_path)
            if current_bak_sha != entry.sha256_original:
                raise ValueError(
                    f"Integrity check failed on backup {entry.backup_path}: "
                    f"expected {entry.sha256_original}, got {current_bak_sha}"
                )

            parent_dir = os.path.dirname(entry.original_path)
            if parent_dir:
                os.makedirs(parent_dir, exist_ok=True)

            shutil.copy2(entry.backup_path, entry.original_path)
            os.chmod(entry.original_path, entry.stat_mode)

            if os.geteuid() == 0:
                os.chown(entry.original_path, entry.stat_uid, entry.stat_gid)

            return True
        except (OSError, PermissionError, ValueError):
            return False

    def _load_manifest(self, session_id: Optional[str] = None) -> Optional[BackupSessionManifest]:
        """Load manifest from disk for a given session or latest session."""
        target_session = session_id or self.current_session_id
        if not target_session:
            latest = self.get_latest_session_id()
            if not latest:
                return None
            target_session = latest

        manifest_path = os.path.join(self.base_dir, target_session, "manifest.json")
        if not os.path.exists(manifest_path):
            return None

        try:
            with open(manifest_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return BackupSessionManifest.model_validate(data)
        except (OSError, json.JSONDecodeError, ValueError):
            return None

    def get_latest_session_id(self) -> Optional[str]:
        """Find the most recent session identifier."""
        sessions = self.list_sessions()
        if not sessions:
            return None
        return sessions[0]["session_id"]

    def list_sessions(self) -> list[dict[str, Any]]:
        """List all available backup sessions ordered from newest to oldest."""
        if not os.path.exists(self.base_dir):
            return []

        results: list[dict[str, Any]] = []
        try:
            for item in sorted(os.listdir(self.base_dir), reverse=True):
                session_path = os.path.join(self.base_dir, item)
                manifest_path = os.path.join(session_path, "manifest.json")
                if os.path.isdir(session_path) and os.path.exists(manifest_path):
                    try:
                        with open(manifest_path, "r", encoding="utf-8") as f:
                            data = json.load(f)
                        results.append({
                            "session_id": data.get("session_id", item),
                            "created_at": data.get("created_at", "UNKNOWN"),
                            "files_backed_up": len(data.get("entries", [])),
                            "path": session_path,
                        })
                    except (OSError, json.JSONDecodeError):
                        continue
        except OSError:
            return []
        return results

    def rollback_session(self, session_id: Optional[str] = None) -> dict[str, Any]:
        """Rollback all files in a backup session deterministically.

        Returns:
            dict containing status, session_id, restored_files, and errors.
        """
        manifest = self._load_manifest(session_id)
        if not manifest:
            return {
                "success": False,
                "session_id": session_id,
                "restored_count": 0,
                "total_count": 0,
                "restored_files": [],
                "errors": ["Session manifest not found"],
            }

        restored_files: list[str] = []
        errors: list[str] = []

        for entry in manifest.entries:
            success = self._restore_entry(entry)
            if success:
                restored_files.append(entry.original_path)
            else:
                errors.append(f"Failed to restore {entry.original_path}")

        return {
            "success": len(errors) == 0,
            "session_id": manifest.session_id,
            "restored_count": len(restored_files),
            "total_count": len(manifest.entries),
            "restored_files": restored_files,
            "errors": errors,
        }
