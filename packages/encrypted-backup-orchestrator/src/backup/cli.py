"""
Command-line interface (CLI) for Encrypted Backup Orchestrator.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sys
from typing import Any, List, Optional
import uuid

from backup.compress import CompressionAlgorithm, Compressor
from backup.crypto import CryptoEngine
from backup.restore_tester import SandboxRestoreTester
from backup.retention import GFSRetentionManager, RetentionPolicy
from backup.scanner import BackupManifest, FileScanner


def get_passphrase(args: argparse.Namespace) -> Optional[str]:
    """Retrieve passphrase from arguments or environment variable."""
    if getattr(args, "no_encrypt", False):
        return None
    if getattr(args, "passphrase", None):
        return args.passphrase
    env_pass = os.getenv("BACKUP_PASSPHRASE")
    if env_pass:
        return env_pass
    return None


def cmd_backup(args: argparse.Namespace) -> int:
    """Execute full/incremental encrypted backup."""
    source_dir = Path(args.source).resolve()
    repo_dir = Path(args.repo).resolve()
    manifests_dir = repo_dir / "manifests"
    chunks_dir = repo_dir / "chunks"

    manifests_dir.mkdir(parents=True, exist_ok=True)
    chunks_dir.mkdir(parents=True, exist_ok=True)

    is_encrypted = not args.no_encrypt
    passphrase = get_passphrase(args)
    if is_encrypted and not passphrase:
        print("[-] Error: Passphrase required for encrypted backup (use --passphrase or BACKUP_PASSPHRASE env)", file=sys.stderr)
        return 1

    algo_str = args.compress.lower()
    try:
        algo = CompressionAlgorithm(algo_str)
    except ValueError:
        print(f"[-] Error: Unsupported compression algorithm '{args.compress}'", file=sys.stderr)
        return 1

    kdf_iterations = getattr(args, "iterations", 600000)

    # 1. Scanner & Deduplication
    print(f"[*] Scanning source directory: {source_dir}")
    scanner = FileScanner(source_dir, chunk_size=args.chunk_size)
    
    # Check latest backup for delta tracking
    prev_manifest: Optional[BackupManifest] = None
    records = GFSRetentionManager.load_records_from_repo(repo_dir)
    if records:
        latest_record = sorted(records, key=lambda r: r.timestamp, reverse=True)[0]
        try:
            with open(latest_record.manifest_path, "r", encoding="utf-8") as f:
                prev_manifest = BackupManifest.model_validate_json(f.read())
        except Exception:
            pass

    scan_result, chunk_pool = scanner.scan(previous_manifest=prev_manifest)
    print(f"[+] Scanned {scan_result.total_files} files ({scan_result.total_bytes} bytes)")
    print(f"[+] Unique chunks: {scan_result.unique_chunks_count} | Dedup ratio: {scan_result.deduplication_ratio}:1")

    # 2. Process and store new chunks (Compress + Encrypt)
    compressed_bytes_total = 0
    stored_chunks = 0
    skipped_chunks = 0

    for chunk_hash, chunk_data in chunk_pool.items():
        chunk_sub = chunk_hash[:2]
        target_sub = chunks_dir / chunk_sub
        target_sub.mkdir(parents=True, exist_ok=True)
        chunk_file = target_sub / chunk_hash

        if chunk_file.exists():
            skipped_chunks += 1
            compressed_bytes_total += chunk_file.stat().st_size
            continue

        # Step A: Compress
        compressed_chunk, _ = Compressor.compress(chunk_data, algorithm=algo)

        # Step B: Encrypt
        if is_encrypted and passphrase:
            final_payload = CryptoEngine.encrypt(
                compressed_chunk,
                passphrase=passphrase,
                iterations=kdf_iterations,
            )
        else:
            final_payload = compressed_chunk

        with open(chunk_file, "wb") as f:
            f.write(final_payload)

        compressed_bytes_total += len(final_payload)
        stored_chunks += 1

    backup_id = f"bkp_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:6]}"
    manifest = BackupManifest(
        backup_id=backup_id,
        timestamp=datetime.now(timezone.utc).isoformat(),
        backup_name=args.name,
        source_path=str(source_dir),
        total_files=scan_result.total_files,
        total_bytes=scan_result.total_bytes,
        unique_chunks=scan_result.unique_chunks_count,
        compressed_bytes=compressed_bytes_total,
        compression_algorithm=algo.value,
        is_encrypted=is_encrypted,
        kdf_iterations=kdf_iterations,
        files=scan_result.files,
        chunk_hashes=scan_result.chunk_hashes,
        previous_backup_id=prev_manifest.backup_id if prev_manifest else None,
    )

    manifest_file = manifests_dir / f"{backup_id}.json"
    with open(manifest_file, "w", encoding="utf-8") as f:
        f.write(manifest.model_dump_json(indent=2))

    print(f"[+] Backup completed successfully! ID: {backup_id}")
    print(f"[+] Manifest written to: {manifest_file}")
    print(f"[+] Stored {stored_chunks} new chunks, {skipped_chunks} existing deduplicated chunks")

    # Optional Sandbox verification
    if getattr(args, "verify_sandbox", False):
        print("[*] Running automated sandbox restore verification...")
        tester = SandboxRestoreTester()
        test_res = tester.run_sandbox_test(manifest, repo_dir, passphrase=passphrase)
        if test_res.success:
            print(f"[+] Sandbox test PASSED: 100% verified ({test_res.files_passed}/{test_res.total_files} files)")
        else:
            print(f"[-] Sandbox test FAILED: {test_res.files_failed} errors", file=sys.stderr)
            for err in test_res.errors:
                print(f"    - {err}", file=sys.stderr)
            return 1

    return 0


def cmd_restore(args: argparse.Namespace) -> int:
    """Restore a backup to target directory."""
    repo_dir = Path(args.repo).resolve()
    target_dir = Path(args.target).resolve()
    passphrase = get_passphrase(args)

    manifests_dir = repo_dir / "manifests"
    if not manifests_dir.exists():
        print(f"[-] Error: Repository manifests not found at {manifests_dir}", file=sys.stderr)
        return 1

    target_id = args.backup_id
    if target_id.lower() == "latest":
        records = GFSRetentionManager.load_records_from_repo(repo_dir)
        if not records:
            print("[-] Error: No backups found in repository", file=sys.stderr)
            return 1
        latest = sorted(records, key=lambda r: r.timestamp, reverse=True)[0]
        manifest_file = Path(latest.manifest_path)
    else:
        manifest_file = manifests_dir / f"{target_id}.json"
        if not manifest_file.exists():
            manifest_file = manifests_dir / target_id
        if not manifest_file.exists():
            print(f"[-] Error: Manifest not found for backup ID: {target_id}", file=sys.stderr)
            return 1

    with open(manifest_file, "r", encoding="utf-8") as f:
        manifest = BackupManifest.model_validate_json(f.read())

    print(f"[*] Restoring backup {manifest.backup_id} to: {target_dir}")
    tester = SandboxRestoreTester()
    statuses = tester.restore_manifest(manifest, repo_dir, target_dir, passphrase=passphrase)

    passed = sum(1 for s in statuses if s.passed)
    failed = len(statuses) - passed

    if failed == 0:
        print(f"[+] Restore completed successfully! {passed}/{len(statuses)} files restored and verified.")
        return 0
    else:
        print(f"[-] Restore finished with {failed} verification errors", file=sys.stderr)
        for s in statuses:
            if not s.passed:
                print(f"    - {s.rel_path}: {s.error}", file=sys.stderr)
        return 1


def cmd_verify(args: argparse.Namespace) -> int:
    """Verify cryptographic integrity of backup."""
    repo_dir = Path(args.repo).resolve()
    passphrase = get_passphrase(args)
    manifests_dir = repo_dir / "manifests"

    target_id = args.backup_id
    if target_id.lower() == "latest":
        records = GFSRetentionManager.load_records_from_repo(repo_dir)
        if not records:
            print("[-] Error: No backups found in repository", file=sys.stderr)
            return 1
        latest = sorted(records, key=lambda r: r.timestamp, reverse=True)[0]
        manifest_file = Path(latest.manifest_path)
    else:
        manifest_file = manifests_dir / f"{target_id}.json"
        if not manifest_file.exists():
            manifest_file = manifests_dir / target_id
        if not manifest_file.exists():
            print(f"[-] Error: Manifest not found for backup ID: {target_id}", file=sys.stderr)
            return 1

    with open(manifest_file, "r", encoding="utf-8") as f:
        manifest = BackupManifest.model_validate_json(f.read())

    print(f"[*] Verifying backup: {manifest.backup_id}")
    tester = SandboxRestoreTester()
    test_res = tester.run_sandbox_test(manifest, repo_dir, passphrase=passphrase)

    if test_res.success:
        print(f"[+] Verification 100% SUCCESS: {test_res.files_passed}/{test_res.total_files} files verified in {test_res.duration_seconds}s")
        return 0
    else:
        print(f"[-] Verification FAILED: {test_res.files_failed}/{test_res.total_files} files corrupted or missing", file=sys.stderr)
        for err in test_res.errors:
            print(f"    - {err}", file=sys.stderr)
        return 1


def cmd_rotate(args: argparse.Namespace) -> int:
    """Evaluate and apply Grandfather-Father-Son rotation policy."""
    repo_dir = Path(args.repo).resolve()
    policy = RetentionPolicy(
        daily_count=args.daily,
        weekly_count=args.weekly,
        monthly_count=args.monthly,
    )
    manager = GFSRetentionManager(policy=policy)
    records = manager.load_records_from_repo(repo_dir)

    print(f"[*] Evaluating {len(records)} backups under GFS Policy ({policy.daily_count}d / {policy.weekly_count}w / {policy.monthly_count}m)...")
    decision = manager.evaluate(records)

    print(f"[+] Backups to KEEP ({decision.total_kept}):")
    for kept in decision.kept_backups:
        print(f"    - [{kept.tier.upper() if kept.tier else 'KEEP'}] {kept.backup_id} ({kept.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')})")

    print(f"[!] Backups to PRUNE ({decision.total_pruned}):")
    for pruned in decision.pruned_backups:
        print(f"    - {pruned.backup_id} ({pruned.timestamp.strftime('%Y-%m-%d %H:%M:%S UTC')})")

    dry_run = not getattr(args, "execute", False)
    if dry_run:
        print("[*] DRY RUN mode active. No files deleted. Pass --execute to apply pruning.")

    result = manager.prune_repository(repo_dir, decision, dry_run=dry_run)
    print(f"[+] Prune finished: {len(result.deleted_manifests)} manifests, {result.deleted_chunks_count} chunks | Reclaimed: {result.reclaimed_bytes} bytes")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    """Display repository status and statistics."""
    repo_dir = Path(args.repo).resolve()
    records = GFSRetentionManager.load_records_from_repo(repo_dir)
    chunks_dir = repo_dir / "chunks"

    total_chunks = 0
    total_chunk_bytes = 0
    if chunks_dir.exists():
        for root, _, files in os.walk(chunks_dir):
            for f in files:
                total_chunks += 1
                total_chunk_bytes += (Path(root) / f).stat().st_size

    total_logical_bytes = sum(r.total_bytes for r in records)
    total_logical_files = sum(r.total_files for r in records)

    ratio = (
        round(total_logical_bytes / total_chunk_bytes, 2)
        if total_chunk_bytes > 0
        else 1.0
    )

    status_data: dict[str, Any] = {
        "repository": str(repo_dir),
        "total_backups": len(records),
        "total_logical_files": total_logical_files,
        "total_logical_bytes": total_logical_bytes,
        "total_chunks_stored": total_chunks,
        "total_storage_bytes": total_chunk_bytes,
        "overall_deduplication_ratio": ratio,
        "backups": [
            {
                "backup_id": r.backup_id,
                "timestamp": r.timestamp.isoformat(),
                "files": r.total_files,
                "bytes": r.total_bytes,
                "tier": r.tier,
            }
            for r in sorted(records, key=lambda x: x.timestamp, reverse=True)
        ],
    }

    if getattr(args, "json", False):
        print(json.dumps(status_data, indent=2))
    else:
        print("=" * 60)
        print("  ENCRYPTED BACKUP ORCHESTRATOR — REPOSITORY STATUS")
        print("=" * 60)
        print(f"Repository:               {status_data['repository']}")
        print(f"Total Backups:            {status_data['total_backups']}")
        print(f"Logical Data:             {status_data['total_logical_bytes']:,} bytes across {status_data['total_logical_files']} files")
        print(f"Deduplicated Storage:     {status_data['total_storage_bytes']:,} bytes in {status_data['total_chunks_stored']} chunks")
        print(f"Deduplication / Savings:  {ratio}:1")
        print("-" * 60)
        print("Recent Backups:")
        for b in status_data["backups"][:10]:
            print(f"  * {b['backup_id']} | {b['timestamp']} | {b['bytes']:,} B | {b['tier'] or 'unclassified'}")
        print("=" * 60)

    return 0


def build_parser() -> argparse.ArgumentParser:
    """Build the top-level argument parser."""
    parser = argparse.ArgumentParser(
        prog="backup-orchestrator",
        description="Enterprise DR Incremental Backup Orchestrator with Block Deduplication & AES-256-GCM",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # Backup command
    p_backup = subparsers.add_parser("backup", help="Create an incremental encrypted backup")
    p_backup.add_argument("--source", "-s", required=True, help="Source directory to back up")
    p_backup.add_argument("--repo", "-r", required=True, help="Target repository directory")
    p_backup.add_argument("--passphrase", "-p", help="Encryption passphrase (or set BACKUP_PASSPHRASE)")
    p_backup.add_argument("--no-encrypt", action="store_true", help="Disable AES-256-GCM encryption")
    p_backup.add_argument("--compress", "-c", default="zstd", choices=["zstd", "gzip", "none"], help="Compression format")
    p_backup.add_argument("--chunk-size", type=int, default=65536, help="Chunk size in bytes (default: 65536)")
    p_backup.add_argument("--name", "-n", help="Optional descriptive name for backup")
    p_backup.add_argument("--iterations", type=int, default=600000, help="PBKDF2 iteration count (default: 600000)")
    p_backup.add_argument("--verify-sandbox", action="store_true", help="Run automated sandbox restore verification after backup")

    # Restore command
    p_restore = subparsers.add_parser("restore", help="Restore files from a backup")
    p_restore.add_argument("--repo", "-r", required=True, help="Repository directory")
    p_restore.add_argument("--backup-id", "-b", default="latest", help="Backup ID or 'latest'")
    p_restore.add_argument("--target", "-t", required=True, help="Target restore directory")
    p_restore.add_argument("--passphrase", "-p", help="Decryption passphrase (or set BACKUP_PASSPHRASE)")

    # Verify command
    p_verify = subparsers.add_parser("verify", help="Verify backup integrity in isolated sandbox")
    p_verify.add_argument("--repo", "-r", required=True, help="Repository directory")
    p_verify.add_argument("--backup-id", "-b", default="latest", help="Backup ID or 'latest'")
    p_verify.add_argument("--passphrase", "-p", help="Decryption passphrase")
    p_verify.add_argument("--sandbox", action="store_true", default=True, help="Execute in temporary sandbox")

    # Rotate command
    p_rotate = subparsers.add_parser("rotate", help="Apply Grandfather-Father-Son (GFS) rotation policy")
    p_rotate.add_argument("--repo", "-r", required=True, help="Repository directory")
    p_rotate.add_argument("--daily", "-d", type=int, default=7, help="Son: daily backups to keep (default: 7)")
    p_rotate.add_argument("--weekly", "-w", type=int, default=4, help="Father: weekly backups to keep (default: 4)")
    p_rotate.add_argument("--monthly", "-m", type=int, default=12, help="Grandfather: monthly backups to keep (default: 12)")
    p_rotate.add_argument("--execute", action="store_true", help="Execute actual deletion (default is dry-run)")

    # Status command
    p_status = subparsers.add_parser("status", help="Display repository status and statistics")
    p_status.add_argument("--repo", "-r", required=True, help="Repository directory")
    p_status.add_argument("--json", action="store_true", help="Output status as JSON")

    return parser


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)

    dispatch = {
        "backup": cmd_backup,
        "restore": cmd_restore,
        "verify": cmd_verify,
        "rotate": cmd_rotate,
        "status": cmd_status,
    }

    handler = dispatch.get(args.command)
    if not handler:
        parser.print_help()
        return 1

    try:
        return handler(args)
    except Exception as exc:
        print(f"[-] Fatal error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
