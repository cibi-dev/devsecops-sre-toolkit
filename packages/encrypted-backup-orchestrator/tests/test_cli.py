"""Tests for Command-Line Interface (CLI)."""

import argparse
import json
from pathlib import Path
import pytest

from backup.cli import main, get_passphrase


def test_cli_get_passphrase(monkeypatch):
    """Test get_passphrase resolution from args and env."""
    args1 = argparse.Namespace(no_encrypt=True, passphrase="custom")
    assert get_passphrase(args1) is None

    args2 = argparse.Namespace(no_encrypt=False, passphrase="cli_password")
    assert get_passphrase(args2) == "cli_password"

    args3 = argparse.Namespace(no_encrypt=False, passphrase=None)
    monkeypatch.setenv("BACKUP_PASSPHRASE", "env_secret")
    assert get_passphrase(args3) == "env_secret"

    monkeypatch.delenv("BACKUP_PASSPHRASE", raising=False)
    assert get_passphrase(args3) is None


def test_cli_backup_restore_and_verify(tmp_path: Path, capsys):
    """Test full CLI lifecycle: backup -> verify -> restore -> status -> rotate."""
    source_dir = tmp_path / "src_data"
    source_dir.mkdir()
    (source_dir / "app.conf").write_text("server_port = 8080\nmax_connections = 100")
    (source_dir / "notes.txt").write_text("Disaster recovery notes 2026")

    repo_dir = tmp_path / "backup_repo"
    restore_dir = tmp_path / "restore_out"

    # 1. Backup with AES-256-GCM + zstd + fast test iterations + sandbox verify + custom name
    ret = main([
        "backup",
        "--source", str(source_dir),
        "--repo", str(repo_dir),
        "--name", "daily_prod_backup",
        "--passphrase", "MasterPassword2026!",
        "--iterations", "2000",
        "--verify-sandbox",
    ])
    assert ret == 0

    # 2. Verify command with explicit backup ID
    manifests_dir = repo_dir / "manifests"
    manifest_files = list(manifests_dir.glob("*.json"))
    assert len(manifest_files) == 1
    bkp_id = manifest_files[0].stem

    ret = main([
        "verify",
        "--repo", str(repo_dir),
        "--backup-id", bkp_id,
        "--passphrase", "MasterPassword2026!",
    ])
    assert ret == 0

    # 3. Restore command with explicit backup ID
    ret = main([
        "restore",
        "--repo", str(repo_dir),
        "--backup-id", bkp_id,
        "--target", str(restore_dir),
        "--passphrase", "MasterPassword2026!",
    ])
    assert ret == 0
    assert (restore_dir / "app.conf").read_text() == (source_dir / "app.conf").read_text()
    assert (restore_dir / "notes.txt").read_text() == (source_dir / "notes.txt").read_text()

    # 4. Status command (plain text & JSON)
    capsys.readouterr()  # Flush previous output
    ret = main(["status", "--repo", str(repo_dir)])
    assert ret == 0

    capsys.readouterr()  # Flush again
    ret = main(["status", "--repo", str(repo_dir), "--json"])
    assert ret == 0
    captured = capsys.readouterr()
    status_json = json.loads(captured.out.strip())
    assert status_json["total_backups"] >= 1
    assert status_json["total_logical_files"] == 2

    # 5. Rotate command
    ret = main(["rotate", "--repo", str(repo_dir), "--daily", "7", "--execute"])
    assert ret == 0


def test_cli_backup_no_encrypt_and_gzip(tmp_path: Path):
    """Test backup without encryption and with gzip compression."""
    source_dir = tmp_path / "gzip_src"
    source_dir.mkdir()
    (source_dir / "data.log").write_text("Log line entries" * 50)
    repo_dir = tmp_path / "gzip_repo"
    restore_dir = tmp_path / "gzip_restore"

    # Backup with no-encrypt and gzip
    ret = main([
        "backup",
        "--source", str(source_dir),
        "--repo", str(repo_dir),
        "--no-encrypt",
        "--compress", "gzip",
    ])
    assert ret == 0

    # Restore with latest
    ret = main([
        "restore",
        "--repo", str(repo_dir),
        "--backup-id", "latest",
        "--target", str(restore_dir),
    ])
    assert ret == 0
    assert (restore_dir / "data.log").read_text() == (source_dir / "data.log").read_text()


def test_cli_incremental_second_backup(tmp_path: Path):
    """Test creating a second incremental backup in same repository."""
    source_dir = tmp_path / "inc_src"
    source_dir.mkdir()
    (source_dir / "file1.txt").write_text("File 1 content")
    repo_dir = tmp_path / "inc_repo"

    # First backup
    ret1 = main([
        "backup",
        "--source", str(source_dir),
        "--repo", str(repo_dir),
        "--no-encrypt",
    ])
    assert ret1 == 0

    # Add second file
    (source_dir / "file2.txt").write_text("File 2 content")
    ret2 = main([
        "backup",
        "--source", str(source_dir),
        "--repo", str(repo_dir),
        "--no-encrypt",
    ])
    assert ret2 == 0


def test_cli_error_cases(tmp_path: Path):
    """Test CLI error handling and validation."""
    source_dir = tmp_path / "src"
    source_dir.mkdir()
    repo_dir = tmp_path / "repo"

    # Backup without passphrase when encryption is enabled
    ret = main([
        "backup",
        "--source", str(source_dir),
        "--repo", str(repo_dir),
    ])
    assert ret == 1

    # Backup with invalid compression (argparse choice validation)
    with pytest.raises(SystemExit):
        main([
            "backup",
            "--source", str(source_dir),
            "--repo", str(repo_dir),
            "--no-encrypt",
            "--compress", "invalid_algo",
        ])

    # Restore with missing manifests dir
    ret = main([
        "restore",
        "--repo", str(repo_dir),
        "--backup-id", "latest",
        "--target", str(tmp_path / "out"),
    ])
    assert ret == 1

    # Verify non-existent backup
    manifests = repo_dir / "manifests"
    manifests.mkdir(parents=True, exist_ok=True)
    ret = main([
        "verify",
        "--repo", str(repo_dir),
        "--backup-id", "non_existent_bkp",
    ])
    assert ret == 1

    # Verify latest on empty manifests dir
    ret = main([
        "verify",
        "--repo", str(repo_dir),
        "--backup-id", "latest",
    ])
    assert ret == 1

def test_cli_dry_run_rotate_and_failed_verify(tmp_path: Path, capsys):
    """Test rotate in dry-run mode and verification failure handling."""
    source_dir = tmp_path / "fail_src"
    source_dir.mkdir()
    (source_dir / "secret.txt").write_text("Confidential")
    repo_dir = tmp_path / "fail_repo"

    # Backup with passphrase
    main([
        "backup",
        "--source", str(source_dir),
        "--repo", str(repo_dir),
        "--passphrase", "CorrectPass123!",
        "--iterations", "2000",
    ])

    # Rotate without --execute (dry-run)
    capsys.readouterr()
    ret_rotate = main(["rotate", "--repo", str(repo_dir)])
    assert ret_rotate == 0
    out = capsys.readouterr().out
    assert "DRY RUN" in out

    # Verify with wrong passphrase
    ret_ver = main([
        "verify",
        "--repo", str(repo_dir),
        "--backup-id", "latest",
        "--passphrase", "WrongPass456!",
    ])
    assert ret_ver == 1

    # Restore with wrong passphrase
    ret_res = main([
        "restore",
        "--repo", str(repo_dir),
        "--backup-id", "latest",
        "--target", str(tmp_path / "fail_restore"),
        "--passphrase", "WrongPass456!",
    ])
    assert ret_res == 1


def test_cli_non_existent_source_dir(tmp_path: Path):
    """Test backup command with non-existent source directory."""
    ret = main([
        "backup",
        "--source", str(tmp_path / "ghost_dir"),
        "--repo", str(tmp_path / "repo"),
        "--no-encrypt",
    ])
    assert ret == 1
