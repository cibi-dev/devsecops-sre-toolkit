"""
Performance Benchmark Suite for Encrypted Backup Orchestrator.

Measures throughput (MB/s), deduplication ratio, compression ratio,
and end-to-end disaster recovery cycle durations.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import time

# Ensure src is in sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from backup.compress import Compressor, CompressionAlgorithm
from backup.crypto import CryptoEngine
from backup.restore_tester import SandboxRestoreTester
from backup.scanner import FileScanner, BackupManifest


def generate_benchmark_dataset(target_dir: Path, target_mb: int = 10) -> int:
    """Generate a representative mix of text, compressible logs, and repeated chunks."""
    target_dir.mkdir(parents=True, exist_ok=True)
    total_bytes = 0

    # 1. Compressible log files (with repeated patterns)
    log_sample = (
        "2026-08-27 12:00:00.123 [INFO] worker-pool-01: Processing transaction id="
        "TXN_9876543210 status=SUCCESS latency_ms=4.52 error_code=NONE user_id=USER_44921\n"
    ).encode("utf-8") * 500  # ~75KB per block

    for i in range(10):
        fpath = target_dir / f"access_log_{i:02d}.log"
        content = log_sample * 4  # ~300KB
        fpath.write_bytes(content)
        total_bytes += len(content)

    # 2. Duplicate data files (testing deduplication)
    dup_block = (b"DUPLICATE_SHARED_BLOCK_PAYLOAD_ABCDEF0123456789\n" * 1024) # ~48KB
    for i in range(20):
        fpath = target_dir / f"duplicate_doc_{i:02d}.dat"
        content = dup_block * 4 # ~192KB
        fpath.write_bytes(content)
        total_bytes += len(content)

    # 3. Random binary data (incompressible payload)
    for i in range(5):
        fpath = target_dir / f"random_binary_{i:02d}.bin"
        content = os.urandom(256 * 1024) # 256KB
        fpath.write_bytes(content)
        total_bytes += len(content)

    return total_bytes


def run_benchmarks() -> dict:
    """Execute complete benchmark suite and return metrics."""
    temp_root = Path(tempfile.mkdtemp(prefix="ebo_benchmark_"))
    try:
        source_dir = temp_root / "dataset"
        repo_dir = temp_root / "repo"
        chunks_dir = repo_dir / "chunks"
        manifests_dir = repo_dir / "manifests"

        chunks_dir.mkdir(parents=True)
        manifests_dir.mkdir(parents=True)

        print("[*] Generating benchmark dataset...")
        total_bytes = generate_benchmark_dataset(source_dir, target_mb=10)
        total_mb = total_bytes / (1024 * 1024)
        print(f"[+] Dataset created: {total_mb:.2f} MB ({total_bytes:,} bytes)")

        # 1. Benchmark: Scan & Deduplication
        print("[*] Benchmarking Scanner & SHA-256 Block Deduplication...")
        scanner = FileScanner(source_dir, chunk_size=65536)
        t0 = time.perf_counter()
        scan_result, chunk_pool = scanner.scan()
        t_scan = time.perf_counter() - t0
        scan_throughput_mb_s = round(total_mb / t_scan, 2)
        print(f"    - Scan time: {t_scan:.4f}s | Throughput: {scan_throughput_mb_s} MB/s | Dedup Ratio: {scan_result.deduplication_ratio}:1")

        # 2. Benchmark: Zstandard Compression
        print("[*] Benchmarking Zstandard Block Compression...")
        all_raw_chunks = b"".join(chunk_pool.values())
        raw_chunks_mb = len(all_raw_chunks) / (1024 * 1024)
        t0 = time.perf_counter()
        compressed_chunks = []
        for chunk in chunk_pool.values():
            comp, _ = Compressor.compress(chunk, algorithm=CompressionAlgorithm.ZSTD, level=3)
            compressed_chunks.append(comp)
        t_compress = time.perf_counter() - t0
        compress_throughput_mb_s = round(raw_chunks_mb / t_compress, 2)
        all_comp_bytes = sum(len(c) for c in compressed_chunks)
        comp_ratio = round(len(all_raw_chunks) / all_comp_bytes, 2) if all_comp_bytes > 0 else 1.0
        print(f"    - Compression time: {t_compress:.4f}s | Throughput: {compress_throughput_mb_s} MB/s | Ratio: {comp_ratio}:1")

        # 3. Benchmark: AES-256-GCM Encryption
        print("[*] Benchmarking AES-256-GCM Encryption...")
        passphrase = "BenchmarkPassphrase#2026!"
        t0 = time.perf_counter()
        encrypted_chunks = []
        for comp in compressed_chunks:
            enc = CryptoEngine.encrypt(comp, passphrase=passphrase, iterations=1000)
            encrypted_chunks.append(enc)
        t_encrypt = time.perf_counter() - t0
        encrypt_throughput_mb_s = round(raw_chunks_mb / t_encrypt, 2)
        print(f"    - Encryption time: {t_encrypt:.4f}s | Throughput: {encrypt_throughput_mb_s} MB/s")

        # Store chunks to disk for E2E restore test
        for (chunk_hash, _), enc in zip(chunk_pool.items(), encrypted_chunks):
            sub = chunks_dir / chunk_hash[:2]
            sub.mkdir(exist_ok=True)
            (sub / chunk_hash).write_bytes(enc)

        manifest = BackupManifest(
            backup_id="bkp_bench_001",
            timestamp="2026-08-27T20:00:00Z",
            source_path=str(source_dir),
            total_files=scan_result.total_files,
            total_bytes=scan_result.total_bytes,
            unique_chunks=scan_result.unique_chunks_count,
            compression_algorithm="zstd",
            is_encrypted=True,
            kdf_iterations=1000,
            files=scan_result.files,
            chunk_hashes=scan_result.chunk_hashes,
        )

        # 4. Benchmark: End-to-End Sandbox Restore & 100% SHA-256 Verification
        print("[*] Benchmarking Automated Sandbox Restore & SHA-256 Verification...")
        tester = SandboxRestoreTester()
        t0 = time.perf_counter()
        test_result = tester.run_sandbox_test(manifest, repo_dir, passphrase=passphrase)
        t_restore = time.perf_counter() - t0
        restore_throughput_mb_s = round(total_mb / t_restore, 2)
        print(f"    - Restore time: {t_restore:.4f}s | Throughput: {restore_throughput_mb_s} MB/s | Verified: {test_result.verification_rate}%")

        total_e2e_time = round(t_scan + t_compress + t_encrypt + t_restore, 4)

        results = {
            "timestamp": "2026-08-27T20:00:00Z",
            "dataset": {
                "total_files": scan_result.total_files,
                "total_bytes": total_bytes,
                "total_mb": round(total_mb, 2),
                "unique_chunks": scan_result.unique_chunks_count,
                "deduplication_ratio": scan_result.deduplication_ratio,
            },
            "metrics": {
                "scan_dedup_throughput_mb_s": scan_throughput_mb_s,
                "compression_throughput_mb_s": compress_throughput_mb_s,
                "compression_ratio": comp_ratio,
                "encryption_throughput_mb_s": encrypt_throughput_mb_s,
                "sandbox_restore_throughput_mb_s": restore_throughput_mb_s,
                "e2e_total_duration_s": total_e2e_time,
                "verification_pass_rate_pct": test_result.verification_rate,
            },
            "status": "PASS" if test_result.success else "FAIL",
        }

        return results
    finally:
        shutil.rmtree(temp_root, ignore_errors=True)


def main():
    results = run_benchmarks()
    out_file = Path(__file__).resolve().parent / "resultados.json"
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"\n[+] Benchmark metrics saved to: {out_file}")
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
