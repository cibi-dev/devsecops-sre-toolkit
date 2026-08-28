"""Performance and throughput benchmark runner for container-secret-scanner."""

from __future__ import annotations

import io
import json
import os
import platform
import sys
import tarfile
import tempfile
import time
from pathlib import Path

# Add src to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from scanner.engine import ScanOptions, SecretScannerEngine


def generate_benchmark_fixtures(target_dir: Path, file_count: int = 150) -> list[Path]:
    """Generate synthetic project files with realistic code, config, and secret density."""
    files: list[Path] = []

    # Clean templates
    clean_templates = [
        "def compute_metrics(x: list[int]) -> dict:\n    return {'sum': sum(x), 'len': len(x)}\n" * 10,
        "import os\nimport sys\n\nclass DataProcessor:\n    def process(self, item):\n        return item.strip().lower()\n" * 15,
        '{\n  "name": "enterprise-service",\n  "version": "2.4.1",\n  "dependencies": {\n    "express": "^4.19.0"\n  }\n}\n' * 8,
        "server:\n  port: 8080\n  host: 0.0.0.0\n  logging:\n    level: INFO\n    format: json\n" * 12,
    ]

    # Secret injections (synthetic strings constructed dynamically)
    secret_injections = [
        "AWS_ACCESS_KEY_ID = '" + "AKIA" + "IOSFODNN7EXAMPLE'\n",
        "GITHUB_TOKEN = '" + "ghp_" + "1234567890abcdefghijklmnopqrstuvwxyz'\n",
        "STRIPE_KEY = '" + "sk_live_" + "51AbCdEfGhIjKlMnOpQrStUvWxYz0123'\n",
        "SLACK_BOT_TOKEN = '" + "xoxb-" + "123456789012-123456789012-abcdefghijklmnopqrstuvwx'\n",
    ]

    for i in range(file_count):
        subdir = target_dir / f"sub_{i % 10}"
        subdir.mkdir(parents=True, exist_ok=True)

        ext = [".py", ".json", ".yaml", ".js", ".env.sample"][i % 5]
        file_path = subdir / f"file_{i:04d}{ext}"

        base_content = clean_templates[i % len(clean_templates)]
        if i % 15 == 0:
            # Inject secret every 15 files
            secret = secret_injections[(i // 15) % len(secret_injections)]
            base_content += "\n" + secret

        # Duplicate to create realistic file sizes (~5KB to 30KB)
        multiplier = (i % 5) + 1
        final_content = base_content * multiplier

        file_path.write_text(final_content, encoding="utf-8")
        files.append(file_path)

    return files


def generate_benchmark_tar(files: list[Path], tar_path: Path) -> int:
    """Pack files into a TAR archive for container layer benchmark."""
    total_bytes = 0
    with tarfile.open(tar_path, "w") as tar:
        for f in files:
            arcname = str(f.name)
            tar.add(f, arcname=arcname)
            total_bytes += f.stat().st_size
    return total_bytes


def run_benchmark() -> dict:
    """Execute complete benchmark suite."""
    print("=" * 68)
    print(" 🚀 RUNNING CONTAINER-SECRET-SCANNER BENCHMARK SUITE")
    print("=" * 68)

    with tempfile.TemporaryDirectory() as temp_dir:
        temp_path = Path(temp_dir)
        fixture_dir = temp_path / "fixtures"
        fixture_dir.mkdir()

        print("📦 Generating 150 synthetic source & config files...")
        files = generate_benchmark_fixtures(fixture_dir, file_count=150)
        total_source_bytes = sum(f.stat().st_size for f in files)
        total_source_mb = total_source_bytes / (1024 * 1024)

        tar_path = temp_path / "container_layer.tar"
        print("📦 Packing into container layer TAR archive...")
        generate_benchmark_tar(files, tar_path)

        # 1. Directory Scan Benchmark (4 Workers)
        print("⚡ Benchmarking Directory Scan (ThreadPool: 4 workers)...")
        engine_dir = SecretScannerEngine(options=ScanOptions(max_workers=4))

        # Warmup
        engine_dir.scan_directory(fixture_dir)

        # Iterations
        iterations = 5
        dir_durations = []
        dir_findings = 0
        for _ in range(iterations):
            start = time.perf_counter()
            summary = engine_dir.scan_directory(fixture_dir)
            dur = time.perf_counter() - start
            dir_durations.append(dur)
            dir_findings = len(summary.findings)

        avg_dir_duration = sum(dir_durations) / len(dir_durations)
        dir_files_per_sec = len(files) / avg_dir_duration
        dir_mb_per_sec = total_source_mb / avg_dir_duration

        # 2. TAR Stream In-Memory Scan Benchmark
        print("⚡ Benchmarking OCI TAR In-Memory Stream Scan...")
        engine_tar = SecretScannerEngine()

        # Warmup
        engine_tar.scan_tar(tar_path)

        tar_durations = []
        tar_findings = 0
        for _ in range(iterations):
            start = time.perf_counter()
            summary_tar = engine_tar.scan_tar(tar_path)
            dur = time.perf_counter() - start
            tar_durations.append(dur)
            tar_findings = len(summary_tar.findings)

        avg_tar_duration = sum(tar_durations) / len(tar_durations)
        tar_files_per_sec = len(files) / avg_tar_duration
        tar_mb_per_sec = total_source_mb / avg_tar_duration

        results = {
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "system": {
                "python_version": platform.python_version(),
                "os": platform.system(),
                "platform": platform.platform(),
                "cpu_count": os.cpu_count() or 1,
            },
            "dataset": {
                "files_count": len(files),
                "total_bytes": total_source_bytes,
                "total_mb": round(total_source_mb, 4),
            },
            "directory_scan": {
                "workers": 4,
                "iterations": iterations,
                "avg_duration_seconds": round(avg_dir_duration, 4),
                "throughput_files_per_second": round(dir_files_per_sec, 2),
                "throughput_mb_per_second": round(dir_mb_per_sec, 2),
                "findings_detected": dir_findings,
            },
            "tar_stream_scan": {
                "iterations": iterations,
                "avg_duration_seconds": round(avg_tar_duration, 4),
                "throughput_files_per_second": round(tar_files_per_sec, 2),
                "throughput_mb_per_second": round(tar_mb_per_sec, 2),
                "findings_detected": tar_findings,
            },
        }

        # Save to benchmarks/resultados.json
        output_file = PROJECT_ROOT / "benchmarks" / "resultados.json"
        output_file.write_text(json.dumps(results, indent=2), encoding="utf-8")

        print("\n" + "=" * 68)
        print(" 📊 BENCHMARK RESULTS SUMMARY")
        print("=" * 68)
        print(f"Files Processed:         {len(files)} files ({total_source_mb:.2f} MB)")
        print(f"Directory Scan Speed:    {dir_files_per_sec:.2f} files/sec | {dir_mb_per_sec:.2f} MB/sec")
        print(f"TAR Stream Scan Speed:   {tar_files_per_sec:.2f} files/sec | {tar_mb_per_sec:.2f} MB/sec")
        print(f"Secrets Discovered:      {dir_findings}")
        print(f"Results Saved:           {output_file}")
        print("=" * 68)

        return results


if __name__ == "__main__":
    run_benchmark()
