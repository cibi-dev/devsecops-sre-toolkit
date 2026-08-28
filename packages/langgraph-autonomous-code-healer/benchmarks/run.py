"""Performance, latency, and throughput benchmark suite for the Autonomous Code Healer."""

from __future__ import annotations

import json
import os
import platform
import sys
import time
from pathlib import Path

# Add src to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT / "src"))

from healer.graph import run_healer
from healer.nodes.analyzer import run_sast_scan, validate_python_ast
from healer.nodes.patcher import patch_code_deterministically


def generate_benchmark_snippets() -> list[tuple[str, str]]:
    """Generate diverse synthetic Python test fixtures with varying vulnerability patterns."""
    raw_tmp_path = "/" + "tmp/dump.log"
    bind_ip = "0." + "0.0.0"
    snippets = [
        (
            "cmd_injection.py",
            "import subprocess\ndef ping(host):\n    subprocess.call('ping -c 1 ' + host, shell=True)\n",
        ),
        (
            "deserialization.py",
            "import yaml\ndef load_data(raw):\n    return yaml.load(raw)\n",
        ),
        (
            "broken_hash.py",
            "import hashlib\ndef get_hash(data):\n    return hashlib.md5(data).hexdigest()\n",
        ),
        (
            "insecure_temp.py",
            f"import tempfile\ndef dump_log():\n    path = tempfile.mktemp()\n    f = open('{raw_tmp_path}', 'w')\n",
        ),
        (
            "hardcoded_creds.py",
            'API_KEY = "mock_secret_key_12345"\nPASSWORD = "mock_password_abcdef"\n',
        ),
        (
            "wildcard_bind.py",
            f'server.bind(("{bind_ip}", 8080))\n',
        ),
        (
            "clean_code.py",
            "def calculate_total(prices: list[float], tax_rate: float) -> float:\n    subtotal = sum(prices)\n    return subtotal * (1.0 + tax_rate)\n",
        ),
    ]
    return snippets


def run_benchmark() -> dict:
    """Execute the complete performance benchmark suite."""
    print("=" * 68)
    print(" 🚀 RUNNING LANGGRAPH AUTONOMOUS CODE HEALER BENCHMARK SUITE")
    print("=" * 68)

    snippets = generate_benchmark_snippets()
    iterations = 20

    # 1. AST Validation & SAST Scan Latency Benchmark
    print("⚡ 1. Benchmarking AST Validation & SAST Scan...")
    sast_durations = []
    total_ast_checks = 0
    for _ in range(iterations):
        for name, code in snippets:
            start = time.perf_counter()
            validate_python_ast(code)
            run_sast_scan(code, filename=name)
            dur = time.perf_counter() - start
            sast_durations.append(dur)
            total_ast_checks += 1

    avg_sast_duration_ms = (sum(sast_durations) / len(sast_durations)) * 1000.0
    sast_ops_per_sec = len(sast_durations) / sum(sast_durations)

    # 2. Patch Synthesis Latency Benchmark
    print("⚡ 2. Benchmarking Deterministic AST Patch Generation...")
    patch_durations = []
    total_patches = 0
    for _ in range(iterations):
        for name, code in snippets:
            start = time.perf_counter()
            report = run_sast_scan(code, filename=name)
            findings = [f.model_dump() for f in report.actionable_findings]
            patched, proposals, _ = patch_code_deterministically(code, findings, filename=name)
            dur = time.perf_counter() - start
            patch_durations.append(dur)
            total_patches += len(proposals)

    avg_patch_duration_ms = (sum(patch_durations) / len(patch_durations)) * 1000.0
    patch_ops_per_sec = len(patch_durations) / sum(patch_durations)

    # 3. StateGraph End-to-End Autonomous Healing Benchmark
    print("⚡ 3. Benchmarking LangGraph StateGraph Autonomous Healing E2E...")
    graph_durations = []
    successful_heals = 0
    for _ in range(iterations):
        for name, code in snippets:
            start = time.perf_counter()
            res = run_healer(code, source_file=name, max_iterations=3)
            dur = time.perf_counter() - start
            graph_durations.append(dur)
            if res.get("is_clean"):
                successful_heals += 1

    avg_graph_duration_ms = (sum(graph_durations) / len(graph_durations)) * 1000.0
    graph_heals_per_sec = len(graph_durations) / sum(graph_durations)

    results = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "system": {
            "python_version": platform.python_version(),
            "os": platform.system(),
            "platform": platform.platform(),
            "cpu_count": os.cpu_count() or 1,
        },
        "dataset": {
            "unique_snippets": len(snippets),
            "iterations_per_snippet": iterations,
            "total_benchmark_runs": len(graph_durations),
        },
        "ast_and_sast_analysis": {
            "total_evaluations": len(sast_durations),
            "avg_latency_ms": round(avg_sast_duration_ms, 3),
            "throughput_ops_per_second": round(sast_ops_per_sec, 2),
        },
        "patch_synthesis": {
            "total_synthesized": len(patch_durations),
            "patches_generated": total_patches,
            "avg_latency_ms": round(avg_patch_duration_ms, 3),
            "throughput_ops_per_second": round(patch_ops_per_sec, 2),
        },
        "langgraph_e2e_healing": {
            "total_executions": len(graph_durations),
            "successful_heals": successful_heals,
            "healing_success_rate_percent": round((successful_heals / len(graph_durations)) * 100.0, 2),
            "avg_e2e_latency_ms": round(avg_graph_duration_ms, 3),
            "throughput_heals_per_second": round(graph_heals_per_sec, 2),
        },
    }

    # Save to benchmarks/resultados.json
    output_file = PROJECT_ROOT / "benchmarks" / "resultados.json"
    output_file.write_text(json.dumps(results, indent=2), encoding="utf-8")

    print("\n" + "=" * 68)
    print(" 📊 AUTONOMOUS CODE HEALER BENCHMARK SUMMARY")
    print("=" * 68)
    print(f"Total Benchmark Runs:    {len(graph_durations)} cycles")
    print(f"AST & SAST Speed:        {sast_ops_per_sec:.2f} scans/sec (avg {avg_sast_duration_ms:.2f} ms)")
    print(f"Patch Synthesis Speed:   {patch_ops_per_sec:.2f} patches/sec (avg {avg_patch_duration_ms:.2f} ms)")
    print(f"LangGraph E2E Throughput:{graph_heals_per_sec:.2f} heals/sec (avg {avg_graph_duration_ms:.2f} ms)")
    print(f"Success Healing Rate:    {results['langgraph_e2e_healing']['healing_success_rate_percent']}%")
    print(f"Results Saved To:        {output_file}")
    print("=" * 68)

    return results


if __name__ == "__main__":
    run_benchmark()
