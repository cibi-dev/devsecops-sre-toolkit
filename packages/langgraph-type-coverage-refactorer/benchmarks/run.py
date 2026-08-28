"""Benchmark suite for langgraph-type-coverage-refactorer.

Measures AST parsing rate, type annotation throughput, test generation rate,
and end-to-end multi-agent refactoring latency.
Outputs structured metrics to benchmarks/resultados.json.
"""

from __future__ import annotations

import json
import os
import time
from typing import Any, Dict

from refactorer.graph import run_refactorer
from refactorer.inspector import ASTInspector
from refactorer.nodes.annotator import TypeAnnotator
from refactorer.nodes.test_gen import TestGenerator

SAMPLE_MODULE_UNITS = [
    """def calculate_discount(price, discount_rate=0.1):
    if price < 0:
        raise ValueError("Negative price")
    if discount_rate > 0.5:
        discount_rate = 0.5
    return price * (1.0 - discount_rate)
""",
    """class UserAccount:
    def __init__(self, username, balance=0):
        self.username = username
        self.balance = balance
        self.transactions = []

    def deposit(self, amount):
        if amount <= 0:
            raise ValueError("Deposit must be positive")
        self.balance += amount
        self.transactions.append(amount)
        return self.balance

    def withdraw(self, amount):
        if amount > self.balance:
            return False
        self.balance -= amount
        self.transactions.append(-amount)
        return True
""",
    """def parse_records(items, strict=False):
    parsed = []
    for item in items:
        if isinstance(item, dict) and "id" in item:
            parsed.append(str(item["id"]))
        elif strict:
            raise TypeError("Invalid item structure")
    return parsed
""",
]


def run_benchmarks() -> Dict[str, Any]:
    print("=" * 65)
    print(" Running Refactorer Performance Benchmarks...")
    print("=" * 65)

    inspector = ASTInspector()
    annotator = TypeAnnotator()
    generator = TestGenerator()

    # 1. AST Inspector Benchmark
    start_time = time.perf_counter()
    num_inspect_runs = 200
    total_issues = 0
    total_branches = 0
    for _ in range(num_inspect_runs):
        for code in SAMPLE_MODULE_UNITS:
            issues, branches, _ = inspector.inspect_source(code)
            total_issues += len(issues)
            total_branches += len(branches)
    inspect_duration = time.perf_counter() - start_time
    total_inspect_files = num_inspect_runs * len(SAMPLE_MODULE_UNITS)
    inspect_rate = total_inspect_files / inspect_duration

    print(f" AST Inspection Rate        : {inspect_rate:.2f} files/sec ({inspect_duration*1000/total_inspect_files:.3f} ms/file)")

    # 2. Type Annotator Benchmark
    start_time = time.perf_counter()
    num_annot_runs = 100
    annotated_chars = 0
    for _ in range(num_annot_runs):
        for code in SAMPLE_MODULE_UNITS:
            annotated = annotator.refactor_source(code)
            annotated_chars += len(annotated)
    annot_duration = time.perf_counter() - start_time
    total_annot_files = num_annot_runs * len(SAMPLE_MODULE_UNITS)
    annot_rate = total_annot_files / annot_duration

    print(f" Type Annotation Rate       : {annot_rate:.2f} files/sec ({annot_duration*1000/total_annot_files:.3f} ms/file)")

    # 3. Test Generation Benchmark
    start_time = time.perf_counter()
    num_gen_runs = 100
    total_tests_generated = 0
    for _ in range(num_gen_runs):
        for code in SAMPLE_MODULE_UNITS:
            tests = generator.generate_tests_for_source(code)
            total_tests_generated += tests.count("def test_")
    gen_duration = time.perf_counter() - start_time
    total_gen_files = num_gen_runs * len(SAMPLE_MODULE_UNITS)
    gen_rate = total_tests_generated / gen_duration

    print(f" Test Generation Throughput : {gen_rate:.2f} tests/sec ({gen_duration*1000/total_gen_files:.3f} ms/module)")

    # 4. End-to-End Multi-Agent Convergence Benchmark
    start_time = time.perf_counter()
    e2e_state = run_refactorer(
        source_code=SAMPLE_MODULE_UNITS[0],
        target_path="discount_calc.py",
        target_coverage=90.0,
        strict_mode=True,
        max_iterations=2,
    )
    e2e_duration = time.perf_counter() - start_time
    e2e_cov = (
        e2e_state.verification_history[-1].coverage_pct
        if e2e_state.verification_history
        else 0.0
    )

    print(f" E2E Workflow Convergence   : {e2e_duration*1000:.2f} ms (Coverage: {e2e_cov:.1f}%, Status: {'PASSED' if e2e_state.is_complete else 'ITER_MAX'})")
    print("=" * 65)

    results: Dict[str, Any] = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "environment": {
            "python_version": "3.10+",
            "platform": "linux",
        },
        "metrics": {
            "ast_inspection_files_per_sec": round(inspect_rate, 2),
            "ast_inspection_ms_per_file": round(inspect_duration * 1000 / total_inspect_files, 3),
            "type_annotation_files_per_sec": round(annot_rate, 2),
            "type_annotation_ms_per_file": round(annot_duration * 1000 / total_annot_files, 3),
            "test_generation_tests_per_sec": round(gen_rate, 2),
            "test_generation_ms_per_module": round(gen_duration * 1000 / total_gen_files, 3),
            "e2e_convergence_latency_ms": round(e2e_duration * 1000, 2),
            "e2e_achieved_coverage_pct": e2e_cov,
            "e2e_success": e2e_state.is_complete,
        },
    }

    base_dir = os.path.dirname(os.path.abspath(__file__))
    out_file = os.path.join(base_dir, "resultados.json")
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f" Benchmark results written to: {out_file}\n")

    return results


if __name__ == "__main__":
    run_benchmarks()
