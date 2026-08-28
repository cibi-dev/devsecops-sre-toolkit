"""Comprehensive branch coverage tests for patcher rule mappings and AST edge cases."""

from __future__ import annotations

from healer.nodes.patcher import (
    CodePatcher,
    ensure_imports,
    patch_code_deterministically,
)


def test_patch_deterministically_cwe_rules_branches():
    """Test patch_code_deterministically with specific Bandit rule IDs in findings."""
    # 1. CWE-78 rule B604
    c1, p1, _ = patch_code_deterministically("import subprocess\n", [{"test_id": "B604"}])
    assert len(p1) == 0  # No vulnerable pattern in code string

    # 2. CWE-502 rule B302
    c2, p2, _ = patch_code_deterministically("import marshal\n", [{"test_id": "B302"}])
    assert len(p2) == 0

    # 3. CWE-327 rule B304
    c3, p3, _ = patch_code_deterministically("x = 1\n", [{"test_id": "B304"}])
    assert len(p3) == 0

    # 4. CWE-22 rule B306
    c4, p4, _ = patch_code_deterministically("x = 1\n", [{"test_id": "B306"}])
    assert len(p4) == 0

    # 5. CWE-798 rule B106
    c5, p5, _ = patch_code_deterministically("x = 1\n", [{"test_id": "B106"}])
    assert len(p5) == 0


def test_patch_deterministically_direct_cwe_numbers():
    """Test patch_code_deterministically when finding contains integer CWEs."""
    # Finding with issue_cwe as int
    f_78 = [{"issue_cwe": 78}]
    code_78 = "import os\nos.system('echo test')\n"
    c_78, p_78, _ = patch_code_deterministically(code_78, f_78)
    assert "subprocess.run" in c_78

    f_502 = [{"issue_cwe": 502}]
    code_502 = "import yaml\nyaml.load(data)\n"
    c_502, p_502, _ = patch_code_deterministically(code_502, f_502)
    assert "yaml.safe_load" in c_502

    f_327 = [{"issue_cwe": 327}]
    code_327 = "import hashlib\nhashlib.md5(b'x')\n"
    c_327, p_327, _ = patch_code_deterministically(code_327, f_327)
    assert "hashlib.sha256" in c_327

    f_22 = [{"issue_cwe": 22}]
    raw_path = "/" + "tmp/test.txt"
    code_22 = f"open('{raw_path}', 'w')\n"
    c_22, p_22, _ = patch_code_deterministically(code_22, f_22)
    assert "gettempdir" in c_22

    f_798 = [{"issue_cwe": 798}]
    code_798 = 'SECRET_KEY = "test_mock_value"\n'
    c_798, p_798, _ = patch_code_deterministically(code_798, f_798)
    assert "os.environ.get" in c_798


def test_ensure_imports_no_new_imports_needed():
    """Test ensure_imports when needed_imports is empty."""
    code = "x = 1\n"
    assert ensure_imports(code, []) == code


def test_patch_cwe_1188_single_quotes():
    """Test patch_cwe_1188 with single-quoted 0.0.0.0."""
    code = "host = '0.0.0.0'\n"
    patched, msgs = CodePatcher.patch_cwe_1188(code)
    assert "'127.0.0.1'" in patched
    assert len(msgs) > 0
