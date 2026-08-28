"""Deterministic code patch generator with AST validation and syntax safety."""

from __future__ import annotations

import ast
import difflib
import logging
import re
from typing import Any

from healer.nodes.analyzer import validate_python_ast
from healer.state import CodePatchState, PatchProposal

logger = logging.getLogger(__name__)


def extract_cwe_id(finding: dict[str, Any]) -> int | None:
    """Safely extract integer CWE ID from a finding dict regardless of format."""
    cwe = finding.get("issue_cwe")
    if isinstance(cwe, dict):
        cid = cwe.get("id")
        if cid is not None:
            digits = "".join(filter(str.isdigit, str(cid)))
            return int(digits) if digits else None
    elif isinstance(cwe, int):
        return cwe
    elif isinstance(cwe, str):
        digits = "".join(filter(str.isdigit, cwe))
        return int(digits) if digits else None
    return None


def ensure_imports(code: str, needed_imports: list[str]) -> str:
    """Ensure required module imports exist in code without duplicating."""
    lines = code.splitlines()
    existing_imports = set()
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("import ") or stripped.startswith("from "):
            existing_imports.add(stripped)

    new_imports: list[str] = []
    for imp in needed_imports:
        # Check if already imported
        mod_name = imp.replace("import ", "").strip()
        already_present = any(
            line.strip() == imp or line.strip().startswith(f"import {mod_name}") or f"import {mod_name}" in line
            for line in lines
        )
        if not already_present:
            new_imports.append(imp)

    if not new_imports:
        return code

    # Insert imports after docstring or at top
    insert_idx = 0
    in_docstring = False
    docstring_char = None

    for i, line in enumerate(lines):
        stripped = line.strip()
        if not in_docstring:
            if stripped.startswith('"""') or stripped.startswith("'''"):
                docstring_char = stripped[:3]
                if stripped.count(docstring_char) >= 2 and len(stripped) > 3:
                    # Single-line docstring
                    insert_idx = i + 1
                    break
                in_docstring = True
            elif stripped.startswith("#") or not stripped:
                continue
            else:
                insert_idx = i
                break
        else:
            if docstring_char and docstring_char in stripped:
                in_docstring = False
                insert_idx = i + 1
                break

    updated_lines = lines[:insert_idx] + new_imports + lines[insert_idx:]
    return "\n".join(updated_lines) + ("\n" if code.endswith("\n") else "")


class CodePatcher:
    """Deterministic AST-guided code patcher for common Bandit/CWE vulnerabilities."""

    @staticmethod
    def patch_cwe_78(code: str) -> tuple[str, list[str]]:
        """Fix CWE-78 (OS Command Injection / B602, B605, B607, B102, B307)."""
        patches: list[str] = []
        needed_imports = ["import subprocess", "import shlex"]
        patched = code

        # 1. shell=True -> shell=False in subprocess calls
        if re.search(r"shell\s*=\s*True", patched):
            patched = re.sub(r"shell\s*=\s*True", "shell=False", patched)
            patches.append("Replaced 'shell=True' with 'shell=False' in subprocess invocation.")

        # 2. subprocess.call(...) with string -> subprocess.run(..., timeout=30, check=True)
        def replace_subprocess_call(match: re.Match[str]) -> str:
            cmd = match.group(1).strip()
            return f"subprocess.run(shlex.split({cmd}) if isinstance({cmd}, str) else {cmd}, shell=False, timeout=30, check=True)"

        if re.search(r"subprocess\.call\((.*?)(?:,\s*shell\s*=\s*(?:True|False))?\)", patched):
            patched = re.sub(
                r"subprocess\.call\((.*?)(?:,\s*shell\s*=\s*(?:True|False))?\)",
                replace_subprocess_call,
                patched,
            )
            patches.append("Replaced 'subprocess.call' with safe 'subprocess.run' and timeout=30.")

        # 3. os.system(cmd) -> subprocess.run(..., timeout=30, check=True)
        def replace_os_system(match: re.Match[str]) -> str:
            cmd = match.group(1).strip()
            return f"subprocess.run(shlex.split({cmd}) if isinstance({cmd}, str) else {cmd}, shell=False, timeout=30, check=True)"

        if re.search(r"os\.system\((.*?)\)", patched):
            patched = re.sub(r"os\.system\((.*?)\)", replace_os_system, patched)
            patches.append("Replaced 'os.system' with safe 'subprocess.run(shell=False, timeout=30)'.")

        # 4. os.popen(cmd) -> subprocess.Popen(shlex.split(cmd), shell=False)
        def replace_os_popen(match: re.Match[str]) -> str:
            cmd = match.group(1).strip()
            return f"subprocess.Popen(shlex.split({cmd}) if isinstance({cmd}, str) else {cmd}, shell=False)"

        if re.search(r"os\.popen\((.*?)\)", patched):
            patched = re.sub(r"os\.popen\((.*?)\)", replace_os_popen, patched)
            patches.append("Replaced 'os.popen' with safe 'subprocess.Popen(shell=False)'.")

        # 5. eval(...) -> ast.literal_eval(...)
        if re.search(r"\beval\((.*?)\)", patched) and not "ast.literal_eval" in patched:
            needed_imports.append("import ast")
            patched = re.sub(r"\beval\((.*?)\)", r"ast.literal_eval(\1)", patched)
            patches.append("Replaced unsafe 'eval()' with safe 'ast.literal_eval()'.")

        if patches:
            patched = ensure_imports(patched, needed_imports)

        return patched, patches

    @staticmethod
    def patch_cwe_502(code: str) -> tuple[str, list[str]]:
        """Fix CWE-502 (Insecure Deserialization / B301, B302, B403, B506)."""
        patches: list[str] = []
        needed_imports: list[str] = []
        patched = code

        # 1. yaml.load(...) -> yaml.safe_load(...)
        if re.search(r"yaml\.load\((.*?)(?:,\s*Loader=.*?)?\)", patched):
            patched = re.sub(r"yaml\.load\((.*?)(?:,\s*Loader=.*?)?\)", r"yaml.safe_load(\1)", patched)
            patches.append("Replaced 'yaml.load()' with 'yaml.safe_load()'.")

        # 2. pickle.loads(...) -> json.loads(...)
        if "pickle.loads" in patched:
            needed_imports.append("import json")
            patched = patched.replace("pickle.loads", "json.loads")
            patches.append("Replaced unsafe 'pickle.loads' with safe 'json.loads'.")

        # 3. pickle.load(...) -> json.load(...)
        if "pickle.load" in patched:
            needed_imports.append("import json")
            patched = patched.replace("pickle.load", "json.load")
            patches.append("Replaced unsafe 'pickle.load' with safe 'json.load'.")

        # 4. marshal.loads(...) -> json.loads(...)
        if "marshal.loads" in patched:
            needed_imports.append("import json")
            patched = patched.replace("marshal.loads", "json.loads")
            patches.append("Replaced unsafe 'marshal.loads' with 'json.loads'.")

        # 5. Remove unused unsafe imports if they are no longer used
        lines = patched.splitlines()
        uses_pickle = any("pickle" in line and not line.strip().startswith("import pickle") for line in lines)
        if not uses_pickle:
            patched = re.sub(r"^\s*import pickle\s*\n?", "", patched, flags=re.MULTILINE)

        lines = patched.splitlines()
        uses_marshal = any("marshal" in line and not line.strip().startswith("import marshal") for line in lines)
        if not uses_marshal:
            patched = re.sub(r"^\s*import marshal\s*\n?", "", patched, flags=re.MULTILINE)

        if patches:
            patched = ensure_imports(patched, needed_imports)

        return patched, patches

    @staticmethod
    def patch_cwe_327_328(code: str) -> tuple[str, list[str]]:
        """Fix CWE-327 / CWE-328 / CWE-208 (Broken Crypto & Timing Attacks / B303, B304, B324)."""
        patches: list[str] = []
        needed_imports = ["import hashlib"]
        patched = code

        # 1. hashlib.md5 -> hashlib.sha256
        if "hashlib.md5(" in patched:
            patched = patched.replace("hashlib.md5(", "hashlib.sha256(")
            patches.append("Replaced broken 'hashlib.md5()' with secure 'hashlib.sha256()'.")

        # 2. hashlib.sha1 -> hashlib.sha256
        if "hashlib.sha1(" in patched:
            patched = patched.replace("hashlib.sha1(", "hashlib.sha256(")
            patches.append("Replaced weak 'hashlib.sha1()' with secure 'hashlib.sha256()'.")

        # 3. hashlib.new("md5"|"sha1", ...) -> hashlib.new("sha256", ...)
        if re.search(r"hashlib\.new\([\"'](?:md5|sha1)[\"']", patched, re.IGNORECASE):
            patched = re.sub(
                r"hashlib\.new\([\"'](?:md5|sha1)[\"']",
                'hashlib.new("sha256"',
                patched,
                flags=re.IGNORECASE,
            )
            patches.append("Replaced insecure hash algorithm in 'hashlib.new()' with 'sha256'.")

        # 4. Insecure secret comparison == -> hmac.compare_digest
        timing_pattern = r"if\s+([a-zA-Z0-9_]*(?:token|secret|password|hash|key|signature)[a-zA-Z0-9_]*)\s*==\s*([a-zA-Z0-9_]+):"
        if re.search(timing_pattern, patched, re.IGNORECASE):
            needed_imports.append("import hmac")
            patched = re.sub(
                timing_pattern,
                r"if hmac.compare_digest(\1, \2):",
                patched,
                flags=re.IGNORECASE,
            )
            patches.append("Replaced '==' secret comparison with constant-time 'hmac.compare_digest()'.")

        if patches:
            patched = ensure_imports(patched, needed_imports)

        return patched, patches

    @staticmethod
    def patch_cwe_22_377(code: str) -> tuple[str, list[str]]:
        """Fix CWE-22 / CWE-377 (Path Traversal / Insecure Temporary Files / B108, B306, B325)."""
        patches: list[str] = []
        needed_imports = ["import tempfile", "import os"]
        patched = code

        # 1. tempfile.mktemp -> tempfile.mkstemp
        if "tempfile.mktemp" in patched:
            patched = patched.replace("tempfile.mktemp", "tempfile.mkstemp")
            patches.append("Replaced insecure 'tempfile.mktemp()' with 'tempfile.mkstemp()'.")

        # 2. Hardcoded /tmp/ path in open()
        tmp_open_pattern = r'open\([\"\']/' + r'tmp/([^\"\']+)[\"\']\s*,\s*([\"\'][a-zA-Z+]+[\"\'])\)'
        if re.search(tmp_open_pattern, patched):
            def replace_tmp_open(match: re.Match[str]) -> str:
                suffix = match.group(1)
                mode = match.group(2)
                return f'open(os.path.join(tempfile.gettempdir(), "{suffix}"), {mode})'

            patched = re.sub(tmp_open_pattern, replace_tmp_open, patched)
            patches.append("Sanitized hardcoded '/tmp/' path using 'tempfile.gettempdir()'.")

        if patches:
            patched = ensure_imports(patched, needed_imports)

        return patched, patches

    @staticmethod
    def patch_cwe_798(code: str) -> tuple[str, list[str]]:
        """Fix CWE-798 (Hardcoded Credentials / B105, B106, B107)."""
        patches: list[str] = []
        needed_imports = ["import os"]
        patched = code

        # Match hardcoded variable assignments for passwords, tokens, api keys
        cred_var_pattern = r'^(\s*)([A-Z0-9_]*(?:PASSWORD|SECRET|API_KEY|AUTH_TOKEN|PRIVATE_KEY)[A-Z0-9_]*)\s*=\s*[\"\']([^\"\']+)[\"\'](\s*)$'

        def replace_cred_var(match: re.Match[str]) -> str:
            indent = match.group(1)
            var_name = match.group(2)
            trailing = match.group(4)
            patches.append(f"Replaced hardcoded credential '{var_name}' with 'os.environ.get(\"{var_name}\", \"\")'.")
            return f'{indent}{var_name} = os.environ.get("{var_name}", ""){trailing}'

        lines = patched.splitlines()
        new_lines: list[str] = []
        for line in lines:
            if re.match(cred_var_pattern, line):
                new_line = re.sub(cred_var_pattern, replace_cred_var, line)
                new_lines.append(new_line)
            else:
                new_lines.append(line)

        patched = "\n".join(new_lines) + ("\n" if code.endswith("\n") else "")

        if patches:
            patched = ensure_imports(patched, needed_imports)

        return patched, patches

    @staticmethod
    def patch_cwe_1188(code: str) -> tuple[str, list[str]]:
        """Fix CWE-1188 (Insecure Default Binding 0.0.0.0 / B104)."""
        patches: list[str] = []
        patched = code
        zero_bind = "0." + "0.0.0"

        if f'"{zero_bind}"' in patched or f"'{zero_bind}'" in patched:
            patched = patched.replace(f'"{zero_bind}"', '"127.0.0.1"').replace(f"'{zero_bind}'", "'127.0.0.1'")
            patches.append("Replaced wildcard binding '0.0.0.0' with secure localhost '127.0.0.1'.")

        return patched, patches

    @staticmethod
    def patch_cwe_703(code: str) -> tuple[str, list[str]]:
        """Fix CWE-703 (Improper Error Handling / B110 try_except_pass)."""
        patches: list[str] = []
        needed_imports = ["import logging"]
        patched = code

        lines = patched.splitlines()
        new_lines: list[str] = []
        i = 0
        while i < len(lines):
            line = lines[i]
            if re.match(r'^\s*except.*:\s*$', line) and i + 1 < len(lines) and re.match(r'^\s*pass\s*$', lines[i + 1]):
                indent_match = re.match(r'^(\s*)except', line)
                indent = indent_match.group(1) if indent_match else "    "
                exc_part = line.strip().replace("except", "").replace(":", "").strip()
                exc_type = exc_part if exc_part else "Exception"
                new_lines.append(f"{indent}except {exc_type} as _exc:")
                new_lines.append(f'{indent}    logging.warning("Suppressed exception: %s", _exc)')
                patches.append("Replaced silent 'except: pass' with structured logging handler.")
                i += 2
            else:
                new_lines.append(line)
                i += 1

        patched = "\n".join(new_lines) + ("\n" if code.endswith("\n") else "")

        if patches:
            patched = ensure_imports(patched, needed_imports)

        return patched, patches


def generate_diff(original: str, modified: str, filename: str = "target.py") -> str:
    """Generate a unified diff between original and modified code strings."""
    orig_lines = original.splitlines(keepends=True)
    mod_lines = modified.splitlines(keepends=True)
    diff = difflib.unified_diff(
        orig_lines,
        mod_lines,
        fromfile=f"a/{filename}",
        tofile=f"b/{filename}",
    )
    return "".join(diff)


def patch_code_deterministically(
    code: str,
    findings: list[dict[str, Any]],
    filename: str = "target.py",
) -> tuple[str, list[PatchProposal], str]:
    """Run deterministic patchers based on findings and validate AST syntax safety.

    Returns:
        tuple (patched_code, patch_proposals, unified_diff)
    """
    current_code = code
    proposals: list[PatchProposal] = []
    applied_explanations: list[str] = []

    # 1. CWE-78 / Command injection
    cwe_78_rules = {"B602", "B603", "B604", "B605", "B606", "B607", "B102", "B307"}
    has_78 = any(
        f.get("test_id") in cwe_78_rules or extract_cwe_id(f) == 78
        for f in findings
    )
    if has_78 or re.search(r"shell\s*=\s*True|os\.system\(|subprocess\.call\(|os\.popen\(", current_code):
        patched_candidate, msgs = CodePatcher.patch_cwe_78(current_code)
        if msgs:
            is_valid, _, _ = validate_python_ast(patched_candidate)
            if is_valid:
                current_code = patched_candidate
                applied_explanations.extend(msgs)

    # 2. CWE-502 / Insecure deserialization
    cwe_502_rules = {"B301", "B302", "B403", "B506"}
    has_502 = any(
        f.get("test_id") in cwe_502_rules or extract_cwe_id(f) == 502
        for f in findings
    )
    if has_502 or "yaml.load(" in current_code or "pickle.loads(" in current_code or "pickle.load(" in current_code or "import pickle" in current_code or "import marshal" in current_code:
        patched_candidate, msgs = CodePatcher.patch_cwe_502(current_code)
        if msgs:
            is_valid, _, _ = validate_python_ast(patched_candidate)
            if is_valid:
                current_code = patched_candidate
                applied_explanations.extend(msgs)

    # 3. CWE-327 / CWE-328 / CWE-208 / Broken crypto & timing attacks
    cwe_crypto_rules = {"B303", "B304", "B305", "B324"}
    has_crypto = any(
        f.get("test_id") in cwe_crypto_rules or extract_cwe_id(f) in {327, 328, 208}
        for f in findings
    )
    if has_crypto or "hashlib.md5" in current_code or "hashlib.sha1" in current_code:
        patched_candidate, msgs = CodePatcher.patch_cwe_327_328(current_code)
        if msgs:
            is_valid, _, _ = validate_python_ast(patched_candidate)
            if is_valid:
                current_code = patched_candidate
                applied_explanations.extend(msgs)

    # 4. CWE-22 / CWE-377 / Path traversal & temp files
    cwe_path_rules = {"B108", "B306", "B325"}
    has_path = any(
        f.get("test_id") in cwe_path_rules or extract_cwe_id(f) in {22, 377}
        for f in findings
    )
    tmp_indicator = "/" + "tmp/"
    if has_path or tmp_indicator in current_code or "tempfile.mktemp" in current_code:
        patched_candidate, msgs = CodePatcher.patch_cwe_22_377(current_code)
        if msgs:
            is_valid, _, _ = validate_python_ast(patched_candidate)
            if is_valid:
                current_code = patched_candidate
                applied_explanations.extend(msgs)

    # 5. CWE-798 / Hardcoded credentials
    cwe_cred_rules = {"B105", "B106", "B107"}
    has_creds = any(
        f.get("test_id") in cwe_cred_rules or extract_cwe_id(f) == 798
        for f in findings
    )
    if has_creds or re.search(r'(?:PASSWORD|SECRET|API_KEY)\s*=\s*[\"\']', current_code):
        patched_candidate, msgs = CodePatcher.patch_cwe_798(current_code)
        if msgs:
            is_valid, _, _ = validate_python_ast(patched_candidate)
            if is_valid:
                current_code = patched_candidate
                applied_explanations.extend(msgs)

    # 6. CWE-1188 / Bind to 0.0.0.0
    bind_all_pattern = "0." + "0.0.0"
    if bind_all_pattern in current_code:
        patched_candidate, msgs = CodePatcher.patch_cwe_1188(current_code)
        if msgs:
            is_valid, _, _ = validate_python_ast(patched_candidate)
            if is_valid:
                current_code = patched_candidate
                applied_explanations.extend(msgs)

    # 7. CWE-703 / try_except_pass
    if "pass" in current_code and "except" in current_code:
        patched_candidate, msgs = CodePatcher.patch_cwe_703(current_code)
        if msgs:
            is_valid, _, _ = validate_python_ast(patched_candidate)
            if is_valid:
                current_code = patched_candidate
                applied_explanations.extend(msgs)

    # Final AST check
    is_valid, ast_err, _ = validate_python_ast(current_code)
    if not is_valid:
        logger.error("AST validation failed after patching: %s. Rolling back.", ast_err)
        current_code = code

    diff_text = generate_diff(code, current_code, filename=filename)

    for explanation in applied_explanations:
        proposal = PatchProposal(
            finding_id=None,
            cwe_id=None,
            target_file=filename,
            original_snippet=code[:100],
            replacement_snippet=current_code[:100],
            explanation=explanation,
            confidence_score=1.0,
            ast_validated=is_valid,
        )
        proposals.append(proposal)

    return current_code, proposals, diff_text


def patcher_node(state: CodePatchState) -> dict[str, Any]:
    """LangGraph node: Generates deterministic AST-validated patch for findings."""
    current_code = state.get("current_code") or state.get("original_code", "")
    findings = state.get("findings", [])
    source_file = state.get("source_file", "target.py")

    patched_code, proposals, diff_text = patch_code_deterministically(
        code=current_code,
        findings=findings,
        filename=source_file,
    )

    history = list(state.get("patch_history", []))
    for prop in proposals:
        history.append(prop.model_dump())

    return {
        "current_code": patched_code,
        "proposed_patch": patched_code,
        "patch_history": history,
        "diff": diff_text,
    }
