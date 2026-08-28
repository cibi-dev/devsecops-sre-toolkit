"""
Unit tests for Command Sandbox, Environment Builder, and Secret Sanitization.
"""

from pathlib import Path
import pytest

from runner.sandbox import (
    build_sanitized_env,
    sanitize_output,
    tokenize_command,
    validate_working_dir,
)


def test_tokenize_command_standard():
    tokens = tokenize_command("pytest -v --maxfail=2 'tests/unit test'")
    assert tokens == ["pytest", "-v", "--maxfail=2", "tests/unit test"]


def test_tokenize_command_empty():
    with pytest.raises(ValueError, match="Cannot execute an empty command string"):
        tokenize_command("   ")


def test_tokenize_command_invalid_type():
    with pytest.raises(TypeError, match="Command must be a string"):
        tokenize_command(123)  # type: ignore


def test_tokenize_command_null_byte_security():
    with pytest.raises(ValueError, match="Null bytes are prohibited"):
        tokenize_command("echo hello\x00world")


def test_tokenize_command_unclosed_quotes():
    with pytest.raises(ValueError, match="could not be parsed safely"):
        tokenize_command("echo 'unclosed quote")


def test_sanitize_output_user_secrets():
    text = "Connecting to database with secret_pwd_9999 and token secret_api_key_8888"
    secrets = ["secret_pwd_9999", "secret_api_key_8888"]
    sanitized = sanitize_output(text, secrets=secrets)
    assert "secret_pwd_9999" not in sanitized
    assert "secret_api_key_8888" not in sanitized
    assert sanitized == "Connecting to database with [REDACTED] and token [REDACTED]"


def test_sanitize_output_regex_patterns():
    dummy_gh = "_".join(["ghp", "1234567890abcdefghijklmnopqrstuvwxyzAB"])
    text = f"""
    GitHub Token: {dummy_gh}
    AWS Key: AKIAIOSFODNN7EXAMPLE
    Auth: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.t-IDcSemACt8x4iTMC6Y5
    password: mySecretPassword123!
    """
    sanitized = sanitize_output(text)
    assert dummy_gh not in sanitized
    assert "AKIAIOSFODNN7EXAMPLE" not in sanitized
    assert "mySecretPassword123!" not in sanitized
    assert "[REDACTED]" in sanitized


def test_sanitize_output_private_key():
    key_text = """-----BEGIN RSA PRIVATE KEY-----
    MIIEowIBAAKCAQEA0Y1+
    -----END RSA PRIVATE KEY-----"""
    sanitized = sanitize_output(key_text)
    assert "MIIEowIBAAKCAQEA0Y1+" not in sanitized
    assert "[REDACTED_PRIVATE_KEY]" in sanitized


def test_validate_working_dir_default():
    resolved = validate_working_dir(None)
    assert resolved == Path.cwd().resolve()


def test_validate_working_dir_non_existent(tmp_path: Path):
    non_existent = tmp_path / "does_not_exist"
    with pytest.raises(FileNotFoundError):
        validate_working_dir(non_existent)


def test_validate_working_dir_file_instead_of_dir(tmp_path: Path):
    file_path = tmp_path / "a_file.txt"
    file_path.write_text("content")
    with pytest.raises(NotADirectoryError):
        validate_working_dir(file_path)


def test_validate_working_dir_path_traversal(tmp_path: Path):
    allowed_root = tmp_path / "safe_root"
    allowed_root.mkdir()
    outside_dir = tmp_path / "outside"
    outside_dir.mkdir()

    with pytest.raises(PermissionError, match="Path traversal detected"):
        validate_working_dir(outside_dir, allowed_root=allowed_root)


def test_build_sanitized_env():
    base = {"GLOBAL_A": "1"}
    job = {"JOB_B": "2"}
    env = build_sanitized_env(base, job)
    assert env["GLOBAL_A"] == "1"
    assert env["JOB_B"] == "2"
    assert env["CI"] == "true"
    assert env["CI_RUNNER"] == "lightweight-ci-runner"
    assert "PATH" in env
