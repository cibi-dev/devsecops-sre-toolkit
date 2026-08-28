"""Unit tests for YAML manifest parser and edge cases."""

from __future__ import annotations

from pathlib import Path
import pytest

from drift.parser import FileSizeExceededError, ManifestParseError, parse_manifest, sanitize_secrets


class TestParser:
    def test_parse_valid_yaml_file(self, tmp_path: Path):
        manifest_file = tmp_path / "valid.yaml"
        manifest_file.write_text("name: test-app\nversion: '1.0'\n", encoding="utf-8")
        manifest = parse_manifest(manifest_file)
        assert manifest.name == "test-app"
        assert manifest.version == "1.0"

    def test_parse_valid_yaml_string(self):
        raw = "name: inline-spec\nversion: '2.0'\nusers: [{name: deploy}]"
        manifest = parse_manifest(raw)
        assert manifest.name == "inline-spec"
        assert len(manifest.users) == 1

    def test_parse_empty_string(self):
        manifest = parse_manifest("")
        assert manifest.name == "host-spec"
        assert len(manifest.users) == 0

    def test_parse_invalid_yaml_syntax(self):
        with pytest.raises(ManifestParseError) as exc:
            parse_manifest("invalid: yaml: syntax: [")
        assert "Invalid YAML syntax" in str(exc.value)

    def test_parse_non_dict_root(self):
        with pytest.raises(ManifestParseError) as exc:
            parse_manifest("- item1\n- item2")
        assert "Expected YAML mapping" in str(exc.value)

    def test_parse_nonexistent_file(self, tmp_path: Path):
        with pytest.raises(ManifestParseError) as exc:
            parse_manifest(tmp_path / "nonexistent_file_manifest_12345.yaml")
        assert "not found" in str(exc.value)

    def test_parse_schema_validation_error(self):
        with pytest.raises(ManifestParseError) as exc:
            parse_manifest("users: [{name: 'invalid name with spaces'}]")
        assert "Schema validation failed" in str(exc.value)

    def test_sanitize_secrets_all_patterns(self):
        mock_gh = "ghp_" + "111111111122222222223333333333444444"
        mock_sk = "sk-" + "123456789012345678901234"
        mock_aws = "AKIA" + "IOSFODNN7EXAMPLE"
        text = (
            f"token: {mock_gh}\n"
            f"open_ai: {mock_sk}\n"
            f"aws: {mock_aws}\n"
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...\n-----END RSA PRIVATE KEY-----\n"
            "password: mysecretpassword\n"
        )
        sanitized = sanitize_secrets(text)
        assert "ghp_" not in sanitized
        assert "sk-1234" not in sanitized
        assert "AKIAIOSFODNN7EXAMPLE" not in sanitized
        assert "MIIEowIBAAKCAQEA0" not in sanitized
        assert "mysecretpassword" not in sanitized
