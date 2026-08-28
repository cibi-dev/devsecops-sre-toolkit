"""Unit tests for the comparator engine and drift detection logic."""

from __future__ import annotations

from pathlib import Path
import pytest

from drift.comparator import DriftComparator, DriftSeverity, DriftType
from drift.inspectors.files import FileInspector, FileLiveState
from drift.inspectors.packages import PackageInspector, PackageLiveState
from drift.inspectors.ports import PortInspector, PortLiveState
from drift.inspectors.services import ServiceInspector, ServiceLiveState
from drift.inspectors.sysctl import SysctlInspector, SysctlLiveState
from drift.inspectors.users import UserInspector, UserLiveState
from drift.schema import (
    FileDesired,
    Manifest,
    PackageDesired,
    PortDesired,
    ServiceDesired,
    SysctlDesired,
    UserDesired,
)


class MockUserInspector(UserInspector):
    def __init__(self, mock_users: dict[str, UserLiveState]):
        super().__init__()
        self.mock_users = mock_users

    def inspect_user(self, username: str) -> UserLiveState | None:
        return self.mock_users.get(username)


class MockServiceInspector(ServiceInspector):
    def __init__(self, mock_services: dict[str, ServiceLiveState]):
        super().__init__()
        self.mock_services = mock_services

    def inspect_service(self, service_name: str) -> ServiceLiveState:
        return self.mock_services.get(
            service_name,
            ServiceLiveState(
                name=service_name,
                active_state="inactive",
                unit_file_state="unknown",
                load_state="not-found",
                exists=False,
                is_running=False,
                is_enabled=False,
            ),
        )


class MockSysctlInspector(SysctlInspector):
    def __init__(self, mock_sysctl: dict[str, str]):
        super().__init__()
        self.mock_sysctl = mock_sysctl

    def inspect_key(self, key: str) -> SysctlLiveState:
        if key in self.mock_sysctl:
            return SysctlLiveState(key=key, value=self.mock_sysctl[key], exists=True)
        return SysctlLiveState(key=key, value="", exists=False)


class MockPortInspector(PortInspector):
    def __init__(self, open_ports: set[tuple[int, str]]):
        super().__init__()
        self.open_ports = open_ports

    def is_port_listening(self, port: int, protocol: str = "tcp", address: str | None = None) -> bool:
        return (port, protocol) in self.open_ports


class MockFileInspector(FileInspector):
    def __init__(self, mock_files: dict[str, FileLiveState]):
        super().__init__()
        self.mock_files = mock_files

    def inspect_file(self, target_path: str | Path, compute_sha256: bool = True) -> FileLiveState:
        path_str = str(target_path)
        return self.mock_files.get(
            path_str,
            FileLiveState(
                path=path_str,
                exists=False,
                mode=None,
                owner=None,
                group=None,
                size=None,
                sha256=None,
            ),
        )


class MockPackageInspector(PackageInspector):
    def __init__(self, mock_packages: dict[str, PackageLiveState]):
        super().__init__()
        self.mock_packages = mock_packages

    def inspect_package(self, package_name: str) -> PackageLiveState:
        return self.mock_packages.get(
            package_name,
            PackageLiveState(name=package_name, version=None, installed=False),
        )


class TestDriftComparator:
    def test_all_in_sync_manifest(self):
        user_mock = MockUserInspector({
            "deploy": UserLiveState(
                name="deploy", uid=1001, gid=1001, login_shell="/bin/bash", home="/home/deploy", groups=["deploy", "docker"]
            )
        })
        svc_mock = MockServiceInspector({
            "nginx": ServiceLiveState(
                name="nginx", active_state="active", unit_file_state="enabled", load_state="loaded", exists=True, is_running=True, is_enabled=True
            )
        })
        sysctl_mock = MockSysctlInspector({"net.ipv4.ip_forward": "1"})
        port_mock = MockPortInspector({(443, "tcp")})
        file_mock = MockFileInspector({
            "/etc/nginx/nginx.conf": FileLiveState(
                path="/etc/nginx/nginx.conf", exists=True, mode="0644", owner="root", group="root", size=1024, sha256="abc"
            )
        })
        pkg_mock = MockPackageInspector({
            "curl": PackageLiveState(name="curl", version="7.88.1", installed=True)
        })

        manifest = Manifest(
            name="production-web",
            users=[UserDesired.model_validate({"name": "deploy", "uid": 1001, "shell": "/bin/bash", "groups": ["docker"]})],
            services=[ServiceDesired(name="nginx", state="running", enabled=True)],
            sysctl=[SysctlDesired(key="net.ipv4.ip_forward", value="1")],
            ports=[PortDesired(port=443, protocol="tcp", state="listening")],
            files=[FileDesired(path="/etc/nginx/nginx.conf", mode="0644", owner="root")],
            packages=[PackageDesired(name="curl", version="7.88.1", state="present")],
        )

        comparator = DriftComparator(
            user_inspector=user_mock,
            service_inspector=svc_mock,
            sysctl_inspector=sysctl_mock,
            port_inspector=port_mock,
            file_inspector=file_mock,
            package_inspector=pkg_mock,
        )

        result = comparator.compare(manifest)
        assert result.drift_detected is False
        assert result.total_checked == 6
        assert result.match_count == 6
        assert len(result.drift_items) == 0

    def test_drift_detections_missing_unexpected_modified(self):
        user_mock = MockUserInspector({
            "hacker": UserLiveState(
                name="hacker", uid=1337, gid=1337, login_shell="/bin/sh", home="/root", groups=["hacker"]
            ),
            "deploy": UserLiveState(
                name="deploy", uid=2000, gid=1001, login_shell="/bin/zsh", home="/home/deploy", groups=["deploy"]
            ),
        })
        svc_mock = MockServiceInspector({
            "nginx": ServiceLiveState(
                name="nginx", active_state="failed", unit_file_state="enabled", load_state="loaded", exists=True, is_running=False, is_enabled=True
            ),
            "telnet": ServiceLiveState(
                name="telnet", active_state="active", unit_file_state="enabled", load_state="loaded", exists=True, is_running=True, is_enabled=True
            ),
        })
        sysctl_mock = MockSysctlInspector({"net.ipv4.ip_forward": "0"})
        port_mock = MockPortInspector({(23, "tcp")})
        file_mock = MockFileInspector({
            "/etc/shadow": FileLiveState(
                path="/etc/shadow", exists=True, mode="0777", owner="root", group="root", size=500, sha256="deadbeef"
            )
        })
        pkg_mock = MockPackageInspector({
            "telnet": PackageLiveState(name="telnet", version="1.0", installed=True)
        })

        manifest = Manifest(
            name="hardened-bastion",
            users=[
                UserDesired(name="hacker", state="absent"),
                UserDesired.model_validate({"name": "deploy", "uid": 1001, "shell": "/bin/bash", "state": "present"}),
                UserDesired(name="missing_user", state="present"),
            ],
            services=[
                ServiceDesired(name="nginx", state="running"),
                ServiceDesired(name="telnet", state="absent"),
                ServiceDesired(name="missing_daemon", state="running"),
            ],
            sysctl=[
                SysctlDesired(key="net.ipv4.ip_forward", value="1"),
                SysctlDesired(key="net.ipv4.tcp_syncookies", value="1"),
            ],
            ports=[
                PortDesired(port=443, protocol="tcp", state="listening"),
                PortDesired(port=23, protocol="tcp", state="closed"),
            ],
            files=[
                FileDesired(path="/etc/shadow", mode="0600", owner="root", state="present"),
                FileDesired(path="/etc/sudoers.d/custom", state="absent"),
                FileDesired(path="/etc/missing.conf", state="present"),
            ],
            packages=[
                PackageDesired(name="telnet", state="absent"),
                PackageDesired(name="curl", state="present"),
            ],
        )

        comparator = DriftComparator(
            user_inspector=user_mock,
            service_inspector=svc_mock,
            sysctl_inspector=sysctl_mock,
            port_inspector=port_mock,
            file_inspector=file_mock,
            package_inspector=pkg_mock,
        )

        result = comparator.compare(manifest)
        assert result.drift_detected is True
        assert result.total_checked == 15
        assert result.match_count == 1  # /etc/sudoers.d/custom correctly absent
        assert result.missing_count == 6  # missing_user, missing_daemon, tcp_syncookies, port 443, /etc/missing.conf, curl
        assert result.unexpected_count == 4  # hacker user, telnet svc, port 23, telnet pkg
        assert result.modified_count >= 3  # deploy user, nginx svc, sysctl ip_forward, /etc/shadow

        # Verify critical severity for /etc/shadow
        shadow_drift = [i for i in result.items if i.name == "/etc/shadow"][0]
        assert shadow_drift.drift_type == DriftType.MODIFIED
        assert shadow_drift.severity == DriftSeverity.CRITICAL
        assert "0777" in shadow_drift.unified_diff
