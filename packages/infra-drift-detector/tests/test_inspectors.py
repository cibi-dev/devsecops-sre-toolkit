"""Unit tests for read-only system inspectors with mocks and real probes."""

from __future__ import annotations

import os
from pathlib import Path
import pytest

from drift.inspectors.files import FileInspector
from drift.inspectors.packages import PackageInspector
from drift.inspectors.ports import PortInspector, decode_ipv4, decode_ipv6
from drift.inspectors.services import ServiceInspector
from drift.inspectors.sysctl import SysctlInspector
from drift.inspectors.users import UserInspector


class TestUserInspector:
    def test_inspect_from_mock_files(self, tmp_path: Path):
        passwd_file = tmp_path / "passwd"
        group_file = tmp_path / "group"

        passwd_content = (
            "root:x:0:0:root:/root:/bin/bash\n"
            "deploy:x:1001:1001:Deploy User:/home/deploy:/bin/bash\n"
            "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin\n"
        )
        group_content = (
            "root:x:0:\n"
            "deploy:x:1001:\n"
            "sudo:x:27:deploy\n"
            "docker:x:999:deploy\n"
        )

        passwd_file.write_text(passwd_content, encoding="utf-8")
        group_file.write_text(group_content, encoding="utf-8")

        inspector = UserInspector(passwd_path=passwd_file, group_path=group_file)

        deploy_user = inspector.inspect_user("deploy")
        assert deploy_user is not None
        assert deploy_user.name == "deploy"
        assert deploy_user.uid == 1001
        assert deploy_user.gid == 1001
        assert deploy_user.shell == "/bin/bash"
        assert "sudo" in deploy_user.groups
        assert "docker" in deploy_user.groups
        assert "deploy" in deploy_user.groups

        missing = inspector.inspect_user("nonexistent")
        assert missing is None

        all_users = inspector.inspect_all()
        assert len(all_users) == 3
        assert "root" in all_users

    def test_inspect_live_system(self):
        inspector = UserInspector()
        all_users = inspector.inspect_all()
        assert len(all_users) > 0
        current_user = inspector.inspect_user("root")
        if current_user:
            assert current_user.uid == 0


class TestServiceInspector:
    def test_service_running_and_enabled(self):
        def mock_runner(cmd: list[str]) -> tuple[int, str, str]:
            out = "ActiveState=active\nUnitFileState=enabled\nLoadState=loaded\n"
            return 0, out, ""

        inspector = ServiceInspector(command_runner=mock_runner)
        status = inspector.inspect_service("nginx")
        assert status.exists is True
        assert status.is_running is True
        assert status.is_enabled is True
        assert status.active_state == "active"

    def test_service_inactive_and_disabled(self):
        def mock_runner(cmd: list[str]) -> tuple[int, str, str]:
            out = "ActiveState=inactive\nUnitFileState=disabled\nLoadState=loaded\n"
            return 0, out, ""

        inspector = ServiceInspector(command_runner=mock_runner)
        status = inspector.inspect_service("apache2")
        assert status.exists is True
        assert status.is_running is False
        assert status.is_enabled is False

    def test_service_not_found(self):
        def mock_runner(cmd: list[str]) -> tuple[int, str, str]:
            out = "ActiveState=inactive\nUnitFileState=unknown\nLoadState=not-found\n"
            return 0, out, ""

        inspector = ServiceInspector(command_runner=mock_runner)
        status = inspector.inspect_service("missing_service")
        assert status.exists is False
        assert status.is_running is False

    def test_service_invalid_name_injection_prevention(self):
        inspector = ServiceInspector()
        status = inspector.inspect_service("nginx; cat /etc/shadow")
        assert status.exists is False
        assert status.active_state == "invalid"

    def test_service_missing_systemctl(self):
        def mock_runner(cmd: list[str]) -> tuple[int, str, str]:
            return 127, "", "systemctl not found"

        inspector = ServiceInspector(command_runner=mock_runner)
        status = inspector.inspect_service("nginx")
        assert status.exists is False
        assert status.active_state == "unknown"


class TestSysctlInspector:
    def test_sysctl_read_success(self, tmp_path: Path):
        proc_sys = tmp_path / "proc" / "sys"
        target_file = proc_sys / "net" / "ipv4" / "ip_forward"
        target_file.parent.mkdir(parents=True)
        target_file.write_text("1\n", encoding="utf-8")

        inspector = SysctlInspector(proc_sys_root=proc_sys)
        state = inspector.inspect_key("net.ipv4.ip_forward")
        assert state.exists is True
        assert state.value == "1"

    def test_sysctl_missing_key(self, tmp_path: Path):
        inspector = SysctlInspector(proc_sys_root=tmp_path)
        state = inspector.inspect_key("kernel.nonexistent_flag")
        assert state.exists is False
        assert state.value == ""

    def test_sysctl_path_traversal_prevention(self, tmp_path: Path):
        inspector = SysctlInspector(proc_sys_root=tmp_path)
        state = inspector.inspect_key("../../etc/shadow")
        assert state.exists is False


class TestPortInspector:
    def test_decode_ipv4(self):
        # 0100007F -> 127.0.0.1
        assert decode_ipv4("0100007F") == "127.0.0.1"
        # 00000000 -> 0.0.0.0
        assert decode_ipv4("00000000") == "0.0.0.0"  # nosec B104

    def test_decode_ipv6(self):
        assert decode_ipv6("00000000000000000000000000000000") == "::"

    def test_inspect_mock_proc_net(self, tmp_path: Path):
        tcp_file = tmp_path / "tcp"
        # Port 80 is 0050 in hex, state 0A is LISTEN
        tcp_content = (
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
            "   0: 0100007F:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0\n"
            "   1: 00000000:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12346 1 0000000000000000 100 0 0 10 0\n"
            "   2: 0100007F:1F90 0100007F:0050 01 00000000:00000000 00:00000000 00000000  1000        0 12347 1 0000000000000000 100 0 0 10 0\n"
        )
        tcp_file.write_text(tcp_content, encoding="utf-8")

        inspector = PortInspector(proc_net_root=tmp_path)
        listening = inspector.get_listening_ports()
        assert len(listening) == 2

        assert inspector.is_port_listening(80, "tcp", "127.0.0.1") is True
        assert inspector.is_port_listening(443, "tcp", "0.0.0.0") is True  # nosec B104
        # Port 8080 (1F90 in hex) has state 01 (ESTABLISHED), not listening
        assert inspector.is_port_listening(8080, "tcp") is False
        assert inspector.is_port_listening(22, "tcp") is False


class TestFileInspector:
    def test_inspect_existing_file(self, tmp_path: Path):
        f = tmp_path / "test.conf"
        f.write_text("server_name localhost;\n", encoding="utf-8")
        f.chmod(0o644)

        inspector = FileInspector()
        state = inspector.inspect_file(f, compute_sha256=True)

        assert state.exists is True
        assert state.mode == "0644"
        assert state.sha256 is not None
        assert len(state.sha256) == 64
        assert state.size is not None and state.size > 0

    def test_inspect_missing_file(self, tmp_path: Path):
        f = tmp_path / "does_not_exist.txt"
        inspector = FileInspector()
        state = inspector.inspect_file(f)
        assert state.exists is False
        assert state.mode is None
        assert state.sha256 is None


class TestPackageInspector:
    def test_inspect_from_mock_dpkg_status(self, tmp_path: Path):
        status_file = tmp_path / "status"
        status_content = (
            "Package: curl\n"
            "Status: install ok installed\n"
            "Version: 7.88.1-10\n\n"
            "Package: nginx\n"
            "Status: deinstall ok config-files\n"
            "Version: 1.22.1-9\n\n"
        )
        status_file.write_text(status_content, encoding="utf-8")

        inspector = PackageInspector(dpkg_status_path=status_file)
        curl_state = inspector.inspect_package("curl")
        assert curl_state.installed is True
        assert curl_state.version == "7.88.1-10"

        nginx_state = inspector.inspect_package("nginx")
        assert nginx_state.installed is False

        missing_state = inspector.inspect_package("git")
        assert missing_state.installed is False

    def test_inspect_rpm_package(self):
        def mock_rpm_runner(cmd: list[str]) -> tuple[int, str, str]:
            if "rpm" in cmd[0]:
                return 0, "3.0.0-1.el9", ""
            return 1, "", "not found"

        inspector = PackageInspector(command_runner=mock_rpm_runner)
        pkg = inspector.inspect_package("bash")
        assert pkg.installed is True
        assert pkg.version == "3.0.0-1.el9"


class TestFileInspectorEdgeCases:
    def test_file_exceeds_max_hash_size(self, tmp_path: Path):
        f = tmp_path / "large_file.bin"
        f.write_bytes(b"A" * 1024)
        inspector = FileInspector(max_hash_bytes=512)
        state = inspector.inspect_file(f, compute_sha256=True)
        assert state.sha256 == "EXCEEDS_MAX_HASH_SIZE"

    def test_file_stat_permission_error(self, tmp_path: Path):
        f = tmp_path / "inaccessible.txt"
        f.write_text("hello", encoding="utf-8")

        from unittest.mock import patch
        with patch.object(Path, "stat", side_effect=PermissionError("Permission denied")):
            inspector = FileInspector()
            state = inspector.inspect_file(f)
            assert state.error is not None
            assert "Permission or I/O error" in state.error


class TestPortInspectorUDP:
    def test_inspect_udp_proc_net(self, tmp_path: Path):
        udp_file = tmp_path / "udp"
        udp_content = (
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"
            "   0: 00000000:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0\n"
        )
        udp_file.write_text(udp_content, encoding="utf-8")

        inspector = PortInspector(proc_net_root=tmp_path)
        assert inspector.is_port_listening(53, "udp") is True

