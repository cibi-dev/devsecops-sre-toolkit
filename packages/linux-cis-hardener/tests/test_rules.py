"""Unit tests for individual CIS Benchmark Level 1 rules."""

import os
import stat
import pytest
import tempfile

from cis.backup_manager import BackupManager
from cis.rules import get_all_rules, get_rule_by_id
from cis.rules.base import (
    RuleStatus,
    Severity,
    resolve_target_path,
    safe_read_file,
    safe_write_file,
)
from cis.rules.firewall import (
    FirewallDefaultDrop,
    FirewallInstalled,
    FirewallLoopback,
)
from cis.rules.permissions import (
    PermDefaultUmask,
    PermGShadow,
    PermGroup,
    PermPasswd,
    PermSSHConfig,
    PermShadow,
)
from cis.rules.ssh import (
    SSHClientAliveInterval,
    SSHLoginGraceTime,
    SSHMaxAuthTries,
    SSHPasswordAuthentication,
    SSHPermitRootLogin,
    SSHX11Forwarding,
    parse_ssh_directives,
    update_ssh_directive,
)
from cis.rules.sysctl import (
    SysctlASLR,
    SysctlAcceptRedirects,
    SysctlAcceptSourceRoute,
    SysctlIPForward,
    SysctlLogMartians,
    SysctlSendRedirects,
    SysctlSyncookies,
    parse_sysctl_file,
    update_sysctl_directive,
)


@pytest.fixture
def sandbox_root(tmp_path):
    """Fixture providing an isolated root directory prefix."""
    root = tmp_path / "sandbox_root"
    root.mkdir()
    (root / "etc").mkdir()
    (root / "etc" / "ssh").mkdir()
    (root / "etc" / "sysctl.d").mkdir()
    return str(root)


# --- BASE & HELPER TESTS ---

def test_resolve_target_path_safety(tmp_path):
    root = str(tmp_path / "root")
    os.makedirs(root)
    safe = resolve_target_path(root, "/etc/passwd")
    assert safe == os.path.join(root, "etc/passwd")

    # Path traversal rejection
    with pytest.raises(ValueError, match="Path traversal"):
        resolve_target_path(root, "../../etc/passwd")


def test_safe_read_write_file(tmp_path):
    fpath = str(tmp_path / "test.txt")
    assert safe_read_file(fpath) is None

    assert safe_write_file(fpath, "hello security", mode=0o600)
    assert safe_read_file(fpath) == "hello security"
    st = os.stat(fpath)
    assert stat.S_IMODE(st.st_mode) == 0o600


def test_get_all_rules_and_get_by_id():
    rules = get_all_rules()
    assert len(rules) >= 15
    rule = get_rule_by_id("CIS-SSH-001")
    assert rule is not None
    assert rule.rule_id == "CIS-SSH-001"
    assert get_rule_by_id("NON-EXISTENT") is None


# --- SSH RULES TESTS ---

def test_ssh_parser_and_updater():
    sample = "# Comment\nPermitRootLogin yes\nPasswordAuthentication yes\n"
    directives = parse_ssh_directives(sample)
    assert directives["permitrootlogin"] == "yes"
    assert directives["passwordauthentication"] == "yes"

    new_content, changed = update_ssh_directive(sample, "PermitRootLogin", "no")
    assert changed is True
    assert "PermitRootLogin no" in new_content

    # Idempotence: update again with same value
    new_content2, changed2 = update_ssh_directive(new_content, "PermitRootLogin", "no")
    assert changed2 is False
    assert new_content == new_content2


def test_ssh_permit_root_login_audit_and_remediate(sandbox_root):
    rule = SSHPermitRootLogin()
    ssh_conf = os.path.join(sandbox_root, "etc/ssh/sshd_config")

    # Missing file audit
    res = rule.audit(root_prefix=sandbox_root)
    assert res.status == RuleStatus.FAILED

    # Write non-compliant
    safe_write_file(ssh_conf, "PermitRootLogin yes\n")
    res = rule.audit(root_prefix=sandbox_root)
    assert res.status == RuleStatus.FAILED
    assert res.current_value == "yes"

    # Dry-run
    rem_dry = rule.remediate(root_prefix=sandbox_root, dry_run=True)
    assert rem_dry.changed is True
    assert "[DRY-RUN]" in rem_dry.details
    assert "PermitRootLogin yes" in safe_read_file(ssh_conf)  # Unmodified

    # Active remediation with backup
    bm = BackupManager(root_prefix=sandbox_root)
    rem = rule.remediate(root_prefix=sandbox_root, dry_run=False, backup_manager=bm)
    assert rem.changed is True
    assert "PermitRootLogin no" in safe_read_file(ssh_conf)

    # Compliant audit
    res_compliant = rule.audit(root_prefix=sandbox_root)
    assert res_compliant.status == RuleStatus.PASSED

    # Rollback
    rb = rule.rollback(backup_manager=bm, root_prefix=sandbox_root)
    assert rb.restored is True
    assert "PermitRootLogin yes" in safe_read_file(ssh_conf)


def test_ssh_other_rules(sandbox_root):
    ssh_conf = os.path.join(sandbox_root, "etc/ssh/sshd_config")
    safe_write_file(ssh_conf, "PasswordAuthentication yes\nMaxAuthTries 10\nX11Forwarding yes\nClientAliveInterval 900\nLoginGraceTime 300\n")

    rules = [
        (SSHPasswordAuthentication(), "no"),
        (SSHMaxAuthTries(), "4"),
        (SSHX11Forwarding(), "no"),
        (SSHClientAliveInterval(), "300"),
        (SSHLoginGraceTime(), "60"),
    ]

    bm = BackupManager(root_prefix=sandbox_root)
    for rule, compliant_val in rules:
        res = rule.audit(root_prefix=sandbox_root)
        assert res.status == RuleStatus.FAILED
        rem = rule.remediate(root_prefix=sandbox_root, backup_manager=bm)
        assert rem.changed is True
        res_post = rule.audit(root_prefix=sandbox_root)
        assert res_post.status == RuleStatus.PASSED


# --- SYSCTL RULES TESTS ---

def test_sysctl_parser_and_updater():
    sample = "# Sysctl\nnet.ipv4.ip_forward = 1\n"
    dirs = parse_sysctl_file(sample)
    assert dirs["net.ipv4.ip_forward"] == "1"

    updated, changed = update_sysctl_directive(sample, "net.ipv4.ip_forward", "0")
    assert changed is True
    assert "net.ipv4.ip_forward = 0" in updated

    updated2, changed2 = update_sysctl_directive(updated, "net.ipv4.ip_forward", "0")
    assert changed2 is False


def test_sysctl_rules_audit_remediate(sandbox_root):
    sysctl_rules = [
        SysctlIPForward(),
        SysctlSendRedirects(),
        SysctlAcceptRedirects(),
        SysctlSyncookies(),
        SysctlASLR(),
        SysctlAcceptSourceRoute(),
        SysctlLogMartians(),
    ]

    bm = BackupManager(root_prefix=sandbox_root)

    for rule in sysctl_rules:
        # Initially missing in sandbox
        res = rule.audit(root_prefix=sandbox_root)
        assert res.status == RuleStatus.FAILED

        # Remediate
        rem = rule.remediate(root_prefix=sandbox_root, backup_manager=bm)
        assert rem.changed is True

        # Now compliant
        res2 = rule.audit(root_prefix=sandbox_root)
        assert res2.status == RuleStatus.PASSED

        # Second remediation is a no-op
        rem2 = rule.remediate(root_prefix=sandbox_root, backup_manager=bm)
        assert rem2.changed is False


# --- PERMISSIONS RULES TESTS ---

def test_file_permissions_rules(sandbox_root):
    passwd = os.path.join(sandbox_root, "etc/passwd")
    shadow = os.path.join(sandbox_root, "etc/shadow")
    gshadow = os.path.join(sandbox_root, "etc/gshadow")
    group = os.path.join(sandbox_root, "etc/group")
    ssh_cfg = os.path.join(sandbox_root, "etc/ssh/sshd_config")

    safe_write_file(passwd, "root:x:0:0:root:/root:/bin/bash\n", mode=0o777)
    safe_write_file(shadow, "root:*:19000:0:99999:7:::\n", mode=0o777)
    safe_write_file(gshadow, "root:*::\n", mode=0o777)
    safe_write_file(group, "root:x:0:\n", mode=0o777)
    safe_write_file(ssh_cfg, "# ssh\n", mode=0o777)

    perm_rules = [
        (PermPasswd(), passwd, 0o644),
        (PermShadow(), shadow, 0o640),
        (PermGShadow(), gshadow, 0o640),
        (PermGroup(), group, 0o644),
        (PermSSHConfig(), ssh_cfg, 0o600),
    ]

    bm = BackupManager(root_prefix=sandbox_root)

    for rule, fpath, target_mode in perm_rules:
        audit_res = rule.audit(root_prefix=sandbox_root)
        assert audit_res.status == RuleStatus.FAILED

        rem = rule.remediate(root_prefix=sandbox_root, backup_manager=bm)
        assert rem.changed is True
        st = os.stat(fpath)
        assert stat.S_IMODE(st.st_mode) == target_mode

        audit_post = rule.audit(root_prefix=sandbox_root)
        assert audit_post.status == RuleStatus.PASSED


def test_umask_rule(sandbox_root):
    login_defs = os.path.join(sandbox_root, "etc/login.defs")
    rule = PermDefaultUmask()

    # Missing file
    assert rule.audit(root_prefix=sandbox_root).status == RuleStatus.FAILED

    # Insecure umask
    safe_write_file(login_defs, "UMASK           022\n")
    assert rule.audit(root_prefix=sandbox_root).status == RuleStatus.FAILED

    # Remediate
    bm = BackupManager(root_prefix=sandbox_root)
    rem = rule.remediate(root_prefix=sandbox_root, backup_manager=bm)
    assert rem.changed is True
    assert "UMASK           027" in safe_read_file(login_defs)

    assert rule.audit(root_prefix=sandbox_root).status == RuleStatus.PASSED


# --- FIREWALL RULES TESTS ---

def test_firewall_rules(sandbox_root):
    fw_inst = FirewallInstalled()
    fw_drop = FirewallDefaultDrop()
    fw_loop = FirewallLoopback()

    nft_path = os.path.join(sandbox_root, "etc/nftables.conf")

    # Missing
    assert fw_inst.audit(root_prefix=sandbox_root).status == RuleStatus.FAILED
    assert fw_drop.audit(root_prefix=sandbox_root).status == RuleStatus.FAILED
    assert fw_loop.audit(root_prefix=sandbox_root).status == RuleStatus.FAILED

    # Remediate installed
    bm = BackupManager(root_prefix=sandbox_root)
    rem = fw_inst.remediate(root_prefix=sandbox_root, backup_manager=bm)
    assert rem.changed is True
    assert os.path.exists(nft_path)

    # Audits now pass
    assert fw_inst.audit(root_prefix=sandbox_root).status == RuleStatus.PASSED
    assert fw_drop.audit(root_prefix=sandbox_root).status == RuleStatus.PASSED
    assert fw_loop.audit(root_prefix=sandbox_root).status == RuleStatus.PASSED

# --- ROLLBACK & ADVANCED RULE EDGE CASES ---

def test_firewall_remediate_and_rollback_all(sandbox_root):
    fw_drop = FirewallDefaultDrop()
    fw_loop = FirewallLoopback()
    bm = BackupManager(root_prefix=sandbox_root)

    # Remediate DefaultDrop
    rem_drop = fw_drop.remediate(root_prefix=sandbox_root, backup_manager=bm)
    assert rem_drop.changed is True
    # Rollback DefaultDrop
    rb_drop = fw_drop.rollback(backup_manager=bm, root_prefix=sandbox_root)
    assert rb_drop.restored is True

    # Remediate Loopback
    rem_loop = fw_loop.remediate(root_prefix=sandbox_root, backup_manager=bm)
    assert rem_loop.changed is True
    # Rollback Loopback
    rb_loop = fw_loop.rollback(backup_manager=bm, root_prefix=sandbox_root)
    assert rb_loop.restored is True

    # Missing backup manager rollback
    assert fw_drop.rollback(backup_manager=None, root_prefix=sandbox_root).restored is False
    assert fw_loop.rollback(backup_manager=None, root_prefix=sandbox_root).restored is False


def test_permissions_rollback(sandbox_root):
    rule = PermPasswd()
    bm = BackupManager(root_prefix=sandbox_root)
    passwd_path = os.path.join(sandbox_root, "etc/passwd")

    safe_write_file(passwd_path, "root:x:0:0:::\n", mode=0o777)
    rem = rule.remediate(root_prefix=sandbox_root, backup_manager=bm)
    assert rem.changed is True

    rb = rule.rollback(backup_manager=bm, root_prefix=sandbox_root)
    assert rb.restored is True
    assert stat.S_IMODE(os.stat(passwd_path).st_mode) == 0o777

    # Missing backup manager rollback
    assert rule.rollback(backup_manager=None, root_prefix=sandbox_root).restored is False

    # Umask rollback
    umask_rule = PermDefaultUmask()
    login_defs = os.path.join(sandbox_root, "etc/login.defs")
    safe_write_file(login_defs, "UMASK 022\n")
    rem_u = umask_rule.remediate(root_prefix=sandbox_root, backup_manager=bm)
    assert rem_u.changed is True
    rb_u = umask_rule.rollback(backup_manager=bm, root_prefix=sandbox_root)
    assert rb_u.restored is True
    assert "UMASK 022" in safe_read_file(login_defs)
    assert umask_rule.rollback(backup_manager=None, root_prefix=sandbox_root).restored is False


def test_sysctl_rollback_and_edge_cases(sandbox_root):
    rule = SysctlIPForward()
    bm = BackupManager(root_prefix=sandbox_root)

    sysctl_conf = os.path.join(sandbox_root, "etc/sysctl.d/99-cis.conf")
    safe_write_file(sysctl_conf, "# Commented\n# net.ipv4.ip_forward = 1\n")

    rem = rule.remediate(root_prefix=sandbox_root, backup_manager=bm)
    assert rem.changed is True
    assert "net.ipv4.ip_forward = 0" in safe_read_file(sysctl_conf)

    rb = rule.rollback(backup_manager=bm, root_prefix=sandbox_root)
    assert rb.restored is True
    assert "# net.ipv4.ip_forward = 1" in safe_read_file(sysctl_conf)

    assert rule.rollback(backup_manager=None, root_prefix=sandbox_root).restored is False


def test_ssh_rule_invalid_values():
    rule_tries = SSHMaxAuthTries()
    assert rule_tries._is_value_compliant("invalid_int") is False
    assert rule_tries._is_value_compliant("5") is False
    assert rule_tries._is_value_compliant("4") is True

    rule_interval = SSHClientAliveInterval()
    assert rule_interval._is_value_compliant("invalid_val") is False
    assert rule_interval._is_value_compliant("500") is False
    assert rule_interval._is_value_compliant("300") is True

    rule_grace = SSHLoginGraceTime()
    assert rule_grace._is_value_compliant("invalid") is False
    assert rule_grace._is_value_compliant("120") is False
    assert rule_grace._is_value_compliant("60") is True


def test_safe_write_file_failure(tmp_path):
    # Try writing to an invalid path that cannot be created
    invalid_path = "/proc/sys/non_writable_test_location/test.txt"
    assert safe_write_file(invalid_path, "fail") is False
