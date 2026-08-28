"""Read-only inspector for Linux users and group memberships (CWE-250, CWE-269)."""

from __future__ import annotations

import grp
import os
from pathlib import Path
import pwd
from typing import NamedTuple


class UserLiveState(NamedTuple):
    """Represents live state of a Linux user."""

    name: str
    uid: int
    gid: int
    login_shell: str
    home: str
    groups: list[str]
    exists: bool = True

    @property
    def shell(self) -> str:
        """Alias for login_shell."""
        return self.login_shell


class UserInspector:
    """Read-only inspector for Linux users and groups."""

    def __init__(
        self,
        passwd_path: Path | str | None = None,
        group_path: Path | str | None = None,
    ) -> None:
        self.passwd_path = Path(passwd_path) if passwd_path else None
        self.group_path = Path(group_path) if group_path else None

    def _get_groups_for_user_from_file(self, username: str, user_gid: int) -> list[str]:
        """Parse group file to find all groups for a user."""
        groups: set[str] = set()
        if not self.group_path or not self.group_path.exists():
            return sorted(groups)

        try:
            with open(self.group_path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split(":")
                    if len(parts) >= 4:
                        group_name = parts[0]
                        try:
                            gid = int(parts[2])
                            if gid == user_gid:
                                groups.add(group_name)
                        except ValueError:
                            pass
                        members = [m.strip() for m in parts[3].split(",") if m.strip()]
                        if username in members:
                            groups.add(group_name)
        except OSError:
            pass
        return sorted(groups)

    def _inspect_from_files(self) -> dict[str, UserLiveState]:
        """Inspect users directly from mock or specific passwd and group files."""
        users: dict[str, UserLiveState] = {}
        if not self.passwd_path or not self.passwd_path.exists():
            return users

        try:
            with open(self.passwd_path, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split(":")
                    if len(parts) >= 7:
                        uname = parts[0]
                        try:
                            uid = int(parts[2])
                            gid = int(parts[3])
                        except ValueError:
                            continue
                        home = parts[5]
                        shell = parts[6]
                        groups = self._get_groups_for_user_from_file(uname, gid)
                        users[uname] = UserLiveState(
                            name=uname,
                            uid=uid,
                            gid=gid,
                            login_shell=shell,
                            home=home,
                            groups=groups,
                            exists=True,
                        )
        except OSError:
            pass
        return users

    def inspect_all(self) -> dict[str, UserLiveState]:
        """Retrieve live state for all users on the host."""
        if self.passwd_path:
            return self._inspect_from_files()

        # Read live system via standard library pwd and grp
        users: dict[str, UserLiveState] = {}
        try:
            all_groups = grp.getgrall()
            user_groups_map: dict[str, set[str]] = {}
            for g in all_groups:
                for member in g.gr_mem:
                    user_groups_map.setdefault(member, set()).add(g.gr_name)

            for entry in pwd.getpwall():
                # Primary group
                try:
                    primary_grp = grp.getgrgid(entry.pw_gid).gr_name
                except KeyError:
                    primary_grp = str(entry.pw_gid)

                supplementary = user_groups_map.get(entry.pw_name, set())
                all_user_groups = sorted(supplementary | {primary_grp})

                users[entry.pw_name] = UserLiveState(
                    name=entry.pw_name,
                    uid=entry.pw_uid,
                    gid=entry.pw_gid,
                    login_shell=entry.pw_shell,
                    home=entry.pw_dir,
                    groups=all_user_groups,
                    exists=True,
                )
        except Exception:
            # Fallback if pwd functions fail in restricted environment
            pass
        return users

    def inspect_user(self, username: str) -> UserLiveState | None:
        """Retrieve live state for a specific user."""
        if self.passwd_path:
            return self._inspect_from_files().get(username)

        try:
            entry = pwd.getpwnam(username)
            try:
                primary_grp = grp.getgrgid(entry.pw_gid).gr_name
            except KeyError:
                primary_grp = str(entry.pw_gid)

            groups: set[str] = {primary_grp}
            for g in grp.getgrall():
                if username in g.gr_mem:
                    groups.add(g.gr_name)

            return UserLiveState(
                name=entry.pw_name,
                uid=entry.pw_uid,
                gid=entry.pw_gid,
                login_shell=entry.pw_shell,
                home=entry.pw_dir,
                groups=sorted(groups),
                exists=True,
            )
        except KeyError:
            return None
        except Exception:
            return None
