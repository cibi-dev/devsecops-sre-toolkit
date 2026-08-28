"""Pydantic v2 schemas for desired infrastructure state manifests."""

from __future__ import annotations

import re
from typing import Any, Literal
from pydantic import BaseModel, ConfigDict, Field, field_validator


class StrictBaseModel(BaseModel):
    """Base model that strictly forbids undeclared extra attributes (CWE-502)."""

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        validate_assignment=True,
    )


class UserDesired(StrictBaseModel):
    """Desired state for a Linux user account."""

    name: str = Field(..., min_length=1, max_length=64)
    uid: int | None = Field(default=None, ge=0, le=2147483647)
    gid: int | None = Field(default=None, ge=0, le=2147483647)
    shell: str | None = Field(default=None, max_length=256)
    home: str | None = Field(default=None, max_length=512)
    groups: list[str] = Field(default_factory=list)
    state: Literal["present", "absent"] = "present"

    @field_validator("name")
    @classmethod
    def validate_username(cls, v: str) -> str:
        if not re.match(r"^[a-zA-Z0-9_.][a-zA-Z0-9_.-]*\$?$", v):
            raise ValueError(f"Invalid Linux username format: '{v}'")
        return v

    @field_validator("groups")
    @classmethod
    def validate_groups(cls, groups: list[str]) -> list[str]:
        for g in groups:
            if not re.match(r"^[a-zA-Z0-9_.][a-zA-Z0-9_.-]*\$?$", g):
                raise ValueError(f"Invalid Linux group name: '{g}'")
        return groups


class ServiceDesired(StrictBaseModel):
    """Desired state for a systemd service."""

    name: str = Field(..., min_length=1, max_length=128)
    state: Literal["running", "stopped", "enabled", "disabled", "present", "absent"] = "running"
    enabled: bool | None = None

    @field_validator("name")
    @classmethod
    def validate_service_name(cls, v: str) -> str:
        # Prevent shell injection and path traversal
        if not re.match(r"^[a-zA-Z0-9_.@-]+(?:\.(?:service|socket|target|timer|mount))?$", v):
            raise ValueError(f"Invalid service unit name format: '{v}'")
        return v


class SysctlDesired(StrictBaseModel):
    """Desired kernel sysctl flag."""

    key: str = Field(..., min_length=1, max_length=256)
    value: str | int = Field(...)

    @field_validator("key")
    @classmethod
    def validate_sysctl_key(cls, v: str) -> str:
        if ".." in v or "/" in v or "\\" in v:
            raise ValueError(f"Path traversal or directory separators detected in sysctl key: '{v}'")
        if not re.match(r"^[a-zA-Z0-9_.-]+$", v):
            raise ValueError(f"Invalid characters in sysctl key: '{v}'")
        return v

    @field_validator("value")
    @classmethod
    def normalize_value(cls, v: Any) -> str:
        return str(v).strip()


class PortDesired(StrictBaseModel):
    """Desired listening network port."""

    port: int = Field(..., ge=1, le=65535)
    protocol: Literal["tcp", "udp", "tcp6", "udp6"] = "tcp"
    address: str = Field(default="0.0.0.0", max_length=128)  # nosec B104
    state: Literal["listening", "closed"] = "listening"
    process: str | None = Field(default=None, max_length=128)

    @field_validator("address")
    @classmethod
    def validate_address(cls, v: str) -> str:
        # Match standard IPv4, IPv6 or *
        if v not in ("0.0.0.0", "127.0.0.1", "::", "::1", "*") and not re.match(  # nosec B104
            r"^[0-9a-fA-F:.]+$", v
        ):
            raise ValueError(f"Invalid network bind address: '{v}'")
        return v


class FileDesired(StrictBaseModel):
    """Desired file/directory attributes and integrity."""

    path: str = Field(..., min_length=1, max_length=1024)
    mode: str | None = Field(default=None, max_length=10)
    owner: str | None = Field(default=None, max_length=64)
    group: str | None = Field(default=None, max_length=64)
    sha256: str | None = Field(default=None, max_length=64)
    state: Literal["present", "absent"] = "present"
    content: str | None = None

    @field_validator("path")
    @classmethod
    def validate_absolute_path(cls, v: str) -> str:
        if not v.startswith("/"):
            raise ValueError(f"File path must be an absolute path: '{v}'")
        if ".." in v.split("/"):
            raise ValueError(f"Path traversal ('..') is not permitted in file path: '{v}'")
        return v

    @field_validator("mode")
    @classmethod
    def validate_mode(cls, v: str | None) -> str | None:
        if v is None:
            return None
        clean = v.strip()
        if not re.match(r"^0?[0-7]{3,4}$", clean):
            raise ValueError(f"File mode must be octal representation (e.g. '0644', '0755'): '{v}'")
        if len(clean) == 3:
            return f"0{clean}"
        return clean

    @field_validator("sha256")
    @classmethod
    def validate_sha256(cls, v: str | None) -> str | None:
        if v is None:
            return None
        clean = v.strip().lower()
        if not re.match(r"^[a-f0-9]{64}$", clean):
            raise ValueError(f"Invalid SHA256 checksum format: '{v}'")
        return clean


class PackageDesired(StrictBaseModel):
    """Desired system package state."""

    name: str = Field(..., min_length=1, max_length=128)
    version: str | None = Field(default=None, max_length=64)
    state: Literal["present", "absent"] = "present"

    @field_validator("name")
    @classmethod
    def validate_package_name(cls, v: str) -> str:
        if not re.match(r"^[a-zA-Z0-9.+~:-]+$", v):
            raise ValueError(f"Invalid package name format: '{v}'")
        return v


class Manifest(StrictBaseModel):
    """Top-level desired state infrastructure specification."""

    version: str = Field(default="1.0", max_length=16)
    name: str = Field(default="host-spec", max_length=128)
    users: list[UserDesired] = Field(default_factory=list)
    services: list[ServiceDesired] = Field(default_factory=list)
    sysctl: list[SysctlDesired] = Field(default_factory=list)
    ports: list[PortDesired] = Field(default_factory=list)
    files: list[FileDesired] = Field(default_factory=list)
    packages: list[PackageDesired] = Field(default_factory=list)
