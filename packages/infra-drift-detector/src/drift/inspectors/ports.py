"""Read-only inspector for open and listening network ports via procfs (CWE-250)."""

from __future__ import annotations

import socket
import struct
from pathlib import Path
from typing import NamedTuple


class PortLiveState(NamedTuple):
    """Live state of an open or listening network port."""

    port: int
    protocol: str  # 'tcp', 'udp', 'tcp6', 'udp6'
    address: str
    state: str  # 'listening', 'active', 'closed'
    raw_state: str


# TCP state '0A' in procfs is TCP_LISTEN
TCP_STATE_LISTEN = "0A"


def decode_ipv4(hex_ip: str) -> str:
    """Decode 8-char hex IP from procfs to dotted-decimal IPv4."""
    if len(hex_ip) != 8:
        return "0.0.0.0"  # nosec B104
    try:
        raw_bytes = bytes.fromhex(hex_ip)
        # procfs stores IPv4 in little-endian order
        return f"{raw_bytes[3]}.{raw_bytes[2]}.{raw_bytes[1]}.{raw_bytes[0]}"
    except ValueError:
        return "0.0.0.0"  # nosec B104


def decode_ipv6(hex_ip: str) -> str:
    """Decode 32-char hex IP from procfs to IPv6 string."""
    if len(hex_ip) != 32:
        return "::"
    try:
        raw_bytes = bytes.fromhex(hex_ip)
        # Parse 4 32-bit words in host byte order
        words = struct.unpack("<IIII", raw_bytes)
        packed = struct.pack(">IIII", *words)
        return socket.inet_ntop(socket.AF_INET6, packed)
    except (ValueError, OSError):
        return "::"


class PortInspector:
    """Read-only inspector for listening network ports via /proc/net."""

    def __init__(self, proc_net_root: Path | str = "/proc/net") -> None:
        self.proc_net_root = Path(proc_net_root)

    def _parse_proc_net_file(self, filename: str, protocol: str) -> list[PortLiveState]:
        """Parse a /proc/net/tcp or udp file."""
        file_path = self.proc_net_root / filename
        if not file_path.exists() or not file_path.is_file():
            return []

        results: list[PortLiveState] = []
        is_v6 = "6" in filename
        is_udp = "udp" in filename

        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
        except OSError:
            return []

        # Skip header line
        for line in lines[1:]:
            parts = line.strip().split()
            if len(parts) < 4:
                continue

            local_addr = parts[1]
            raw_state = parts[3]

            if ":" not in local_addr:
                continue

            hex_ip, hex_port = local_addr.split(":", 1)
            try:
                port = int(hex_port, 16)
            except ValueError:
                continue

            ip = decode_ipv6(hex_ip) if is_v6 else decode_ipv4(hex_ip)

            # For TCP, 0A is LISTEN. For UDP, sockets are connectionless; state is active.
            if not is_udp:
                is_listening = raw_state.upper() == TCP_STATE_LISTEN
                state = "listening" if is_listening else "connected"
            else:
                is_listening = True
                state = "listening"

            results.append(
                PortLiveState(
                    port=port,
                    protocol=protocol,
                    address=ip,
                    state=state,
                    raw_state=raw_state,
                )
            )

        return results

    def inspect_all(self) -> list[PortLiveState]:
        """Inspect all TCP and UDP listening sockets."""
        all_ports: list[PortLiveState] = []
        all_ports.extend(self._parse_proc_net_file("tcp", "tcp"))
        all_ports.extend(self._parse_proc_net_file("tcp6", "tcp6"))
        all_ports.extend(self._parse_proc_net_file("udp", "udp"))
        all_ports.extend(self._parse_proc_net_file("udp6", "udp6"))
        return all_ports

    def get_listening_ports(self) -> list[PortLiveState]:
        """Return only sockets currently in listening state."""
        return [p for p in self.inspect_all() if p.state == "listening"]

    def is_port_listening(
        self,
        port: int,
        protocol: str = "tcp",
        address: str | None = None,
    ) -> bool:
        """Check if a specific port is listening."""
        for p in self.get_listening_ports():
            if p.port == port and p.protocol.startswith(protocol):
                if address is None or address in ("0.0.0.0", "::", "*") or p.address == address or p.address in ("0.0.0.0", "::"):  # nosec B104
                    return True
        return False
