"""Direct procfs collector for Linux SRE Watchdog.

Reads directly from /proc/stat, /proc/meminfo, /proc/loadavg, and /proc/[pid]/stat
without external dependencies or C-extensions.
"""

from __future__ import annotations

import os
import sys
import time
from pathlib import Path
from typing import NamedTuple, Optional

from pydantic import BaseModel, ConfigDict, Field


class CPUStats(BaseModel):
    """Raw and computed CPU statistics."""

    model_config = ConfigDict(extra="forbid")

    user: int = Field(default=0, description="Time spent in user mode (clock ticks)")
    nice: int = Field(default=0, description="Time spent in nice mode")
    system: int = Field(default=0, description="Time spent in system mode")
    idle: int = Field(default=0, description="Time spent in idle task")
    iowait: int = Field(default=0, description="Time waiting for I/O")
    irq: int = Field(default=0, description="Time servicing interrupts")
    softirq: int = Field(default=0, description="Time servicing softirqs")
    steal: int = Field(default=0, description="Stolen time by hypervisor")
    guest: int = Field(default=0, description="Time spent running guest OS")
    guest_nice: int = Field(default=0, description="Time running nice guest OS")
    total: int = Field(default=0, description="Total CPU ticks")
    idle_all: int = Field(default=0, description="Total idle CPU ticks (idle + iowait)")
    usage_percent: float = Field(default=0.0, description="Aggregated CPU usage percentage")


class MemoryStats(BaseModel):
    """Memory statistics parsed directly from /proc/meminfo."""

    model_config = ConfigDict(extra="forbid")

    total_bytes: int = Field(default=0, description="Total physical RAM in bytes")
    free_bytes: int = Field(default=0, description="Free RAM in bytes")
    available_bytes: int = Field(default=0, description="Available RAM in bytes")
    buffers_bytes: int = Field(default=0, description="Buffers in bytes")
    cached_bytes: int = Field(default=0, description="Cached memory in bytes")
    swap_total_bytes: int = Field(default=0, description="Total swap in bytes")
    swap_free_bytes: int = Field(default=0, description="Free swap in bytes")
    swap_used_bytes: int = Field(default=0, description="Used swap in bytes")
    used_bytes: int = Field(default=0, description="Used RAM in bytes")
    usage_percent: float = Field(default=0.0, description="RAM usage percentage (0-100)")
    swap_usage_percent: float = Field(default=0.0, description="Swap usage percentage (0-100)")


class LoadAvgStats(BaseModel):
    """System load averages from /proc/loadavg."""

    model_config = ConfigDict(extra="forbid")

    load1: float = Field(default=0.0, description="1-minute load average")
    load5: float = Field(default=0.0, description="5-minute load average")
    load15: float = Field(default=0.0, description="15-minute load average")
    running_threads: int = Field(default=0, description="Currently running executable entities")
    total_threads: int = Field(default=0, description="Total number of threads/processes")
    last_pid: int = Field(default=0, description="Most recently created PID")


class ZombieInfo(BaseModel):
    """Information regarding an identified zombie (defunct) process."""

    model_config = ConfigDict(extra="forbid")

    pid: int = Field(description="Zombie process PID")
    ppid: int = Field(description="Parent PID responsible for reaping")
    comm: str = Field(description="Executable command name")


class SystemSnapshot(BaseModel):
    """Full system resource and process state snapshot."""

    model_config = ConfigDict(extra="forbid")

    timestamp: float = Field(default_factory=time.time, description="Epoch timestamp of sample")
    cpu: CPUStats = Field(description="Aggregated CPU metrics")
    memory: MemoryStats = Field(description="System memory metrics")
    loadavg: LoadAvgStats = Field(description="System load averages")
    zombies: list[ZombieInfo] = Field(default_factory=list, description="List of detected zombies")
    total_processes: int = Field(default=0, description="Total inspected processes in procfs")
    core_count: int = Field(default=1, description="Detected number of logical CPU cores")


class _CPUTickSample(NamedTuple):
    total: int
    idle_all: int


class ProcfsCollector:
    """Zero-overhead procfs metrics collector.

    Reads raw kernel virtual files in /proc without spawning external subprocesses.
    Operates strictly in unprivileged read-only user space (CWE-250 compliant).
    """

    def __init__(self, proc_root: str | Path = "/proc") -> None:
        self.proc_root = Path(proc_root)
        self._last_cpu_sample: Optional[_CPUTickSample] = None
        self._core_count: int = self._detect_core_count()

    def _detect_core_count(self) -> int:
        """Detect the number of CPU cores from /proc/stat or os.cpu_count()."""
        stat_file = self.proc_root / "stat"
        if stat_file.is_file():
            try:
                count = 0
                with stat_file.open("r", encoding="utf-8", errors="replace") as f:
                    for line in f:
                        if line.startswith("cpu") and len(line) > 3 and line[3].isdigit():
                            count += 1
                if count > 0:
                    return count
            except (OSError, UnicodeDecodeError):
                pass
        return os.cpu_count() or 1

    def read_cpu_raw(self) -> CPUStats:
        """Read current cumulative CPU ticks from /proc/stat."""
        stat_file = self.proc_root / "stat"
        if not stat_file.is_file():
            return CPUStats()

        try:
            with stat_file.open("r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    if line.startswith("cpu "):
                        parts = line.split()
                        # cpu user nice system idle iowait irq softirq steal guest guest_nice
                        values = [int(p) for p in parts[1:]]
                        # Pad with zeroes if kernel version returns fewer fields
                        while len(values) < 10:
                            values.append(0)

                        user, nice, system, idle, iowait, irq, softirq, steal, guest, guest_nice = values[:10]

                        # In Linux kernel accounting:
                        # guest is already included in user, and guest_nice in nice
                        # Real user ticks = user - guest
                        # Real nice ticks = nice - guest_nice
                        idle_all = idle + iowait
                        non_idle = user + nice + system + irq + softirq + steal
                        total = idle_all + non_idle

                        return CPUStats(
                            user=user,
                            nice=nice,
                            system=system,
                            idle=idle,
                            iowait=iowait,
                            irq=irq,
                            softirq=softirq,
                            steal=steal,
                            guest=guest,
                            guest_nice=guest_nice,
                            total=total,
                            idle_all=idle_all,
                            usage_percent=0.0,
                        )
        except (OSError, ValueError, IndexError):
            pass

        return CPUStats()

    def collect_cpu(self, sample_interval: float = 0.0) -> CPUStats:
        """Collect CPU usage percentage.

        If sample_interval > 0, sleeps for interval and computes delta.
        Otherwise computes delta relative to the previous sample.
        """
        first = self.read_cpu_raw()

        if sample_interval > 0:
            time.sleep(sample_interval)
            second = self.read_cpu_raw()
            usage = self._calc_cpu_usage(first, second)
            self._last_cpu_sample = _CPUTickSample(total=second.total, idle_all=second.idle_all)
            return second.model_copy(update={"usage_percent": usage})

        if self._last_cpu_sample is None:
            self._last_cpu_sample = _CPUTickSample(total=first.total, idle_all=first.idle_all)
            return first.model_copy(update={"usage_percent": 0.0})

        prev = self._last_cpu_sample
        curr = _CPUTickSample(total=first.total, idle_all=first.idle_all)
        usage = self._calc_cpu_usage_raw(prev, curr)
        self._last_cpu_sample = curr
        return first.model_copy(update={"usage_percent": usage})

    @staticmethod
    def _calc_cpu_usage_raw(prev: _CPUTickSample, curr: _CPUTickSample) -> float:
        total_delta = curr.total - prev.total
        idle_delta = curr.idle_all - prev.idle_all
        if total_delta <= 0:
            return 0.0
        usage = ((total_delta - idle_delta) / total_delta) * 100.0
        return max(0.0, min(100.0, round(usage, 2)))

    def _calc_cpu_usage(self, s1: CPUStats, s2: CPUStats) -> float:
        total_delta = s2.total - s1.total
        idle_delta = s2.idle_all - s1.idle_all
        if total_delta <= 0:
            return 0.0
        usage = ((total_delta - idle_delta) / total_delta) * 100.0
        return max(0.0, min(100.0, round(usage, 2)))

    def collect_memory(self) -> MemoryStats:
        """Parse /proc/meminfo directly."""
        meminfo_file = self.proc_root / "meminfo"
        if not meminfo_file.is_file():
            return MemoryStats()

        raw_kb: dict[str, int] = {}
        try:
            with meminfo_file.open("r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    if ":" not in line:
                        continue
                    key, rest = line.split(":", 1)
                    key = key.strip()
                    parts = rest.strip().split()
                    if parts:
                        try:
                            raw_kb[key] = int(parts[0])
                        except ValueError:
                            continue
        except OSError:
            return MemoryStats()

        total_kb = raw_kb.get("MemTotal", 0)
        free_kb = raw_kb.get("MemFree", 0)
        available_kb = raw_kb.get("MemAvailable", 0)
        buffers_kb = raw_kb.get("Buffers", 0)
        cached_kb = raw_kb.get("Cached", 0)
        swap_total_kb = raw_kb.get("SwapTotal", 0)
        swap_free_kb = raw_kb.get("SwapFree", 0)

        # If MemAvailable is not reported by kernel (older Linux), estimate it
        if available_kb == 0 and total_kb > 0:
            available_kb = free_kb + buffers_kb + cached_kb

        used_kb = max(0, total_kb - available_kb)
        swap_used_kb = max(0, swap_total_kb - swap_free_kb)

        usage_pct = (used_kb / total_kb * 100.0) if total_kb > 0 else 0.0
        swap_usage_pct = (swap_used_kb / swap_total_kb * 100.0) if swap_total_kb > 0 else 0.0

        return MemoryStats(
            total_bytes=total_kb * 1024,
            free_bytes=free_kb * 1024,
            available_bytes=available_kb * 1024,
            buffers_bytes=buffers_kb * 1024,
            cached_bytes=cached_kb * 1024,
            swap_total_bytes=swap_total_kb * 1024,
            swap_free_bytes=swap_free_kb * 1024,
            swap_used_bytes=swap_used_kb * 1024,
            used_bytes=used_kb * 1024,
            usage_percent=round(usage_pct, 2),
            swap_usage_percent=round(swap_usage_pct, 2),
        )

    def collect_loadavg(self) -> LoadAvgStats:
        """Parse /proc/loadavg directly."""
        load_file = self.proc_root / "loadavg"
        if not load_file.is_file():
            return LoadAvgStats()

        try:
            with load_file.open("r", encoding="utf-8", errors="replace") as f:
                content = f.read().strip()
            parts = content.split()
            if len(parts) >= 5:
                load1 = float(parts[0])
                load5 = float(parts[1])
                load15 = float(parts[2])
                threads_part = parts[3]
                running_threads, total_threads = 0, 0
                if "/" in threads_part:
                    t_parts = threads_part.split("/")
                    running_threads = int(t_parts[0])
                    total_threads = int(t_parts[1])
                last_pid = int(parts[4])
                return LoadAvgStats(
                    load1=load1,
                    load5=load5,
                    load15=load15,
                    running_threads=running_threads,
                    total_threads=total_threads,
                    last_pid=last_pid,
                )
        except (OSError, ValueError, IndexError):
            pass

        return LoadAvgStats()

    def collect_processes_and_zombies(self) -> tuple[int, list[ZombieInfo]]:
        """Iterate over /proc/[pid]/stat to detect active processes and zombies.

        Handles processes exiting during traversal gracefully.
        """
        if not self.proc_root.is_dir():
            return 0, []

        zombies: list[ZombieInfo] = []
        process_count = 0
        proc_root_str = str(self.proc_root)

        try:
            with os.scandir(proc_root_str) as it:
                for entry in it:
                    name = entry.name
                    if not name.isdigit():
                        continue

                    stat_path = f"{proc_root_str}/{name}/stat"
                    try:
                        fd = os.open(stat_path, os.O_RDONLY)
                        try:
                            data = os.read(fd, 160)
                        finally:
                            os.close(fd)
                    except (OSError, ProcessLookupError):
                        continue

                    process_count += 1

                    p1 = data.find(b"(")
                    p2 = data.rfind(b")")
                    if p1 == -1 or p2 == -1 or p2 <= p1:
                        continue

                    rest = data[p2 + 1 :].strip().split()
                    if not rest:
                        continue

                    state = rest[0]
                    if state == b"Z":
                        comm = data[p1 + 1 : p2].decode("utf-8", "replace")
                        pid = int(name)
                        ppid = 1
                        if len(rest) > 1:
                            try:
                                ppid = int(rest[1])
                            except ValueError:
                                ppid = 1
                        zombies.append(ZombieInfo(pid=pid, ppid=ppid, comm=comm))
        except OSError:
            return 0, []

        return process_count, zombies

    def take_snapshot(self, sample_interval: float = 0.0) -> SystemSnapshot:
        """Capture a complete, cohesive system snapshot."""
        # Check privileges (CWE-250 security notice)
        if os.geteuid() == 0:
            print("SECURITY WARNING: ProcfsCollector does not require root privileges.", file=sys.stderr)

        cpu = self.collect_cpu(sample_interval=sample_interval)
        memory = self.collect_memory()
        loadavg = self.collect_loadavg()
        total_procs, zombies = self.collect_processes_and_zombies()

        return SystemSnapshot(
            timestamp=time.time(),
            cpu=cpu,
            memory=memory,
            loadavg=loadavg,
            zombies=zombies,
            total_processes=total_procs,
            core_count=self._core_count,
        )
