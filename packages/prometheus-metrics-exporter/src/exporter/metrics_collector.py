"""Native Linux host metrics collector conforming to OpenMetrics/Prometheus standards.

Collects CPU (per-core and aggregate), RAM, Disk I/O, Network, File Descriptors,
Load Average, and Uptime from Linux /proc and statvfs.
"""

from __future__ import annotations

import enum
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


class MetricType(str, enum.Enum):
    """OpenMetrics standard metric types."""
    GAUGE = "gauge"
    COUNTER = "counter"
    HISTOGRAM = "histogram"
    SUMMARY = "summary"
    UNTYPED = "untyped"


@dataclass
class MetricSample:
    """A single metric observation with value, labels, and optional timestamp."""
    name: str
    value: float
    labels: Dict[str, str] = field(default_factory=dict)
    timestamp: Optional[float] = None

    def __post_init__(self) -> None:
        self.value = float(self.value)


@dataclass
class MetricFamily:
    """A family of metric samples sharing name, help docstring, and type."""
    name: str
    help_text: str
    metric_type: MetricType
    unit: Optional[str] = None
    samples: List[MetricSample] = field(default_factory=list)

    def add_sample(
        self,
        name: str,
        value: float,
        labels: Optional[Dict[str, str]] = None,
        timestamp: Optional[float] = None,
    ) -> None:
        self.samples.append(
            MetricSample(
                name=name,
                value=value,
                labels=labels or {},
                timestamp=timestamp,
            )
        )


class MetricsCollector:
    """Gathers native host metrics from Linux /proc filesystem and os system calls."""

    CPU_MODES: Tuple[str, ...] = (
        "user",
        "nice",
        "system",
        "idle",
        "iowait",
        "irq",
        "softirq",
        "steal",
        "guest",
        "guest_nice",
    )

    def __init__(
        self,
        proc_root: str | Path = "/proc",
        mountpoints: Optional[List[str]] = None,
    ) -> None:
        self.proc_root = Path(proc_root)
        self.mountpoints = mountpoints or ["/"]
        self._prev_cpu_times: Dict[str, Tuple[float, float]] = {}  # cpu -> (idle_ticks, total_ticks)
        self._prev_scrape_time: float = time.time()
        self._scrape_errors: int = 0

    def _read_proc_file(self, relative_path: str) -> Optional[str]:
        """Safely reads a file from proc_root with strict error handling."""
        try:
            target = self.proc_root / relative_path
            if not target.exists() or not target.is_file():
                return None
            return target.read_text(encoding="utf-8", errors="replace")
        except (OSError, IOError, PermissionError):
            self._scrape_errors += 1
            return None

    def collect_cpu_metrics(self) -> List[MetricFamily]:
        """Collects CPU metrics per core and aggregate from /proc/stat."""
        families: List[MetricFamily] = []
        content = self._read_proc_file("stat")
        if not content:
            return families

        cpu_seconds_family = MetricFamily(
            name="node_cpu_seconds_total",
            help_text="Seconds the CPUs spent in each mode.",
            metric_type=MetricType.COUNTER,
            unit="seconds",
        )
        cpu_usage_family = MetricFamily(
            name="node_cpu_usage_percent",
            help_text="Estimated instant or windowed CPU usage percentage (0-100).",
            metric_type=MetricType.GAUGE,
            unit="percent",
        )

        user_hz = 100.0  # standard Linux clock ticks per second

        for line in content.splitlines():
            line = line.strip()
            if not line.startswith("cpu"):
                continue

            parts = line.split()
            cpu_name = parts[0]
            if cpu_name == "cpu":
                cpu_label = "total"
            elif cpu_name.startswith("cpu") and cpu_name[3:].isdigit():
                cpu_label = cpu_name[3:]
            else:
                continue

            raw_values = [float(p) for p in parts[1:]]
            total_ticks = sum(raw_values)
            idle_ticks = raw_values[3] + (raw_values[4] if len(raw_values) > 4 else 0.0)

            # Record per-mode counter metrics
            for idx, mode in enumerate(self.CPU_MODES):
                if idx < len(raw_values):
                    seconds = raw_values[idx] / user_hz
                    cpu_seconds_family.add_sample(
                        name="node_cpu_seconds_total",
                        value=seconds,
                        labels={"cpu": cpu_label, "mode": mode},
                    )

            # Calculate CPU usage percentage (delta if previous sample exists, else instant ratio)
            if cpu_name in self._prev_cpu_times:
                prev_idle, prev_total = self._prev_cpu_times[cpu_name]
                delta_total = total_ticks - prev_total
                delta_idle = idle_ticks - prev_idle
                if delta_total > 0:
                    cpu_pct = max(0.0, min(100.0, (1.0 - (delta_idle / delta_total)) * 100.0))
                else:
                    cpu_pct = 0.0
            else:
                if total_ticks > 0:
                    cpu_pct = max(0.0, min(100.0, (1.0 - (idle_ticks / total_ticks)) * 100.0))
                else:
                    cpu_pct = 0.0

            self._prev_cpu_times[cpu_name] = (idle_ticks, total_ticks)

            cpu_usage_family.add_sample(
                name="node_cpu_usage_percent",
                value=round(cpu_pct, 2),
                labels={"cpu": cpu_label},
            )

        families.extend([cpu_seconds_family, cpu_usage_family])
        return families

    def collect_memory_metrics(self) -> List[MetricFamily]:
        """Collects RAM and swap metrics from /proc/meminfo."""
        families: List[MetricFamily] = []
        content = self._read_proc_file("meminfo")
        if not content:
            return families

        mem_map: Dict[str, float] = {}
        for line in content.splitlines():
            line = line.strip()
            if ":" not in line:
                continue
            k, v = line.split(":", 1)
            k = k.strip()
            parts = v.strip().split()
            if parts and parts[0].isdigit():
                val_kb = float(parts[0])
                mem_map[k] = val_kb * 1024.0  # Convert kB to bytes

        mem_total = mem_map.get("MemTotal", 0.0)
        mem_free = mem_map.get("MemFree", 0.0)
        mem_avail = mem_map.get("MemAvailable", mem_free)
        buffers = mem_map.get("Buffers", 0.0)
        cached = mem_map.get("Cached", 0.0)
        swap_total = mem_map.get("SwapTotal", 0.0)
        swap_free = mem_map.get("SwapFree", 0.0)

        used_bytes = max(0.0, mem_total - mem_avail)
        used_percent = (used_bytes / mem_total * 100.0) if mem_total > 0 else 0.0

        mem_family = MetricFamily(
            name="node_memory_bytes",
            help_text="Memory statistics in bytes.",
            metric_type=MetricType.GAUGE,
            unit="bytes",
        )
        mem_family.add_sample("node_memory_MemTotal_bytes", mem_total)
        mem_family.add_sample("node_memory_MemFree_bytes", mem_free)
        mem_family.add_sample("node_memory_MemAvailable_bytes", mem_avail)
        mem_family.add_sample("node_memory_Buffers_bytes", buffers)
        mem_family.add_sample("node_memory_Cached_bytes", cached)
        mem_family.add_sample("node_memory_SwapTotal_bytes", swap_total)
        mem_family.add_sample("node_memory_SwapFree_bytes", swap_free)
        mem_family.add_sample("node_memory_used_bytes", used_bytes)

        pct_family = MetricFamily(
            name="node_memory_used_percent",
            help_text="Percentage of memory currently in use.",
            metric_type=MetricType.GAUGE,
            unit="percent",
        )
        pct_family.add_sample("node_memory_used_percent", round(used_percent, 2))

        families.extend([mem_family, pct_family])
        return families

    def collect_disk_metrics(self) -> List[MetricFamily]:
        """Collects Disk I/O stats from /proc/diskstats and filesystem space."""
        families: List[MetricFamily] = []

        # Diskstats
        content = self._read_proc_file("diskstats")
        if content:
            reads_family = MetricFamily(
                name="node_disk_reads_completed_total",
                help_text="The total number of reads completed successfully.",
                metric_type=MetricType.COUNTER,
            )
            read_bytes_family = MetricFamily(
                name="node_disk_read_bytes_total",
                help_text="The total number of bytes read successfully.",
                metric_type=MetricType.COUNTER,
                unit="bytes",
            )
            writes_family = MetricFamily(
                name="node_disk_writes_completed_total",
                help_text="The total number of writes completed successfully.",
                metric_type=MetricType.COUNTER,
            )
            written_bytes_family = MetricFamily(
                name="node_disk_written_bytes_total",
                help_text="The total number of bytes written successfully.",
                metric_type=MetricType.COUNTER,
                unit="bytes",
            )
            io_now_family = MetricFamily(
                name="node_disk_io_now",
                help_text="The number of I/Os currently in progress.",
                metric_type=MetricType.GAUGE,
            )

            for line in content.splitlines():
                parts = line.strip().split()
                if len(parts) < 14:
                    continue
                dev_name = parts[2]
                # Filter out loop and ram devices for cleaner noise reduction
                if dev_name.startswith(("loop", "ram", "sr")):
                    continue

                try:
                    reads_completed = float(parts[3])
                    sectors_read = float(parts[5])
                    writes_completed = float(parts[7])
                    sectors_written = float(parts[9])
                    io_now = float(parts[11])
                except (ValueError, IndexError):
                    continue

                labels = {"device": dev_name}
                reads_family.add_sample("node_disk_reads_completed_total", reads_completed, labels)
                read_bytes_family.add_sample("node_disk_read_bytes_total", sectors_read * 512.0, labels)
                writes_family.add_sample("node_disk_writes_completed_total", writes_completed, labels)
                written_bytes_family.add_sample("node_disk_written_bytes_total", sectors_written * 512.0, labels)
                io_now_family.add_sample("node_disk_io_now", io_now, labels)

            families.extend([
                reads_family,
                read_bytes_family,
                writes_family,
                written_bytes_family,
                io_now_family,
            ])

        # Filesystem stats via os.statvfs
        fs_size_family = MetricFamily(
            name="node_filesystem_size_bytes",
            help_text="Filesystem size in bytes.",
            metric_type=MetricType.GAUGE,
            unit="bytes",
        )
        fs_free_family = MetricFamily(
            name="node_filesystem_free_bytes",
            help_text="Filesystem free space in bytes.",
            metric_type=MetricType.GAUGE,
            unit="bytes",
        )
        fs_avail_family = MetricFamily(
            name="node_filesystem_avail_bytes",
            help_text="Filesystem available space for unprivileged users in bytes.",
            metric_type=MetricType.GAUGE,
            unit="bytes",
        )
        fs_used_pct_family = MetricFamily(
            name="node_filesystem_used_percent",
            help_text="Filesystem used percentage.",
            metric_type=MetricType.GAUGE,
            unit="percent",
        )

        for mp in self.mountpoints:
            try:
                st = os.statvfs(mp)
                total_bytes = float(st.f_blocks * st.f_frsize)
                free_bytes = float(st.f_bfree * st.f_frsize)
                avail_bytes = float(st.f_bavail * st.f_frsize)
                used_bytes = max(0.0, total_bytes - free_bytes)
                used_pct = (used_bytes / total_bytes * 100.0) if total_bytes > 0 else 0.0

                labels = {"mountpoint": mp}
                fs_size_family.add_sample("node_filesystem_size_bytes", total_bytes, labels)
                fs_free_family.add_sample("node_filesystem_free_bytes", free_bytes, labels)
                fs_avail_family.add_sample("node_filesystem_avail_bytes", avail_bytes, labels)
                fs_used_pct_family.add_sample("node_filesystem_used_percent", round(used_pct, 2), labels)
            except OSError:
                self._scrape_errors += 1

        families.extend([fs_size_family, fs_free_family, fs_avail_family, fs_used_pct_family])
        return families

    def collect_network_metrics(self) -> List[MetricFamily]:
        """Collects network interface stats from /proc/net/dev."""
        families: List[MetricFamily] = []
        content = self._read_proc_file("net/dev")
        if not content:
            return families

        rx_bytes_fam = MetricFamily(
            name="node_network_receive_bytes_total",
            help_text="Network device receive bytes total.",
            metric_type=MetricType.COUNTER,
            unit="bytes",
        )
        rx_packets_fam = MetricFamily(
            name="node_network_receive_packets_total",
            help_text="Network device receive packets total.",
            metric_type=MetricType.COUNTER,
        )
        rx_errs_fam = MetricFamily(
            name="node_network_receive_errs_total",
            help_text="Network device receive errors total.",
            metric_type=MetricType.COUNTER,
        )
        rx_drop_fam = MetricFamily(
            name="node_network_receive_drop_total",
            help_text="Network device receive drop total.",
            metric_type=MetricType.COUNTER,
        )
        tx_bytes_fam = MetricFamily(
            name="node_network_transmit_bytes_total",
            help_text="Network device transmit bytes total.",
            metric_type=MetricType.COUNTER,
            unit="bytes",
        )
        tx_packets_fam = MetricFamily(
            name="node_network_transmit_packets_total",
            help_text="Network device transmit packets total.",
            metric_type=MetricType.COUNTER,
        )
        tx_errs_fam = MetricFamily(
            name="node_network_transmit_errs_total",
            help_text="Network device transmit errors total.",
            metric_type=MetricType.COUNTER,
        )
        tx_drop_fam = MetricFamily(
            name="node_network_transmit_drop_total",
            help_text="Network device transmit drop total.",
            metric_type=MetricType.COUNTER,
        )

        lines = content.splitlines()
        for line in lines:
            line = line.strip()
            if ":" not in line:
                continue
            iface, stats_str = line.split(":", 1)
            iface = iface.strip()
            parts = stats_str.strip().split()
            if len(parts) < 16:
                continue

            try:
                rx_bytes = float(parts[0])
                rx_packets = float(parts[1])
                rx_errs = float(parts[2])
                rx_drop = float(parts[3])
                tx_bytes = float(parts[8])
                tx_packets = float(parts[9])
                tx_errs = float(parts[10])
                tx_drop = float(parts[11])
            except (ValueError, IndexError):
                continue

            labels = {"device": iface}
            rx_bytes_fam.add_sample("node_network_receive_bytes_total", rx_bytes, labels)
            rx_packets_fam.add_sample("node_network_receive_packets_total", rx_packets, labels)
            rx_errs_fam.add_sample("node_network_receive_errs_total", rx_errs, labels)
            rx_drop_fam.add_sample("node_network_receive_drop_total", rx_drop, labels)
            tx_bytes_fam.add_sample("node_network_transmit_bytes_total", tx_bytes, labels)
            tx_packets_fam.add_sample("node_network_transmit_packets_total", tx_packets, labels)
            tx_errs_fam.add_sample("node_network_transmit_errs_total", tx_errs, labels)
            tx_drop_fam.add_sample("node_network_transmit_drop_total", tx_drop, labels)

        families.extend([
            rx_bytes_fam,
            rx_packets_fam,
            rx_errs_fam,
            rx_drop_fam,
            tx_bytes_fam,
            tx_packets_fam,
            tx_errs_fam,
            tx_drop_fam,
        ])
        return families

    def collect_fd_metrics(self) -> List[MetricFamily]:
        """Collects file descriptor counts from /proc/sys/fs/file-nr and /proc/self/fd."""
        families: List[MetricFamily] = []

        file_nr_content = self._read_proc_file("sys/fs/file-nr")
        if file_nr_content:
            parts = file_nr_content.strip().split()
            if len(parts) >= 3:
                try:
                    allocated = float(parts[0])
                    maximum = float(parts[2])
                    used_pct = (allocated / maximum * 100.0) if maximum > 0 else 0.0

                    fd_alloc_fam = MetricFamily(
                        name="node_filefd_allocated",
                        help_text="File descriptor allocation count on system.",
                        metric_type=MetricType.GAUGE,
                    )
                    fd_alloc_fam.add_sample("node_filefd_allocated", allocated)

                    fd_max_fam = MetricFamily(
                        name="node_filefd_maximum",
                        help_text="Maximum file descriptors allowable on system.",
                        metric_type=MetricType.GAUGE,
                    )
                    fd_max_fam.add_sample("node_filefd_maximum", maximum)

                    fd_pct_fam = MetricFamily(
                        name="node_filefd_allocated_percent",
                        help_text="Percentage of file descriptors currently allocated.",
                        metric_type=MetricType.GAUGE,
                        unit="percent",
                    )
                    fd_pct_fam.add_sample("node_filefd_allocated_percent", round(used_pct, 2))

                    families.extend([fd_alloc_fam, fd_max_fam, fd_pct_fam])
                except ValueError:
                    pass

        # Process open FDs
        self_fd_path = self.proc_root / "self" / "fd"
        try:
            if self_fd_path.exists() and self_fd_path.is_dir():
                open_fds = len(os.listdir(self_fd_path))
                proc_fd_fam = MetricFamily(
                    name="process_open_fds",
                    help_text="Number of open file descriptors for the current process.",
                    metric_type=MetricType.GAUGE,
                )
                proc_fd_fam.add_sample("process_open_fds", float(open_fds))
                families.append(proc_fd_fam)
        except OSError:
            pass

        return families

    def collect_load_and_uptime(self) -> List[MetricFamily]:
        """Collects load averages and system uptime."""
        families: List[MetricFamily] = []

        # Load average
        loadavg_content = self._read_proc_file("loadavg")
        if loadavg_content:
            parts = loadavg_content.strip().split()
            if len(parts) >= 3:
                try:
                    l1 = float(parts[0])
                    l5 = float(parts[1])
                    l15 = float(parts[2])

                    load_fam = MetricFamily(
                        name="node_load",
                        help_text="System load average (1m, 5m, 15m).",
                        metric_type=MetricType.GAUGE,
                    )
                    load_fam.add_sample("node_load1", l1)
                    load_fam.add_sample("node_load5", l5)
                    load_fam.add_sample("node_load15", l15)
                    families.append(load_fam)
                except ValueError:
                    pass

        # Uptime
        uptime_content = self._read_proc_file("uptime")
        if uptime_content:
            parts = uptime_content.strip().split()
            if parts:
                try:
                    up_secs = float(parts[0])
                    up_fam = MetricFamily(
                        name="node_uptime_seconds",
                        help_text="System uptime in seconds.",
                        metric_type=MetricType.GAUGE,
                        unit="seconds",
                    )
                    up_fam.add_sample("node_uptime_seconds", up_secs)
                    families.append(up_fam)
                except ValueError:
                    pass

        return families

    def collect_all(self) -> List[MetricFamily]:
        """Collects all metric families and adds exporter performance metrics."""
        t0 = time.perf_counter()
        all_families: List[MetricFamily] = []

        all_families.extend(self.collect_cpu_metrics())
        all_families.extend(self.collect_memory_metrics())
        all_families.extend(self.collect_disk_metrics())
        all_families.extend(self.collect_network_metrics())
        all_families.extend(self.collect_fd_metrics())
        all_families.extend(self.collect_load_and_uptime())

        duration = time.perf_counter() - t0
        total_samples = sum(len(f.samples) for f in all_families)

        # Internal exporter metrics
        exp_duration_fam = MetricFamily(
            name="exporter_scrape_duration_seconds",
            help_text="Time taken to collect host metrics.",
            metric_type=MetricType.GAUGE,
            unit="seconds",
        )
        exp_duration_fam.add_sample("exporter_scrape_duration_seconds", round(duration, 6))

        exp_samples_fam = MetricFamily(
            name="exporter_scrape_samples_collected",
            help_text="Total number of metric samples collected in last scrape.",
            metric_type=MetricType.GAUGE,
        )
        exp_samples_fam.add_sample("exporter_scrape_samples_collected", float(total_samples))

        exp_err_fam = MetricFamily(
            name="exporter_scrape_errors_total",
            help_text="Total count of scrape errors encountered.",
            metric_type=MetricType.COUNTER,
        )
        exp_err_fam.add_sample("exporter_scrape_errors_total", float(self._scrape_errors))

        all_families.extend([exp_duration_fam, exp_samples_fam, exp_err_fam])
        return all_families

    def collect_as_dict(self) -> Dict[str, float]:
        """Flattens collected metrics into a dict mapping 'name' or 'name{label=val}' to float value.

        Useful for rapid alert evaluation and testing.
        """
        metrics_dict: Dict[str, float] = {}
        for family in self.collect_all():
            for s in family.samples:
                metrics_dict[s.name] = s.value
                if s.labels:
                    # Create labeled key, e.g. 'node_cpu_usage_percent{cpu="total"}'
                    label_str = ",".join(f'{k}="{v}"' for k, v in sorted(s.labels.items()))
                    metrics_dict[f"{s.name}{{{label_str}}}"] = s.value
        return metrics_dict
