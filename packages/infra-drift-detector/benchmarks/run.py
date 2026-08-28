import json
import os
import platform
import statistics
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from drift.comparator import DriftComparator
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


class FastUserInspector(UserInspector):
    def inspect_user(self, username: str) -> UserLiveState | None:
        return UserLiveState(name=username, uid=1000, gid=1000, login_shell="/bin/bash", home="/home", groups=["sudo"])


class FastServiceInspector(ServiceInspector):
    def inspect_service(self, service_name: str) -> ServiceLiveState:
        return ServiceLiveState(
            name=service_name,
            active_state="active",
            unit_file_state="enabled",
            load_state="loaded",
            exists=True,
            is_running=True,
            is_enabled=True,
        )


class FastSysctlInspector(SysctlInspector):
    def inspect_key(self, key: str) -> SysctlLiveState:
        return SysctlLiveState(key=key, value="1", exists=True)


class FastPortInspector(PortInspector):
    def is_port_listening(self, port: int, protocol: str = "tcp", address: str | None = None) -> bool:
        return True


class FastFileInspector(FileInspector):
    def inspect_file(self, target_path: str | Path, compute_sha256: bool = True) -> FileLiveState:
        return FileLiveState(
            path=str(target_path),
            exists=True,
            mode="0644",
            owner="root",
            group="root",
            size=1024,
            sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        )


class FastPackageInspector(PackageInspector):
    def inspect_package(self, package_name: str) -> PackageLiveState:
        return PackageLiveState(name=package_name, version="1.0.0", installed=True)


def create_synthetic_manifest(size: int = 150) -> Manifest:
    """Generate a large synthetic manifest containing various resource categories."""
    users = [UserDesired(name=f"user_{i}", uid=1000 + i, state="present") for i in range(size // 5)]
    services = [ServiceDesired(name=f"service-{i}.service", state="running") for i in range(size // 5)]
    sysctl = [SysctlDesired(key=f"net.ipv4.conf.eth0.forwarding_{i}", value="1") for i in range(size // 5)]
    ports = [PortDesired(port=1000 + i, protocol="tcp", state="listening") for i in range(size // 5)]
    files = [FileDesired(path=f"/etc/app/config_{i}.conf", mode="0644", state="present") for i in range(size // 5)]
    packages = [PackageDesired(name=f"pkg-{i}", state="present") for i in range(size // 5)]

    return Manifest(
        name=f"benchmark-spec-{size}",
        users=users,
        services=services,
        sysctl=sysctl,
        ports=ports,
        files=files,
        packages=packages,
    )


def run_benchmark(iterations: int = 100, batch_size: int = 150) -> dict[str, object]:
    """Execute benchmark runs and collect latency and throughput statistics."""
    manifest = create_synthetic_manifest(batch_size)
    total_resources = (
        len(manifest.users)
        + len(manifest.services)
        + len(manifest.sysctl)
        + len(manifest.ports)
        + len(manifest.files)
        + len(manifest.packages)
    )

    comparator = DriftComparator(
        user_inspector=FastUserInspector(),
        service_inspector=FastServiceInspector(),
        sysctl_inspector=FastSysctlInspector(),
        port_inspector=FastPortInspector(),
        file_inspector=FastFileInspector(),
        package_inspector=FastPackageInspector(),
    )

    latencies_ms: list[float] = []

    # Warmup
    for _ in range(10):
        comparator.compare(manifest)

    # Timed runs
    start_total = time.perf_counter()
    for _ in range(iterations):
        t0 = time.perf_counter()
        comparator.compare(manifest)
        t1 = time.perf_counter()
        latencies_ms.append((t1 - t0) * 1000.0)
    end_total = time.perf_counter()

    total_time_sec = end_total - start_total
    total_audits = iterations
    total_resources_audited = total_audits * total_resources

    p50 = statistics.median(latencies_ms)
    p95 = statistics.quantiles(latencies_ms, n=20)[18] if len(latencies_ms) >= 20 else max(latencies_ms)
    p99 = statistics.quantiles(latencies_ms, n=100)[98] if len(latencies_ms) >= 100 else max(latencies_ms)
    mean_lat = statistics.mean(latencies_ms)
    stdev_lat = statistics.stdev(latencies_ms) if len(latencies_ms) > 1 else 0.0

    # Also measure single live host audit time
    live_manifest = Manifest(
        name="live-host-audit",
        users=[UserDesired(name="root", state="present")],
        services=[ServiceDesired(name="systemd-journald", state="running")],
        sysctl=[SysctlDesired(key="net.ipv4.ip_forward", value="1")],
        ports=[PortDesired(port=22, protocol="tcp", state="listening")],
        files=[FileDesired(path="/etc/hosts", mode="0644", state="present")],
    )
    live_comparator = DriftComparator()
    t_live_start = time.perf_counter()
    live_result = live_comparator.compare(live_manifest)
    t_live_end = time.perf_counter()
    live_audit_ms = (t_live_end - t_live_start) * 1000.0

    results = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "system": {
            "os": platform.system(),
            "release": platform.release(),
            "architecture": platform.machine(),
            "python_version": platform.python_version(),
            "cpu_count": os.cpu_count(),
        },
        "benchmark_config": {
            "iterations": iterations,
            "resources_per_manifest": total_resources,
            "total_resources_evaluated": total_resources_audited,
        },
        "live_host_audit": {
            "resources_checked": live_result.total_checked,
            "latency_ms": round(live_audit_ms, 3),
        },
        "metrics": {
            "total_time_seconds": round(total_time_sec, 4),
            "audits_per_second": round(total_audits / total_time_sec, 2),
            "resources_per_second": round(total_resources_audited / total_time_sec, 2),
            "latency_ms": {
                "mean": round(mean_lat, 3),
                "median_p50": round(p50, 3),
                "p95": round(p95, 3),
                "p99": round(p99, 3),
                "min": round(min(latencies_ms), 3),
                "max": round(max(latencies_ms), 3),
                "stdev": round(stdev_lat, 3),
            },
        },
    }

    return results


def main() -> None:
    output_dir = Path(__file__).resolve().parent
    results_path = output_dir / "resultados.json"

    print("🚀 Running infra-drift-detector performance benchmark...")
    benchmark_data = run_benchmark(iterations=100, batch_size=150)

    results_path.write_text(json.dumps(benchmark_data, indent=2), encoding="utf-8")
    print(f"✅ Benchmark finished. Results saved to {results_path}")
    print(f"📊 Summary:")
    print(f"   Throughput: {benchmark_data['metrics']['resources_per_second']} resources/sec")
    print(f"   Mean Latency: {benchmark_data['metrics']['latency_ms']['mean']} ms ({benchmark_data['benchmark_config']['resources_per_manifest']} resources/manifest)")
    print(f"   p95 Latency:  {benchmark_data['metrics']['latency_ms']['p95']} ms")
    print(f"   Live Host Audit: {benchmark_data['live_host_audit']['latency_ms']} ms")


if __name__ == "__main__":
    main()
