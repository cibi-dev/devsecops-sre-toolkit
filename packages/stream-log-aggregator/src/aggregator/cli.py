"""Command-line Interface for stream-log-aggregator."""

import argparse
import asyncio
import json
import os
import signal
import sys
import time
from typing import List, Optional
from aggregator import LogEvent, __version__
from aggregator.inputs.file_tail import FileTailInput
from aggregator.inputs.tcp import SyslogTCPInput, UnixSocketInput
from aggregator.inputs.udp import SyslogUDPInput
from aggregator.outputs.file import RotatingFileOutput
from aggregator.outputs.stdout import StdoutOutput
from aggregator.outputs.webhook import WebhookOutput
from aggregator.pipeline import LogPipeline
from aggregator.transformers.grok import GrokTransformer
from aggregator.transformers.sanitizer import PIISanitizer


def build_parser() -> argparse.ArgumentParser:
    """Construct CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="stream-log-aggregator",
        description="Enterprise Async Multi-channel Log Ingestion Daemon with PII Sanitization and Disk Buffer.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")

    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Command: start
    start_parser = subparsers.add_parser("start", help="Start the log aggregation daemon")
    start_parser.add_argument("--tcp-port", type=int, default=None, help="Syslog TCP listener port (e.g. 5140)")
    start_parser.add_argument("--udp-port", type=int, default=None, help="Syslog UDP listener port (e.g. 5140)")
    start_parser.add_argument("--unix-socket", type=str, default=None, help="Unix domain socket path")
    start_parser.add_argument("--tail-file", type=str, default=None, help="Path of log file to tail")
    start_parser.add_argument("--workers", type=int, default=4, help="Transformer worker count (default: 4)")
    start_parser.add_argument("--buffer-dir", type=str, default=None, help="Directory for persistent disk buffer")
    start_parser.add_argument("--output-stdout", action="store_true", default=True, help="Enable stdout sink")
    start_parser.add_argument("--output-file", type=str, default=None, help="Destination file for rotating log sink")
    start_parser.add_argument("--output-webhook", type=str, default=None, help="Webhook URL for HTTP batch sink")

    # Command: test-input
    test_parser = subparsers.add_parser("test-input", help="Send test log lines to verify ingestion & parsing")
    test_parser.add_argument("--protocol", choices=["tcp", "udp", "direct"], default="direct", help="Transport to test")
    test_parser.add_argument("--host", default="127.0.0.1", help="Target host (default: 127.0.0.1)")
    test_parser.add_argument("--port", type=int, default=5140, help="Target port (default: 5140)")
    test_parser.add_argument("--message", type=str, default=None, help="Custom log message string")

    # Command: benchmark
    bench_parser = subparsers.add_parser("benchmark", help="Run local synthetic benchmark")
    bench_parser.add_argument("--events", type=int, default=10000, help="Number of synthetic events (default: 10000)")
    bench_parser.add_argument("--workers", type=int, default=4, help="Pipeline workers (default: 4)")
    bench_parser.add_argument("--batch-size", type=int, default=200, help="Dispatcher batch size (default: 200)")

    # Command: status
    status_parser = subparsers.add_parser("status", help="Display daemon operational status")

    return parser


async def run_start(args: argparse.Namespace) -> int:
    """Run daemon until interrupted."""
    pipeline = LogPipeline(
        worker_count=args.workers,
        buffer_dir=args.buffer_dir,
    )

    # Attach Transformers
    pipeline.add_transformer(GrokTransformer())
    pipeline.add_transformer(PIISanitizer())

    # Attach Inputs
    has_input = False
    if args.tcp_port:
        pipeline.add_input(SyslogTCPInput(port=args.tcp_port))
        has_input = True
    if args.udp_port:
        pipeline.add_input(SyslogUDPInput(port=args.udp_port))
        has_input = True
    if args.unix_socket:
        pipeline.add_input(UnixSocketInput(socket_path=args.unix_socket))
        has_input = True
    if args.tail_file:
        pipeline.add_input(FileTailInput(file_path=args.tail_file, start_from_beginning=False))
        has_input = True

    if not has_input:
        # Default fallback TCP input
        pipeline.add_input(SyslogTCPInput(port=5140))

    # Attach Outputs
    if args.output_file:
        pipeline.add_output(RotatingFileOutput(file_path=args.output_file))
    if args.output_webhook:
        pipeline.add_output(WebhookOutput(url=args.output_webhook))
    if args.output_stdout:
        pipeline.add_output(StdoutOutput())

    print(f"[*] Starting stream-log-aggregator v{__version__} with {args.workers} workers...")
    await pipeline.start()
    print("[*] Pipeline active. Listening for events. Press Ctrl+C to stop.")

    stop_event = asyncio.Event()

    def _signal_handler():
        print("\n[*] Shutdown signal received...")
        stop_event.set()

    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        try:
            loop.add_signal_handler(sig, _signal_handler)
        except NotImplementedError:
            pass

    try:
        await stop_event.wait()
    finally:
        print("[*] Stopping pipeline and draining buffer...")
        await pipeline.stop(drain=True)
        print("[*] Pipeline gracefully stopped.")
        print(json.dumps(pipeline.metrics, indent=2))

    return 0


async def run_test_input(args: argparse.Namespace) -> int:
    """Send test message and print parsed output."""
    sample_msg = args.message or (
        "<134>Feb 15 14:02:30 db-node1 postgres[5432]: Connection from 192.168.1.50: user=admin "
        "password=SecretPassword123! token=Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.abc "
        "email=admin@internal.corp query='SELECT * FROM users'"
    )

    print(f"[*] Testing input ingestion ({args.protocol})...")
    print(f"[*] Raw input: {sample_msg}")

    if args.protocol == "direct":
        pipeline = LogPipeline(worker_count=1)
        pipeline.add_transformer(GrokTransformer())
        pipeline.add_transformer(PIISanitizer())
        await pipeline.start()

        await pipeline.push_raw(sample_msg, source="test-direct")
        await asyncio.sleep(0.1)
        await pipeline.stop()

        # Demonstrate transform directly
        event = LogEvent.create(sample_msg, source="test")
        grok = GrokTransformer()
        sanitizer = PIISanitizer()
        event = grok.transform(event)
        event = sanitizer.transform(event)

        print("[+] Processed & Sanitized Event:")
        print(json.dumps(event.to_dict(), indent=2))
        return 0

    elif args.protocol == "tcp":
        reader, writer = await asyncio.open_connection(args.host, args.port)
        writer.write((sample_msg + "\n").encode("utf-8"))
        await writer.drain()
        writer.close()
        await writer.wait_closed()
        print(f"[+] Sent via TCP to {args.host}:{args.port}")
        return 0

    elif args.protocol == "udp":
        class _UDPClientProtocol(asyncio.DatagramProtocol):
            def __init__(self, message, on_con_lost):
                self.message = message
                self.on_con_lost = on_con_lost
                self.transport = None

            def connection_made(self, transport):
                self.transport = transport
                self.transport.sendto(self.message.encode("utf-8"))
                self.transport.close()

            def connection_lost(self, exc):
                self.on_con_lost.set_result(True)

        loop = asyncio.get_running_loop()
        on_con_lost = loop.create_future()
        transport, protocol = await loop.create_datagram_endpoint(
            lambda: _UDPClientProtocol(sample_msg, on_con_lost),
            remote_addr=(args.host, args.port),
        )
        await on_con_lost
        print(f"[+] Sent via UDP to {args.host}:{args.port}")
        return 0

    return 0


async def run_benchmark(args: argparse.Namespace) -> int:
    """Execute synthetic benchmark from CLI."""
    print(f"[*] Running CLI benchmark with {args.events} events, {args.workers} workers...")
    from aggregator.transformers.grok import GrokTransformer
    from aggregator.transformers.sanitizer import PIISanitizer

    pipeline = LogPipeline(
        worker_count=args.workers,
        batch_size=args.batch_size,
    )
    pipeline.add_transformer(GrokTransformer())
    pipeline.add_transformer(PIISanitizer())

    class SilentSink(StdoutOutput):
        def __init__(self):
            super().__init__(name="silent")
            self.total_received = 0

        async def send_batch(self, events: List[LogEvent]) -> bool:
            self.total_received += len(events)
            self._events_sent += len(events)
            self._batches_sent += 1
            return True

    sink = SilentSink()
    pipeline.add_output(sink)
    await pipeline.start()

    sample_log = (
        "<134>Feb 15 14:02:30 auth-node1 app[101]: User john.doe@example.com logged in "
        "from 10.0.0.45 with token=Bearer abc123def456 and password=mysecretpassword"
    )

    t0 = time.perf_counter()
    for _ in range(args.events):
        await pipeline.push_raw(sample_log, source="bench")

    # Wait for queue to drain
    while sink.total_received < args.events and time.perf_counter() - t0 < 30.0:
        await asyncio.sleep(0.01)

    elapsed = time.perf_counter() - t0
    await pipeline.stop(drain=True)

    throughput = args.events / elapsed if elapsed > 0 else 0.0
    print(f"[+] Benchmark completed:")
    print(f"    - Events processed : {sink.total_received}/{args.events}")
    print(f"    - Elapsed time     : {elapsed:.3f} s")
    print(f"    - Throughput       : {throughput:.1f} events/s")
    return 0


def run_status() -> int:
    """Display status info."""
    print(f"stream-log-aggregator version {__version__}")
    print("Status: Daemon ready.")
    return 0


def main(argv: Optional[List[str]] = None) -> int:
    """CLI entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)

    if not args.command:
        parser.print_help()
        return 0

    if args.command == "start":
        return asyncio.run(run_start(args))
    elif args.command == "test-input":
        return asyncio.run(run_test_input(args))
    elif args.command == "benchmark":
        return asyncio.run(run_benchmark(args))
    elif args.command == "status":
        return run_status()

    return 0


if __name__ == "__main__":
    sys.exit(main())
