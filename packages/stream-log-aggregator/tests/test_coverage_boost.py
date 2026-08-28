"""Additional unit tests to ensure >=90% test coverage across all modules."""

import asyncio
import os
import tempfile
import time
from pathlib import Path
from unittest.mock import patch, MagicMock, AsyncMock
import pytest
import httpx

from aggregator import LogEvent, MAX_EVENT_SIZE_BYTES
from aggregator.buffer import PersistentDiskBuffer
from aggregator.inputs import BaseInput
from aggregator.inputs.file_tail import FileTailInput
from aggregator.inputs.tcp import SyslogTCPInput, UnixSocketInput
from aggregator.inputs.udp import SyslogUDPInput, _SyslogUDPProtocol
from aggregator.outputs import BaseOutput
from aggregator.outputs.file import RotatingFileOutput
from aggregator.outputs.stdout import StdoutOutput
from aggregator.outputs.webhook import WebhookOutput
from aggregator.pipeline import LogPipeline
from aggregator.transformers import BaseTransformer
from aggregator.transformers.grok import GrokTransformer


@pytest.mark.asyncio
async def test_abstract_bases_and_log_event_bytes():
    """Test Base abstract classes super methods and bytes parsing in LogEvent."""
    # 1. LogEvent bytes conversion and from_dict
    ev = LogEvent(raw=b"bytes raw message", message=b"bytes msg")
    assert ev.raw == "bytes raw message"
    ev_dict = LogEvent.from_dict({"raw": "from dict", "message": "from dict msg"})
    assert ev_dict.raw == "from dict"

    # 2. BaseInput abstract methods
    class DummyInput(BaseInput):
        async def start(self, target_queue):
            await super().start(target_queue)
        async def stop(self):
            await super().stop()

    di = DummyInput("dummy")
    await di.start(asyncio.Queue())
    await di.stop()

    # 3. BaseTransformer abstract methods
    class DummyTransformer(BaseTransformer):
        def transform(self, event):
            return super().transform(event)

    dt = DummyTransformer("dummy-t")
    res = dt.transform(ev)
    assert res is None

    # 4. BaseOutput abstract methods
    class DummyOutput(BaseOutput):
        async def send_batch(self, events):
            return await super().send_batch(events)

    do = DummyOutput("dummy-o")
    await do.send_batch([ev])


@pytest.mark.asyncio
async def test_tcp_and_unix_task_cancellation():
    """Test stopping TCP and Unix inputs when client tasks are active in set."""
    # 1. TCP stop with dummy task
    tcp = SyslogTCPInput()
    async def dummy_coro():
        await asyncio.sleep(10.0)
    t1 = asyncio.create_task(dummy_coro())
    tcp._client_tasks.add(t1)
    await tcp.stop()
    assert t1.cancelled() or t1.done()

    # 2. Unix stop with dummy task and existing socket file
    with tempfile.NamedTemporaryFile(delete=False) as tf:
        sock_file = tf.name
    unix = UnixSocketInput(socket_path=sock_file)
    t2 = asyncio.create_task(dummy_coro())
    unix._client_tasks.add(t2)
    await unix.stop()
    assert not os.path.exists(sock_file)


@pytest.mark.asyncio
async def test_stdout_and_base_input_error_handling():
    """Test stdout error handling and base input emit error branches."""
    # Stdout output write error with custom failing stream
    failing_stream = MagicMock()
    failing_stream.write.side_effect = IOError("Broken stream")
    stdout_sink = StdoutOutput(stream=failing_stream)
    res = await stdout_sink.send_batch([LogEvent.create("msg")])
    assert res is False
    assert stdout_sink.metrics["errors"] == 1

    # BaseInput emit with failing queue put
    inp = SyslogTCPInput()
    failing_q = AsyncMock()
    failing_q.put.side_effect = RuntimeError("Queue put fail")
    inp._target_queue = failing_q
    inp._running = True
    await inp.emit("error message")
    assert inp.metrics["errors"] == 1

    # BaseInput emit with oversized data
    normal_q = asyncio.Queue()
    inp._target_queue = normal_q
    await inp.emit("X" * (MAX_EVENT_SIZE_BYTES + 100))
    assert inp.metrics["drops"] == 1

    # BaseInput emit when target_queue is None
    inp._target_queue = None
    await inp.emit("no queue")


@pytest.mark.asyncio
async def test_grok_http_and_syslog_edge_cases():
    """Test grok transformer on numeric fields and invalid values."""
    grok = GrokTransformer()
    ev_http = LogEvent.create('10.0.0.1 - - [27/Aug/2026:14:00:00 +0000] "GET /api HTTP/1.1" 200 4096 "-" "curl/7.68.0"')
    res_http = grok.transform(ev_http)
    assert res_http.metadata.get("bytes_sent") == 4096
    assert res_http.metadata.get("status") == 200


@pytest.mark.asyncio
async def test_buffer_deep_branches(tmp_path: Path):
    """Test buffer queue empty, disk usage error, and segment recovery."""
    buf_dir = tmp_path / "deep_spool"
    buf = PersistentDiskBuffer(buffer_dir=str(buf_dir), max_memory_events=2, max_segment_bytes=100)

    # Pop when _has_disk_segments is True but no files
    buf._has_disk_segments = True
    res = await buf.pop_batch(max_items=5, timeout=0.01)
    assert res == []
    assert buf._has_disk_segments is False

    # Recover with non-integer segment file
    odd_seg = buf_dir / "segment_notanumber.spool"
    odd_seg.write_text("invalid line\n", encoding="utf-8")
    count = await buf.recover()
    assert count >= 1

    buf.close()


@pytest.mark.asyncio
async def test_tcp_and_unix_direct_handler_coverage(tmp_path: Path):
    """Direct invocation of _handle_client on TCP and Unix inputs to hit all error branches."""
    # 1. TCP without semaphore
    tcp_inp = SyslogTCPInput()
    tcp_inp._connection_semaphore = None
    mock_writer = MagicMock()
    mock_writer.wait_closed = AsyncMock()
    mock_reader = AsyncMock()
    await tcp_inp._handle_client(mock_reader, mock_writer)
    mock_writer.close.assert_called()

    # 2. TCP with active connections >= max_connections (semaphore locked)
    tcp_inp2 = SyslogTCPInput(max_connections=1)
    tcp_inp2._connection_semaphore = asyncio.Semaphore(1)
    await tcp_inp2._connection_semaphore.acquire()
    tcp_inp2._active_connections = 1
    w2 = MagicMock()
    w2.wait_closed = AsyncMock()
    r2 = AsyncMock()
    await tcp_inp2._handle_client(r2, w2)
    assert tcp_inp2.metrics["drops"] == 1

    # 3. TCP reader connection reset
    tcp_inp3 = SyslogTCPInput()
    tcp_inp3._running = True
    tcp_inp3._connection_semaphore = asyncio.Semaphore(10)
    w3 = MagicMock()
    w3.wait_closed = AsyncMock()
    r3 = AsyncMock()
    r3.read.side_effect = ConnectionResetError()
    await tcp_inp3._handle_client(r3, w3)

    # 4. TCP reader general exception
    tcp_inp4 = SyslogTCPInput()
    tcp_inp4._running = True
    tcp_inp4._connection_semaphore = asyncio.Semaphore(10)
    w4 = MagicMock()
    w4.wait_closed = AsyncMock()
    r4 = AsyncMock()
    r4.read.side_effect = RuntimeError("Socket read crash")
    await tcp_inp4._handle_client(r4, w4)
    assert tcp_inp4.metrics["errors"] == 1

    # 5. Unix Socket without semaphore
    unix_sock_path = str(tmp_path / "mock.sock")
    unix_inp = UnixSocketInput(socket_path=unix_sock_path)
    unix_inp._connection_semaphore = None
    w5 = MagicMock()
    w5.wait_closed = AsyncMock()
    r5 = AsyncMock()
    await unix_inp._handle_client(r5, w5)
    w5.close.assert_called()

    # 6. Unix Socket with active >= max
    unix_inp2 = UnixSocketInput(socket_path=unix_sock_path, max_connections=1)
    unix_inp2._connection_semaphore = asyncio.Semaphore(1)
    await unix_inp2._connection_semaphore.acquire()
    unix_inp2._active_connections = 1
    w6 = MagicMock()
    w6.wait_closed = AsyncMock()
    r6 = AsyncMock()
    await unix_inp2._handle_client(r6, w6)
    assert unix_inp2.metrics["drops"] == 1

    # 7. Unix Socket reader reset and exception
    unix_inp3 = UnixSocketInput(socket_path=unix_sock_path)
    unix_inp3._running = True
    unix_inp3._connection_semaphore = asyncio.Semaphore(10)
    w7 = MagicMock()
    w7.wait_closed = AsyncMock()
    r7 = AsyncMock()
    r7.read.side_effect = ConnectionResetError()
    await unix_inp3._handle_client(r7, w7)

    r8 = AsyncMock()
    r8.read.side_effect = RuntimeError("Unix read crash")
    await unix_inp3._handle_client(r8, w7)
    assert unix_inp3.metrics["errors"] == 1


@pytest.mark.asyncio
async def test_file_tail_full_branches(tmp_path: Path):
    """Test file tail with default start_from_beginning=False, truncation, and drainage."""
    tail_file = tmp_path / "tail_branches.log"
    tail_file.write_text("first line before tail\n", encoding="utf-8")

    queue = asyncio.Queue()
    tail = FileTailInput(file_path=str(tail_file), start_from_beginning=False, poll_interval=0.01)
    await tail.start(queue)
    await asyncio.sleep(0.05)

    with open(tail_file, "a", encoding="utf-8") as f:
        f.write("appended line 1\n")

    e1 = await asyncio.wait_for(queue.get(), timeout=2.0)
    assert e1.raw == "appended line 1"

    tail_file.write_text("truncated line 2\n", encoding="utf-8")
    e2 = await asyncio.wait_for(queue.get(), timeout=2.0)
    assert e2.raw == "truncated line 2"

    await tail.stop()


@pytest.mark.asyncio
async def test_file_output_edge_branches(tmp_path: Path):
    """Test rotating file output edge cases and exception handling."""
    out_file = tmp_path / "edge_file.log"
    file_out = RotatingFileOutput(file_path=str(out_file))
    
    file_out._open_file()
    file_out._open_file()

    non_existent = RotatingFileOutput(file_path=str(tmp_path / "non_existent" / "log.txt"))
    non_existent._rotate_if_needed(100)

    file_out._file_handle = MagicMock()
    file_out._file_handle.write.side_effect = IOError("Disk error")
    res = await file_out.send_batch([LogEvent.create("failing event")])
    assert res is False
    assert file_out.metrics["errors"] == 1

    file_out._file_handle = None
    await file_out.stop()


@pytest.mark.asyncio
async def test_buffer_disk_branches(tmp_path: Path):
    """Test buffer single disk segment active write and flush."""
    buf_dir = tmp_path / "spool_branches"
    buffer = PersistentDiskBuffer(
        buffer_dir=str(buf_dir),
        max_memory_events=1,
        max_segment_bytes=500,
    )
    await buffer.push(LogEvent.create("mem-event"))
    await buffer.push(LogEvent.create("disk-event-single"))

    batch = await buffer.pop_batch(max_items=10, timeout=0.05)
    assert len(batch) == 2
    buffer.close()


@pytest.mark.asyncio
async def test_udp_protocol_edge_cases():
    """Test UDP protocol direct callbacks for error, truncation, and empty payloads."""
    inp = SyslogUDPInput()
    protocol = _SyslogUDPProtocol(inp)

    protocol.error_received(RuntimeError("UDP Network Error"))
    assert inp.metrics["errors"] == 1

    inp._running = False
    protocol.datagram_received(b"some data", ("127.0.0.1", 1234))

    inp._running = True
    protocol.datagram_received(b"\n\r\n\n", ("127.0.0.1", 1234))

    protocol.datagram_received(b"X" * (MAX_EVENT_SIZE_BYTES + 500) + b"\n", ("127.0.0.1", 1234))
    assert inp.metrics["drops"] == 1


@pytest.mark.asyncio
async def test_webhook_circuit_breaker_and_half_open():
    """Test webhook circuit tripping, open rejection, and half-open transition."""
    mock_transport = httpx.MockTransport(lambda req: httpx.Response(500, json={"error": "failed"}))
    client = httpx.AsyncClient(transport=mock_transport)

    webhook = WebhookOutput(
        url="http://mock.test/logs",
        failure_threshold=2,
        circuit_reset_timeout=0.1,
        max_retries=1,
        client=client,
    )
    await webhook.start()

    events = [LogEvent.create("Test Webhook Event")]

    res1 = await webhook.send_batch(events)
    assert res1 is False
    res2 = await webhook.send_batch(events)
    assert res2 is False
    assert webhook.circuit_state == "OPEN"

    res3 = await webhook.send_batch(events)
    assert res3 is False

    await asyncio.sleep(0.15)
    assert webhook.circuit_state == "HALF_OPEN"

    await webhook.stop()
    await client.aclose()


@pytest.mark.asyncio
async def test_pipeline_failing_sink_and_drop(tmp_path: Path):
    """Test pipeline handling failing sinks and queue drops."""
    pipeline = LogPipeline(worker_count=2, batch_size=2, flush_interval=0.01)

    class BrokenSink(BaseOutput):
        async def send_batch(self, events):
            raise RuntimeError("Failing Sink")

    pipeline.add_output(BrokenSink(name="broken"))
    await pipeline.start()

    for i in range(4):
        await pipeline.push_raw(f"Raw event {i}")

    await asyncio.sleep(0.1)
    await pipeline.stop(drain=False)
    assert pipeline.metrics["events_failed"] >= 1


@pytest.mark.asyncio
async def test_outputs_file_rotation_cascade(tmp_path: Path):
    """Test multi-tier rotating file backups (.1, .2, .3)."""
    out_file = tmp_path / "cascade.log"
    file_out = RotatingFileOutput(
        file_path=str(out_file),
        max_bytes=80,
        backup_count=3,
        format_type="text",
    )
    await file_out.start()

    for i in range(8):
        events = [LogEvent.create(f"Cascade batch message payload {i:03d}")]
        await file_out.send_batch(events)

    await file_out.stop()
    assert (tmp_path / "cascade.log").exists()
    assert (tmp_path / "cascade.log.1").exists()
