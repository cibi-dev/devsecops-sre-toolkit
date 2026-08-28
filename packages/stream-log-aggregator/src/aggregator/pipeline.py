"""Asynchronous Log Aggregation Pipeline with Backpressure, Worker Pool, and Disk Buffer."""

import asyncio
import time
from typing import Any, Dict, List, Optional
from aggregator import LogEvent, MAX_EVENT_SIZE_BYTES
from aggregator.buffer import PersistentDiskBuffer
from aggregator.inputs import BaseInput
from aggregator.outputs import BaseOutput
from aggregator.transformers import BaseTransformer


class LogPipeline:
    """Orchestrates input ingestion, transformer worker pool, disk buffer, and sink fanout."""

    def __init__(
        self,
        worker_count: int = 4,
        queue_max_size: int = 20000,
        batch_size: int = 200,
        flush_interval: float = 0.02,
        buffer_dir: Optional[str] = None,
    ):
        self.worker_count = worker_count
        self.queue_max_size = queue_max_size
        self.batch_size = batch_size
        self.flush_interval = flush_interval

        self.inputs: List[BaseInput] = []
        self.transformers: List[BaseTransformer] = []
        self.outputs: List[BaseOutput] = []

        self.buffer = PersistentDiskBuffer(buffer_dir=buffer_dir)
        self._ingestion_queue: asyncio.Queue[LogEvent] = asyncio.Queue(maxsize=queue_max_size)

        self._running = False
        self._worker_tasks: List[asyncio.Task] = []
        self._dispatcher_task: Optional[asyncio.Task] = None

        # Global metrics
        self._events_ingested: int = 0
        self._events_transformed: int = 0
        self._events_dispatched: int = 0
        self._events_dropped: int = 0
        self._events_failed: int = 0
        self._total_latency_ms: float = 0.0

    @property
    def is_running(self) -> bool:
        """Return True if pipeline is active."""
        return self._running

    @property
    def metrics(self) -> Dict[str, Any]:
        """Return aggregated operational metrics across all stages."""
        avg_latency = (
            self._total_latency_ms / self._events_dispatched
            if self._events_dispatched > 0
            else 0.0
        )
        return {
            "running": self._running,
            "ingestion_queue_size": self._ingestion_queue.qsize(),
            "events_ingested": self._events_ingested,
            "events_transformed": self._events_transformed,
            "events_dispatched": self._events_dispatched,
            "events_dropped": self._events_dropped,
            "events_failed": self._events_failed,
            "average_latency_ms": round(avg_latency, 3),
            "buffer": self.buffer.metrics,
            "inputs": [inp.metrics for inp in self.inputs],
            "transformers": [tf.metrics for tf in self.transformers],
            "outputs": [out.metrics for out in self.outputs],
        }

    def add_input(self, inp: BaseInput) -> "LogPipeline":
        """Attach an input receiver."""
        self.inputs.append(inp)
        return self

    def add_transformer(self, transformer: BaseTransformer) -> "LogPipeline":
        """Attach a transformer stage."""
        self.transformers.append(transformer)
        return self

    def add_output(self, output: BaseOutput) -> "LogPipeline":
        """Attach an output sink."""
        self.outputs.append(output)
        return self

    async def push_raw(self, raw: str, source: str = "direct") -> None:
        """Directly inject an event into the pipeline with backpressure."""
        if len(raw.encode("utf-8", errors="replace")) > MAX_EVENT_SIZE_BYTES:
            self._events_dropped += 1
            raw = raw[:MAX_EVENT_SIZE_BYTES] + "...[TRUNCATED_OVER_64KB]"

        event = LogEvent.create(raw=raw, source=source)
        self._events_ingested += 1
        await self._ingestion_queue.put(event)

    async def start(self) -> None:
        """Start inputs, transformer workers, dispatcher, and sinks."""
        if self._running:
            return
        self._running = True

        # Recover un-acked disk buffer events if any
        await self.buffer.recover()

        # Start outputs
        for out in self.outputs:
            await out.start()

        # Start transformer worker pool
        for i in range(self.worker_count):
            task = asyncio.create_task(self._worker_loop(i))
            self._worker_tasks.append(task)

        # Start output dispatcher task
        self._dispatcher_task = asyncio.create_task(self._dispatcher_loop())

        # Start inputs
        for inp in self.inputs:
            await inp.start(self._ingestion_queue)

    async def _worker_loop(self, worker_id: int) -> None:
        """Worker task executing transformation chain and pushing to disk buffer in micro-batches."""
        transformers = self.transformers
        while self._running:
            try:
                first_event = await self._ingestion_queue.get()
                events = [first_event]

                # Fast drain of currently available items
                while len(events) < 50 and not self._ingestion_queue.empty():
                    try:
                        events.append(self._ingestion_queue.get_nowait())
                    except asyncio.QueueEmpty:
                        break

                for event in events:
                    for tf in transformers:
                        try:
                            event = tf.transform(event)
                        except Exception:
                            self._events_failed += 1

                    self._events_transformed += 1
                    pushed = await self.buffer.push(event)
                    if not pushed:
                        self._events_dropped += 1

                    self._ingestion_queue.task_done()

            except asyncio.CancelledError:
                break
            except Exception:
                self._events_failed += 1

    async def _dispatcher_loop(self) -> None:
        """Dispatcher task popping batches from buffer and forwarding to sinks."""
        while self._running:
            try:
                batch = await self.buffer.pop_batch(
                    max_items=self.batch_size,
                    timeout=self.flush_interval,
                )

                if not batch:
                    await asyncio.sleep(self.flush_interval)
                    continue

                start_time = time.time()
                for out in self.outputs:
                    try:
                        success = await out.send_batch(batch)
                        if not success:
                            self._events_failed += len(batch)
                    except Exception:
                        self._events_failed += len(batch)

                elapsed_ms = (time.time() - start_time) * 1000.0
                self._events_dispatched += len(batch)
                self._total_latency_ms += elapsed_ms

            except asyncio.CancelledError:
                break
            except Exception:
                await asyncio.sleep(self.flush_interval)

    async def stop(self, drain: bool = True, timeout: float = 5.0) -> None:
        """Gracefully stop inputs, drain queues, flush outputs, and release resources."""
        # 1. Stop inputs first so no new events arrive
        for inp in self.inputs:
            try:
                await inp.stop()
            except Exception:
                pass

        # 2. Wait for ingestion queue to drain if requested
        if drain:
            try:
                if not self._ingestion_queue.empty():
                    await asyncio.wait_for(self._ingestion_queue.join(), timeout=timeout)
            except (asyncio.TimeoutError, Exception):
                pass

        self._running = False

        # 3. Stop workers
        for task in self._worker_tasks:
            task.cancel()
        if self._worker_tasks:
            await asyncio.gather(*self._worker_tasks, return_exceptions=True)
            self._worker_tasks.clear()

        # 4. Stop dispatcher
        if self._dispatcher_task:
            self._dispatcher_task.cancel()
            try:
                await self._dispatcher_task
            except asyncio.CancelledError:
                pass
            self._dispatcher_task = None

        # 5. Flush and stop outputs
        for out in self.outputs:
            try:
                await out.stop()
            except Exception:
                pass

        # 6. Close buffer
        self.buffer.close()
