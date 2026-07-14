from __future__ import annotations

import asyncio
import contextlib
import socket
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from typing import Any

from msys_core.manifest import Component
from msys_core.msysd import Instance, Msysd
from msys_core.protocol import send_packet


@unittest.skipUnless(
    hasattr(socket, "AF_UNIX") and hasattr(socket, "SOCK_SEQPACKET"),
    "mIPC requires Unix SOCK_SEQPACKET sockets",
)
class MipcExecutorStarvationTests(unittest.TestCase):
    def test_component_return_is_read_while_default_executor_is_saturated(self) -> None:
        asyncio.run(self._exercise_saturated_executor())

    async def _exercise_saturated_executor(self) -> None:
        loop = asyncio.get_running_loop()
        worker_count = 2
        executor = ThreadPoolExecutor(
            max_workers=worker_count,
            thread_name_prefix="msys-test-blocked",
        )
        loop.set_default_executor(executor)

        release_workers = threading.Event()
        started_lock = threading.Lock()
        started_count = 0

        def occupy_worker() -> None:
            nonlocal started_count
            with started_lock:
                started_count += 1
            release_workers.wait()

        blockers = [
            loop.run_in_executor(None, occupy_worker)
            for _ in range(worker_count)
        ]
        parent_sock: socket.socket | None = None
        component_sock: socket.socket | None = None
        reader_task: asyncio.Task[None] | None = None

        try:
            # Do not use asyncio.to_thread here: the executor is intentionally
            # unavailable.  Polling also proves all workers really are busy
            # before the mIPC reader starts.
            async def wait_until_workers_are_busy() -> None:
                while True:
                    with started_lock:
                        if started_count == worker_count:
                            return
                    await asyncio.sleep(0.005)

            await asyncio.wait_for(wait_until_workers_are_busy(), timeout=1.0)

            parent_sock, component_sock = socket.socketpair(
                socket.AF_UNIX,
                socket.SOCK_SEQPACKET,
            )
            parent_sock.setblocking(False)

            component = Component(
                package_id="org.msys.test",
                package_version="1.0.0",
                id="provider",
                exec=[],
                lifecycle="background",
            )
            instance = Instance(
                component=component,
                generation=1,
                sock=parent_sock,
            )

            # Construct only the small daemon state used by _read_component;
            # no manifests, subprocesses, or target services are needed.
            daemon = object.__new__(Msysd)
            daemon.instances = {component.key: instance}

            request_id = 73
            pending_return: asyncio.Future[dict[str, Any]] = loop.create_future()
            instance.pending_calls[request_id] = pending_return
            reader_task = asyncio.create_task(daemon._read_component(instance))

            send_packet(
                component_sock,
                {
                    "type": "return",
                    "id": request_id,
                    "payload": {"ok": True},
                },
            )

            response = await asyncio.wait_for(pending_return, timeout=0.5)
            self.assertEqual(response["type"], "return")
            self.assertEqual(response["payload"], {"ok": True})
            self.assertNotIn(request_id, instance.pending_calls)
        finally:
            if reader_task is not None:
                reader_task.cancel()
                with contextlib.suppress(asyncio.CancelledError):
                    await reader_task
            if parent_sock is not None:
                parent_sock.close()
            if component_sock is not None:
                component_sock.close()
            release_workers.set()
            await asyncio.gather(*blockers)
            executor.shutdown(wait=True)


if __name__ == "__main__":
    unittest.main()
