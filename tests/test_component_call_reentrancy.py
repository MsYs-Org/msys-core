from __future__ import annotations

import asyncio
import socket
import types
import unittest

from msys_core.manifest import Component
from msys_core.msysd import Msysd
from msys_core.protocol import decode


class ComponentCallReentrancyTests(unittest.IsolatedAsyncioTestCase):
    async def test_component_reader_schedules_call_without_awaiting_dispatch(self) -> None:
        daemon = object.__new__(Msysd)
        scheduled: list[object] = []
        daemon._track_task = lambda coroutine: scheduled.append(coroutine)
        instance = types.SimpleNamespace(component=types.SimpleNamespace(key="provider"))
        message = {"type": "call", "id": 4, "target": "role:other", "method": "ping"}

        await Msysd._handle_component_message(daemon, instance, message)

        self.assertEqual(len(scheduled), 1)
        scheduled[0].close()

    async def test_scheduled_call_replies_on_same_generation_channel(self) -> None:
        daemon = object.__new__(Msysd)
        left, right = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.addCleanup(left.close)
        self.addCleanup(right.close)
        component = Component(
            package_id="org.example",
            package_version="1.0.0",
            id="provider",
            exec=[],
            lifecycle="background",
            permissions=["mipc.call:role:other"],
        )
        instance = types.SimpleNamespace(component=component, sock=left)
        daemon.instances = {component.key: instance}

        async def dispatch(message, source):
            self.assertEqual(source, component.key)
            await asyncio.sleep(0)
            return {"type": "return", "id": message["id"], "payload": {"ok": True}}

        daemon.dispatch_call = dispatch
        await Msysd._dispatch_component_call(
            daemon,
            instance,
            {"type": "call", "id": 9, "target": "role:other", "method": "ping"},
        )

        self.assertEqual(decode(right.recv(4096))["payload"], {"ok": True})


if __name__ == "__main__":
    unittest.main()
