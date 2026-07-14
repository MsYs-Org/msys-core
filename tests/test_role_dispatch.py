from __future__ import annotations

import asyncio
import os
import types
import time
import unittest
from unittest import mock

from msys_core.manifest import Component
from msys_core.msysd import Instance, Msysd, forwarded_timeout_seconds


def provider(name: str):
    return types.SimpleNamespace(component=types.SimpleNamespace(key=name))


class FakeRoleDaemon:
    def __init__(self, responses: list[dict]) -> None:
        self.providers = [provider(f"provider-{index}") for index in range(len(responses))]
        self.responses = list(responses)
        self.forwarded: list[str] = []
        self.stopped: list[str] = []
        self.actions: list[str] = []
        self.fallback_calls: list[str] = []
        self.fallback_response = None
        self.profile = {"env": {}}

    async def _announce_foreground_closing(self):
        self.actions.append("closing")
        return None

    async def _provider_for_role(self, role: str, *, exclude: set[str] | None = None):
        excluded = exclude or set()
        return next((item for item in self.providers if item.component.key not in excluded), None)

    async def _forward_call(self, selected, msg, source: str):
        self.actions.append("forward")
        self.forwarded.append(selected.component.key)
        return self.responses[len(self.forwarded) - 1]

    async def stop_component(self, key: str, *, expected=None) -> None:
        self.stopped.append(key)

    async def _x11_window_policy_call(self, msg):
        self.fallback_calls.append(str(msg.get("method", "")))
        return self.fallback_response

    def _session_display(self):
        return ":24"


class RoleDispatchContractTests(unittest.IsolatedAsyncioTestCase):
    async def test_cold_start_deadline_expiry_does_not_stop_role_provider(self) -> None:
        daemon = FakeRoleDaemon([{
            "type": "error",
            "id": 1,
            "code": "CALL_TIMEOUT",
            "message": "call deadline already expired",
        }])
        response = await Msysd._dispatch_role_call(
            daemon,
            {
                "type": "call",
                "id": 8,
                "target": "role:window-manager",
                "method": "recents",
                "idempotent": True,
            },
            source="test",
        )

        self.assertEqual(response["code"], "CALL_TIMEOUT")
        self.assertEqual(response["id"], 8)
        self.assertEqual(daemon.forwarded, ["provider-0"])
        self.assertEqual(daemon.stopped, [])

    def test_forward_timeout_consumes_original_monotonic_deadline(self) -> None:
        deadline = int(time.monotonic() * 1000 + 12_000)
        remaining = forwarded_timeout_seconds({"deadline_ms": deadline})
        self.assertGreater(remaining, 11.5)
        self.assertLessEqual(remaining, 12.0)
        self.assertEqual(
            forwarded_timeout_seconds({"deadline_ms": int(time.monotonic() * 1000 - 1)}),
            0.0,
        )
        self.assertEqual(forwarded_timeout_seconds({}), 5.0)

    async def test_non_idempotent_timeout_is_not_replayed(self) -> None:
        daemon = FakeRoleDaemon([
            {"type": "error", "id": 1, "code": "CALL_TIMEOUT"},
            {"type": "return", "id": 1, "payload": {"ok": True}},
        ])
        response = await Msysd._dispatch_role_call(
            daemon,
            {"type": "call", "id": 9, "target": "role:window-manager", "method": "close_active"},
            source="test",
        )
        self.assertEqual(response["code"], "OUTCOME_UNKNOWN")
        self.assertEqual(daemon.forwarded, ["provider-0"])
        self.assertEqual(daemon.actions, ["closing", "forward"])
        self.assertEqual(daemon.fallback_calls, [])

    async def test_back_announces_closing_before_native_window_policy(self) -> None:
        daemon = FakeRoleDaemon([
            {"type": "return", "id": 1, "payload": {"ok": True}},
        ])

        response = await Msysd._dispatch_role_call(
            daemon,
            {"type": "call", "id": 10, "target": "role:window-manager", "method": "back"},
            source="navigation",
        )

        self.assertEqual(response["type"], "return")
        self.assertEqual(daemon.actions, ["closing", "forward"])
        self.assertEqual(daemon.fallback_calls, [])

    async def test_missing_policy_uses_marked_core_control_fallback(self) -> None:
        daemon = FakeRoleDaemon([])
        daemon.fallback_response = {
            "type": "return",
            "id": 12,
            "payload": {"windows": []},
        }

        with mock.patch("builtins.print") as output:
            response = await Msysd._dispatch_role_call(
                daemon,
                {"type": "call", "id": 12, "target": "role:window-manager", "method": "recents"},
                source="task-switcher",
            )

        self.assertTrue(response["fallback"])
        self.assertTrue(response["payload"]["fallback"])
        self.assertEqual(daemon.fallback_calls, ["recents"])
        self.assertIn("core X11 control fallback", output.call_args.args[0])

    async def test_definite_provider_error_can_use_control_fallback(self) -> None:
        daemon = FakeRoleDaemon([
            {"type": "error", "id": 13, "code": "NO_METHOD", "message": "recents"},
        ])
        daemon.fallback_response = {
            "type": "return",
            "id": 13,
            "payload": {"windows": []},
        }

        response = await Msysd._dispatch_role_call(
            daemon,
            {"type": "call", "id": 13, "target": "role:window-manager", "method": "recents"},
            source="task-switcher",
        )

        self.assertTrue(response["payload"]["fallback"])
        self.assertEqual(daemon.forwarded, ["provider-0"])
        self.assertEqual(daemon.fallback_calls, ["recents"])

    async def test_read_only_timeout_can_fail_over(self) -> None:
        daemon = FakeRoleDaemon([
            {"type": "error", "id": 1, "code": "CALL_TIMEOUT"},
            {"type": "return", "id": 1, "payload": {"windows": []}},
        ])
        response = await Msysd._dispatch_role_call(
            daemon,
            {"type": "call", "id": 9, "target": "role:window-manager", "method": "recents"},
            source="test",
        )
        self.assertEqual(response["type"], "return")
        self.assertEqual(daemon.forwarded, ["provider-0", "provider-1"])
        self.assertEqual(daemon.fallback_calls, [])

    async def test_successful_forward_trace_requires_debug_flag(self) -> None:
        class CaptureSocket:
            def sendall(self, _data: bytes) -> None:
                pass

        component = Component(
            package_id="org.example.provider",
            package_version="1.0.0",
            id="main",
            exec=["true"],
            lifecycle="on-demand",
        )

        async def exercise(debug: str) -> int:
            daemon = object.__new__(Msysd)
            daemon.next_request_id = 1
            selected = Instance(
                component=component,
                generation=1,
                sock=CaptureSocket(),  # type: ignore[arg-type]
                ready=True,
            )
            with mock.patch.dict(os.environ, {"MSYS_DEBUG_IPC": debug}), mock.patch(
                "builtins.print"
            ) as output:
                task = asyncio.create_task(Msysd._forward_call(
                    daemon,
                    selected,
                    {
                        "type": "call",
                        "id": 4,
                        "method": "state",
                        "payload": {},
                        "deadline_ms": int(time.monotonic() * 1000 + 1000),
                    },
                    "test",
                ))
                await asyncio.sleep(0)
                selected.pending_calls[1].set_result({
                    "type": "return",
                    "id": 1,
                    "payload": {"ok": True},
                })
                response = await task
                self.assertEqual(response["type"], "return")
                return output.call_count

        self.assertEqual(await exercise(""), 0)
        self.assertEqual(await exercise("1"), 1)


class ChooserCancellationDispatchTests(unittest.IsolatedAsyncioTestCase):
    async def test_cancel_bypasses_busy_chooser_role_lock(self) -> None:
        class FakeDaemon:
            role_locks = {"chooser": asyncio.Lock()}

            async def _dispatch_role_call(self, message, source):
                return {"type": "return", "id": message["id"], "payload": {"source": source}}

        daemon = FakeDaemon()
        await daemon.role_locks["chooser"].acquire()
        try:
            response = await Msysd.dispatch_call(
                daemon,
                {
                    "type": "call",
                    "id": 11,
                    "target": "role:chooser",
                    "method": "cancel_choice",
                },
                source="window-policy",
            )
        finally:
            daemon.role_locks["chooser"].release()
        self.assertEqual(response["payload"]["source"], "window-policy")


class TaskSwitcherReentrantDispatchTests(unittest.IsolatedAsyncioTestCase):
    class Registry:
        @staticmethod
        def active_provider(role: str):
            return "org.example.shell:tasks" if role == "task-switcher" else None

    class FakeDaemon:
        def __init__(self) -> None:
            self.role_locks = {"window-manager": asyncio.Lock()}
            self.role_registry = TaskSwitcherReentrantDispatchTests.Registry()

        async def _dispatch_role_call(self, message, source):
            return {
                "type": "return",
                "id": message["id"],
                "payload": {"source": source, "windows": []},
            }

    async def test_active_task_switcher_recents_bypasses_outer_window_lock(self) -> None:
        daemon = self.FakeDaemon()
        await daemon.role_locks["window-manager"].acquire()
        try:
            response = await Msysd.dispatch_call(
                daemon,
                {
                    "type": "call",
                    "id": 12,
                    "target": "role:window-manager",
                    "method": "recents",
                },
                source="org.example.shell:tasks",
            )
        finally:
            daemon.role_locks["window-manager"].release()
        self.assertEqual(response["payload"]["source"], "org.example.shell:tasks")

    async def test_other_recents_callers_remain_serialized(self) -> None:
        daemon = self.FakeDaemon()
        lock = daemon.role_locks["window-manager"]
        await lock.acquire()
        task = asyncio.create_task(Msysd.dispatch_call(
            daemon,
            {
                "type": "call",
                "id": 13,
                "target": "role:window-manager",
                "method": "recents",
            },
            source="org.example.other:caller",
        ))
        await asyncio.sleep(0)
        self.assertFalse(task.done())
        lock.release()
        response = await task
        self.assertEqual(response["payload"]["source"], "org.example.other:caller")


if __name__ == "__main__":
    unittest.main()
