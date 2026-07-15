from __future__ import annotations

import asyncio
import os
import types
import time
import unittest
from unittest import mock

from msys_core.manifest import Component
from msys_core.msysd import Instance, Msysd, forwarded_timeout_seconds
from msys_core.protocol import decode


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
    async def test_forward_preserves_bounded_logical_route_without_changing_target(self) -> None:
        class CaptureSocket:
            def __init__(self) -> None:
                self.packet = None

            def sendall(self, data: bytes) -> None:
                self.packet = decode(data)

        component = Component(
            package_id="org.example.provider",
            package_version="1.0.0",
            id="main",
            exec=["true"],
            lifecycle="on-demand",
        )
        daemon = object.__new__(Msysd)
        daemon.next_request_id = 1
        socket = CaptureSocket()
        selected = Instance(
            component=component,
            generation=1,
            sock=socket,  # type: ignore[arg-type]
            ready=True,
        )
        task = asyncio.create_task(Msysd._forward_call(
            daemon,
            selected,
            {
                "type": "call",
                "id": 4,
                "target": "role:notification-center",
                "method": "show",
                "payload": {},
                "deadline_ms": int(time.monotonic() * 1000 + 1000),
            },
            "test",
        ))
        await asyncio.sleep(0)
        self.assertIsNotNone(socket.packet)
        self.assertEqual(socket.packet["target"], component.key)
        self.assertEqual(
            socket.packet["logical_target"], "role:notification-center"
        )
        selected.pending_calls[1].set_result({
            "type": "return", "id": 1, "payload": {"ok": True}
        })
        self.assertEqual((await task)["type"], "return")

    async def test_invalid_logical_route_is_not_forwarded(self) -> None:
        class CaptureSocket:
            def __init__(self) -> None:
                self.packet = None

            def sendall(self, data: bytes) -> None:
                self.packet = decode(data)

        component = Component(
            package_id="org.example.provider",
            package_version="1.0.0",
            id="main",
            exec=["true"],
            lifecycle="on-demand",
        )
        daemon = object.__new__(Msysd)
        daemon.next_request_id = 1
        socket = CaptureSocket()
        selected = Instance(
            component=component,
            generation=1,
            sock=socket,  # type: ignore[arg-type]
            ready=True,
        )
        task = asyncio.create_task(Msysd._forward_call(
            daemon,
            selected,
            {
                "type": "call",
                "id": 5,
                "target": "role:" + "x" * 300,
                "method": "show",
                "deadline_ms": int(time.monotonic() * 1000 + 1000),
            },
            "test",
        ))
        await asyncio.sleep(0)
        self.assertNotIn("logical_target", socket.packet)
        selected.pending_calls[1].set_result({
            "type": "return", "id": 1, "payload": {"ok": True}
        })
        await task

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

    async def test_back_does_not_announce_a_close_before_backgrounding(self) -> None:
        daemon = FakeRoleDaemon([
            {"type": "return", "id": 1, "payload": {"ok": True}},
        ])

        response = await Msysd._dispatch_role_call(
            daemon,
            {"type": "call", "id": 10, "target": "role:window-manager", "method": "back"},
            source="navigation",
        )

        self.assertEqual(response["type"], "return")
        self.assertEqual(daemon.actions, ["forward"])
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


class NoStartHideDispatchTests(unittest.IsolatedAsyncioTestCase):
    class Registry:
        @staticmethod
        def active_provider(_role: str):
            return None

        @staticmethod
        def preferred_provider(role: str):
            return f"org.example:{role}"

        @staticmethod
        def candidate_ids(role: str):
            return (f"org.example:{role}",)

    class Daemon:
        def __init__(self) -> None:
            self.role_registry = NoStartHideDispatchTests.Registry()
            self.instances = {}
            self.provider_calls = 0
            self.forward_calls = 0

        def _role_provider_is_running(self, role: str) -> bool:
            return Msysd._role_provider_is_running(self, role)

        async def _provider_for_role(self, role: str, *, exclude=None):
            self.provider_calls += 1
            return types.SimpleNamespace(
                component=types.SimpleNamespace(key=f"org.example:{role}")
            )

        async def _forward_call(self, provider, message, source):
            self.forward_calls += 1
            return {
                "type": "return",
                "id": message["id"],
                "payload": {"ok": True, "method": message["method"]},
            }

    async def test_hidden_lazy_roles_do_not_cold_start(self) -> None:
        for role in ("input-method", "notification-center"):
            with self.subTest(role=role):
                daemon = self.Daemon()
                response = await Msysd._dispatch_role_call(daemon, {
                    "type": "call",
                    "id": 31,
                    "target": f"role:{role}",
                    "method": "hide",
                    "payload": {},
                }, source="window-policy")
                self.assertEqual(response["payload"], {
                    "ok": True,
                    "role": role,
                    "visible": False,
                    "already_hidden": True,
                })
                self.assertEqual(daemon.provider_calls, 0)
                self.assertEqual(daemon.forward_calls, 0)

    async def test_show_and_toggle_keep_normal_provider_activation(self) -> None:
        for method in ("show", "toggle"):
            with self.subTest(method=method):
                daemon = self.Daemon()
                response = await Msysd._dispatch_role_call(daemon, {
                    "type": "call",
                    "id": 32,
                    "target": "role:input-method",
                    "method": method,
                    "payload": {},
                }, source="application")
                self.assertEqual(response["payload"]["method"], method)
                self.assertEqual(daemon.provider_calls, 1)
                self.assertEqual(daemon.forward_calls, 1)

    async def test_hide_is_forwarded_when_provider_is_already_running(self) -> None:
        daemon = self.Daemon()
        daemon.instances["org.example:input-method"] = types.SimpleNamespace(
            finalized=False,
            process=types.SimpleNamespace(poll=lambda: None),
        )

        response = await Msysd._dispatch_role_call(daemon, {
            "type": "call",
            "id": 33,
            "target": "role:input-method",
            "method": "hide",
            "payload": {},
        }, source="window-policy")

        self.assertEqual(response["payload"]["method"], "hide")
        self.assertEqual(daemon.provider_calls, 1)
        self.assertEqual(daemon.forward_calls, 1)


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
