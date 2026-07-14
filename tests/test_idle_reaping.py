from __future__ import annotations

import asyncio
import json
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest.mock import AsyncMock

from msys_core.manifest import (
    MAX_IDLE_TIMEOUT_MS,
    MIN_IDLE_TIMEOUT_MS,
    Component,
    load_manifest,
)
from msys_core.msysd import Instance, Msysd


class CaptureSocket:
    def __init__(self) -> None:
        self.packets: list[dict] = []

    def sendall(self, data: bytes) -> None:
        self.packets.append(json.loads(data.decode("utf-8")))


def on_demand_component(
    *,
    idle_timeout_ms: int | None = MIN_IDLE_TIMEOUT_MS,
    lifecycle: str = "on-demand",
) -> Component:
    return Component(
        package_id="org.example.idle",
        package_version="1.0.0",
        id="provider",
        exec=["true"],
        lifecycle=lifecycle,
        idle_timeout_ms=idle_timeout_ms,
        permissions=["mipc.call:msys.core"],
    )


def runtime(component: Component | None = None) -> tuple[Msysd, Instance]:
    selected = component or on_demand_component()
    instance = Instance(
        component=selected,
        generation=1,
        sock=CaptureSocket(),  # type: ignore[arg-type]
        state="ready",
        ready=True,
    )
    daemon = object.__new__(Msysd)
    daemon.instances = {selected.key: instance}
    daemon.stopping = False
    daemon.stop_requests = set()
    daemon.next_request_id = 1
    return daemon, instance


async def cancel_idle(instance: Instance) -> None:
    task = instance.idle_task
    instance.idle_task = None
    if task is not None and not task.done():
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


class IdleManifestTests(unittest.TestCase):
    def write_manifest(self, root: Path, *, lifecycle: str, marker=...) -> Path:
        component = {
            "id": "provider",
            "runtime": "native",
            "exec": ["true"],
            "lifecycle": lifecycle,
            "restart": "never",
        }
        if marker is not ...:
            component["idle_timeout_ms"] = marker
        path = root / "manifest.json"
        path.write_text(json.dumps({
            "schema": "msys.manifest.v1",
            "package": {
                "id": "org.example.idle",
                "version": "1.0.0",
                "kind": "system",
            },
            "components": [component],
        }), encoding="utf-8")
        return path

    def test_omission_preserves_resident_on_demand_compatibility(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            loaded = load_manifest(
                self.write_manifest(Path(temporary), lifecycle="on-demand")
            )[0]
        self.assertIsNone(loaded.idle_timeout_ms)

    def test_valid_timeout_reaches_component_contract(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            loaded = load_manifest(self.write_manifest(
                Path(temporary),
                lifecycle="on-demand",
                marker=MIN_IDLE_TIMEOUT_MS,
            ))[0]
        self.assertEqual(loaded.idle_timeout_ms, MIN_IDLE_TIMEOUT_MS)

    def test_timeout_type_and_bounds_are_strict(self) -> None:
        invalid = (
            True,
            None,
            "1000",
            MIN_IDLE_TIMEOUT_MS - 1,
            MAX_IDLE_TIMEOUT_MS + 1,
        )
        for value in invalid:
            with self.subTest(value=value), tempfile.TemporaryDirectory() as temporary:
                path = self.write_manifest(
                    Path(temporary),
                    lifecycle="on-demand",
                    marker=value,
                )
                with self.assertRaisesRegex(ValueError, "idle_timeout_ms"):
                    load_manifest(path)

    def test_only_on_demand_lifecycle_may_declare_timeout(self) -> None:
        for lifecycle in ("manual", "background", "session"):
            with self.subTest(lifecycle=lifecycle), tempfile.TemporaryDirectory() as temporary:
                path = self.write_manifest(
                    Path(temporary),
                    lifecycle=lifecycle,
                    marker=MIN_IDLE_TIMEOUT_MS,
                )
                with self.assertRaisesRegex(ValueError, "lifecycle=on-demand"):
                    load_manifest(path)


class IdleRuntimeTests(unittest.IsolatedAsyncioTestCase):
    async def test_ready_arms_timer_but_default_and_other_lifecycles_do_not(self) -> None:
        daemon, instance = runtime()
        daemon.role_registry = types.SimpleNamespace(list_role_info=lambda: [])
        daemon.components = {instance.component.key: instance.component}

        Msysd._component_became_ready(daemon, instance)
        self.assertIsNotNone(instance.idle_task)
        await cancel_idle(instance)

        for component in (
            on_demand_component(idle_timeout_ms=None),
            on_demand_component(lifecycle="background"),
            on_demand_component(lifecycle="manual"),
            on_demand_component(lifecycle="session"),
        ):
            with self.subTest(lifecycle=component.lifecycle, timeout=component.idle_timeout_ms):
                other_daemon, other = runtime(component)
                self.assertIsNone(Msysd._schedule_idle_task(other_daemon, other))

    async def test_concurrent_calls_rearm_only_after_last_completion(self) -> None:
        daemon, instance = runtime()
        old_idle = Msysd._schedule_idle_task(daemon, instance)
        self.assertIsNotNone(old_idle)

        deadline = int(time.monotonic() * 1000 + 5_000)
        first = asyncio.create_task(Msysd._forward_call(
            daemon,
            instance,
            {"type": "call", "id": 10, "method": "one", "deadline_ms": deadline},
            "caller",
        ))
        await asyncio.sleep(0)
        second = asyncio.create_task(Msysd._forward_call(
            daemon,
            instance,
            {"type": "call", "id": 11, "method": "two", "deadline_ms": deadline},
            "caller",
        ))
        await asyncio.sleep(0)

        self.assertEqual(instance.in_flight_calls, 2)
        self.assertIsNone(instance.idle_task)
        self.assertTrue(old_idle.cancelled() or old_idle.cancelling())

        instance.pending_calls[1].set_result({"type": "return", "id": 1, "payload": {}})
        await first
        self.assertEqual(instance.in_flight_calls, 1)
        self.assertIsNone(instance.idle_task)

        instance.pending_calls[2].set_result({"type": "return", "id": 2, "payload": {}})
        await second
        self.assertEqual(instance.in_flight_calls, 0)
        self.assertIsNotNone(instance.idle_task)
        await cancel_idle(instance)

    async def test_reentrant_component_call_keeps_outer_provider_busy(self) -> None:
        daemon, instance = runtime()
        deadline = int(time.monotonic() * 1000 + 5_000)
        outer = asyncio.create_task(Msysd._forward_call(
            daemon,
            instance,
            {"type": "call", "id": 12, "method": "outer", "deadline_ms": deadline},
            "caller",
        ))
        await asyncio.sleep(0)
        self.assertEqual(instance.in_flight_calls, 1)

        daemon.dispatch_call = AsyncMock(
            return_value={"type": "return", "id": 90, "payload": {"ok": True}}
        )
        await Msysd._dispatch_component_call(
            daemon,
            instance,
            {
                "type": "call",
                "id": 90,
                "target": "msys.core",
                "method": "list_components",
            },
        )
        self.assertEqual(instance.in_flight_calls, 1)
        self.assertIsNone(instance.idle_task)

        instance.pending_calls[1].set_result({"type": "return", "id": 1, "payload": {}})
        await outer
        self.assertEqual(instance.in_flight_calls, 0)
        self.assertIsNotNone(instance.idle_task)
        await cancel_idle(instance)

    async def test_deadline_timeout_rearms_and_clears_pending_accounting(self) -> None:
        daemon, instance = runtime()
        response = await Msysd._forward_call(
            daemon,
            instance,
            {
                "type": "call",
                "id": 13,
                "method": "expired",
                "deadline_ms": int(time.monotonic() * 1000 - 1),
            },
            "caller",
        )

        self.assertEqual(response["code"], "CALL_TIMEOUT")
        self.assertEqual(instance.in_flight_calls, 0)
        self.assertEqual(instance.pending_calls, {})
        self.assertIsNotNone(instance.idle_task)
        await cancel_idle(instance)

    async def test_call_start_cancels_old_timer_and_finish_gets_full_new_timer(self) -> None:
        daemon, instance = runtime()
        old_idle = Msysd._schedule_idle_task(daemon, instance)
        self.assertIsNotNone(old_idle)

        Msysd._begin_forward_call(daemon, instance)
        self.assertEqual(instance.in_flight_calls, 1)
        self.assertIsNone(instance.idle_task)
        self.assertTrue(old_idle.cancelled() or old_idle.cancelling())

        Msysd._finish_forward_call(daemon, instance)
        self.assertEqual(instance.in_flight_calls, 0)
        self.assertIsNotNone(instance.idle_task)
        self.assertIsNot(instance.idle_task, old_idle)
        await cancel_idle(instance)

    async def test_expiry_uses_graceful_expected_generation_stop(self) -> None:
        daemon, instance = runtime()
        daemon.stop_component = AsyncMock()
        task = asyncio.create_task(Msysd._idle_stop_after(daemon, instance, 0))
        instance.idle_task = task

        await task

        daemon.stop_component.assert_awaited_once_with(
            instance.component.key,
            expected=instance,
        )
        self.assertIsNone(instance.idle_task)

    async def test_expiry_never_stops_busy_or_replacement_generation(self) -> None:
        daemon, old = runtime()
        daemon.stop_component = AsyncMock()

        old.in_flight_calls = 1
        busy_task = asyncio.create_task(Msysd._idle_stop_after(daemon, old, 0))
        old.idle_task = busy_task
        await busy_task
        daemon.stop_component.assert_not_awaited()

        old.in_flight_calls = 0
        replacement = Instance(
            component=old.component,
            generation=2,
            state="ready",
            ready=True,
        )
        daemon.instances[old.component.key] = replacement
        stale_task = asyncio.create_task(Msysd._idle_stop_after(daemon, old, 0))
        old.idle_task = stale_task
        await stale_task
        daemon.stop_component.assert_not_awaited()
        self.assertIs(daemon.instances[old.component.key], replacement)

    async def test_instance_shutdown_cancels_idle_timer(self) -> None:
        daemon, instance = runtime()
        idle = Msysd._schedule_idle_task(daemon, instance)
        self.assertIsNotNone(idle)

        await Msysd._cancel_instance_tasks(daemon, instance, include_watch=True)

        self.assertTrue(idle.cancelled())
        self.assertIsNone(instance.idle_task)


if __name__ == "__main__":
    unittest.main()
