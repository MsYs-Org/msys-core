from __future__ import annotations

import asyncio
import unittest
from typing import Any

from msys_core.manifest import Component
from msys_core.msysd import Instance, Msysd


class FakeProcess:
    def __init__(self, returncode: int | None) -> None:
        self.returncode = returncode

    def poll(self) -> int | None:
        return self.returncode


def component(*, restart: str) -> Component:
    return Component(
        package_id="org.msys.test",
        package_version="1.0.0",
        id="service",
        exec=["unused"],
        lifecycle="background",
        restart=restart,
        readiness_mode="mipc-ready",
        readiness_timeout_ms=250,
    )


def daemon_state(item: Component) -> Msysd:
    daemon = object.__new__(Msysd)
    daemon.components = {item.key: item}
    daemon.instances = {}
    daemon.stopping = False
    daemon.stop_requests = set()
    daemon.quarantined = set()
    return daemon


class ReadinessSupervisionTests(unittest.TestCase):
    def test_ensure_ready_follows_automatic_restart_generation(self) -> None:
        asyncio.run(self._ensure_ready_follows_automatic_restart_generation())

    async def _ensure_ready_follows_automatic_restart_generation(self) -> None:
        item = component(restart="on-failure")
        daemon = daemon_state(item)
        failed = Instance(
            component=item,
            generation=1,
            process=FakeProcess(1),  # type: ignore[arg-type]
            state="failed",
        )
        replacement = Instance(
            component=item,
            generation=2,
            process=FakeProcess(None),  # type: ignore[arg-type]
            state="handshaking",
        )
        calls = 0

        async def supervised_restart() -> None:
            # Model the real watch task owning restart/backoff and publishing
            # the replacement generation before it completes.
            await asyncio.sleep(0.01)
            daemon.instances[item.key] = replacement
            asyncio.get_running_loop().call_soon(mark_replacement_ready)

        failed.watch_task = asyncio.create_task(supervised_restart())

        async def ensure_started(
            key: str,
            activation: dict[str, Any] | None = None,
        ) -> Instance:
            nonlocal calls
            self.assertEqual(key, item.key)
            calls += 1
            daemon.instances[key] = failed
            return failed

        def mark_replacement_ready() -> None:
            replacement.ready = True
            replacement.state = "ready"
            replacement.ready_event.set()

        leased: list[int] = []
        daemon.ensure_started = ensure_started  # type: ignore[method-assign]
        daemon._lease_preferred_roles = lambda value: leased.append(value.generation)  # type: ignore[method-assign]

        result = await daemon.ensure_ready(item.key)

        self.assertIs(result, replacement)
        # ensure_ready follows the supervisor's generation; it must not race
        # the watcher by spawning a replacement itself.
        self.assertEqual(calls, 1)
        self.assertEqual(leased, [2])

    def test_ensure_ready_does_not_restart_when_policy_forbids_it(self) -> None:
        asyncio.run(self._ensure_ready_does_not_restart_when_policy_forbids_it())

    async def _ensure_ready_does_not_restart_when_policy_forbids_it(self) -> None:
        item = component(restart="never")
        daemon = daemon_state(item)
        failed = Instance(
            component=item,
            generation=1,
            process=FakeProcess(1),  # type: ignore[arg-type]
            state="failed",
        )
        calls = 0

        async def ensure_started(
            key: str,
            activation: dict[str, Any] | None = None,
        ) -> Instance:
            nonlocal calls
            calls += 1
            daemon.instances[key] = failed
            return failed

        daemon.ensure_started = ensure_started  # type: ignore[method-assign]

        with self.assertRaisesRegex(RuntimeError, "did not become ready"):
            await daemon.ensure_ready(item.key)
        self.assertEqual(calls, 1)


if __name__ == "__main__":
    unittest.main()
