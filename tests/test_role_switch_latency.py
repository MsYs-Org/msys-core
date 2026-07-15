from __future__ import annotations

import asyncio
import subprocess
import sys
import unittest
from unittest import mock

from msys_core.manifest import Component, Provide
from msys_core.msysd import Instance, Msysd
from msys_core.roles import RoleRegistry


def provider(package: str) -> Component:
    return Component(
        package_id=package,
        package_version="1.0.0",
        id="main",
        exec=["true"],
        lifecycle="background",
        provides=[Provide("role", "hal-manager", exclusive=True)],
    )


def switch_daemon(old: Component, new: Component) -> Msysd:
    daemon = object.__new__(Msysd)
    daemon.components = {old.key: old, new.key: new}
    daemon.role_registry = RoleRegistry(
        daemon.components,
        {"hal-manager": [new.key, old.key]},
    )
    daemon.role_registry.acquire("hal-manager", old.key, holder="generation:1")
    daemon.catalog_lock = asyncio.Lock()
    daemon.catalog_epoch = 1
    daemon.role_preference_overrides = {}
    daemon.supervisor_tasks = set()
    daemon.instances = {
        old.key: Instance(component=old, generation=1, state="ready", ready=True),
        new.key: Instance(component=new, generation=1, state="ready", ready=True),
    }

    async def ensure_ready(key: str) -> Instance:
        return daemon.instances[key]

    daemon.ensure_ready = ensure_ready  # type: ignore[method-assign]
    daemon._persist_role_preferences = lambda: None  # type: ignore[method-assign]
    return daemon


class RoleSwitchLatencyTests(unittest.IsolatedAsyncioTestCase):
    async def test_ready_provider_switch_does_not_wait_for_old_stop_grace(self) -> None:
        old = provider("org.example.old")
        new = provider("org.example.new")
        daemon = switch_daemon(old, new)
        stop_entered = asyncio.Event()
        release_stop = asyncio.Event()

        async def slow_stop(key: str, *, expected=None) -> None:
            self.assertEqual(key, old.key)
            self.assertIs(expected, daemon.instances[old.key])
            stop_entered.set()
            await release_stop.wait()

        daemon.stop_component = slow_stop  # type: ignore[method-assign]

        response = await asyncio.wait_for(
            Msysd._switch_role(
                daemon,
                "hal-manager",
                new.key,
                preference_mode="select",
            ),
            timeout=0.2,
        )

        self.assertTrue(stop_entered.is_set())
        self.assertEqual(response["active"], new.key)
        self.assertEqual(response["cleanup_pending"], old.key)
        self.assertEqual(daemon.role_registry.active_provider("hal-manager"), new.key)

        release_stop.set()
        await asyncio.gather(*tuple(daemon.supervisor_tasks))

    async def test_reselecting_exact_live_provider_skips_flash_and_cleanup(self) -> None:
        selected = provider("org.example.selected")
        unused = provider("org.example.unused")
        daemon = switch_daemon(unused, selected)
        daemon.role_registry.release_provider(unused.key)
        daemon.role_registry.acquire(
            "hal-manager", selected.key, holder="generation:1"
        )
        daemon.role_preference_overrides["hal-manager"] = selected.key
        persist = mock.Mock()
        daemon._persist_role_preferences = persist  # type: ignore[method-assign]
        daemon.stop_component = mock.AsyncMock()  # type: ignore[method-assign]

        response = await Msysd._switch_role(
            daemon,
            "hal-manager",
            selected.key,
            preference_mode="select",
        )

        self.assertEqual(response["active"], selected.key)
        persist.assert_not_called()
        daemon.stop_component.assert_not_awaited()


@unittest.skipUnless(hasattr(__import__("os"), "pidfd_open"), "Linux pidfd required")
class ProcessExitLatencyTests(unittest.IsolatedAsyncioTestCase):
    async def test_pidfd_exit_wait_does_not_use_poll_sleep(self) -> None:
        process = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(0.03)"],
        )
        try:
            with mock.patch(
                "msys_core.msysd.asyncio.sleep",
                side_effect=AssertionError("pidfd path fell back to polling"),
            ):
                await asyncio.wait_for(
                    Msysd._wait_for_process_exit(process),
                    timeout=1.0,
                )
            self.assertEqual(process.returncode, 0)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=1)


if __name__ == "__main__":
    unittest.main()
