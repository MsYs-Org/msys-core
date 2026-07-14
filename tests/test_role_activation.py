from __future__ import annotations

import asyncio
import unittest
from unittest.mock import AsyncMock

from msys_core.manifest import Component, Provide
from msys_core.msysd import Instance, Msysd
from msys_core.roles import RoleRegistry


def launcher(
    package: str,
    identifier: str,
    *,
    title: str,
    identity: str,
    priority: int = 50,
) -> Component:
    return Component(
        package_id=package,
        package_version="1.0.0",
        package_name=f"{title} Package",
        id=identifier,
        exec=["true"],
        lifecycle="manual",
        windowing={
            "system": "x11",
            "mode": "window",
            "title": title,
            "identity": {
                "app_id": identity,
                "x11_wm_class": identity,
            },
        },
        provides=[Provide("role", "launcher", exclusive=True, priority=priority)],
    )


def activation_daemon(
    components: list[Component],
    *,
    profile_order: list[str] | None = None,
) -> Msysd:
    daemon = object.__new__(Msysd)
    daemon.components = {component.key: component for component in components}
    daemon.role_registry = RoleRegistry(
        daemon.components,
        {"launcher": profile_order or [component.key for component in components]},
    )
    daemon.catalog_lock = asyncio.Lock()
    daemon.catalog_epoch = 1
    daemon.role_locks = {}
    daemon.foreground_stack = []
    daemon.instances = {}
    return daemon


class RoleActivationTests(unittest.IsolatedAsyncioTestCase):
    async def test_internal_window_activation_bypasses_outer_home_role_lock(self) -> None:
        class ReentrantDaemon:
            role_locks = {"window-manager": asyncio.Lock()}

            async def _dispatch_role_call(self, message, source):
                return {
                    "type": "return",
                    "id": message["id"],
                    "payload": {"ok": True, "source": source},
                }

        daemon = ReentrantDaemon()
        await daemon.role_locks["window-manager"].acquire()
        try:
            response = await asyncio.wait_for(Msysd.dispatch_call(
                daemon,
                {
                    "type": "call",
                    "id": 19,
                    "target": "role:window-manager",
                    "method": "activate_component",
                    "payload": {"component": "org.vendor.home:main"},
                },
                source="msys.core",
            ), timeout=0.2)
        finally:
            daemon.role_locks["window-manager"].release()

        self.assertEqual(response["payload"]["source"], "msys.core")

    async def test_third_party_launcher_uses_selected_manifest_identity(self) -> None:
        selected = launcher(
            "org.vendor.nebula",
            "home",
            title="Nebula Home",
            identity="org.vendor.nebula.home",
        )
        daemon = activation_daemon([selected])
        instance = Instance(
            component=selected,
            generation=7,
            state="ready",
            ready=True,
        )
        daemon.instances[selected.key] = instance
        daemon.ensure_ready = AsyncMock(return_value=instance)
        daemon.dispatch_call = AsyncMock(return_value={
            "type": "return",
            "id": 0,
            "payload": {
                "ok": True,
                "component": selected.key,
                "identity": "org.vendor.nebula.home",
                "title": "Nebula Home",
            },
        })

        response = await Msysd._core_call(daemon, {
            "type": "call",
            "id": 21,
            "method": "activate_role",
            "payload": {"role": "launcher"},
        })

        self.assertEqual(response["type"], "return")
        self.assertEqual(response["payload"]["provider"], selected.key)
        self.assertEqual(response["payload"]["generation"], 7)
        self.assertEqual(daemon.foreground_stack, [selected.key])
        daemon.ensure_ready.assert_awaited_once_with(selected.key)
        activation = daemon.dispatch_call.await_args.args[0]
        self.assertEqual(activation["target"], "role:window-manager")
        self.assertEqual(activation["method"], "activate_component")
        self.assertEqual(activation["payload"], {
            "component": selected.key,
            "identity": "org.vendor.nebula.home",
            "title": "Nebula Home",
        })
        self.assertNotIn("org.msys.shell", str(activation))

    async def test_active_provider_wins_and_running_generation_is_reactivated(self) -> None:
        active = launcher(
            "org.vendor.active",
            "launcher",
            title="Active Home",
            identity="org.vendor.active.home",
        )
        preferred = launcher(
            "org.vendor.preferred",
            "launcher",
            title="Preferred Home",
            identity="org.vendor.preferred.home",
        )
        daemon = activation_daemon(
            [active, preferred],
            profile_order=[preferred.key, active.key],
        )
        daemon.role_registry.acquire("launcher", active.key, holder="generation:3")
        instance = Instance(
            component=active,
            generation=3,
            state="ready",
            ready=True,
        )
        daemon.instances[active.key] = instance
        daemon.ensure_ready = AsyncMock(return_value=instance)
        daemon.dispatch_call = AsyncMock(return_value={
            "type": "return",
            "id": 0,
            "payload": {"ok": True, "component": active.key},
        })
        request = {
            "type": "call",
            "id": 22,
            "method": "activate_role",
            "payload": {"role": "launcher"},
        }

        first = await Msysd._core_call(daemon, request)
        second = await Msysd._core_call(daemon, request)

        self.assertEqual(first["payload"]["provider"], active.key)
        self.assertEqual(second["payload"]["provider"], active.key)
        self.assertEqual(first["payload"]["generation"], 3)
        self.assertEqual(daemon.ensure_ready.await_count, 2)
        self.assertEqual(daemon.dispatch_call.await_count, 2)

    async def test_payload_role_provider_and_recursion_errors_are_typed(self) -> None:
        selected = launcher(
            "org.vendor.home",
            "main",
            title="Home",
            identity="org.vendor.home",
        )
        daemon = activation_daemon([selected])

        bad_payload = await Msysd._core_call(daemon, {
            "type": "call", "id": 1, "method": "activate_role", "payload": [],
        })
        bad_role = await Msysd._core_call(daemon, {
            "type": "call", "id": 2, "method": "activate_role", "payload": {},
        })
        unknown = await Msysd._core_call(daemon, {
            "type": "call",
            "id": 3,
            "method": "activate_role",
            "payload": {"role": "not-installed"},
        })
        recursive = await Msysd._core_call(daemon, {
            "type": "call",
            "id": 4,
            "method": "activate_role",
            "payload": {"role": "window-manager"},
        })

        self.assertEqual(bad_payload["code"], "BAD_PAYLOAD")
        self.assertEqual(bad_role["code"], "BAD_ROLE")
        self.assertEqual(unknown["code"], "UNKNOWN_ROLE")
        self.assertEqual(recursive["code"], "ROLE_ACTIVATION_RECURSION")

        empty = activation_daemon([])
        empty.role_registry = RoleRegistry({}, {"launcher": []})
        no_provider = await Msysd._core_call(empty, {
            "type": "call",
            "id": 5,
            "method": "activate_role",
            "payload": {"role": "launcher"},
        })
        self.assertEqual(no_provider["code"], "NO_PROVIDER")

    async def test_start_and_window_activation_failures_are_distinct(self) -> None:
        selected = launcher(
            "org.vendor.failure",
            "home",
            title="Failure Home",
            identity="org.vendor.failure.home",
        )
        unavailable = activation_daemon([selected])
        unavailable.ensure_ready = AsyncMock(side_effect=RuntimeError("did not become ready"))
        failed_start = await Msysd._core_call(unavailable, {
            "type": "call",
            "id": 31,
            "method": "activate_role",
            "payload": {"role": "launcher"},
        })
        self.assertEqual(failed_start["code"], "ROLE_UNAVAILABLE")
        self.assertEqual(failed_start["payload"]["provider"], selected.key)

        activation_failure = activation_daemon([selected])
        instance = Instance(component=selected, generation=2, state="ready", ready=True)
        activation_failure.instances[selected.key] = instance
        activation_failure.ensure_ready = AsyncMock(return_value=instance)
        activation_failure.dispatch_call = AsyncMock(return_value={
            "type": "error",
            "id": 0,
            "code": "NO_PROVIDER",
            "message": "window-manager",
        })
        failed_raise = await Msysd._core_call(activation_failure, {
            "type": "call",
            "id": 32,
            "method": "activate_role",
            "payload": {"role": "launcher"},
        })
        self.assertEqual(failed_raise["code"], "ROLE_ACTIVATION_FAILED")
        self.assertEqual(failed_raise["payload"]["provider"], selected.key)
        self.assertEqual(
            failed_raise["payload"]["activation"]["code"],
            "NO_PROVIDER",
        )

    async def test_core_x11_home_fallback_delegates_to_generic_role_api(self) -> None:
        daemon = object.__new__(Msysd)
        daemon._core_call = AsyncMock(return_value={
            "type": "return",
            "id": 44,
            "payload": {"ok": True, "provider": "org.vendor.home:main"},
        })
        message = {
            "type": "call",
            "id": 44,
            "method": "home",
            "deadline_ms": 123456,
        }

        response = await Msysd._x11_window_policy_call(daemon, message)

        self.assertEqual(response["payload"]["provider"], "org.vendor.home:main")
        forwarded = daemon._core_call.await_args.args[0]
        self.assertEqual(forwarded["method"], "activate_role")
        self.assertEqual(forwarded["payload"], {"role": "launcher"})
        self.assertEqual(forwarded["deadline_ms"], 123456)
        self.assertEqual(daemon._core_call.await_args.kwargs["source"], "msys.core")


if __name__ == "__main__":
    unittest.main()
