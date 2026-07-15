from __future__ import annotations

import types
import unittest

from msys_core.manifest import Component, Provide
from msys_core.msysd import Msysd


def component(*, navigation: bool) -> Component:
    return Component(
        package_id="org.example.app",
        package_version="1.0.0",
        id="main",
        exec=["app"],
        lifecycle="manual",
        runtime="tk",
        readiness_mode="mipc-ready",
        provides=(
            [Provide("interface", "org.msys.application-navigation.v1")]
            if navigation
            else []
        ),
        windowing={"mode": "window"},
    )


class FakeDaemon:
    def __init__(self, *, navigation: bool, response: dict | None = None) -> None:
        selected = component(navigation=navigation)
        self.components = {selected.key: selected}
        self.foreground_stack = [selected.key]
        self.response = response
        self.forwarded: list[tuple[object, dict, str]] = []
        self.instances = {
            selected.key: types.SimpleNamespace(
                component=selected,
                sock=object(),
                ready=True,
                process=types.SimpleNamespace(poll=lambda: None),
                state="ready",
            )
        }
        self.backgrounded_components: set[str] = set()

    def _foreground_entries(self) -> list[dict[str, str]]:
        return Msysd._foreground_entries(self)  # type: ignore[return-value]

    def _is_foreground_app(self, selected: Component) -> bool:
        return Msysd._is_foreground_app(self, selected)

    def _background_foreground(self, key: str) -> tuple[bool, bool]:
        return Msysd._background_foreground(self, key)

    async def _forward_call(self, instance, message, source: str) -> dict:
        self.forwarded.append((instance, message, source))
        assert self.response is not None
        return self.response


class ApplicationNavigationTests(unittest.IsolatedAsyncioTestCase):
    async def call(self, daemon: FakeDaemon) -> dict:
        return await Msysd._core_call(daemon, {
            "type": "call",
            "id": 17,
            "method": "navigation_back",
            "payload": {},
            "deadline_ms": 12345,
        }, source="org.msys.x11.session:window-policy")

    async def test_declared_application_handles_back_before_lifecycle_fallback(self) -> None:
        daemon = FakeDaemon(
            navigation=True,
            response={"type": "return", "id": 17, "payload": {"handled": True, "page": "wifi"}},
        )
        response = await self.call(daemon)
        self.assertTrue(response["payload"]["handled"])
        self.assertFalse(response["payload"]["fallback"])
        self.assertEqual(daemon.forwarded[0][1]["method"], "navigation_back")
        self.assertEqual(daemon.forwarded[0][1]["deadline_ms"], 12345)

    async def test_root_page_allows_previous_task_fallback(self) -> None:
        daemon = FakeDaemon(
            navigation=True,
            response={"type": "return", "id": 17, "payload": {"handled": False}},
        )
        response = await self.call(daemon)
        self.assertFalse(response["payload"]["handled"])
        self.assertTrue(response["payload"]["fallback"])

    async def test_legacy_application_skips_call_and_allows_fallback(self) -> None:
        daemon = FakeDaemon(navigation=False)
        response = await self.call(daemon)
        self.assertEqual(response["payload"]["reason"], "interface-not-provided")
        self.assertTrue(response["payload"]["fallback"])
        self.assertEqual(daemon.forwarded, [])

    async def test_declared_provider_failure_does_not_close_application(self) -> None:
        daemon = FakeDaemon(
            navigation=True,
            response={"type": "error", "id": 17, "code": "CALL_TIMEOUT"},
        )
        response = await self.call(daemon)
        self.assertFalse(response["payload"]["handled"])
        self.assertFalse(response["payload"]["fallback"])
        self.assertEqual(response["payload"]["reason"], "CALL_TIMEOUT")

    async def test_background_keeps_process_and_recents_but_removes_active_app(self) -> None:
        daemon = FakeDaemon(navigation=False)
        component_id = daemon.foreground_stack[0]
        process = daemon.instances[component_id].process

        response = await Msysd._core_call(daemon, {
            "type": "call",
            "id": 18,
            "method": "background_component",
            "payload": {"component": component_id},
        }, source="org.msys.x11.session:window-policy")

        self.assertEqual(response["payload"]["state"], "background")
        self.assertIsNone(process.poll())
        self.assertEqual(daemon.foreground_stack, [component_id])
        self.assertEqual(daemon._foreground_entries()[0]["state"], "background")
        navigation = await self.call(daemon)
        self.assertEqual(
            navigation["payload"]["reason"], "no-foreground-application"
        )

    async def test_only_current_live_application_can_be_backgrounded(self) -> None:
        daemon = FakeDaemon(navigation=False)
        response = await Msysd._core_call(daemon, {
            "type": "call",
            "id": 19,
            "method": "background_component",
            "payload": {"component": "org.example.missing:main"},
        })
        self.assertEqual(response["type"], "error")
        self.assertEqual(response["code"], "COMPONENT_UNAVAILABLE")


if __name__ == "__main__":
    unittest.main()
