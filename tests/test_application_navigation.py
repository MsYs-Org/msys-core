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
            )
        }

    def _foreground_entries(self) -> list[dict[str, str]]:
        return [{"component": self.foreground_stack[0]}] if self.foreground_stack else []

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


if __name__ == "__main__":
    unittest.main()
