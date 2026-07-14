from __future__ import annotations

import types
import unittest

from msys_core.manifest import Component, Provide
from msys_core.msysd import Msysd
from msys_core.services import ServiceCatalog


def provider(name: str):
    return types.SimpleNamespace(component=types.SimpleNamespace(key=name))


class FakeInterfaceDaemon:
    def __init__(self, responses: list[dict]) -> None:
        self.providers = [provider(f"provider-{index}") for index in range(len(responses))]
        self.responses = list(responses)
        self.forwarded: list[str] = []
        self.stopped: list[str] = []

    async def _provider_for_interface(self, interface: str, *, exclude=None):
        self.interface = interface
        excluded = exclude or set()
        return next(
            (item for item in self.providers if item.component.key not in excluded),
            None,
        )

    async def _forward_call(self, selected, msg, source: str):
        self.forwarded.append(selected.component.key)
        self.source = source
        return self.responses[len(self.forwarded) - 1]

    async def stop_component(self, key: str, *, expected=None) -> None:
        self.stopped.append(key)


def component(
    key: str,
    provides: list[Provide],
    *,
    runtime: str = "native",
) -> Component:
    package_id, component_id = key.split(":", 1)
    return Component(
        package_id=package_id,
        package_version="1.0.0",
        id=component_id,
        exec=["worker"],
        lifecycle="on-demand",
        runtime=runtime,
        provides=provides,
    )


class InterfaceDispatchTests(unittest.IsolatedAsyncioTestCase):
    async def test_cold_start_deadline_expiry_does_not_stop_ready_provider(self) -> None:
        daemon = FakeInterfaceDaemon([{
            "type": "error",
            "id": 1,
            "code": "CALL_TIMEOUT",
            "message": "call deadline already expired",
        }])
        response = await Msysd._dispatch_interface_call(
            daemon,
            {
                "type": "call",
                "id": 7,
                "target": "interface:org.example.echo.v1",
                "method": "status",
                "idempotent": True,
            },
            source="org.example:caller",
        )

        self.assertEqual(response["code"], "CALL_TIMEOUT")
        self.assertEqual(response["id"], 7)
        self.assertEqual(daemon.forwarded, ["provider-0"])
        self.assertEqual(daemon.stopped, [])

    async def test_idempotent_interface_call_fails_over(self) -> None:
        daemon = FakeInterfaceDaemon([
            {"type": "error", "id": 1, "code": "CALL_TIMEOUT"},
            {"type": "return", "id": 1, "payload": {"runtime": "c"}},
        ])
        response = await Msysd._dispatch_interface_call(
            daemon,
            {
                "type": "call",
                "id": 8,
                "target": "interface:org.example.echo.v1",
                "method": "status",
                "idempotent": True,
            },
            source="org.example:caller",
        )

        self.assertEqual(response["type"], "return")
        self.assertEqual(daemon.interface, "org.example.echo.v1")
        self.assertEqual(daemon.forwarded, ["provider-0", "provider-1"])
        self.assertEqual(daemon.stopped, ["provider-0"])

    async def test_non_idempotent_interface_timeout_is_not_replayed(self) -> None:
        daemon = FakeInterfaceDaemon([
            {"type": "error", "id": 1, "code": "CALL_TIMEOUT"},
            {"type": "return", "id": 1, "payload": {"ok": True}},
        ])
        response = await Msysd._dispatch_interface_call(
            daemon,
            {
                "type": "call",
                "id": 9,
                "target": "interface:org.example.writer.v1",
                "method": "append",
            },
            source="test",
        )

        self.assertEqual(response["code"], "OUTCOME_UNKNOWN")
        self.assertEqual(daemon.forwarded, ["provider-0"])

    async def test_exact_component_target_wakes_and_forwards(self) -> None:
        selected = provider("org.example.worker:sync")

        class FakeDaemon:
            components = {"org.example.worker:sync": object()}

            async def ensure_ready(self, key):
                self.started = key
                return selected

            async def _forward_call(self, instance, message, source):
                self.forwarded = (instance, message, source)
                return {"type": "return", "id": message["id"], "payload": {"ok": True}}

        daemon = FakeDaemon()
        response = await Msysd._dispatch_component_target_call(
            daemon,
            {
                "type": "call",
                "id": 4,
                "target": "component:org.example.worker:sync",
                "method": "wake",
            },
            source="caller",
        )
        self.assertEqual(response["payload"], {"ok": True})
        self.assertEqual(daemon.started, "org.example.worker:sync")
        self.assertEqual(daemon.forwarded[2], "caller")


class DiscoveryTests(unittest.IsolatedAsyncioTestCase):
    async def test_discovery_exposes_all_providers_and_exact_targets(self) -> None:
        components = {
            "org.example:c": component(
                "org.example:c",
                [
                    Provide("interface", "org.example.echo.v1", priority=80),
                    Provide("capability", "runtime.native-c"),
                ],
            ),
            "org.example:python": component(
                "org.example:python",
                [Provide("interface", "org.example.echo.v1", priority=40)],
                runtime="python",
            ),
        }
        daemon = object.__new__(Msysd)
        daemon.components = components
        daemon.instances = {}
        daemon.service_catalog = ServiceCatalog(components)

        response = await Msysd._core_call(
            daemon,
            {
                "type": "call",
                "id": 12,
                "method": "discover",
                "payload": {"kind": "interface", "name": "org.example.echo.v1"},
            },
        )

        services = response["payload"]["services"]
        self.assertEqual(len(services), 1)
        self.assertEqual(services[0]["target"], "interface:org.example.echo.v1")
        self.assertEqual(
            [item["target"] for item in services[0]["providers"]],
            ["component:org.example:c", "component:org.example:python"],
        )

    async def test_discovery_rejects_unknown_kind(self) -> None:
        daemon = object.__new__(Msysd)
        response = await Msysd._core_call(
            daemon,
            {
                "type": "call",
                "id": 13,
                "method": "discover",
                "payload": {"kind": "role"},
            },
        )
        self.assertEqual(response["code"], "BAD_SERVICE_KIND")


if __name__ == "__main__":
    unittest.main()
