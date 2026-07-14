from __future__ import annotations

import unittest

from msys_core.manifest import Component, Provide
from msys_core.services import (
    ServiceCatalog,
    UnknownServiceError,
    UnknownServiceProviderError,
)


def component(key: str, provides: list[Provide]) -> Component:
    package_id, component_id = key.split(":", 1)
    return Component(
        package_id=package_id,
        package_version="1.0.0",
        id=component_id,
        exec=["true"],
        lifecycle="on-demand",
        provides=provides,
    )


class ServiceCatalogTests(unittest.TestCase):
    def test_interface_providers_are_priority_then_identity_ordered(self) -> None:
        catalog = ServiceCatalog({
            "org.example:low": component(
                "org.example:low",
                [Provide("interface", "org.example.echo.v1", priority=10)],
            ),
            "org.example:z": component(
                "org.example:z",
                [Provide("interface", "org.example.echo.v1", priority=50)],
            ),
            "org.example:a": component(
                "org.example:a",
                [Provide("interface", "org.example.echo.v1", priority=50)],
            ),
        })

        self.assertEqual(
            catalog.provider_ids("interface", "org.example.echo.v1"),
            ("org.example:a", "org.example:z", "org.example:low"),
        )

    def test_duplicate_declarations_are_folded_conservatively(self) -> None:
        catalog = ServiceCatalog({
            "org.example:one": component(
                "org.example:one",
                [
                    Provide("capability", "sensor.touch", priority=1),
                    Provide("capability", "sensor.touch", exclusive=True, priority=7),
                ],
            ),
        })

        provider = catalog.get_provider("capability", "sensor.touch")
        self.assertEqual(provider.priority, 7)
        self.assertTrue(provider.exclusive)

    def test_explicit_provider_must_implement_interface(self) -> None:
        catalog = ServiceCatalog({
            "org.example:one": component(
                "org.example:one",
                [Provide("interface", "org.example.echo.v1")],
            ),
        })

        with self.assertRaises(UnknownServiceProviderError):
            catalog.get_provider(
                "interface",
                "org.example.echo.v1",
                "org.example:missing",
            )

    def test_unknown_service_is_distinct_from_empty_catalog(self) -> None:
        catalog = ServiceCatalog({})
        self.assertEqual(catalog.names("interface"), ())
        with self.assertRaises(UnknownServiceError):
            catalog.providers("interface", "org.example.missing.v1")

    def test_entries_can_filter_kind(self) -> None:
        catalog = ServiceCatalog({
            "org.example:both": component(
                "org.example:both",
                [
                    Provide("interface", "org.example.echo.v1"),
                    Provide("capability", "sensor.touch"),
                ],
            ),
        })
        self.assertEqual(
            [entry.kind for entry in catalog.entries("capability")],
            ["capability"],
        )
        self.assertEqual(
            {entry.kind for entry in catalog.entries()},
            {"interface", "capability"},
        )


if __name__ == "__main__":
    unittest.main()
