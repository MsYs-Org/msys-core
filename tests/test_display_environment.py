from __future__ import annotations

import os
import unittest
from unittest import mock

from msys_core.manifest import Component, Provide
from msys_core.msysd import DEFAULT_X11_DISPLAY, Msysd
from msys_core.roles import RoleRegistry


def component(key: str, *, env: dict[str, str] | None = None) -> Component:
    package_id, component_id = key.split(":", 1)
    return Component(
        package_id=package_id,
        package_version="1.0.0",
        id=component_id,
        exec=["unused"],
        lifecycle="manual",
        env=env or {},
    )


def display_provider(key: str, *, env: dict[str, str]) -> Component:
    provider = component(key, env=env)
    provider.lifecycle = "background"
    provider.provides = [Provide("role", "display-output", exclusive=True)]
    return provider


def daemon_with(
    target: Component,
    *providers: Component,
    candidates: list[str] | None = None,
) -> Msysd:
    daemon = object.__new__(Msysd)
    daemon.components = {item.key: item for item in (*providers, target)}
    daemon.profile = {
        "roles": {"display-output": candidates or [item.key for item in providers]},
        "startup": [],
        "env": {},
    }
    daemon.role_registry = RoleRegistry.from_profile(daemon.components, daemon.profile)
    return daemon


class DisplayEnvironmentTests(unittest.TestCase):
    def test_spi_and_hdmi_follow_selected_display_output_provider(self) -> None:
        target = component("org.example:viewer")
        spi = display_provider(
            "org.example:spi-output",
            env={"DISPLAY_ID": ":24"},
        )
        hdmi = display_provider(
            "org.example:hdmi-output",
            env={"DISPLAY": ":0"},
        )
        daemon = daemon_with(target, spi, hdmi)

        with mock.patch.dict(os.environ, {"DISPLAY": ":91"}, clear=True):
            self.assertEqual(daemon._component_environment(target)["DISPLAY"], ":24")
            daemon.role_registry.select_preferred("display-output", hdmi.key)
            self.assertEqual(daemon._component_environment(target)["DISPLAY"], ":0")

    def test_active_fallback_provider_describes_the_live_session(self) -> None:
        target = component("org.example:viewer")
        spi = display_provider("org.example:spi-output", env={"DISPLAY_ID": ":24"})
        hdmi = display_provider("org.example:hdmi-output", env={"DISPLAY_ID": ":0"})
        daemon = daemon_with(target, spi, hdmi)
        daemon.role_registry.acquire("display-output", hdmi.key, holder="generation:3")

        self.assertEqual(daemon._component_environment(target)["DISPLAY"], ":0")

    def test_component_display_is_an_explicit_final_override(self) -> None:
        target = component("org.example:viewer", env={"DISPLAY": ":77"})
        spi = display_provider("org.example:spi-output", env={"DISPLAY_ID": ":24"})
        daemon = daemon_with(target, spi)

        self.assertEqual(daemon._component_environment(target)["DISPLAY"], ":77")

    def test_missing_provider_keeps_inherited_then_conventional_fallback(self) -> None:
        target = component("org.example:viewer")
        daemon = daemon_with(target, candidates=["org.not-installed:display-output"])

        with mock.patch.dict(os.environ, {"DISPLAY": ":88"}, clear=True):
            self.assertEqual(daemon._component_environment(target)["DISPLAY"], ":88")
        with mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(
                daemon._component_environment(target)["DISPLAY"],
                DEFAULT_X11_DISPLAY,
            )


if __name__ == "__main__":
    unittest.main()
