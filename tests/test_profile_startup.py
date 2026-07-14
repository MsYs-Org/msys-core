from __future__ import annotations

import unittest
from pathlib import Path

from msys_core.manifest import Component, Provide
from msys_core.msysd import Msysd
from msys_core.roles import RoleRegistry


DISPLAY_PROVIDER = "org.msys.openstick.ch347:x11-spi-touch-output"
HDMI_PROVIDER = "org.msys.x11.session:hdmi-output"
WINDOW_POLICY = "org.msys.x11.session:window-policy"
LEGACY_WINDOW_POLICY = "org.msys.shell.pyside:window-policy"
INPUT_METHOD = "org.msys.input.touch:keyboard"
NATIVE_HAL = "org.msys.hal.linux:native-manager"
PYTHON_HAL = "org.msys.hal.linux:manager"
NATIVE_SHELL = "org.msys.shell.native:desktop-shell"
TASK_SWITCHER = NATIVE_SHELL
PYSIDE_TASK_SWITCHER = "org.msys.shell.pyside:task-switcher"
NATIVE_ROLES = {
    "launcher": "org.msys.shell.pyside:launcher",
    "system-chrome": "org.msys.shell.pyside:chrome",
    "navigation-bar": "org.msys.shell.pyside:navigation",
    "task-switcher": PYSIDE_TASK_SWITCHER,
    "notification-presenter": "org.msys.shell.pyside:notifications",
}
PYSIDE_UNIMPLEMENTED_ON_DEMAND = {
    "notification-center": "org.msys.shell.pyside:notification-center",
    "chooser": "org.msys.shell.pyside:intent-chooser",
    "transition-presenter": "org.msys.shell.pyside:transitions",
}
LEAN_ON_DEMAND = {
    "org.msys.core.install:install-agent",
    "org.msys.core.install:update-agent",
    PYTHON_HAL,
    INPUT_METHOD,
    "org.msys.shell.pyside:transitions",
    "org.msys.shell.pyside:status-agent",
    "org.msys.shell.pyside:notifications",
    "org.msys.shell.pyside:notification-center",
    PYSIDE_TASK_SWITCHER,
    "org.msys.shell.pyside:intent-chooser",
}


def provider(key: str, role: str) -> Component:
    package_id, component_id = key.split(":", 1)
    return Component(
        package_id=package_id,
        package_version="1.0.0",
        id=component_id,
        exec=["provider"],
        lifecycle="background",
        provides=[Provide("role", role, exclusive=True)],
    )


def starts_at_profile_boot(daemon: Msysd, key: str) -> bool:
    component = daemon.components[key]
    requested = (
        key in daemon.profile.get("startup", [])
        or component.lifecycle in {"background", "session"}
    )
    return requested and daemon._is_eager_role_provider(key)


class ProfileStartupTests(unittest.TestCase):
    def test_background_provider_stays_dormant_when_its_role_is_disabled(self) -> None:
        chrome = provider("org.example:chrome", "system-chrome")
        daemon = object.__new__(Msysd)
        daemon.components = {chrome.key: chrome}
        daemon.role_registry = RoleRegistry.from_profile(
            daemon.components,
            {"roles": {}, "disabled_roles": ["system-chrome"]},
        )

        self.assertFalse(Msysd._is_eager_role_provider(daemon, chrome.key))

    def test_enabled_background_role_provider_remains_eager(self) -> None:
        policy = provider("org.example:policy", "window-policy")
        daemon = object.__new__(Msysd)
        daemon.components = {policy.key: policy}
        daemon.role_registry = RoleRegistry.from_profile(
            daemon.components,
            {"roles": {"window-policy": [policy.key]}},
        )

        self.assertTrue(Msysd._is_eager_role_provider(daemon, policy.key))

    def test_kiosk_profile_omits_shell_ui_but_keeps_policy_and_demo(self) -> None:
        config = Path(__file__).resolve().parents[1] / "examples" / "config"
        daemon = Msysd(config, Path("/tmp/msys-profile-test"), "kiosk-spi")

        for key in (
            NATIVE_SHELL,
            "org.msys.shell.pyside:chrome",
            "org.msys.shell.pyside:launcher",
            "org.msys.shell.pyside:navigation",
            "org.msys.shell.pyside:notifications",
            "org.msys.shell.pyside:notification-center",
            "org.msys.shell.pyside:task-switcher",
            "org.msys.shell.pyside:intent-chooser",
        ):
            self.assertFalse(daemon._is_eager_role_provider(key), key)
        self.assertEqual(daemon.profile["roles"]["window-policy"], [WINDOW_POLICY])
        self.assertEqual(daemon.profile["roles"]["window-manager"], [WINDOW_POLICY])
        self.assertIn("org.msys.demo:demo-app", daemon.profile["startup"])
        self.assertIn(NATIVE_HAL, daemon.profile["startup"])
        self.assertNotIn(PYTHON_HAL, daemon.profile["startup"])
        self.assertTrue(starts_at_profile_boot(daemon, NATIVE_HAL))
        self.assertFalse(starts_at_profile_boot(daemon, PYTHON_HAL))
        self.assertEqual(daemon.profile["roles"]["input-method"], [INPUT_METHOD])
        self.assertNotIn(INPUT_METHOD, daemon.profile["startup"])
        self.assertFalse(starts_at_profile_boot(daemon, INPUT_METHOD))
        self.assertFalse(starts_at_profile_boot(
            daemon, "org.msys.shell.pyside:transitions"
        ))
        self.assertEqual(daemon.profile["env"]["MSYS_LAYOUT_PROFILE"], "kiosk")

    def test_desktop_profiles_select_desktop_layout(self) -> None:
        config = Path(__file__).resolve().parents[1] / "examples" / "config"
        for profile in ("desktop-spi", "desktop-hdmi"):
            with self.subTest(profile=profile):
                daemon = Msysd(config, Path("/tmp/msys-profile-test"), profile)
                self.assertEqual(daemon.profile["env"]["MSYS_LAYOUT_PROFILE"], "desktop")
                self.assertEqual(daemon.profile["env"]["MSYS_NATIVE_NAV_MODE"], "buttons")
                self.assertTrue(starts_at_profile_boot(
                    daemon, NATIVE_SHELL
                ))
                self.assertFalse(starts_at_profile_boot(
                    daemon, "org.msys.shell.pyside:chrome"
                ))
                self.assertFalse(starts_at_profile_boot(
                    daemon, "org.msys.shell.pyside:transitions"
                ))
                self.assertTrue(starts_at_profile_boot(
                    daemon, NATIVE_HAL
                ))
                self.assertFalse(starts_at_profile_boot(daemon, PYTHON_HAL))
                self.assertFalse(starts_at_profile_boot(daemon, INPUT_METHOD))

    def test_mobile_profiles_keep_hal_eager_and_visual_helpers_lazy(self) -> None:
        config = Path(__file__).resolve().parents[1] / "examples" / "config"
        for profile in ("mobile-spi", "mobile-spi-pill", "mobile-hdmi"):
            with self.subTest(profile=profile):
                daemon = Msysd(config, Path("/tmp/msys-profile-test"), profile)
                expected_mode = "pill" if profile == "mobile-spi-pill" else "buttons"
                self.assertEqual(
                    daemon.profile["env"]["MSYS_NATIVE_NAV_MODE"],
                    expected_mode,
                )
                self.assertFalse(starts_at_profile_boot(
                    daemon, "org.msys.shell.pyside:transitions"
                ))
                self.assertTrue(starts_at_profile_boot(
                    daemon, NATIVE_HAL
                ))
                self.assertFalse(starts_at_profile_boot(daemon, PYTHON_HAL))
                self.assertFalse(starts_at_profile_boot(daemon, INPUT_METHOD))

    def test_all_reference_profiles_keep_lean_roles_routable_but_dormant(self) -> None:
        config = Path(__file__).resolve().parents[1] / "examples" / "config"
        profiles = (
            "desktop-hdmi",
            "desktop-spi",
            "kiosk-spi",
            "mobile-hdmi",
            "mobile-spi-pill",
            "mobile-spi",
        )
        for profile_id in profiles:
            with self.subTest(profile=profile_id):
                daemon = Msysd(config, Path("/tmp/msys-profile-test"), profile_id)
                self.assertTrue(LEAN_ON_DEMAND.isdisjoint(daemon.profile["startup"]))
                for key in LEAN_ON_DEMAND:
                    self.assertEqual(daemon.components[key].lifecycle, "on-demand")
                    self.assertFalse(starts_at_profile_boot(daemon, key), key)
                if profile_id != "kiosk-spi":
                    self.assertEqual(
                        daemon.role_registry.preferred_provider("task-switcher"),
                        TASK_SWITCHER,
                    )

    def test_all_reference_profiles_apply_release_owned_grayscale_fonts(self) -> None:
        config = Path(__file__).resolve().parents[1] / "examples" / "config"
        expected = (
            "/opt/msys/current/msys-x11-session/files/share/"
            "fontconfig/msys-fonts.conf"
        )
        for profile_id in (
            "desktop-hdmi",
            "desktop-spi",
            "kiosk-spi",
            "mobile-hdmi",
            "mobile-spi-pill",
            "mobile-spi",
        ):
            with self.subTest(profile=profile_id):
                daemon = Msysd(config, Path("/tmp/msys-profile-test"), profile_id)
                self.assertEqual(daemon.profile["env"]["FONTCONFIG_FILE"], expected)

    def test_all_profiles_use_one_native_hal_with_lazy_python_fallback(self) -> None:
        config = Path(__file__).resolve().parents[1] / "examples" / "config"
        for profile_id in (
            "desktop-hdmi",
            "desktop-spi",
            "kiosk-spi",
            "mobile-hdmi",
            "mobile-spi-pill",
            "mobile-spi",
        ):
            with self.subTest(profile=profile_id):
                daemon = Msysd(config, Path("/tmp/msys-profile-test"), profile_id)
                self.assertEqual(
                    daemon.profile["roles"]["hal-manager"],
                    [NATIVE_HAL, PYTHON_HAL],
                )
                self.assertEqual(daemon.profile["startup"].count(NATIVE_HAL), 1)
                self.assertNotIn(PYTHON_HAL, daemon.profile["startup"])
                self.assertTrue(starts_at_profile_boot(daemon, NATIVE_HAL))
                self.assertEqual(daemon.components[PYTHON_HAL].lifecycle, "on-demand")
                self.assertFalse(starts_at_profile_boot(daemon, PYTHON_HAL))

    def test_mobile_and_desktop_profiles_use_one_native_resident_shell(self) -> None:
        config = Path(__file__).resolve().parents[1] / "examples" / "config"
        profile_ids = (
            "desktop-hdmi",
            "desktop-spi",
            "mobile-hdmi",
            "mobile-spi-pill",
            "mobile-spi",
        )
        for profile_id in profile_ids:
            with self.subTest(profile=profile_id):
                daemon = Msysd(config, Path("/tmp/msys-profile-test"), profile_id)
                profile = daemon.profile
                self.assertEqual(profile["startup"].count(NATIVE_SHELL), 1)
                self.assertTrue(starts_at_profile_boot(daemon, NATIVE_SHELL))
                for role, pyside_fallback in NATIVE_ROLES.items():
                    candidates = profile["roles"][role]
                    self.assertEqual(candidates[0], NATIVE_SHELL, role)
                    self.assertIn(pyside_fallback, candidates, role)
                    self.assertFalse(
                        starts_at_profile_boot(daemon, pyside_fallback),
                        pyside_fallback,
                    )
                for role, pyside_provider in PYSIDE_UNIMPLEMENTED_ON_DEMAND.items():
                    self.assertEqual(profile["roles"][role][0], pyside_provider)
                    self.assertEqual(daemon.components[pyside_provider].lifecycle, "on-demand")
                    self.assertFalse(starts_at_profile_boot(daemon, pyside_provider))

    def test_pill_profile_keeps_pyside_pill_as_first_dormant_fallback(self) -> None:
        config = Path(__file__).resolve().parents[1] / "examples" / "config"
        daemon = Msysd(config, Path("/tmp/msys-profile-test"), "mobile-spi-pill")
        profile = daemon.profile
        pill = "org.msys.shell.pyside:navigation-pill"
        buttons = "org.msys.shell.pyside:navigation"
        self.assertEqual(profile["roles"]["navigation-bar"][:2], [NATIVE_SHELL, pill])
        self.assertEqual(profile["env"]["MSYS_NATIVE_NAV_MODE"], "pill")
        self.assertIn(NATIVE_SHELL, profile["startup"])
        self.assertNotIn(pill, profile["startup"])
        self.assertNotIn(buttons, profile["startup"])
        self.assertTrue(daemon._is_eager_role_provider(NATIVE_SHELL))
        self.assertFalse(starts_at_profile_boot(daemon, pill))
        self.assertFalse(starts_at_profile_boot(daemon, buttons))

    def test_reference_profiles_start_display_then_independent_window_policy(self) -> None:
        config = Path(__file__).resolve().parents[1] / "examples" / "config"
        profiles = {
            "mobile-spi": DISPLAY_PROVIDER,
            "mobile-spi-pill": DISPLAY_PROVIDER,
            "kiosk-spi": DISPLAY_PROVIDER,
            "desktop-spi": DISPLAY_PROVIDER,
            "mobile-hdmi": HDMI_PROVIDER,
            "desktop-hdmi": HDMI_PROVIDER,
        }
        for profile_id, display_provider in profiles.items():
            with self.subTest(profile=profile_id):
                daemon = Msysd(config, Path("/tmp/msys-profile-test"), profile_id)
                profile = daemon.profile
                startup = profile["startup"]
                self.assertEqual(profile["roles"]["window-policy"], [WINDOW_POLICY])
                self.assertEqual(profile["roles"]["window-manager"], [WINDOW_POLICY])
                self.assertEqual(profile["roles"]["input-method"], [INPUT_METHOD])
                self.assertNotIn(INPUT_METHOD, startup)
                self.assertIn(WINDOW_POLICY, daemon.components)
                self.assertNotIn(LEGACY_WINDOW_POLICY, daemon.components)
                self.assertEqual(
                    daemon.role_registry.preferred_provider("window-policy"),
                    WINDOW_POLICY,
                )
                self.assertEqual(
                    daemon.role_registry.preferred_provider("window-manager"),
                    WINDOW_POLICY,
                )
                policy = daemon.components[WINDOW_POLICY]
                self.assertNotIn("DISPLAY", policy.env)
                self.assertEqual(policy.windowing.get("display"), "inherit")
                self.assertEqual(
                    set(policy.after),
                    {DISPLAY_PROVIDER, HDMI_PROVIDER},
                )
                for component in daemon.components.values():
                    if (
                        component.package_id in {
                            "org.msys.shell.native",
                            "org.msys.shell.pyside",
                        }
                        and component.windowing.get("system") == "x11"
                    ):
                        self.assertNotIn("DISPLAY", component.env, component.key)
                        self.assertEqual(
                            set(component.after),
                            {DISPLAY_PROVIDER, HDMI_PROVIDER},
                            component.key,
                        )
                self.assertNotIn(
                    "DISPLAY",
                    daemon.components["org.msys.demo:demo-app"].env,
                )
                self.assertEqual(startup.count(WINDOW_POLICY), 1)
                self.assertNotIn(LEGACY_WINDOW_POLICY, startup)
                self.assertNotIn("DISPLAY", profile.get("env", {}))
                self.assertEqual(
                    profile["roles"]["display-output"],
                    [display_provider],
                )
                self.assertLess(startup.index(display_provider), startup.index(WINDOW_POLICY))
                visual_clients = [
                    component
                    for component in startup
                    if component.startswith("org.msys.shell.pyside:")
                    or component == NATIVE_SHELL
                    or component == INPUT_METHOD
                    or component == "org.msys.demo:demo-app"
                ]
                self.assertTrue(visual_clients)
                for component in visual_clients:
                    self.assertLess(startup.index(WINDOW_POLICY), startup.index(component))


if __name__ == "__main__":
    unittest.main()
