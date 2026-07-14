from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from msys_core.manifest import Component
from msys_core.msysd import Msysd


def component(*, env: dict[str, str] | None = None) -> Component:
    return Component(
        package_id="org.example.localized",
        package_version="1.0.0",
        id="main",
        exec=["unused"],
        lifecycle="manual",
        env=env or {},
    )


def daemon_with_profile(env: dict[str, str] | None = None) -> Msysd:
    daemon = object.__new__(Msysd)
    daemon.profile = {"env": env or {}}
    return daemon


class ComponentLocaleEnvironmentTests(unittest.TestCase):
    def test_isolated_application_keeps_locale_categories_and_gets_sdk_locale(self) -> None:
        daemon = daemon_with_profile()
        app = component(env={
            "MSYS_LOCALE": "en-US",
            "LANG": "en_US.UTF-8",
            "LC_CTYPE": "C",
        })
        with mock.patch.dict(os.environ, {
            "LANG": "zh_CN.UTF-8",
            "LC_CTYPE": "zh_CN.UTF-8",
            "LC_TIME": "zh_CN.UTF-8",
        }, clear=True):
            env = daemon._component_environment(app)

        # The application manifest cannot split the visual session into a
        # different language.  The Core-owned inherited categories survive.
        self.assertEqual(env["MSYS_LOCALE"], "zh-CN")
        self.assertEqual(env["LANG"], "zh_CN.UTF-8")
        self.assertEqual(env["LC_CTYPE"], "zh_CN.UTF-8")
        self.assertEqual(env["LC_TIME"], "zh_CN.UTF-8")

        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            daemon.state_dir = root / "state"
            daemon.runtime_dir = root / "runtime"
            daemon.builtin_components = {}
            daemon._apply_component_isolation(env, app)

        # Private HOME/XDG/Python setup must not regress locale propagation.
        self.assertEqual(env["MSYS_LOCALE"], "zh-CN")
        self.assertEqual(env["LANG"], "zh_CN.UTF-8")
        self.assertEqual(env["LC_CTYPE"], "zh_CN.UTF-8")

    def test_profile_locale_is_the_session_preference_and_beats_a_manifest(self) -> None:
        daemon = daemon_with_profile({
            "MSYS_LOCALE": "zh_Hans_CN",
            "LANG": "en_US.UTF-8",
            "LC_MESSAGES": "en_US.UTF-8",
        })
        app = component(env={
            "MSYS_LOCALE": "en-US",
            "LANG": "en_GB.UTF-8",
            "LC_MESSAGES": "en_GB.UTF-8",
            "LC_NUMERIC": "C",
        })
        with mock.patch.dict(os.environ, {
            "LANG": "en_US.UTF-8",
            "LC_NUMERIC": "zh_CN.UTF-8",
        }, clear=True):
            env = daemon._component_environment(app)

        self.assertEqual(env["MSYS_LOCALE"], "zh-Hans-CN")
        self.assertEqual(env["LANG"], "en_US.UTF-8")
        self.assertEqual(env["LC_MESSAGES"], "en_US.UTF-8")
        self.assertEqual(env["LC_NUMERIC"], "zh_CN.UTF-8")

    def test_c_locale_keeps_documented_precedence_without_fabricating_a_locale(self) -> None:
        daemon = daemon_with_profile()
        with mock.patch.dict(os.environ, {
            "LC_ALL": "C",
            "LANG": "zh_CN.UTF-8",
        }, clear=True):
            env = daemon._component_environment(component())

        self.assertEqual(env["LC_ALL"], "C")
        self.assertEqual(env["LANG"], "zh_CN.UTF-8")
        self.assertNotIn("MSYS_LOCALE", env)


if __name__ == "__main__":
    unittest.main()
