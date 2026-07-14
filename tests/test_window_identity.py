from __future__ import annotations

import types
import unittest

from msys_core.manifest import Component
from msys_core.msysd import Msysd


class ForegroundIdentityTests(unittest.TestCase):
    def test_foreground_entries_expose_manifest_identity_not_title(self) -> None:
        daemon = object.__new__(Msysd)
        component = Component(
            package_id="org.example.viewer",
            package_version="1.0.0",
            id="main",
            exec=["viewer"],
            lifecycle="manual",
            raw={"name": "Localized Viewer"},
            windowing={
                "title": "Presentation title",
                "identity": {
                    "app_id": "org.example.viewer",
                    "x11_wm_class": "OrgExampleViewer",
                },
            },
        )
        process = types.SimpleNamespace(poll=lambda: None)
        daemon.instances = {
            component.key: types.SimpleNamespace(
                component=component,
                process=process,
                state="ready",
            )
        }
        daemon.foreground_stack = [component.key]

        self.assertEqual(
            daemon._foreground_entries(),
            [
                {
                    "component": component.key,
                    "title": "Localized Viewer",
                    "identity": "OrgExampleViewer",
                    "state": "ready",
                }
            ],
        )


if __name__ == "__main__":
    unittest.main()
