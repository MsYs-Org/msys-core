from __future__ import annotations

import asyncio
import json
import tempfile
import unittest
from pathlib import Path

from msys_core.manifest import Provide, load_manifest
from msys_core.msysd import Msysd


class ComponentPresentationTests(unittest.TestCase):
    def _daemon(self, root: Path) -> tuple[Msysd, dict[str, object]]:
        manifest = root / "manifest.json"
        manifest.write_text(json.dumps({
            "schema": "msys.manifest.v1",
            "package": {
                "id": "org.example.apps",
                "version": "1.0.0",
                "kind": "application",
                "name": "Example Apps",
                "icons": [{
                    "path": "files/package.ppm",
                    "size": 32,
                    "mime": "image/x-portable-pixmap",
                }],
            },
            "components": [
                {
                    "id": "notes",
                    "name": "Notes",
                    "runtime": "tk",
                    "exec": ["python", "notes.py"],
                    "lifecycle": "manual",
                    "activation": {"launchable": True},
                    "windowing": {"system": "x11", "display": "inherit", "mode": "window"},
                    "icons": [
                        {
                            "path": "files/notes.ppm",
                            "size": 64,
                            "mime": "image/x-portable-pixmap",
                            "untrusted": "discarded",
                        },
                        {"path": "../escape.ppm", "size": 99},
                    ],
                    "package_root": "/attacker-controlled",
                },
                {
                    "id": "fallback",
                    "runtime": "tk",
                    "exec": ["python", "fallback.py"],
                    "lifecycle": "manual",
                    "activation": {"launchable": True},
                    "windowing": {"system": "x11", "display": "inherit", "mode": "window"},
                },
                {
                    "id": "metadata-only",
                    "runtime": "native",
                    "exec": ["worker"],
                    "lifecycle": "background",
                    "activation": {"launchable": False},
                    "icons": [{"path": "files/worker.ppm", "size": 16}],
                },
            ],
        }), encoding="utf-8")
        components = {item.key: item for item in load_manifest(manifest)}
        daemon = object.__new__(Msysd)
        daemon.components = components
        daemon.instances = {}
        daemon.foreground_stack = []
        return daemon, components

    def test_component_icons_override_package_icons_without_core_path_joining(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            daemon, components = self._daemon(root)
            summary = daemon._component_summary(
                "org.example.apps:notes",
                components["org.example.apps:notes"],
            )
            self.assertEqual(summary["package_root"], str(root.resolve()))
            self.assertEqual(summary["icons"], [{
                "path": "files/notes.ppm",
                "size": 64,
                "mime": "image/x-portable-pixmap",
            }])
            self.assertFalse(Path(summary["icons"][0]["path"]).is_absolute())

    def test_package_icons_are_fallback_and_metadata_does_not_make_app_launchable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            daemon, components = self._daemon(Path(temporary))
            fallback = daemon._component_summary(
                "org.example.apps:fallback",
                components["org.example.apps:fallback"],
            )
            self.assertEqual(fallback["icons"][0]["path"], "files/package.ppm")
            metadata = daemon._component_summary(
                "org.example.apps:metadata-only",
                components["org.example.apps:metadata-only"],
            )
            self.assertEqual(metadata["icons"][0]["path"], "files/worker.ppm")
            self.assertFalse(metadata["launchable"])

    def test_unsafe_component_icons_fall_back_to_safe_package_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            daemon, components = self._daemon(Path(temporary))
            component = components["org.example.apps:fallback"]
            component.raw["icons"] = [
                {"path": "/absolute/icon.ppm"},
                {"path": "../../outside.ppm"},
                {"path": "bad\0name.ppm"},
            ]
            summary = daemon._component_summary(component.key, component)
            self.assertEqual(summary["icons"][0]["path"], "files/package.ppm")

    def test_list_apps_exposes_component_icons_and_trusted_package_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            daemon, _components = self._daemon(root)
            response = asyncio.run(daemon._core_call({
                "type": "call",
                "id": 8,
                "method": "list_apps",
                "payload": {},
            }))
            apps = {
                app["id"]: app
                for app in response["payload"]["apps"]
            }
            notes = apps["org.example.apps:notes"]
            self.assertEqual(notes["package_root"], str(root.resolve()))
            self.assertEqual(notes["icons"][0]["path"], "files/notes.ppm")
            self.assertNotIn("org.example.apps:metadata-only", apps)

    def test_builtin_development_fixtures_are_not_launcher_apps(self) -> None:
        config = Path(__file__).resolve().parents[1] / "examples" / "config"
        daemon = Msysd(config, Path("/tmp/msys-presentation-test"), "desktop-spi")
        response = asyncio.run(daemon._core_call({
            "type": "call",
            "id": 9,
            "method": "list_apps",
            "payload": {},
        }))
        app_ids = {app["id"] for app in response["payload"]["apps"]}
        self.assertNotIn("org.msys.demo:demo-app", app_ids)
        self.assertNotIn("org.msys.x11demo:xterm-hold", app_ids)
        self.assertNotIn("org.msys.x11demo:xmessage", app_ids)
        # They remain addressable for explicit start-component diagnostics.
        self.assertIn("org.msys.demo:demo-app", daemon.components)
        self.assertIn("org.msys.x11demo:xterm-hold", daemon.components)

    def test_manual_fullscreen_role_provider_is_not_a_foreground_app(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            daemon, components = self._daemon(Path(temporary))
            ordinary = components["org.example.apps:notes"]
            provider = components["org.example.apps:fallback"]
            provider.windowing["mode"] = "fullscreen"
            provider.provides = [
                Provide(kind="role", name="screen-shield", exclusive=True)
            ]

            self.assertTrue(daemon._is_foreground_app(ordinary))
            self.assertFalse(daemon._is_foreground_app(provider))


if __name__ == "__main__":
    unittest.main()
