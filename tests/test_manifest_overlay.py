from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from msys_core.manifest import (
    Component,
    load_manifest,
    load_manifest_paths,
    replace_package_components,
)
from msys_core.msysd import parse_args


def component(package: str, identifier: str, version: str = "1.0.0") -> Component:
    return Component(
        package_id=package,
        package_version=version,
        id=identifier,
        exec=["true"],
        lifecycle="manual",
    )


class PackageOverlayTests(unittest.TestCase):
    def test_native_hal_fallback_uses_the_safe_development_executable(self) -> None:
        root = Path(__file__).resolve().parents[1]
        path = root / "examples" / "config" / "manifests" / "msys-hal.json"
        components = {component.id: component for component in load_manifest(path)}

        native = components["native-manager"]
        python = components["manager"]
        self.assertEqual(
            native.exec,
            ["/opt/msys-dev/msys-hal/files/bin/msys-hal-native"],
        )
        self.assertEqual(native.lifecycle, "background")
        self.assertEqual(python.lifecycle, "on-demand")
        self.assertEqual(
            [provide.name for provide in native.provides if provide.kind == "role"],
            ["hal-manager"],
        )
        self.assertEqual(
            [provide.name for provide in python.provides if provide.kind == "role"],
            ["hal-manager"],
        )

    def test_native_shell_fallback_uses_the_safe_development_executable(self) -> None:
        root = Path(__file__).resolve().parents[1]
        path = root / "examples" / "config" / "manifests" / "shell-native.json"
        document = json.loads(path.read_text(encoding="utf-8-sig"))
        loaded = load_manifest(path)

        self.assertEqual(document["package"]["id"], "org.msys.shell.native")
        self.assertEqual(len(loaded), 1)
        component = loaded[0]
        self.assertEqual(component.key, "org.msys.shell.native:desktop-shell")
        self.assertEqual(
            component.exec,
            ["/opt/msys-dev/msys-shell-native/bin/msys-shell-native"],
        )
        self.assertEqual(component.lifecycle, "background")
        self.assertEqual(component.readiness_mode, "mipc-ready")
        self.assertEqual(
            {provide.name for provide in component.provides if provide.kind == "role"},
            {
                "launcher",
                "system-chrome",
                "navigation-bar",
                "task-switcher",
                "notification-presenter",
                "notification-center",
            },
        )

    def test_x11_fallbacks_keep_versioned_role_contract_claims(self) -> None:
        root = Path(__file__).resolve().parents[1]
        manifests = root / "examples" / "config" / "manifests"
        x11 = json.loads((manifests / "x11-session.json").read_text(encoding="utf-8-sig"))
        legacy = json.loads(
            (manifests / "openstick-ch347-x11.json").read_text(encoding="utf-8-sig")
        )
        components = {component["id"]: component for component in x11["components"]}
        policy = components["window-policy"]
        hdmi = components["hdmi-output"]
        window_manager = next(
            item for item in policy["provides"] if item.get("role") == "window-manager"
        )
        display_outputs = [
            next(item for item in component["provides"] if item.get("role") == "display-output")
            for component in (hdmi, legacy["components"][0])
        ]
        self.assertEqual(
            window_manager["x-msys-contract"],
            {"id": "org.msys.role.window-manager.v1", "version": "1.0.0"},
        )
        for provide in display_outputs:
            self.assertEqual(
                provide["x-msys-contract"],
                {"id": "org.msys.role.display-output.v1", "version": "1.0.0"},
            )

    def test_core_install_fallback_is_a_complete_compatibility_snapshot(self) -> None:
        root = Path(__file__).resolve().parents[1]
        path = root / "examples" / "config" / "manifests" / "core-install.json"
        document = json.loads(path.read_text(encoding="utf-8-sig"))
        loaded = {component.id: component for component in load_manifest(path)}

        self.assertEqual(document["package"]["id"], "org.msys.core.install")
        self.assertEqual(document["package"]["version"], "0.1.10")
        self.assertEqual(set(loaded), {"install-agent", "update-agent"})
        for identifier, role in (
            ("install-agent", "install-agent"),
            ("update-agent", "update-agent"),
        ):
            component = loaded[identifier]
            self.assertEqual(component.lifecycle, "on-demand")
            self.assertEqual(component.idle_timeout_ms, 30000)
            self.assertEqual(component.restart, "on-failure")
            self.assertEqual(component.readiness_mode, "mipc-ready")
            self.assertEqual(component.isolation.profile, "baseline")
            self.assertEqual(
                [(item.kind, item.name, item.exclusive, item.priority) for item in component.provides],
                [("role", role, True, 100)],
            )
            self.assertIn("mipc.call:msys.core", component.permissions)

    def test_replacement_removes_components_deleted_by_new_package(self) -> None:
        old_main = component("org.example.app", "main")
        old_helper = component("org.example.app", "obsolete-helper")
        unrelated = component("org.example.other", "main")
        new_main = component("org.example.app", "main", "2.0.0")

        result = replace_package_components(
            {item.key: item for item in (old_main, old_helper, unrelated)},
            {new_main.key: new_main},
        )

        self.assertIs(result[new_main.key], new_main)
        self.assertNotIn(old_helper.key, result)
        self.assertIs(result[unrelated.key], unrelated)

    def test_explicit_manifest_is_exact_and_keeps_source_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "manifest.json"
            path.write_text(json.dumps({
                "schema": "msys.manifest.v1",
                "package": {
                    "id": "org.example.canonical",
                    "version": "1.0.0",
                    "kind": "system",
                },
                "components": [{
                    "id": "worker",
                    "exec": ["worker"],
                    "lifecycle": "background",
                }],
            }), encoding="utf-8")

            loaded = load_manifest_paths((path, path))

            selected = loaded["org.example.canonical:worker"]
            self.assertEqual(selected.manifest_path, path.resolve())

    def test_two_canonical_files_cannot_define_same_component(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            paths = []
            document = {
                "schema": "msys.manifest.v1",
                "package": {
                    "id": "org.example.duplicate",
                    "version": "1.0.0",
                    "kind": "system",
                },
                "components": [{"id": "worker", "exec": ["true"]}],
            }
            for name in ("one.json", "two.json"):
                path = Path(temporary) / name
                path.write_text(json.dumps(document), encoding="utf-8")
                paths.append(path)
            with self.assertRaisesRegex(ValueError, "duplicate canonical component"):
                load_manifest_paths(paths)

    def test_local_dependency_references_are_normalized_to_global_ids(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "manifest.json"
            path.write_text(json.dumps({
                "schema": "msys.manifest.v1",
                "package": {"id": "org.example.refs", "version": "1.0.0"},
                "components": [
                    {"id": "base", "exec": ["true"], "lifecycle": "manual"},
                    {
                        "id": "app",
                        "exec": ["true"],
                        "lifecycle": "manual",
                        "requires": ["base", "org.example.other:provider"],
                        "after": ["base"],
                    },
                ],
            }), encoding="utf-8")
            loaded = load_manifest_paths((path,))
            app = loaded["org.example.refs:app"]
            self.assertEqual(
                app.requires,
                ["org.example.refs:base", "org.example.other:provider"],
            )
            self.assertEqual(app.after, ["org.example.refs:base"])

    def test_cli_accepts_repeated_canonical_manifests(self) -> None:
        args = parse_args([
            "--config", "config",
            "--runtime-dir", "run",
            "--profile", "mobile",
            "--manifest", "shell/manifest.json",
            "--manifest", "hal/manifest.json",
        ])
        self.assertEqual(args.manifest, ["shell/manifest.json", "hal/manifest.json"])


if __name__ == "__main__":
    unittest.main()
