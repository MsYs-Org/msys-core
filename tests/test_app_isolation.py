from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from msys_core.manifest import Component
from msys_core.msysd import Msysd


def make_component(package: str = "org.example.viewer") -> Component:
    return Component(
        package_id=package,
        package_version="1.0.0",
        id="main",
        exec=["files/app"],
        lifecycle="manual",
    )


class InstalledAppIsolationTests(unittest.TestCase):
    def test_installed_package_gets_private_state_and_clean_python_environment(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            daemon = object.__new__(Msysd)
            daemon.state_dir = root / "state"
            daemon.runtime_dir = root / "runtime"
            daemon.builtin_components = {}
            app = make_component()
            env = {
                "HOME": "/root",
                "PYTHONPATH": "/opt/msys-dev/msys-core:/host/site-packages",
                "VIRTUAL_ENV": "/host/venv",
                "DISPLAY": ":24",
            }

            daemon._apply_component_isolation(env, app)

            self.assertNotIn("PYTHONPATH", env)
            self.assertNotIn("VIRTUAL_ENV", env)
            self.assertEqual(env["PYTHONNOUSERSITE"], "1")
            self.assertEqual(env["PYTHONDONTWRITEBYTECODE"], "1")
            self.assertEqual(env["DISPLAY"], ":24")
            self.assertTrue(Path(env["HOME"]).is_dir())
            self.assertTrue(Path(env["XDG_CONFIG_HOME"]).is_dir())
            self.assertTrue(Path(env["XDG_RUNTIME_DIR"]).is_dir())
            self.assertTrue(Path(env["TMPDIR"]).is_dir())
            self.assertTrue(str(Path(env["HOME"])).startswith(str(daemon.state_dir)))

    def test_builtin_provider_keeps_shared_msys_development_runtime(self) -> None:
        daemon = object.__new__(Msysd)
        built_in = make_component("org.msys.shell")
        daemon.builtin_components = {built_in.key: built_in}
        env = {"HOME": "/root", "PYTHONPATH": "/opt/msys-dev/msys-sdk"}

        daemon._apply_component_isolation(env, built_in)

        self.assertEqual(env["HOME"], "/root")
        self.assertEqual(env["PYTHONPATH"], "/opt/msys-dev/msys-sdk")

    def test_installed_system_package_receives_only_platform_sdk_path(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            sdk = root / "release" / "msys-sdk"
            (sdk / "msys_sdk").mkdir(parents=True)
            (sdk / "msys_sdk" / "__init__.py").write_text("", encoding="utf-8")
            daemon = object.__new__(Msysd)
            daemon.state_dir = root / "state"
            daemon.runtime_dir = root / "runtime"
            daemon.builtin_components = {}
            system = make_component("org.msys.shell")
            system.package_kind = "system"
            env = {
                "HOME": "/root",
                "PYTHONPATH": "/manifest/cannot-override",
                "MSYS_PLATFORM_PYTHONPATH": "/manifest/cannot-override",
            }

            with patch.dict(
                "os.environ",
                {
                    "PYTHONPATH": str(sdk),
                    "MSYS_PLATFORM_PYTHONPATH": str(sdk),
                },
                clear=True,
            ):
                daemon._apply_component_isolation(env, system)

            self.assertEqual(env["PYTHONPATH"], str(sdk.resolve()))
            self.assertEqual(env["MSYS_PLATFORM_PYTHONPATH"], str(sdk.resolve()))
            self.assertNotIn("/manifest/cannot-override", env["PYTHONPATH"])
            self.assertTrue(str(Path(env["HOME"])).startswith(str(daemon.state_dir)))

    def test_application_cannot_request_platform_pythonpath(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            daemon = object.__new__(Msysd)
            daemon.state_dir = root / "state"
            daemon.runtime_dir = root / "runtime"
            daemon.builtin_components = {}
            app = make_component()
            env = {
                "PYTHONPATH": "/manifest/path",
                "MSYS_PLATFORM_PYTHONPATH": "/manifest/path",
            }

            daemon._apply_component_isolation(env, app)

            self.assertNotIn("PYTHONPATH", env)
            self.assertNotIn("MSYS_PLATFORM_PYTHONPATH", env)


if __name__ == "__main__":
    unittest.main()
