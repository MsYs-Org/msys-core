from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path

from msys_core.manifest import Component
from msys_core.msysd import Msysd


def component(argv: list[str], package_root: Path | None) -> Component:
    return Component(
        package_id="org.example.exec",
        package_version="1.0.0",
        id="main",
        exec=argv,
        lifecycle="manual",
        manifest_path=(package_root / "manifest.json" if package_root else None),
    )


class PackageExecResolutionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.daemon = object.__new__(Msysd)

    @staticmethod
    def executable(path: Path) -> Path:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
        path.chmod(0o755)
        return path

    def test_safe_package_executable_and_arguments_resolve_inside_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "package"
            root.mkdir()
            worker = self.executable(root / "files/bin/worker")
            config = root / "files/config/settings.json"
            config.parent.mkdir(parents=True)
            config.write_text("{}", encoding="utf-8")

            argv = self.daemon._resolve_exec(component([
                "@package/files/bin/worker",
                "--config",
                "@package/files/config/settings.json",
            ], root))

            self.assertEqual(argv, [
                str(worker.resolve()),
                "--config",
                str(config.resolve()),
            ])

    def test_python_alias_keeps_host_runtime_and_allows_nonexec_script(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "package"
            script = root / "files/app/main.py"
            script.parent.mkdir(parents=True)
            script.write_text("print('ok')\n", encoding="utf-8")
            script.chmod(0o600)

            argv = self.daemon._resolve_exec(component([
                "python",
                "@package/files/app/main.py",
            ], root))

            self.assertEqual(argv, [sys.executable, str(script.resolve())])

    def test_host_and_ordinary_relative_commands_are_unchanged(self) -> None:
        cases = [
            ["bash", "-lc", "true"],
            ["/usr/bin/env", "true"],
            ["../host-tools/worker", "./relative-argument"],
            ["@package-helper", "value"],
        ]
        for original in cases:
            with self.subTest(argv=original):
                self.assertEqual(
                    self.daemon._resolve_exec(component(original, None)),
                    original,
                )

    def test_missing_non_executable_package_argument_remains_supported(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "package"
            root.mkdir()
            argv = self.daemon._resolve_exec(component([
                "python",
                "@package/generated/config.json",
            ], root))
            self.assertEqual(argv[1], str((root / "generated/config.json").resolve()))

    def test_malformed_package_references_are_rejected(self) -> None:
        invalid = [
            "@package",
            "@package/",
            "@package/.",
            "@package/..",
            "@package/./worker",
            "@package/bin/../worker",
            "@package//etc/passwd",
            "@package/bin//worker",
            "@package/bin/worker/",
            "@package/bin\\worker",
        ]
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "package"
            root.mkdir()
            for value in invalid:
                with self.subTest(value=value):
                    with self.assertRaisesRegex(RuntimeError, "@package"):
                        self.daemon._resolve_exec(component(["python", value], root))

    def test_package_reference_requires_manifest_identity(self) -> None:
        with self.assertRaisesRegex(RuntimeError, "without a manifest"):
            self.daemon._resolve_exec(component([
                "python",
                "@package/files/app.py",
            ], None))

    def test_symlinked_parent_cannot_escape_package_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            root = base / "package"
            outside = base / "outside"
            root.mkdir()
            outside.mkdir()
            (outside / "config.json").write_text("{}", encoding="utf-8")
            try:
                (root / "escape").symlink_to(outside, target_is_directory=True)
            except OSError as exc:
                self.skipTest(f"symlinks unavailable: {exc}")

            with self.assertRaisesRegex(RuntimeError, "escapes"):
                self.daemon._resolve_exec(component([
                    "python",
                    "@package/escape/config.json",
                ], root))

    def test_package_argv0_rejects_symlink_even_when_target_is_inside(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "package"
            root.mkdir()
            target = self.executable(root / "bin/real-worker")
            link = root / "bin/worker"
            try:
                link.symlink_to(target.name)
            except OSError as exc:
                self.skipTest(f"symlinks unavailable: {exc}")

            with self.assertRaisesRegex(RuntimeError, "must not be a symlink"):
                self.daemon._resolve_exec(component([
                    "@package/bin/worker",
                ], root))

    def test_package_argv0_must_be_regular_executable_file(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "package"
            root.mkdir()

            directory = root / "bin/directory"
            directory.mkdir(parents=True)
            with self.assertRaisesRegex(RuntimeError, "not a regular file"):
                self.daemon._resolve_exec(component([
                    "@package/bin/directory",
                ], root))

            plain = root / "bin/plain"
            plain.write_text("not executable", encoding="utf-8")
            plain.chmod(0o600)
            with self.assertRaisesRegex(RuntimeError, "not executable"):
                self.daemon._resolve_exec(component([
                    "@package/bin/plain",
                ], root))

            with self.assertRaisesRegex(RuntimeError, "unavailable"):
                self.daemon._resolve_exec(component([
                    "@package/bin/missing",
                ], root))


if __name__ == "__main__":
    unittest.main()
