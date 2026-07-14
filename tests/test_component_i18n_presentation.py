from __future__ import annotations

import asyncio
import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from msys_core.manifest import load_manifest
from msys_core.msysd import Msysd
from msys_core.presentation_i18n import PresentationCatalog


def catalog_document(messages: dict[str, dict[str, str]]) -> dict[str, object]:
    return {
        "schema": "msys.i18n.catalog.v1",
        "id": "org.example.presentation",
        "default_locale": "en-US",
        "messages": messages,
    }


class ComponentI18nPresentationTests(unittest.TestCase):
    def _daemon(
        self,
        root: Path,
        *,
        package_i18n: object,
        component_i18n: object = None,
        component_i18n_present: bool = False,
    ) -> tuple[Msysd, str]:
        package: dict[str, object] = {
            "id": "org.example.localized",
            "version": "1.0.0",
            "kind": "application",
            "name": "Static package name",
            "summary": "Static package summary",
            "x-msys-i18n": package_i18n,
        }
        component: dict[str, object] = {
            "id": "main",
            "name": "Static component name",
            "summary": "Static component summary",
            "runtime": "native",
            "exec": ["unused"],
            "lifecycle": "manual",
            "activation": {"launchable": True},
            "windowing": {"system": "x11", "mode": "window"},
        }
        if component_i18n_present:
            component["x-msys-i18n"] = component_i18n
        manifest = root / "manifest.json"
        manifest.write_text(
            json.dumps({
                "schema": "msys.manifest.v1",
                "package": package,
                "components": [component],
            }, ensure_ascii=False),
            encoding="utf-8",
        )
        loaded = load_manifest(manifest)[0]
        daemon = object.__new__(Msysd)
        daemon.components = {loaded.key: loaded}
        daemon.instances = {}
        daemon.foreground_stack = []
        daemon.profile = {"env": {}}
        return daemon, loaded.key

    @staticmethod
    def _write_catalog(root: Path, document: object) -> Path:
        path = root / "files" / "share" / "catalog.json"
        path.parent.mkdir(parents=True)
        path.write_text(json.dumps(document, ensure_ascii=False), encoding="utf-8")
        return path

    @staticmethod
    def _list_app(daemon: Msysd) -> dict[str, object]:
        response = asyncio.run(daemon._core_call({
            "type": "call",
            "id": 1,
            "method": "list_apps",
            "payload": {},
        }))
        return response["payload"]["apps"][0]

    def test_posix_zh_cn_locale_localizes_list_apps_name_and_summary(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            declaration = {
                "catalog": "files/share/catalog.json",
                "name_key": "package.name",
                "summary_key": "package.summary",
            }
            daemon, _key = self._daemon(root, package_i18n=declaration)
            self._write_catalog(root, catalog_document({
                "en-US": {
                    "package.name": "English name",
                    "package.summary": "English summary",
                },
                "zh-CN": {
                    "package.name": "设置",
                    "package.summary": "设备与系统设置",
                },
            }))
            daemon.profile = {"env": {"LANG": "zh_CN.UTF-8"}}
            with mock.patch.dict(os.environ, {}, clear=True):
                app = self._list_app(daemon)
            self.assertEqual(app["name"], "设置")
            self.assertEqual(app["summary"], "设备与系统设置")

    def test_zh_hans_cn_uses_locale_first_partial_parent_overlays(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            declaration = {
                "catalog": "files/share/catalog.json",
                "name_key": "app.name",
                "summary_key": "app.summary",
            }
            daemon, _key = self._daemon(
                root,
                package_i18n={
                    "catalog": "files/share/catalog.json",
                    "name_key": "package.name",
                },
                component_i18n=declaration,
                component_i18n_present=True,
            )
            self._write_catalog(root, catalog_document({
                "en-US": {"app.name": "App", "app.summary": "Summary"},
                "zh": {"app.summary": "中文摘要"},
                "zh-Hans": {"app.summary": "简体摘要"},
                "zh-Hans-CN": {"app.name": "中国区应用"},
            }))
            daemon.profile = {"env": {"MSYS_LOCALE": "zh-Hans-CN"}}
            with mock.patch.dict(os.environ, {}, clear=True):
                app = self._list_app(daemon)
            self.assertEqual(app["name"], "中国区应用")
            self.assertEqual(app["summary"], "简体摘要")

    def test_component_declaration_overrides_package_declaration(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            daemon, _key = self._daemon(
                root,
                package_i18n={
                    "catalog": "files/share/catalog.json",
                    "name_key": "package.name",
                    "summary_key": "package.summary",
                },
                component_i18n={
                    "catalog": "files/share/catalog.json",
                    "name_key": "component.name",
                    "summary_key": "component.summary",
                },
                component_i18n_present=True,
            )
            self._write_catalog(root, catalog_document({
                "en-US": {
                    "package.name": "Wrong package name",
                    "package.summary": "Wrong package summary",
                    "component.name": "Component name",
                    "component.summary": "Component summary",
                },
            }))
            with mock.patch.dict(os.environ, {"LANG": "en_GB.UTF-8"}, clear=True):
                app = self._list_app(daemon)
            self.assertEqual(app["name"], "Component name")
            self.assertEqual(app["summary"], "Component summary")

    def test_catalog_path_escape_falls_back_to_manifest_text(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "package"
            root.mkdir()
            outside = root.parent / "outside.json"
            outside.write_text(json.dumps(catalog_document({
                "en-US": {"app.name": "Escaped"},
            })), encoding="utf-8")
            daemon, _key = self._daemon(root, package_i18n={
                "catalog": "../outside.json",
                "name_key": "app.name",
            })
            app = self._list_app(daemon)
            self.assertEqual(app["name"], "Static component name")
            self.assertEqual(app["summary"], "Static component summary")

    def test_catalog_symlink_cannot_escape_package_root(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            root = parent / "package"
            root.mkdir()
            outside = parent / "outside.json"
            outside.write_text(json.dumps(catalog_document({
                "en-US": {"app.name": "Escaped through symlink"},
            })), encoding="utf-8")
            link = root / "files" / "share" / "catalog.json"
            link.parent.mkdir(parents=True)
            try:
                link.symlink_to(outside)
            except OSError as exc:
                self.skipTest(f"symlinks unavailable: {exc}")
            daemon, _key = self._daemon(root, package_i18n={
                "catalog": "files/share/catalog.json",
                "name_key": "app.name",
            })
            app = self._list_app(daemon)
            self.assertEqual(app["name"], "Static component name")

    def test_bad_catalog_and_missing_key_fall_back_without_crashing(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            daemon, _key = self._daemon(root, package_i18n={
                "catalog": "files/share/catalog.json",
                "name_key": "missing.name",
                "summary_key": "missing.summary",
            })
            path = root / "files" / "share" / "catalog.json"
            path.parent.mkdir(parents=True)
            path.write_bytes(b"\xffnot utf-8")
            with mock.patch.dict(os.environ, {"LANG": "ja_JP.UTF-8"}, clear=True):
                app = self._list_app(daemon)
            self.assertEqual(app["name"], "Static component name")
            self.assertEqual(app["summary"], "Static component summary")

    def test_catalog_success_and_failure_are_cached(self) -> None:
        for valid in (True, False):
            with self.subTest(valid=valid), tempfile.TemporaryDirectory() as temporary:
                root = Path(temporary)
                daemon, _key = self._daemon(root, package_i18n={
                    "catalog": "files/share/catalog.json",
                    "name_key": "app.name",
                })
                path = root / "files" / "share" / "catalog.json"
                path.parent.mkdir(parents=True)
                if valid:
                    path.write_text(json.dumps(catalog_document({
                        "en-US": {"app.name": "Cached name"},
                    })), encoding="utf-8")
                else:
                    path.write_text("not json", encoding="utf-8")
                original = PresentationCatalog.load
                with mock.patch.object(
                    PresentationCatalog,
                    "load",
                    wraps=original,
                ) as load:
                    self._list_app(daemon)
                    self._list_app(daemon)
                self.assertEqual(load.call_count, 1)


if __name__ == "__main__":
    unittest.main()
