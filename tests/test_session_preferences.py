from __future__ import annotations

import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from msys_core.msysd import (
    Msysd,
    SESSION_PREFERENCES_SCHEMA,
    SESSION_PREFERENCES_TOPIC,
)


class SessionPreferenceStorageTests(unittest.TestCase):
    def daemon(self, root: Path) -> Msysd:
        daemon = object.__new__(Msysd)
        daemon.state_dir = root
        daemon.profile = {"env": {"LANG": "zh_CN.UTF-8"}}
        daemon.session_language = "system"
        return daemon

    def test_language_is_persisted_atomically_and_loaded(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            daemon = self.daemon(root)
            daemon.session_language = "en-US"
            daemon._persist_session_preferences()

            document = json.loads(
                (root / "preferences/session.json").read_text(encoding="utf-8")
            )
            self.assertEqual(document, {
                "schema": SESSION_PREFERENCES_SCHEMA,
                "language": "en-US",
            })
            self.assertEqual(list((root / "preferences").glob("*.tmp-*")), [])

            loaded = self.daemon(root)
            loaded._load_session_preferences()
            self.assertEqual(loaded.session_language, "en-US")

    def test_only_system_or_canonical_locale_is_accepted(self) -> None:
        self.assertEqual(Msysd._validate_session_language("system"), "system")
        self.assertEqual(Msysd._validate_session_language("zh-CN"), "zh-CN")
        for value in ("zh_CN.UTF-8", "C", "../en-US", "en-us"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                Msysd._validate_session_language(value)

    def test_selected_language_overrides_manifest_without_losing_posix_categories(self) -> None:
        daemon = self.daemon(Path("/state"))
        daemon.session_language = "en-US"
        component = SimpleNamespace(env={"LANG": "ja_JP.UTF-8", "MSYS_LOCALE": "ja-JP"})
        with (
            mock.patch.dict("os.environ", {"LANG": "C.UTF-8"}, clear=True),
            mock.patch.object(daemon, "_session_display", return_value=":24"),
        ):
            environment = daemon._component_environment(component)
        self.assertEqual(environment["MSYS_LOCALE"], "en-US")
        self.assertEqual(environment["LANG"], "zh_CN.UTF-8")
        self.assertEqual(environment["DISPLAY"], ":24")


class SessionPreferenceRpcTests(unittest.IsolatedAsyncioTestCase):
    async def test_set_broadcasts_and_updates_component_presentation_locale(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            daemon = object.__new__(Msysd)
            daemon.state_dir = Path(directory)
            daemon.profile = {"env": {"LANG": "zh_CN.UTF-8"}}
            daemon.session_language = "system"
            daemon._presentation_locale_value = "zh-CN"
            daemon.broadcast = mock.AsyncMock()

            response = await daemon._core_call({
                "type": "call",
                "id": 7,
                "method": "set_session_preferences",
                "payload": {"language": "en-US"},
            }, source="org.msys.settings:main")

            self.assertEqual(response["type"], "return")
            self.assertEqual(response["payload"]["language"], "en-US")
            self.assertTrue(response["payload"]["changed"])
            self.assertNotIn("_presentation_locale_value", daemon.__dict__)
            self.assertEqual(daemon._presentation_locale(), "en-US")
            daemon.broadcast.assert_awaited_once_with(
                SESSION_PREFERENCES_TOPIC,
                response["payload"],
                source="org.msys.settings:main",
            )

    async def test_invalid_update_does_not_write_or_broadcast(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            daemon = object.__new__(Msysd)
            daemon.state_dir = Path(directory)
            daemon.profile = {"env": {}}
            daemon.session_language = "system"
            daemon.broadcast = mock.AsyncMock()

            response = await daemon._core_call({
                "type": "call",
                "id": 8,
                "method": "set_session_preferences",
                "payload": {"language": "zh_CN.UTF-8"},
            })

            self.assertEqual(response["type"], "error")
            self.assertEqual(response["code"], "BAD_LANGUAGE")
            self.assertFalse((daemon._session_preferences_path).exists())
            daemon.broadcast.assert_not_awaited()


if __name__ == "__main__":
    unittest.main()
