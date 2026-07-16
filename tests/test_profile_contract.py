from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from msys_core.manifest import load_profile
from msys_core.profile_contract import ProfileContractError, validate_profile


def valid_profile() -> dict:
    return {
        "schema": "msys.profile.v1",
        "id": "mobile-test",
        "roles": {
            "launcher": ["org.example.shell:launcher"],
            "window-manager": ["org.example.window:policy"],
        },
        "disabled_roles": ["notification-center"],
        "startup": ["org.example.window:policy", "local-worker"],
        "env": {"DISPLAY": ":24", "EMPTY_VALUE": ""},
        "state_dir": "/opt/msys-state",
        "isolation": {"seccomp_helper": "/opt/msys/bin/seccomp-helper"},
        "settings": {
            "orientation": "portrait",
            "background_apps": True,
            "vendor": {"threshold": 0.75},
        },
        "x-example": {"enabled": True},
    }


class ProfileContractTests(unittest.TestCase):
    def test_all_reference_profiles_route_audio_without_hard_startup_dependency(self) -> None:
        config = Path(__file__).resolve().parents[1] / "examples" / "config"
        audio_manager = "org.msys.audio.bluez:audio-manager"
        for profile_id in (
            "desktop-hdmi",
            "desktop-spi",
            "kiosk-spi",
            "mobile-hdmi",
            "mobile-spi-pill",
            "mobile-spi",
        ):
            with self.subTest(profile_id=profile_id):
                profile = load_profile(config, profile_id)
                self.assertEqual(profile["roles"]["audio-manager"], [audio_manager])
                self.assertNotIn(audio_manager, profile["startup"])

    def test_complete_profile_and_extensions_are_valid(self) -> None:
        profile = valid_profile()
        self.assertIs(validate_profile(profile, expected_id="mobile-test"), profile)

    def test_required_fields_and_schema_are_strict(self) -> None:
        for field in ("schema", "id", "roles", "startup"):
            profile = valid_profile()
            del profile[field]
            with self.subTest(field=field), self.assertRaises(ProfileContractError):
                validate_profile(profile)
        profile = valid_profile()
        profile["schema"] = "msys.profile.v2"
        with self.assertRaisesRegex(ProfileContractError, "msys.profile.v1"):
            validate_profile(profile)

    def test_unknown_fields_require_x_prefix(self) -> None:
        profile = valid_profile()
        profile["typo"] = True
        with self.assertRaisesRegex(ProfileContractError, "unknown field"):
            validate_profile(profile)
        profile = valid_profile()
        profile["isolation"]["helper_typo"] = "helper"
        with self.assertRaisesRegex(ProfileContractError, "unknown field"):
            validate_profile(profile)

    def test_profile_id_is_bounded_and_must_match_requested_name(self) -> None:
        for profile_id in ("../mobile", "Mobile", "mobile_sp", "", "a" * 129):
            profile = valid_profile()
            profile["id"] = profile_id
            with self.subTest(profile_id=profile_id), self.assertRaises(ProfileContractError):
                validate_profile(profile)
        with self.assertRaisesRegex(ProfileContractError, "must match requested"):
            validate_profile(valid_profile(), expected_id="desktop-test")

    def test_role_candidates_startup_and_disabled_items_are_unique(self) -> None:
        cases = []
        role_duplicate = valid_profile()
        role_duplicate["roles"]["launcher"].append("org.example.shell:launcher")
        cases.append(role_duplicate)
        startup_duplicate = valid_profile()
        startup_duplicate["startup"].append("local-worker")
        cases.append(startup_duplicate)
        disabled_duplicate = valid_profile()
        disabled_duplicate["disabled_roles"].append("notification-center")
        cases.append(disabled_duplicate)
        for position, profile in enumerate(cases):
            with self.subTest(position=position), self.assertRaisesRegex(
                ProfileContractError, "duplicate"
            ):
                validate_profile(profile)

    def test_enabled_and_disabled_role_sets_must_be_disjoint(self) -> None:
        profile = valid_profile()
        profile["disabled_roles"].append("launcher")
        with self.assertRaisesRegex(ProfileContractError, "conflict.*launcher"):
            validate_profile(profile)

    def test_component_references_are_syntax_checked_but_not_catalog_checked(self) -> None:
        optional = valid_profile()
        optional["startup"].append("org.not.installed:future-provider")
        validate_profile(optional)
        for location in ("role", "startup"):
            profile = valid_profile()
            if location == "role":
                profile["roles"]["launcher"] = ["bad ref"]
            else:
                profile["startup"] = ["../bad"]
            with self.subTest(location=location), self.assertRaisesRegex(
                ProfileContractError, "invalid format"
            ):
                validate_profile(profile)

    def test_env_state_dir_isolation_and_settings_types_are_checked(self) -> None:
        mutations = (
            lambda profile: profile["env"].update({"BAD-NAME": "x"}),
            lambda profile: profile["env"].update({"VALUE": 3}),
            lambda profile: profile.update({"state_dir": "relative/state"}),
            lambda profile: profile.update({"isolation": "none"}),
            lambda profile: profile.update({"settings": []}),
        )
        for position, mutate in enumerate(mutations):
            profile = valid_profile()
            mutate(profile)
            with self.subTest(position=position), self.assertRaises(ProfileContractError):
                validate_profile(profile)


class ProfileLoadingTests(unittest.TestCase):
    def test_all_reference_runtime_profiles_validate(self) -> None:
        config = Path(__file__).resolve().parents[1] / "examples" / "config"
        for profile_id in (
            "mobile-spi",
            "mobile-spi-pill",
            "kiosk-spi",
            "desktop-spi",
            "mobile-hdmi",
            "desktop-hdmi",
        ):
            with self.subTest(profile_id=profile_id):
                profile = load_profile(config, profile_id)
                self.assertEqual(profile["id"], profile_id)
                expected_hal = ["org.msys.hal.linux:native-manager"]
                if profile_id != "mobile-spi":
                    expected_hal.append("org.msys.hal.linux:manager")
                self.assertEqual(profile["roles"]["hal-manager"], expected_hal)
                self.assertIn("org.msys.hal.linux:native-manager", profile["startup"])
                self.assertNotIn("org.msys.hal.linux:manager", profile["startup"])

    def test_interactive_profiles_select_native_shell_without_changing_kiosk(self) -> None:
        config = Path(__file__).resolve().parents[1] / "examples" / "config"
        native = "org.msys.shell.native:desktop-shell"
        native_roles = (
            "launcher",
            "system-chrome",
            "navigation-bar",
            "task-switcher",
            "notification-presenter",
            "notification-center",
        )
        for profile_id in (
            "mobile-spi",
            "mobile-spi-pill",
            "mobile-hdmi",
            "desktop-spi",
            "desktop-hdmi",
        ):
            with self.subTest(profile_id=profile_id):
                profile = load_profile(config, profile_id)
                self.assertEqual(profile["startup"].count(native), 1)
                for role in native_roles:
                    self.assertEqual(profile["roles"][role][0], native)
                    if profile_id == "mobile-spi":
                        self.assertEqual(profile["roles"][role], [native])

        kiosk = load_profile(config, "kiosk-spi")
        self.assertNotIn(native, kiosk["startup"])
        for role in native_roles:
            self.assertIn(role, kiosk["disabled_roles"])

    def test_loader_rejects_path_traversal_before_file_access(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(ProfileContractError):
                load_profile(Path(temporary), "../outside")

    def test_loader_rejects_filename_identity_mismatch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary)
            profiles = config / "profiles"
            profiles.mkdir()
            profile = valid_profile()
            profile["id"] = "different"
            (profiles / "requested.json").write_text(json.dumps(profile), encoding="utf-8")
            with self.assertRaisesRegex(ProfileContractError, "must match requested"):
                load_profile(config, "requested")

    def test_loader_rejects_duplicate_json_fields_and_nonfinite_numbers(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            config = Path(temporary)
            profiles = config / "profiles"
            profiles.mkdir()
            (profiles / "duplicate.json").write_text(
                '{"schema":"msys.profile.v1","id":"duplicate",'
                '"roles":{},"roles":{},"startup":[]}',
                encoding="utf-8",
            )
            with self.assertRaisesRegex(ProfileContractError, "duplicate JSON"):
                load_profile(config, "duplicate")
            profile = valid_profile()
            profile["id"] = "nonfinite"
            (profiles / "nonfinite.json").write_text(
                json.dumps(profile).replace("0.75", "NaN"), encoding="utf-8"
            )
            with self.assertRaisesRegex(ProfileContractError, "non-finite"):
                load_profile(config, "nonfinite")


if __name__ == "__main__":
    unittest.main()
