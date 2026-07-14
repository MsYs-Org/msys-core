from __future__ import annotations

import importlib.util
from pathlib import Path
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "compile_runtime_plan", ROOT / "scripts" / "compile_runtime_plan.py"
)
assert SPEC is not None and SPEC.loader is not None
compiler = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(compiler)


def component(name: str, *, after: list[str] | None = None) -> dict:
    return {
        "id": name,
        "kind": "display" if name == "display" else "shell",
        "critical": True,
        "restart": "on-failure",
        "readiness": {"mode": "fd", "timeout_ms": 5000},
        "backoff": {"initial_ms": 10, "max_ms": 100, "limit": 3},
        "exec": ["/bin/true", "--name", name],
        "after": after or [],
        "env": {"DISPLAY": ":24"},
    }


def document(components: list[dict] | None = None) -> dict:
    return {
        "schema": compiler.SCHEMA,
        "stop_grace_ms": 500,
        "components": components or [component("display")],
    }


def v2_component(name: str, *, role: str | None = None) -> dict:
    key = f"org.msys.test:{name}"
    provides = [] if role is None else [{"role": role, "exclusive": True, "priority": 50}]
    return {
        "id": key,
        "kind": "shell" if role == "launcher" else "other",
        "critical": True,
        "lifecycle": "background",
        "restart": "on-failure",
        "readiness": {"mode": "mipc-ready", "timeout_ms": 5000},
        "exec": ["/bin/true", name],
        "provides": provides,
        "permissions": ["mipc.call:msys.core"],
        "package": {"id": "org.msys.test", "name": "Test", "version": "1", "kind": "system"},
        "name": name.title(),
        "summary": "native runtime fixture",
        "windowing": {"system": "x11", "display": "inherit", "mode": "window"},
        "launchable": role is None,
    }


def v2_document() -> dict:
    launcher = v2_component("launcher", role="launcher")
    app = v2_component("app")
    app["critical"] = False
    app["lifecycle"] = "manual"
    return {
        "schema": compiler.SCHEMA_V2,
        "stop_grace_ms": 500,
        "profile": {
            "id": "test-profile",
            "display": ":24",
            "roles": {"launcher": [launcher["id"]]},
            "startup": [launcher["id"]],
            "env": {"MSYS_LAYOUT_PROFILE": "mobile"},
        },
        "components": [app, launcher],
    }


class PlanCompilerTests(unittest.TestCase):
    def test_checked_in_example_is_valid(self) -> None:
        example = compiler.load_json(ROOT / "examples" / "native-lite-plan.source.json")
        compiled = compiler.compile_document(example)
        self.assertTrue(compiled.endswith("end\n"))

    def test_mipc_readiness_is_compiled(self) -> None:
        source = document()
        source["components"][0]["readiness"]["mode"] = "mipc-ready"
        compiled = compiler.compile_document(source)
        self.assertIn("\ton-failure\tmipc-ready\t", compiled)

    def test_v2_catalog_profile_and_metadata_are_compiled(self) -> None:
        compiled = compiler.compile_document(v2_document())
        self.assertTrue(compiled.startswith("MSYS_NATIVE_LITE_PLAN\t2\n"))
        self.assertIn("profile\t746573742d70726f66696c65\t3a3234\t1\t1\t1\n", compiled)
        self.assertIn("role\t6c61756e63686572\t1\n", compiled)
        self.assertIn("provider\torg.msys.test:launcher\n", compiled)
        self.assertIn("\tbackground\t0\t1\t1\t0\n", compiled)
        self.assertIn("provide\trole\t6c61756e63686572\t1\t50\n", compiled)
        self.assertIn("permission\t6d6970632e63616c6c3a6d7379732e636f7265\n", compiled)

    def test_v2_rejects_bad_role_preference_and_idle_policy(self) -> None:
        missing = v2_document()
        missing["profile"]["roles"]["launcher"] = ["org.msys.test:missing"]
        with self.assertRaisesRegex(compiler.PlanError, "missing component"):
            compiler.compile_document(missing)
        wrong_role = v2_document()
        wrong_role["profile"]["roles"]["other"] = wrong_role["profile"]["roles"].pop("launcher")
        with self.assertRaisesRegex(compiler.PlanError, "does not provide"):
            compiler.compile_document(wrong_role)
        idle = v2_document()
        idle["components"][0]["lifecycle"] = "on-demand"
        idle["components"][0]["idle_timeout_ms"] = 1
        with self.assertRaisesRegex(compiler.PlanError, "at least 100"):
            compiler.compile_document(idle)

    def test_output_is_stable_topological_and_hex_encoded(self) -> None:
        source = document([component("shell", after=["display"]), component("display")])
        first = compiler.compile_document(source)
        second = compiler.compile_document(source)
        self.assertEqual(first, second)
        self.assertTrue(first.startswith("MSYS_NATIVE_LITE_PLAN\t1\n"))
        self.assertLess(first.index("component\tdisplay"), first.index("component\tshell"))
        self.assertIn("arg\t2f62696e2f74727565", first)
        self.assertNotIn("/bin/true", first)

    def test_rejects_unknown_duplicate_missing_cycle_and_relative_exec(self) -> None:
        cases = []
        unknown = document()
        unknown["unexpected"] = True
        cases.append(unknown)
        cases.append(document([component("same"), component("same")]))
        cases.append(document([component("shell", after=["missing"])]))
        cases.append(document([component("display", after=["shell"]), component("shell", after=["display"])]))
        relative = document()
        relative["components"][0]["exec"][0] = "bin/true"
        cases.append(relative)
        for case in cases:
            with self.subTest(case=case), self.assertRaises(compiler.PlanError):
                compiler.compile_document(case)

    def test_rejects_reserved_environment_and_unbounded_values(self) -> None:
        for key in compiler.RESERVED_ENV:
            reserved = document()
            reserved["components"][0]["env"] = {key: "7"}
            with self.subTest(key=key), self.assertRaisesRegex(compiler.PlanError, "reserved"):
                compiler.compile_document(reserved)
        oversized = document()
        oversized["components"][0]["env"] = {"VALUE": "x" * 4097}
        with self.assertRaises(compiler.PlanError):
            compiler.compile_document(oversized)

    def test_malformed_enum_values_report_plan_errors(self) -> None:
        for field, value in (
            ("kind", []),
            ("restart", {}),
        ):
            malformed = document()
            malformed["components"][0][field] = value
            with self.subTest(field=field), self.assertRaises(compiler.PlanError):
                compiler.compile_document(malformed)

        malformed_mode = document()
        malformed_mode["components"][0]["readiness"]["mode"] = []
        with self.assertRaises(compiler.PlanError):
            compiler.compile_document(malformed_mode)

    def test_source_loader_rejects_duplicate_keys_and_invalid_utf8(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            duplicate = Path(temporary) / "duplicate.json"
            duplicate.write_text('{"schema": 1, "schema": 2}', encoding="utf-8")
            with self.assertRaisesRegex(compiler.PlanError, "duplicate JSON key"):
                compiler.load_json(duplicate)

            invalid_utf8 = Path(temporary) / "invalid-utf8.json"
            invalid_utf8.write_bytes(b"{\xff}")
            with self.assertRaisesRegex(compiler.PlanError, "not UTF-8"):
                compiler.load_json(invalid_utf8)

    def test_atomic_output_is_not_group_or_world_writable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary) / "runtime.plan"
            compiler.write_atomic(target, compiler.compile_document(document()))
            self.assertEqual(target.stat().st_mode & 0o022, 0)


if __name__ == "__main__":
    unittest.main()
