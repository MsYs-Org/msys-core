from __future__ import annotations

import asyncio
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from msys_core.isolation import (
    BEST_EFFORT,
    FAIL_CLOSED,
    NAMESPACE_ORDER,
    RLIMIT_RESOURCES,
    IsolationCapabilities,
    IsolationConfigurationError,
    IsolationPreexec,
    IsolationUnavailable,
    PartialIsolationError,
    detect_capabilities,
    parse_isolation,
    prepare_isolation_launch,
)
from msys_core.manifest import load_manifest
from msys_core.msysd import Msysd


def capabilities(
    *,
    linux: bool = True,
    prctl: bool = True,
    unshare: bool = True,
    namespaces: frozenset[str] = frozenset(NAMESPACE_ORDER),
    rlimits: frozenset[str] = frozenset(RLIMIT_RESOURCES),
    helper: str | None = None,
) -> IsolationCapabilities:
    return IsolationCapabilities(linux, prctl, unshare, namespaces, rlimits, helper)


class IsolationManifestTests(unittest.TestCase):
    def test_absent_declaration_preserves_compatibility(self) -> None:
        spec = parse_isolation(None)
        self.assertEqual(spec.profile, "none")
        self.assertEqual(spec.failure, BEST_EFFORT)
        self.assertFalse(spec.requested)
        plan = prepare_isolation_launch(spec, ["app"], capabilities=capabilities())
        self.assertEqual(plan.argv, ["app"])
        self.assertIsNone(plan.preexec_fn)

    def test_baseline_and_custom_profiles_are_typed(self) -> None:
        baseline = parse_isolation("baseline")
        custom = parse_isolation({
            "profile": "custom",
            "failure": "best-effort",
            "namespaces": ["mount", "ipc", "mount"],
            "no_new_privs": True,
            "dumpable": False,
            "rlimits": {
                "core": 0,
                "nofile": {"soft": 64, "hard": 128},
            },
            "seccomp": {"mode": "helper", "profile": "desktop-v1"},
        })
        self.assertEqual(baseline.failure, FAIL_CLOSED)
        self.assertTrue(baseline.no_new_privs)
        self.assertEqual(baseline.rlimits["core"].hard, 0)
        self.assertEqual(custom.namespaces, ("mount", "ipc"))
        self.assertEqual(custom.rlimits["nofile"].soft, 64)
        self.assertEqual(custom.rlimits["nofile"].hard, 128)
        self.assertEqual(custom.seccomp.profile, "desktop-v1")

    def test_unsafe_or_unimplemented_declarations_are_rejected(self) -> None:
        cases = [
            {"profile": "missing"},
            {"profile": "custom", "namespaces": ["pid"]},
            {"profile": "custom", "failure": "sometimes"},
            {"profile": "custom", "rlimits": {"nofile": {"soft": 10, "hard": 5}}},
            {"profile": "custom", "no_new_privs": False, "seccomp": "helper"},
            {"profile": "custom", "unknown": True},
        ]
        for raw in cases:
            with self.subTest(raw=raw), self.assertRaises(IsolationConfigurationError):
                parse_isolation(raw)

    def test_manifest_accepts_first_class_and_extension_spelling(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for index, field in enumerate(("isolation", "x-msys-isolation")):
                path = root / f"manifest-{index}.json"
                path.write_text(json.dumps({
                    "schema": "msys.manifest.v1",
                    "package": {"id": f"org.example.app{index}", "version": "1.0.0"},
                    "components": [{
                        "id": "main",
                        "exec": ["files/app"],
                        "lifecycle": "manual",
                        field: {"profile": "baseline", "failure": "fail-closed"},
                    }],
                }), encoding="utf-8")
                component = load_manifest(path)[0]
                self.assertEqual(component.isolation.profile, "baseline")


class IsolationPlanningTests(unittest.TestCase):
    def test_fail_closed_rejects_a_missing_kernel_capability(self) -> None:
        spec = parse_isolation({
            "profile": "custom",
            "failure": "fail-closed",
            "namespaces": ["network"],
        })
        with self.assertRaisesRegex(IsolationUnavailable, "namespace:network"):
            prepare_isolation_launch(
                spec,
                ["app"],
                capabilities=capabilities(namespaces=frozenset()),
            )

    def test_best_effort_records_every_static_degradation(self) -> None:
        spec = parse_isolation({
            "profile": "custom",
            "failure": "best-effort",
            "namespaces": ["network"],
            "no_new_privs": True,
            "dumpable": False,
            "rlimits": {"core": 0},
            "seccomp": "helper",
        })
        plan = prepare_isolation_launch(
            spec,
            ["app"],
            capabilities=capabilities(
                linux=False,
                prctl=False,
                unshare=False,
                namespaces=frozenset(),
                rlimits=frozenset(),
            ),
        )
        self.assertIsNone(plan.preexec_fn)
        self.assertEqual(plan.argv, ["app"])
        self.assertEqual(plan.skipped, [
            "namespace:network",
            "no_new_privs",
            "dumpable",
            "rlimit:core",
            "seccomp:helper",
        ])
        self.assertTrue(plan.summary()["degraded"])
        self.assertEqual(plan.environment()["MSYS_ISOLATION_DEGRADED"], "1")

    def test_seccomp_helper_wraps_argv_without_shell_parsing(self) -> None:
        spec = parse_isolation({
            "profile": "baseline",
            "seccomp": {"mode": "helper", "profile": "gui"},
        })
        plan = prepare_isolation_launch(
            spec,
            ["app", "argument with spaces"],
            capabilities=capabilities(helper="/trusted/msys-seccomp-exec"),
            backend_factory=FakeBackend,
        )
        self.assertEqual(plan.argv, [
            "/trusted/msys-seccomp-exec",
            "--profile",
            "gui",
            "--",
            "app",
            "argument with spaces",
        ])
        self.assertEqual(plan.summary()["seccomp"]["helper"], "/trusted/msys-seccomp-exec")

    def test_capability_report_does_not_claim_permission_probe_or_full_sandbox(self) -> None:
        report = detect_capabilities().as_dict()
        self.assertEqual(report["permission_probe"], "deferred-to-child")
        self.assertEqual(report["security_boundary"], "partial-not-a-filesystem-sandbox")
        self.assertIn("namespaces", report)
        self.assertIn("seccomp", report)

    def test_core_exposes_read_only_capability_probe(self) -> None:
        daemon = object.__new__(Msysd)
        daemon.profile = {}
        daemon._isolation_capabilities = None
        response = asyncio.run(daemon._core_call({
            "type": "call",
            "id": 42,
            "method": "isolation_capabilities",
            "payload": {},
        }))
        self.assertEqual(response["type"], "return")
        self.assertEqual(response["id"], 42)
        self.assertIn("security_boundary", response["payload"])


class FakeBackend:
    def __init__(self, failures: set[str] | None = None) -> None:
        self.failures = failures or set()
        self.calls: list[str] = []

    def _call(self, name: str) -> None:
        self.calls.append(name)
        if name in self.failures:
            raise OSError(name)

    def enter_user_namespace(self) -> None:
        self._call("namespace:user")

    def unshare(self, namespace: str) -> None:
        self._call(f"namespace:{namespace}")

    def make_mounts_private(self) -> None:
        self._call("mount-private")

    def set_no_new_privs(self) -> None:
        self._call("no-new-privs")

    def set_dumpable(self, enabled: bool) -> None:
        self._call(f"dumpable:{enabled}")

    def set_rlimit(self, name: str, _limit) -> None:
        self._call(f"rlimit:{name}")


class IsolationPreexecTests(unittest.TestCase):
    def test_operations_run_in_security_order(self) -> None:
        spec = parse_isolation({
            "profile": "custom",
            "failure": "fail-closed",
            "namespaces": ["network", "mount", "user"],
            "no_new_privs": True,
            "dumpable": False,
            "rlimits": {"core": 0},
        })
        backend = FakeBackend()
        IsolationPreexec(spec, backend)()
        self.assertEqual(backend.calls, [
            "namespace:user",
            "namespace:mount",
            "mount-private",
            "namespace:network",
            "no-new-privs",
            "dumpable:False",
            "rlimit:core",
        ])

    @mock.patch.object(IsolationPreexec, "_warn")
    def test_best_effort_does_not_touch_mount_propagation_if_unshare_failed(self, warning) -> None:
        spec = parse_isolation({
            "profile": "custom",
            "failure": "best-effort",
            "namespaces": ["mount"],
            "no_new_privs": True,
        })
        backend = FakeBackend({"namespace:mount"})
        IsolationPreexec(spec, backend)()
        self.assertEqual(backend.calls, ["namespace:mount", "no-new-privs"])
        warning.assert_called_once()

    @mock.patch.object(IsolationPreexec, "_abort")
    def test_fail_closed_stops_at_first_runtime_failure(self, _abort) -> None:
        spec = parse_isolation({
            "profile": "custom",
            "failure": "fail-closed",
            "namespaces": ["mount"],
            "no_new_privs": True,
        })
        backend = FakeBackend({"namespace:mount"})
        with self.assertRaisesRegex(IsolationUnavailable, "namespace:mount"):
            IsolationPreexec(spec, backend)()
        self.assertEqual(backend.calls, ["namespace:mount"])

    @mock.patch.object(IsolationPreexec, "_abort")
    def test_partial_user_namespace_failure_is_always_fatal(self, _abort) -> None:
        class PartialBackend(FakeBackend):
            def enter_user_namespace(self) -> None:
                raise PartialIsolationError("mapping failed")

        spec = parse_isolation({
            "profile": "custom",
            "failure": "best-effort",
            "namespaces": ["user"],
        })
        with self.assertRaisesRegex(PartialIsolationError, "mapping failed"):
            IsolationPreexec(spec, PartialBackend())()

    @unittest.skipUnless(sys.platform.startswith("linux"), "Linux-only kernel primitive check")
    def test_real_no_new_privs_and_rlimit_are_visible_after_exec(self) -> None:
        detected = detect_capabilities()
        if not detected.prctl or "core" not in detected.rlimits:
            self.skipTest("prctl/rlimit unavailable")
        spec = parse_isolation({
            "profile": "custom",
            "failure": "fail-closed",
            "no_new_privs": True,
            "dumpable": False,
            "rlimits": {"core": 0},
        })
        plan = prepare_isolation_launch(spec, [sys.executable], capabilities=detected)
        script = (
            "import resource; "
            "status=open('/proc/self/status', encoding='ascii').read(); "
            "print(next(x for x in status.splitlines() if x.startswith('NoNewPrivs:'))); "
            "print(resource.getrlimit(resource.RLIMIT_CORE))"
        )
        result = subprocess.run(
            [*plan.argv, "-c", script],
            preexec_fn=plan.preexec_fn,
            check=True,
            text=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.assertIn("NoNewPrivs:\t1", result.stdout)
        self.assertIn("(0, 0)", result.stdout)


@unittest.skipUnless(sys.platform.startswith("linux"), "Linux-only supervisor launch check")
class IsolationSupervisorIntegrationTests(unittest.TestCase):
    def test_manifest_policy_reaches_real_supervised_process(self) -> None:
        asyncio.run(self._exercise_supervisor_launch())

    async def _exercise_supervisor_launch(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            config = root / "config"
            manifests = config / "manifests"
            profiles = config / "profiles"
            manifests.mkdir(parents=True)
            profiles.mkdir(parents=True)
            output = root / "child-status.txt"
            script = (
                "import pathlib,resource,time; "
                "s=open('/proc/self/status', encoding='ascii').read(); "
                "n=next(x for x in s.splitlines() if x.startswith('NoNewPrivs:')); "
                f"pathlib.Path({str(output)!r}).write_text(n+'\\n'+str(resource.getrlimit(resource.RLIMIT_CORE))); "
                "time.sleep(30)"
            )
            manifest = {
                "schema": "msys.manifest.v1",
                "package": {"id": "org.example.isolated", "version": "1.0.0"},
                "components": [{
                    "id": "worker",
                    "runtime": "native",
                    "exec": [sys.executable, "-c", script],
                    "lifecycle": "manual",
                    "restart": "never",
                    "isolation": {
                        "profile": "custom",
                        "failure": "fail-closed",
                        "no_new_privs": True,
                        "dumpable": False,
                        "rlimits": {"core": 0},
                    },
                }],
            }
            (manifests / "app.json").write_text(json.dumps(manifest), encoding="utf-8")
            (profiles / "test.json").write_text(json.dumps({
                "schema": "msys.profile.v1",
                "id": "test",
                "roles": {},
                "startup": [],
                "state_dir": str(root / "state"),
            }), encoding="utf-8")

            daemon = Msysd(config, root / "runtime", "test")
            key = "org.example.isolated:worker"
            instance = await daemon.ensure_started(key)
            try:
                for _ in range(100):
                    if output.exists():
                        break
                    await asyncio.sleep(0.01)
                self.assertTrue(output.exists())
                self.assertEqual(instance.isolation["profile"], "custom")
                self.assertFalse(instance.isolation["degraded"])
                status = output.read_text(encoding="utf-8")
                self.assertIn("NoNewPrivs:\t1", status)
                self.assertIn("(0, 0)", status)
            finally:
                await daemon.stop_component(key)


if __name__ == "__main__":
    unittest.main()
