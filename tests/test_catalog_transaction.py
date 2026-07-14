from __future__ import annotations

import asyncio
import json
import tempfile
import unittest
from pathlib import Path

from msys_core.msysd import CatalogPreflightError, Instance, Msysd


class CatalogTransactionTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.config = self.root / "config"
        (self.config / "manifests").mkdir(parents=True)
        (self.config / "profiles").mkdir()
        self.state = self.root / "state"
        profile = {
            "schema": "msys.profile.v1",
            "id": "test",
            "roles": {},
            "startup": [],
            "state_dir": str(self.state.resolve()),
        }
        (self.config / "profiles/test.json").write_text(
            json.dumps(profile), encoding="utf-8"
        )
        self.write_manifest(
            self.config / "manifests/base.json",
            "org.example.base",
            "1.0.0",
            [{
                "id": "main",
                "runtime": "native",
                "exec": ["true"],
                "lifecycle": "manual",
                "restart": "never",
            }],
        )

    def tearDown(self) -> None:
        self.temporary.cleanup()

    @staticmethod
    def write_manifest(
        path: Path,
        package: str,
        version: str,
        components: list[dict],
    ) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps({
                "schema": "msys.manifest.v1",
                "package": {
                    "id": package,
                    "version": version,
                    "kind": "system",
                },
                "components": components,
            }),
            encoding="utf-8",
        )

    def candidate(
        self,
        *,
        requires: list[str] | None = None,
        lifecycle: str = "manual",
        provides: list[dict] | None = None,
    ) -> Path:
        target = self.state / "packages/org.example.candidate/versions/2.0.0"
        component = {
            "id": "main",
            "runtime": "native",
            "exec": ["true"],
            "lifecycle": lifecycle,
            "restart": "never",
            "requires": requires or [],
            "readiness": {"mode": "exec", "timeout_ms": 100},
        }
        if provides is not None:
            component["provides"] = provides
        self.write_manifest(
            target / "manifest.json",
            "org.example.candidate",
            "2.0.0",
            [component],
        )
        return target

    def daemon(self) -> Msysd:
        return Msysd(self.config, self.root / "runtime", "test")

    def commit_registry(self, target: Path) -> None:
        registry = self.state / "registry"
        registry.mkdir(parents=True, exist_ok=True)
        (registry / "installed.json").write_text(
            json.dumps({
                "schema": "msys.installed.v1",
                "packages": [{
                    "package": "org.example.candidate",
                    "version": "2.0.0",
                    "path": str(target.resolve()),
                    "content_sha256": "0" * 64,
                }],
            }),
            encoding="utf-8",
        )

    def commit_package_registry(
        self,
        target: Path,
        *,
        package: str,
        version: str,
    ) -> None:
        registry = self.state / "registry"
        registry.mkdir(parents=True, exist_ok=True)
        (registry / "installed.json").write_text(
            json.dumps({
                "schema": "msys.installed.v1",
                "packages": [{
                    "package": package,
                    "version": version,
                    "path": str(target.resolve()),
                }],
            }),
            encoding="utf-8",
        )

    @staticmethod
    def fake_runtime(daemon: Msysd, stopped: list[str]) -> None:
        async def stop_component(key: str, *, expected=None) -> None:
            if expected is not None and daemon.instances.get(key) is not expected:
                return
            stopped.append(key)
            daemon.instances.pop(key, None)

        async def ensure_ready(key: str, activation=None) -> Instance:
            del activation
            component = daemon.components[key]
            existing = daemon.instances.get(key)
            if existing is not None and existing.component is component:
                return existing
            generation = daemon.generations.get(key, 0) + 1
            daemon.generations[key] = generation
            instance = Instance(
                component=component,
                generation=generation,
                state="ready",
                ready=True,
            )
            instance.ready_event.set()
            daemon.instances[key] = instance
            return instance

        daemon.stop_component = stop_component  # type: ignore[method-assign]
        daemon.ensure_ready = ensure_ready  # type: ignore[method-assign]

    def test_cross_package_missing_requires_is_rejected_before_commit(self) -> None:
        daemon = self.daemon()
        target = self.candidate(requires=["org.example.missing:provider"])
        with self.assertRaises(CatalogPreflightError) as caught:
            daemon.preflight_installed_candidate("org.example.candidate", target)
        self.assertEqual(caught.exception.code, "CATALOG_PREFLIGHT_FAILED")
        self.assertIn("requires missing", caught.exception.details["reason"])
        response = asyncio.run(daemon._core_call({
            "type": "call",
            "id": 7,
            "method": "preflight_registry",
            "payload": {
                "package": "org.example.candidate",
                "path": str(target),
            },
        }))
        self.assertEqual(response["code"], "CATALOG_PREFLIGHT_FAILED")

    def test_cross_package_builtin_requires_passes_prospective_catalog(self) -> None:
        daemon = self.daemon()
        target = self.candidate(requires=["org.example.base:main"])
        result = daemon.preflight_installed_candidate("org.example.candidate", target)
        self.assertEqual(result["components"], ["org.example.candidate:main"])
        self.assertEqual(result["catalog_components"], 2)

    def test_update_cannot_remove_component_required_by_another_package(self) -> None:
        provider_v1 = self.state / "packages/org.example.provider/versions/1.0.0"
        self.write_manifest(
            provider_v1 / "manifest.json",
            "org.example.provider",
            "1.0.0",
            [{"id": "legacy", "runtime": "native", "exec": ["true"], "lifecycle": "manual"}],
        )
        consumer = self.state / "packages/org.example.consumer/versions/1.0.0"
        self.write_manifest(
            consumer / "manifest.json",
            "org.example.consumer",
            "1.0.0",
            [{
                "id": "main",
                "runtime": "native",
                "exec": ["true"],
                "lifecycle": "manual",
                "requires": ["org.example.provider:legacy"],
            }],
        )
        registry = self.state / "registry"
        registry.mkdir(parents=True)
        (registry / "installed.json").write_text(json.dumps({
            "schema": "msys.installed.v1",
            "packages": [
                {"package": "org.example.provider", "version": "1.0.0", "path": str(provider_v1)},
                {"package": "org.example.consumer", "version": "1.0.0", "path": str(consumer)},
            ],
        }), encoding="utf-8")
        daemon = self.daemon()
        provider_v2 = self.state / "packages/org.example.provider/versions/2.0.0"
        self.write_manifest(
            provider_v2 / "manifest.json",
            "org.example.provider",
            "2.0.0",
            [{"id": "replacement", "runtime": "native", "exec": ["true"], "lifecycle": "manual"}],
        )
        with self.assertRaises(CatalogPreflightError) as caught:
            daemon.preflight_installed_candidate("org.example.provider", provider_v2)
        self.assertIn("org.example.provider:legacy", caught.exception.details["reason"])

    def test_uninstall_preflight_accepts_an_independent_installed_package(self) -> None:
        target = self.candidate()
        self.commit_registry(target)
        daemon = self.daemon()

        result = daemon.preflight_installed_removal("org.example.candidate")
        self.assertEqual(result["package"], "org.example.candidate")
        self.assertEqual(result["components"], ["org.example.candidate:main"])
        self.assertEqual(result["catalog_components"], 1)

        response = asyncio.run(daemon._core_call({
            "type": "call",
            "id": 81,
            "method": "preflight_registry_remove",
            "payload": {"package": "org.example.candidate"},
        }))
        self.assertEqual(response["type"], "return")
        self.assertEqual(response["id"], 81)

    def test_uninstall_preflight_rejects_cross_package_dependency_breakage(self) -> None:
        provider = self.state / "packages/org.example.provider/versions/1.0.0"
        self.write_manifest(
            provider / "manifest.json",
            "org.example.provider",
            "1.0.0",
            [{
                "id": "main",
                "runtime": "native",
                "exec": ["true"],
                "lifecycle": "manual",
                "restart": "never",
            }],
        )
        consumer = self.state / "packages/org.example.consumer/versions/1.0.0"
        self.write_manifest(
            consumer / "manifest.json",
            "org.example.consumer",
            "1.0.0",
            [{
                "id": "main",
                "runtime": "native",
                "exec": ["true"],
                "lifecycle": "manual",
                "restart": "never",
                "requires": ["org.example.provider:main"],
            }],
        )
        registry = self.state / "registry"
        registry.mkdir(parents=True)
        (registry / "installed.json").write_text(
            json.dumps({
                "schema": "msys.installed.v1",
                "packages": [
                    {
                        "package": "org.example.provider",
                        "version": "1.0.0",
                        "path": str(provider),
                    },
                    {
                        "package": "org.example.consumer",
                        "version": "1.0.0",
                        "path": str(consumer),
                    },
                ],
            }),
            encoding="utf-8",
        )
        daemon = self.daemon()

        with self.assertRaises(CatalogPreflightError) as caught:
            daemon.preflight_installed_removal("org.example.provider")
        self.assertIn("requires missing", caught.exception.details["reason"])

    def test_uninstall_preflight_rejects_missing_installed_package(self) -> None:
        daemon = self.daemon()
        with self.assertRaises(CatalogPreflightError) as caught:
            daemon.preflight_installed_removal("org.example.unknown")
        self.assertIn("not present", caught.exception.details["reason"])

        response = asyncio.run(daemon._core_call({
            "type": "call",
            "id": 82,
            "method": "preflight_registry_remove",
            "payload": {"package": "org.example.unknown"},
        }))
        self.assertEqual(response["type"], "error")
        self.assertEqual(response["code"], "CATALOG_PREFLIGHT_FAILED")

    def test_reload_graph_failure_is_a_typed_error(self) -> None:
        daemon = self.daemon()
        target = self.candidate(requires=["org.example.missing:provider"])
        self.commit_registry(target)
        response = asyncio.run(daemon._core_call({
            "type": "call",
            "id": 8,
            "method": "reload_registry",
            "payload": {"verify_health": True},
        }))
        self.assertEqual(response["type"], "error")
        self.assertEqual(response["code"], "CATALOG_RELOAD_FAILED")
        self.assertIn("requires missing", response["payload"]["reason"])

    def test_critical_background_readiness_failure_is_typed(self) -> None:
        daemon = self.daemon()
        target = self.candidate(lifecycle="background")
        self.commit_registry(target)

        async def fail_ready(key: str, activation=None):
            raise RuntimeError(f"{key} did not become ready")

        daemon.ensure_ready = fail_ready  # type: ignore[method-assign]
        response = asyncio.run(daemon._core_call({
            "type": "call",
            "id": 9,
            "method": "reload_registry",
            "payload": {"verify_health": True},
        }))
        self.assertEqual(response["type"], "error")
        self.assertEqual(response["code"], "CATALOG_HEALTH_FAILED")
        self.assertEqual(
            response["payload"]["failures"][0]["component"],
            "org.example.candidate:main",
        )

    def test_selected_role_provider_is_health_checked_even_when_on_demand(self) -> None:
        profile_path = self.config / "profiles/test.json"
        profile = json.loads(profile_path.read_text(encoding="utf-8"))
        profile["roles"] = {"critical-provider": ["org.example.candidate:main"]}
        profile_path.write_text(json.dumps(profile), encoding="utf-8")
        daemon = self.daemon()
        target = self.candidate(
            lifecycle="on-demand",
            provides=[{
                "role": "critical-provider",
                "exclusive": True,
                "priority": 100,
            }],
        )
        self.commit_registry(target)

        async def fail_ready(key: str, activation=None):
            raise RuntimeError(f"{key} did not become ready")

        daemon.ensure_ready = fail_ready  # type: ignore[method-assign]
        response = asyncio.run(daemon._core_call({
            "type": "call",
            "id": 10,
            "method": "reload_registry",
            "payload": {"verify_health": True},
        }))
        self.assertEqual(response["code"], "CATALOG_HEALTH_FAILED")
        self.assertEqual(
            response["payload"]["targets"],
            ["org.example.candidate:main"],
        )

    def test_transaction_restarts_only_running_manual_component_on_new_generation(self) -> None:
        package = "org.example.runtime"
        v1 = self.state / f"packages/{package}/versions/1.0.0"
        components = [
            {
                "id": component,
                "runtime": "native",
                "exec": ["true"],
                "lifecycle": "manual",
                "restart": "never",
                "readiness": {"mode": "exec", "timeout_ms": 100},
            }
            for component in ("main", "dormant")
        ]
        self.write_manifest(v1 / "manifest.json", package, "1.0.0", components)
        self.commit_package_registry(v1, package=package, version="1.0.0")
        daemon = self.daemon()
        main = f"{package}:main"
        dormant = f"{package}:dormant"
        old = Instance(
            component=daemon.components[main],
            generation=4,
            state="ready",
            ready=True,
        )
        daemon.instances[main] = old
        daemon.generations[main] = 4
        base = "org.example.base:main"
        unrelated = Instance(
            component=daemon.components[base],
            generation=9,
            state="ready",
            ready=True,
        )
        daemon.instances[base] = unrelated
        daemon.generations[base] = 9
        stopped: list[str] = []
        self.fake_runtime(daemon, stopped)

        v2 = self.state / f"packages/{package}/versions/2.0.0"
        self.write_manifest(v2 / "manifest.json", package, "2.0.0", components)
        self.commit_package_registry(v2, package=package, version="2.0.0")
        response = asyncio.run(daemon._core_call({
            "type": "call",
            "id": 91,
            "method": "reload_registry",
            "payload": {
                "verify_health": True,
                "transaction": {
                    "schema": "msys.catalog-transaction.v1",
                    "package": package,
                    "version": "2.0.0",
                    "path": str(v2.resolve()),
                    "removed": False,
                },
            },
        }))

        self.assertEqual(response["type"], "return")
        proof = response["payload"]["transaction"]
        self.assertTrue(proof["generation_verified"])
        self.assertEqual(proof["running_before"], [main])
        self.assertEqual(proof["restarted_components"][0]["from_generation"], 4)
        self.assertGreater(proof["restarted_components"][0]["to_generation"], 4)
        self.assertEqual(
            daemon.instances[main].component.manifest_path.parent.resolve(),
            v2.resolve(),
        )
        self.assertNotIn(dormant, daemon.instances)
        self.assertIs(daemon.instances[base], unrelated)
        self.assertNotIn(base, stopped)

    def test_old_ready_process_cannot_satisfy_transaction_health_gate(self) -> None:
        package = "org.example.runtime"
        main = f"{package}:main"
        component = [{
            "id": "main",
            "runtime": "native",
            "exec": ["true"],
            "lifecycle": "manual",
            "restart": "never",
            "readiness": {"mode": "exec", "timeout_ms": 100},
        }]
        v1 = self.state / f"packages/{package}/versions/1.0.0"
        self.write_manifest(v1 / "manifest.json", package, "1.0.0", component)
        self.commit_package_registry(v1, package=package, version="1.0.0")
        daemon = self.daemon()
        stale = Instance(
            component=daemon.components[main],
            generation=3,
            state="ready",
            ready=True,
        )
        daemon.instances[main] = stale
        daemon.generations[main] = 3

        async def ignore_stop(key: str, *, expected=None) -> None:
            del key, expected

        async def stale_ready(key: str, activation=None) -> Instance:
            del key, activation
            return stale

        daemon.stop_component = ignore_stop  # type: ignore[method-assign]
        daemon.ensure_ready = stale_ready  # type: ignore[method-assign]
        v2 = self.state / f"packages/{package}/versions/2.0.0"
        self.write_manifest(v2 / "manifest.json", package, "2.0.0", component)
        self.commit_package_registry(v2, package=package, version="2.0.0")

        response = asyncio.run(daemon._core_call({
            "type": "call",
            "id": 92,
            "method": "reload_registry",
            "payload": {
                "verify_health": True,
                "transaction": {
                    "schema": "msys.catalog-transaction.v1",
                    "package": package,
                    "version": "2.0.0",
                    "path": str(v2.resolve()),
                    "removed": False,
                },
            },
        }))

        self.assertEqual(response["code"], "CATALOG_HEALTH_FAILED")
        self.assertIn("previous catalog", response["payload"]["failures"][0]["message"])
        self.assertEqual(response["payload"]["resume_components"], [main])

    def test_transaction_rejects_registry_version_that_does_not_match_manifest(self) -> None:
        package = "org.example.runtime"
        target = self.state / f"packages/{package}/versions/2.0.0"
        self.write_manifest(
            target / "manifest.json",
            package,
            "1.0.0",
            [{
                "id": "main",
                "runtime": "native",
                "exec": ["true"],
                "lifecycle": "manual",
                "restart": "never",
            }],
        )
        daemon = self.daemon()
        self.commit_package_registry(target, package=package, version="2.0.0")

        response = asyncio.run(daemon._core_call({
            "type": "call",
            "id": 921,
            "method": "reload_registry",
            "payload": {
                "verify_health": True,
                "transaction": {
                    "schema": "msys.catalog-transaction.v1",
                    "package": package,
                    "version": "2.0.0",
                    "path": str(target.resolve()),
                    "removed": False,
                },
            },
        }))

        self.assertEqual(response["type"], "error")
        self.assertEqual(response["code"], "CATALOG_RELOAD_FAILED")
        self.assertIn("manifest version", response["payload"]["reason"])
        self.assertNotIn(f"{package}:main", daemon.components)

    def test_rollback_resume_set_restores_stopped_manual_component(self) -> None:
        package = "org.example.runtime"
        main = f"{package}:main"
        declaration = [{
            "id": "main",
            "runtime": "native",
            "exec": ["true"],
            "lifecycle": "manual",
            "restart": "never",
            "readiness": {"mode": "exec", "timeout_ms": 100},
        }]
        v2 = self.state / f"packages/{package}/versions/2.0.0"
        self.write_manifest(v2 / "manifest.json", package, "2.0.0", declaration)
        self.commit_package_registry(v2, package=package, version="2.0.0")
        daemon = self.daemon()
        daemon.generations[main] = 7
        stopped: list[str] = []
        self.fake_runtime(daemon, stopped)

        v1 = self.state / f"packages/{package}/versions/1.0.0"
        self.write_manifest(v1 / "manifest.json", package, "1.0.0", declaration)
        self.commit_package_registry(v1, package=package, version="1.0.0")
        response = asyncio.run(daemon._core_call({
            "type": "call",
            "id": 93,
            "method": "reload_registry",
            "payload": {
                "verify_health": True,
                "transaction": {
                    "schema": "msys.catalog-transaction.v1",
                    "package": package,
                    "version": "1.0.0",
                    "path": str(v1.resolve()),
                    "removed": False,
                    "resume_components": [main],
                },
            },
        }))

        self.assertEqual(response["type"], "return")
        self.assertEqual(daemon.instances[main].component.package_version, "1.0.0")
        self.assertGreater(daemon.instances[main].generation, 7)
        self.assertEqual(response["payload"]["transaction"]["resumed_components"], [main])

    def test_startup_uses_restore_pointer_from_health_pending_journal(self) -> None:
        target = self.candidate(requires=["org.example.missing:provider"])
        self.commit_registry(target)
        transaction = {
            "schema": "msys.install-transaction.v1",
            "id": "crashed-health-gate",
            "phase": "health_pending",
            "package": "org.example.candidate",
            "commit_current": {
                "package": "org.example.candidate",
                "version": "2.0.0",
                "path": str(target),
            },
            "commit_previous": None,
            "restore_current": None,
            "restore_previous": None,
        }
        (self.state / "registry/install-transaction.json").write_text(
            json.dumps(transaction), encoding="utf-8"
        )
        daemon = self.daemon()
        self.assertNotIn("org.example.candidate:main", daemon.components)
        self.assertIn("org.example.base:main", daemon.components)


if __name__ == "__main__":
    unittest.main()
