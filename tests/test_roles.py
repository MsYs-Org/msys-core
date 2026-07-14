from __future__ import annotations

import unittest

from msys_core.manifest import Component, Provide
from msys_core.roles import (
    LeaseConflictError,
    NoCandidateError,
    RoleLease,
    RoleRegistry,
    UnknownCandidateError,
    UnknownLeaseError,
    UnknownRoleError,
)


def component(
    provider_id: str,
    *provides: Provide,
) -> Component:
    package_id, component_id = provider_id.split(":", 1)
    return Component(
        package_id=package_id,
        package_version="1.0.0",
        id=component_id,
        exec=[],
        lifecycle="on-demand",
        provides=list(provides),
    )


def role(
    name: str,
    *,
    priority: int = 0,
    exclusive: bool = True,
) -> Provide:
    return Provide(
        kind="role",
        name=name,
        priority=priority,
        exclusive=exclusive,
    )


class RoleCandidateTests(unittest.TestCase):
    def setUp(self) -> None:
        self.components = {
            "pkg:low": component("pkg:low", role("launcher", priority=5)),
            "pkg:high-z": component(
                "pkg:high-z",
                role("launcher", priority=90),
            ),
            "pkg:high-a": component(
                "pkg:high-a",
                role("launcher", priority=90),
            ),
            "pkg:plain": component("pkg:plain"),
            "pkg:status": component(
                "pkg:status",
                role("status-source", exclusive=False),
            ),
        }

    def test_profile_order_precedes_priority_and_candidates_are_deduplicated(self) -> None:
        registry = RoleRegistry(
            self.components,
            {
                "launcher": [
                    "pkg:low",
                    "pkg:low",
                    "pkg:not-installed",
                    "pkg:plain",
                ]
            },
        )

        self.assertEqual(
            registry.candidate_ids("launcher"),
            ("pkg:low", "pkg:plain", "pkg:high-a", "pkg:high-z"),
        )
        candidates = registry.list_candidates("launcher")
        self.assertEqual(candidates[0].profile_rank, 0)
        # The duplicate occupied profile rank 1, so the next accepted item
        # retains its actual position in the configured fallback list.
        self.assertEqual(candidates[1].profile_rank, 3)
        self.assertTrue(candidates[0].declared)
        self.assertFalse(candidates[1].declared)
        self.assertEqual(candidates[2].priority, 90)
        self.assertTrue(candidates[0].explicit)
        self.assertFalse(candidates[2].explicit)

    def test_duplicate_provides_use_highest_priority_and_strict_exclusivity(self) -> None:
        provider = component(
            "pkg:provider",
            role("mixed", priority=10, exclusive=False),
            role("mixed", priority=30, exclusive=True),
        )
        registry = RoleRegistry({provider.key: provider})

        candidate = registry.list_candidates("mixed")[0]
        self.assertEqual(candidate.priority, 30)
        self.assertTrue(candidate.exclusive)
        self.assertTrue(registry.info("mixed").exclusive)

    def test_roles_follow_profile_then_discovered_role_order(self) -> None:
        registry = RoleRegistry(
            self.components,
            {"empty-role": ["pkg:not-installed"], "launcher": []},
        )

        self.assertEqual(
            registry.list_roles(),
            ("empty-role", "launcher", "status-source"),
        )
        self.assertEqual(registry.list_candidates("empty-role"), ())
        with self.assertRaises(NoCandidateError):
            registry.resolve("empty-role")

    def test_complete_profile_constructor(self) -> None:
        registry = RoleRegistry.from_profile(
            self.components,
            {"schema": "msys.profile.v1", "roles": {"launcher": ["pkg:low"]}},
        )
        self.assertEqual(registry.resolve("launcher"), "pkg:low")

    def test_profile_can_disable_a_discovered_role(self) -> None:
        registry = RoleRegistry.from_profile(
            self.components,
            {
                "schema": "msys.profile.v1",
                "roles": {"launcher": ["pkg:low"]},
                "disabled_roles": ["launcher"],
            },
        )

        self.assertNotIn("launcher", registry.list_roles())
        self.assertEqual(registry.disabled_roles(), ("launcher",))
        self.assertIn("status-source", registry.list_roles())

    def test_disabled_roles_must_be_a_sequence(self) -> None:
        with self.assertRaises(TypeError):
            RoleRegistry.from_profile(
                self.components,
                {"roles": {}, "disabled_roles": "launcher"},
            )


class RolePreferenceTests(unittest.TestCase):
    def setUp(self) -> None:
        first = component("pkg:first", role("launcher", priority=10))
        second = component("pkg:second", role("launcher", priority=20))
        self.registry = RoleRegistry(
            {first.key: first, second.key: second},
            {"launcher": [first.key]},
        )

    def test_select_and_reset_preferred_provider(self) -> None:
        self.assertEqual(self.registry.preferred_provider("launcher"), "pkg:first")
        self.assertEqual(
            self.registry.select_preferred("launcher", "pkg:second"),
            "pkg:second",
        )
        self.assertEqual(self.registry.resolve("launcher"), "pkg:second")

        self.assertEqual(self.registry.reset_preferred("launcher"), "pkg:first")
        self.assertEqual(self.registry.resolve("launcher"), "pkg:first")

    def test_selection_validates_role_and_candidate(self) -> None:
        with self.assertRaises(UnknownCandidateError):
            self.registry.select_preferred("launcher", "pkg:missing")
        with self.assertRaises(UnknownRoleError):
            self.registry.select_preferred("unknown", "pkg:first")


class RoleLeaseTests(unittest.TestCase):
    def test_exclusive_role_has_only_one_active_lease(self) -> None:
        first = component("pkg:first", role("launcher", priority=20))
        second = component("pkg:second", role("launcher", priority=10))
        registry = RoleRegistry({first.key: first, second.key: second})

        lease = registry.acquire("launcher", holder="generation:1")
        self.assertEqual(lease.provider_id, "pkg:first")
        self.assertEqual(registry.active_provider("launcher"), "pkg:first")
        self.assertEqual(registry.info("launcher").lease_count, 1)

        with self.assertRaises(LeaseConflictError):
            registry.acquire("launcher", "pkg:first")
        with self.assertRaises(LeaseConflictError):
            registry.acquire("launcher", "pkg:second")

        self.assertEqual(registry.release(lease), lease)
        self.assertIsNone(registry.active_provider("launcher"))
        fallback = registry.acquire("launcher", "pkg:second")
        self.assertEqual(registry.active_provider("launcher"), "pkg:second")
        registry.release(fallback.token)

    def test_nonexclusive_role_can_have_multiple_active_leases(self) -> None:
        first = component(
            "pkg:first",
            role("status-source", priority=20, exclusive=False),
        )
        second = component(
            "pkg:second",
            role("status-source", priority=10, exclusive=False),
        )
        registry = RoleRegistry({first.key: first, second.key: second})

        first_lease = registry.acquire("status-source", "pkg:first")
        second_lease = registry.acquire("status-source", "pkg:second")

        self.assertEqual(
            registry.active_providers("status-source"),
            ("pkg:first", "pkg:second"),
        )
        self.assertEqual(
            registry.active_leases("status-source"),
            (first_lease, second_lease),
        )

    def test_release_provider_clears_all_of_its_leases(self) -> None:
        provider = component(
            "pkg:provider",
            role("source-a", exclusive=False),
            role("source-b", exclusive=False),
        )
        registry = RoleRegistry({provider.key: provider})
        lease_a = registry.acquire("source-a", holder="generation:7")
        lease_b = registry.acquire("source-b", holder="generation:7")

        self.assertEqual(
            registry.release_provider(provider.key),
            (lease_a, lease_b),
        )
        self.assertEqual(registry.active_leases("source-a"), ())
        self.assertEqual(registry.active_leases("source-b"), ())

    def test_unknown_or_forged_lease_cannot_be_released(self) -> None:
        provider = component("pkg:provider", role("launcher"))
        registry = RoleRegistry({provider.key: provider})
        lease = registry.acquire("launcher")

        with self.assertRaises(UnknownLeaseError):
            registry.release(9999)
        with self.assertRaises(UnknownLeaseError):
            registry.release(
                RoleLease(
                    token=lease.token,
                    role=lease.role,
                    provider_id=lease.provider_id,
                    holder="forged-holder",
                )
            )
        self.assertEqual(registry.active_leases("launcher"), (lease,))


if __name__ == "__main__":
    unittest.main()
