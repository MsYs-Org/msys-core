from __future__ import annotations

import unittest

from msys_core.manifest import Component
from msys_core.msysd import Msysd


def component(
    name: str,
    requires: list[str] | None = None,
    after: list[str] | None = None,
) -> Component:
    return Component(
        package_id="org.msys.test",
        package_version="1.0.0",
        id=name,
        exec=["true"],
        lifecycle="manual",
        requires=requires or [],
        after=after or [],
    )


class DependencyGraphTests(unittest.TestCase):
    def test_valid_acyclic_requires(self) -> None:
        base = component("base")
        app = component("app", [base.key])
        Msysd._validate_dependency_graph({base.key: base, app.key: app})

    def test_missing_hard_dependency_is_rejected(self) -> None:
        app = component("app", ["org.msys.test:missing"])
        with self.assertRaisesRegex(ValueError, "requires missing"):
            Msysd._validate_dependency_graph({app.key: app})

    def test_hard_dependency_cycle_is_rejected(self) -> None:
        first = component("first", ["org.msys.test:second"])
        second = component("second", [first.key])
        with self.assertRaisesRegex(ValueError, "dependency cycle"):
            Msysd._validate_dependency_graph({first.key: first, second.key: second})

    def test_ordering_cycle_is_rejected_without_starting_dependencies(self) -> None:
        first = component("first", after=["org.msys.test:second"])
        second = component("second", after=[first.key])
        with self.assertRaisesRegex(ValueError, "dependency cycle"):
            Msysd._validate_dependency_graph({first.key: first, second.key: second})


if __name__ == "__main__":
    unittest.main()
