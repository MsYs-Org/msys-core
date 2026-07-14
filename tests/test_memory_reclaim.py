from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import AsyncMock

from msys_core.manifest import Component
from msys_core.msysd import (
    Instance,
    MemoryReclaimPolicy,
    Msysd,
    read_mem_available_kib,
)


class LiveProcess:
    def poll(self) -> None:
        return None


def app(identifier: str, *, started_at: float) -> Instance:
    return Instance(
        component=Component(
            package_id="org.example.apps",
            package_version="1.0.0",
            id=identifier,
            exec=["/bin/true"],
            lifecycle="manual",
            windowing={"system": "x11", "mode": "window"},
        ),
        generation=1,
        process=LiveProcess(),  # type: ignore[arg-type]
        ready=True,
        state="ready",
        started_at=started_at,
    )


class MemoryReclaimTests(unittest.IsolatedAsyncioTestCase):
    def test_profile_policy_is_strict_and_bounded(self) -> None:
        policy = MemoryReclaimPolicy.from_profile({
            "settings": {
                "memory_reclaim": {
                    "enabled": True,
                    "available_kib": 32768,
                    "poll_ms": 1000,
                    "min_app_age_ms": 5000,
                }
            }
        })
        self.assertTrue(policy.enabled)
        self.assertEqual(policy.available_kib, 32768)
        with self.assertRaisesRegex(ValueError, "unknown fields"):
            MemoryReclaimPolicy.from_profile({
                "settings": {"memory_reclaim": {"kill_everything": True}}
            })
        with self.assertRaisesRegex(ValueError, "available_kib"):
            MemoryReclaimPolicy.from_profile({
                "settings": {"memory_reclaim": {"available_kib": 1}}
            })

    def test_memavailable_parser_requires_kernel_kib_shape(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "meminfo"
            path.write_text(
                "MemTotal:       391248 kB\nMemAvailable:    48123 kB\n",
                encoding="ascii",
            )
            self.assertEqual(read_mem_available_kib(path), 48123)
            path.write_text("MemAvailable: unlimited kB\n", encoding="ascii")
            self.assertIsNone(read_mem_available_kib(path))

    async def test_only_oldest_background_ordinary_app_is_reclaimed(self) -> None:
        daemon = object.__new__(Msysd)
        now = time.monotonic()
        front = app("front", started_at=now - 120)
        middle = app("middle", started_at=now - 90)
        oldest = app("oldest", started_at=now - 180)
        daemon.instances = {
            item.component.key: item for item in (front, middle, oldest)
        }
        daemon.foreground_stack = [
            front.component.key,
            middle.component.key,
            oldest.component.key,
        ]
        daemon.memory_reclaim_policy = MemoryReclaimPolicy(
            enabled=True,
            available_kib=49152,
            poll_ms=2000,
            min_app_age_ms=15000,
        )
        daemon.stop_component = AsyncMock()  # type: ignore[method-assign]

        reclaimed = await daemon._reclaim_one_background_app(12000)

        self.assertEqual(reclaimed, oldest.component.key)
        daemon.stop_component.assert_awaited_once_with(
            oldest.component.key,
            expected=oldest,
        )

    def test_front_app_and_young_background_app_are_never_candidates(self) -> None:
        daemon = object.__new__(Msysd)
        now = time.monotonic()
        front = app("front", started_at=now - 120)
        young = app("young", started_at=now - 1)
        daemon.instances = {
            front.component.key: front,
            young.component.key: young,
        }
        daemon.foreground_stack = [front.component.key, young.component.key]
        daemon.memory_reclaim_policy = MemoryReclaimPolicy(min_app_age_ms=15000)

        self.assertIsNone(daemon._memory_reclaim_candidate(now))


if __name__ == "__main__":
    unittest.main()
