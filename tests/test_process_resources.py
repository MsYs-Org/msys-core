from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from msys_core.msysd import process_memory_snapshot


def process(
    root: Path,
    pid: int,
    group: int,
    *,
    rss: int,
    pss: int | None,
) -> None:
    directory = root / str(pid)
    directory.mkdir()
    (directory / "stat").write_text(
        f"{pid} (test process) S 1 {group} {group} 0 0 0\n",
        encoding="ascii",
    )
    fields = f"Rss: {rss} kB\n"
    if pss is not None:
        fields += f"Pss: {pss} kB\n"
    (directory / "smaps_rollup").write_text(fields, encoding="ascii")
    (directory / "status").write_text(f"VmRSS: {rss} kB\n", encoding="ascii")


class ProcessResourceTests(unittest.TestCase):
    def test_snapshot_sums_one_component_process_group(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            process(root, 100, 100, rss=8000, pss=6000)
            process(root, 101, 100, rss=4000, pss=3000)
            process(root, 200, 200, rss=90000, pss=70000)

            snapshot = process_memory_snapshot(100, root)

        self.assertTrue(snapshot["available"])
        self.assertEqual(snapshot["scope"], "process-group")
        self.assertEqual(snapshot["member_count"], 2)
        self.assertEqual(snapshot["rss_kib"], 12000)
        self.assertTrue(snapshot["pss_available"])
        self.assertEqual(snapshot["pss_kib"], 9000)
        self.assertIsNone(snapshot["reason"])

    def test_snapshot_falls_back_to_explicit_rss_when_pss_is_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            process(root, 100, 100, rss=8000, pss=6000)
            process(root, 101, 100, rss=4000, pss=None)

            snapshot = process_memory_snapshot(100, root)

        self.assertTrue(snapshot["available"])
        self.assertEqual(snapshot["rss_kib"], 12000)
        self.assertFalse(snapshot["pss_available"])
        self.assertIsNone(snapshot["pss_kib"])
        self.assertEqual(snapshot["reason"], "pss-unavailable")

    def test_missing_process_group_is_truthfully_unavailable(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            snapshot = process_memory_snapshot(100, Path(temporary))

        self.assertFalse(snapshot["available"])
        self.assertIsNone(snapshot["rss_kib"])
        self.assertIsNone(snapshot["pss_kib"])
        self.assertEqual(snapshot["reason"], "memory-unavailable")


if __name__ == "__main__":
    unittest.main()
