from __future__ import annotations

import re
import unittest
from pathlib import Path

from msys_core import __version__


ROOT = Path(__file__).resolve().parents[1]
EXPECTED_VERSION = "0.1.18"


class VersionConsistencyTests(unittest.TestCase):
    def test_export_project_metadata_and_readme_match(self) -> None:
        self.assertEqual(__version__, EXPECTED_VERSION)
        project = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        declared = re.search(
            r"(?ms)^\[project\]\s+.*?^version\s*=\s*\"([^\"]+)\"\s*$",
            project,
        )
        self.assertIsNotNone(declared)
        self.assertEqual(declared.group(1), __version__)

        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn(f"Current source version: `{__version__}`.", readme)


if __name__ == "__main__":
    unittest.main()
