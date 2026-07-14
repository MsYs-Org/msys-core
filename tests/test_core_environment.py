from __future__ import annotations

import os
import unittest
from unittest import mock

from msys_core import msysd


class StopBeforeDaemon(Exception):
    pass


class CoreEnvironmentTests(unittest.TestCase):
    def test_main_consumes_only_core_trim_tuning_before_components_exist(self) -> None:
        with mock.patch.dict(
            os.environ,
            {
                "MALLOC_TRIM_THRESHOLD_": "262144",
                "MALLOC_ARENA_MAX": "2",
            },
            clear=False,
        ):
            with (
                mock.patch.object(
                    msysd,
                    "parse_args",
                    side_effect=StopBeforeDaemon,
                ),
                self.assertRaises(StopBeforeDaemon),
            ):
                msysd.main([])
            self.assertNotIn("MALLOC_TRIM_THRESHOLD_", os.environ)
            self.assertEqual(os.environ["MALLOC_ARENA_MAX"], "2")


if __name__ == "__main__":
    unittest.main()
