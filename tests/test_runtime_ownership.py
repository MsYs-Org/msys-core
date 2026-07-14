from __future__ import annotations

import asyncio
import os
import tempfile
import unittest
from pathlib import Path

from msys_core.msysd import Msysd, RuntimeOwnershipError


def bare_daemon(runtime: Path) -> Msysd:
    daemon = object.__new__(Msysd)
    daemon.runtime_dir = runtime
    daemon._runtime_lock_fd = None
    daemon.public_server = None
    return daemon


class RuntimeOwnershipTests(unittest.TestCase):
    def test_second_supervisor_cannot_claim_the_same_runtime(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            runtime = Path(temporary) / "runtime"
            first = bare_daemon(runtime)
            second = bare_daemon(runtime)
            first._acquire_runtime_ownership()
            self.addCleanup(first._release_runtime_ownership)
            self.assertEqual(
                (runtime / ".msysd.lock").read_text(encoding="ascii").strip(),
                str(os.getpid()),
            )
            with self.assertRaises(RuntimeOwnershipError):
                second._acquire_runtime_ownership()
            first._release_runtime_ownership()
            second._acquire_runtime_ownership()
            second._release_runtime_ownership()

    def test_owner_may_remove_a_stale_control_socket(self) -> None:
        async def exercise(runtime: Path) -> None:
            daemon = bare_daemon(runtime)
            daemon._acquire_runtime_ownership()
            try:
                stale = runtime / "control.sock"
                stale.write_text("stale", encoding="ascii")
                await daemon._start_public_socket()
                self.assertTrue(stale.exists())
                self.assertTrue(stale.is_socket())
                assert daemon.public_server is not None
                daemon.public_server.close()
                await daemon.public_server.wait_closed()
            finally:
                daemon._release_runtime_ownership()

        with tempfile.TemporaryDirectory() as temporary:
            asyncio.run(exercise(Path(temporary) / "runtime"))


if __name__ == "__main__":
    unittest.main()
