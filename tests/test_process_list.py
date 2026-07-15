from __future__ import annotations

import asyncio
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from msys_core.manifest import Component
from msys_core.msysd import Instance, Msysd, system_process_snapshot


PUBLIC_FIELDS = {
    "pid",
    "ppid",
    "uid",
    "name",
    "state",
    "rss_kib",
    "source",
    "msys_owned",
    "component",
    "component_state",
    "runtime",
    "lifecycle",
    "generation",
}


class LiveProcess:
    def __init__(self, pid: int, running: bool = True) -> None:
        self.pid = pid
        self.running = running

    def poll(self) -> int | None:
        return None if self.running else 0


def component(
    component_id: str,
    *,
    display_name: str | None = None,
    lifecycle: str = "background",
    windowing: dict[str, object] | None = None,
    role_windows: bool = False,
) -> Component:
    raw: dict[str, object] = {
        "id": component_id,
        "name": display_name or component_id.title(),
    }
    if role_windows:
        raw["x-msys-role-windows"] = {
            "navigation-bar": {"system": "x11", "mode": "overlay"}
        }
    return Component(
        package_id="org.example",
        package_version="1.0.0",
        id=component_id,
        exec=["worker"],
        lifecycle=lifecycle,
        runtime="native",
        windowing=dict(windowing or {}),
        raw=raw,
    )


def proc_process(
    root: Path,
    pid: int,
    *,
    name: str,
    ppid: int,
    group: int,
    session: int,
    state: str = "S",
    uid: int = 1000,
    rss_kib: int | None = 128,
) -> None:
    directory = root / str(pid)
    directory.mkdir()
    (directory / "stat").write_text(
        f"{pid} ({name}) {state} {ppid} {group} {session} 0 0 0\n",
        encoding="ascii",
    )
    status = f"Name:\t{name}\nUid:\t{uid}\t{uid}\t{uid}\t{uid}\n"
    if rss_kib is not None:
        status += f"VmRSS:\t{rss_kib} kB\n"
    (directory / "status").write_text(status, encoding="ascii")


class ProcessListTests(unittest.TestCase):
    def daemon(self, root: Path) -> Msysd:
        daemon = object.__new__(Msysd)
        daemon.proc_root = root
        daemon.components = {}
        daemon.instances = {}
        return daemon

    @staticmethod
    def add_instance(
        daemon: Msysd,
        declared: Component,
        pid: int,
        *,
        running: bool = True,
        generation: int = 1,
    ) -> None:
        instance = Instance(
            component=declared,
            generation=generation,
            process=LiveProcess(pid, running),  # type: ignore[arg-type]
            state="ready" if running else "exited",
            ready=running,
        )
        daemon.components[declared.key] = declared
        daemon.instances[declared.key] = instance

    def call(self, daemon: Msysd, payload: object) -> dict[str, object]:
        return asyncio.run(daemon._core_call({
            "type": "call",
            "id": 41,
            "method": "list_processes",
            "payload": payload,
        }))

    def test_default_lists_only_live_headless_msys_components(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            proc_process(
                root, 100, name="hal-worker", ppid=50, group=100, session=100,
                uid=0, rss_kib=2048,
            )
            proc_process(
                root, 200, name="settings", ppid=50, group=200, session=200,
            )
            proc_process(
                root, 300, name="old-worker", ppid=50, group=300, session=300,
            )
            proc_process(
                root, 400, name="shell", ppid=50, group=400, session=400,
            )
            daemon = self.daemon(root)
            self.add_instance(
                daemon, component("hal", display_name="硬件服务"), 100,
                generation=7,
            )
            self.add_instance(
                daemon,
                component(
                    "settings",
                    lifecycle="manual",
                    windowing={"system": "x11", "mode": "window"},
                ),
                200,
            )
            self.add_instance(daemon, component("old"), 300, running=False)
            self.add_instance(
                daemon, component("shell", role_windows=True), 400,
            )

            response = self.call(daemon, {})

        self.assertEqual(response["type"], "return")
        payload = response["payload"]
        self.assertEqual(payload["schema"], "msys.process-list.v1")
        self.assertEqual(payload["filter"], "headless-msys")
        self.assertFalse(payload["include_system"])
        self.assertEqual(payload["managed_count"], 2)
        self.assertEqual(payload["system_count"], 0)
        self.assertFalse(payload["managed_truncated"])
        self.assertFalse(payload["system_truncated"])
        self.assertEqual(len(payload["processes"]), 2)
        core = next(
            item for item in payload["processes"]
            if item["component"] == "msys.core"
        )
        self.assertEqual(set(core), PUBLIC_FIELDS)
        self.assertEqual(core["source"], "msys-core")
        self.assertTrue(core["msys_owned"])
        self.assertEqual(core["name"], "MSYS Core")
        self.assertEqual(core["component_state"], "ready")
        self.assertEqual(core["lifecycle"], "supervisor")
        process = next(
            item for item in payload["processes"]
            if item["component"] == "org.example:hal"
        )
        self.assertEqual(set(process), PUBLIC_FIELDS)
        self.assertEqual(process["component"], "org.example:hal")
        self.assertEqual(process["generation"], 7)
        self.assertEqual(process["source"], "msys-supervisor")
        self.assertTrue(process["msys_owned"])
        self.assertEqual(process["name"], "硬件服务")
        self.assertEqual(process["rss_kib"], 2048)

    def test_include_system_excludes_every_msys_process_group_and_is_bounded(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            proc_process(
                root, 1, name="init", ppid=0, group=1, session=1, uid=0,
            )
            proc_process(
                root, 100, name="hal", ppid=900, group=100, session=100, uid=0,
            )
            proc_process(
                root, 101, name="hal-child", ppid=100, group=100, session=100,
                uid=0,
            )
            proc_process(
                root, 200, name="gui", ppid=900, group=200, session=200,
            )
            proc_process(
                root, 201, name="gui-child", ppid=200, group=200, session=200,
            )
            proc_process(
                root, 300, name="ssh", ppid=1, group=300, session=300,
            )
            proc_process(
                root, 400, name="logger", ppid=1, group=400, session=400,
                rss_kib=None,
            )
            proc_process(
                root, 900, name="msysd", ppid=1, group=900, session=900, uid=0,
            )
            daemon = self.daemon(root)
            self.add_instance(daemon, component("hal"), 100)
            self.add_instance(
                daemon,
                component(
                    "gui",
                    lifecycle="manual",
                    windowing={"system": "x11", "mode": "window"},
                ),
                200,
            )

            with mock.patch("msys_core.msysd.os.getpid", return_value=900), mock.patch(
                "msys_core.msysd.subprocess.run",
                side_effect=AssertionError("list_processes must not execute ps"),
            ):
                response = self.call(
                    daemon, {"include_system": True, "limit": 2}
                )

        payload = response["payload"]
        self.assertEqual(payload["managed_count"], 2)
        self.assertEqual(payload["system_count"], 2)
        self.assertTrue(payload["system_truncated"])
        external = [
            item for item in payload["processes"] if not item["msys_owned"]
        ]
        self.assertEqual([item["pid"] for item in external], [1, 300])
        for item in external:
            self.assertEqual(set(item), PUBLIC_FIELDS)
            self.assertEqual(item["source"], "procfs")
            self.assertIsNone(item["component"])
            self.assertIsNone(item["generation"])
        self.assertNotIn(101, [item["pid"] for item in payload["processes"]])
        self.assertNotIn(201, [item["pid"] for item in payload["processes"]])
        self.assertNotIn(900, [item["pid"] for item in external])
        core = next(
            item for item in payload["processes"]
            if item["component"] == "msys.core"
        )
        self.assertEqual(core["pid"], 900)
        self.assertEqual(core["source"], "msys-core")

    def test_payload_is_closed_and_strictly_typed(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            daemon = self.daemon(Path(temporary))
            invalid = (
                None,
                [],
                {"include_system": 1},
                {"limit": True},
                {"limit": 0},
                {"limit": 129},
                {"unexpected": True},
            )
            for request in invalid:
                with self.subTest(request=request):
                    response = self.call(daemon, request)
                    self.assertEqual(response["type"], "error")
                    self.assertEqual(response["code"], "BAD_PAYLOAD")

    def test_proc_parser_handles_parentheses_and_bounds_names(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            name = "worker ) with spaces" + "x" * 100
            proc_process(
                root, 77, name=name, ppid=1, group=77, session=77, state="R",
                uid=123, rss_kib=456,
            )

            processes, truncated = system_process_snapshot(
                set(), proc_root=root, limit=4, supervisor_pid=999,
            )

        self.assertFalse(truncated)
        self.assertEqual(len(processes), 1)
        self.assertEqual(set(processes[0]), PUBLIC_FIELDS)
        self.assertEqual(processes[0]["pid"], 77)
        self.assertEqual(processes[0]["ppid"], 1)
        self.assertEqual(processes[0]["uid"], 123)
        self.assertEqual(processes[0]["state"], "running")
        self.assertEqual(processes[0]["rss_kib"], 456)
        self.assertEqual(len(processes[0]["name"]), 64)

    def test_system_results_filter_kernel_threads_and_prioritize_rss(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            proc_process(
                root, 2, name="kthreadd", ppid=0, group=2, session=2,
                uid=0, rss_kib=None,
            )
            proc_process(
                root, 20, name="kworker/0:1", ppid=2, group=20, session=2,
                uid=0, rss_kib=None,
            )
            proc_process(
                root, 10, name="no-rss-user", ppid=1, group=10, session=10,
                rss_kib=None,
            )
            proc_process(
                root, 30, name="small", ppid=1, group=30, session=30,
                rss_kib=100,
            )
            proc_process(
                root, 50, name="large-later", ppid=1, group=50, session=50,
                rss_kib=900,
            )
            proc_process(
                root, 40, name="large-first", ppid=1, group=40, session=40,
                rss_kib=900,
            )
            proc_process(
                root, 60, name="tiny", ppid=1, group=60, session=60,
                rss_kib=50,
            )

            processes, truncated = system_process_snapshot(
                set(), proc_root=root, limit=3, supervisor_pid=999,
            )

        self.assertTrue(truncated)
        self.assertEqual([item["pid"] for item in processes], [40, 50, 30])
        self.assertNotIn(2, [item["pid"] for item in processes])
        self.assertNotIn(20, [item["pid"] for item in processes])


if __name__ == "__main__":
    unittest.main()
