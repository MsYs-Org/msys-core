from __future__ import annotations

import types
import unittest

from msys_core.manifest import Component
from msys_core.msysd import Instance, Msysd


def app() -> Component:
    return Component(
        package_id="org.example.app",
        package_version="1.0.0",
        package_name="Example Package",
        id="main",
        exec=["app"],
        lifecycle="manual",
        raw={"name": "Example App"},
        windowing={
            "mode": "window",
            "title": "Fallback Title",
            "identity": {
                "app_id": "org.example.app",
                "x11_wm_class": "OrgExampleApp",
            },
        },
    )


class LifecycleTransitionTests(unittest.IsolatedAsyncioTestCase):
    async def test_transition_payload_uses_stable_component_and_identity(self) -> None:
        daemon = object.__new__(Msysd)
        sent: list[tuple[str, dict, str]] = []

        async def broadcast(topic, payload, source):
            sent.append((topic, payload, source))

        daemon.broadcast = broadcast
        await Msysd._emit_component_transition(
            daemon,
            "launching",
            app(),
            generation=4,
        )

        topic, payload, source = sent[0]
        self.assertEqual(topic, "msys.lifecycle.transition")
        self.assertEqual(source, "msys.core")
        self.assertEqual(payload["component"], "org.example.app:main")
        self.assertEqual(payload["identity"], "OrgExampleApp")
        self.assertEqual(payload["title"], "Example App")
        self.assertEqual(payload["generation"], 4)

    async def test_ready_emits_launched_only_once_per_generation(self) -> None:
        component = app()
        instance = types.SimpleNamespace(
            component=component,
            generation=3,
            ready=True,
            transition_launched=False,
        )

        class FakeDaemon:
            instances = {component.key: instance}

            async def ensure_started(self, key, activation=None):
                return instance

            def _lease_preferred_roles(self, selected):
                self.leased = selected

            def _is_foreground_app(self, selected):
                return Msysd._is_foreground_app(self, selected)

            async def _emit_component_transition(self, phase, selected, **payload):
                self.transitions = getattr(self, "transitions", []) + [
                    (phase, selected.key, payload)
                ]

        daemon = FakeDaemon()
        await Msysd.ensure_ready(daemon, component.key)
        await Msysd.ensure_ready(daemon, component.key)
        self.assertEqual([item[0] for item in daemon.transitions], ["launched"])

    async def test_unknown_phase_is_rejected(self) -> None:
        daemon = object.__new__(Msysd)
        daemon.broadcast = None
        with self.assertRaises(ValueError):
            await Msysd._emit_component_transition(daemon, "opening", app())

    async def test_preclose_targets_live_foreground_generation_once(self) -> None:
        class RunningProcess:
            returncode = 0

            def poll(self):
                return None

        foreground = app()
        overlay = Component(
            package_id="org.example.overlay",
            package_version="1.0.0",
            id="chrome",
            exec=["unused"],
            lifecycle="background",
            windowing={"system": "x11", "mode": "overlay"},
        )
        foreground_instance = Instance(
            component=foreground,
            generation=7,
            process=RunningProcess(),  # type: ignore[arg-type]
        )
        overlay_instance = Instance(
            component=overlay,
            generation=2,
            process=RunningProcess(),  # type: ignore[arg-type]
        )
        daemon = object.__new__(Msysd)
        daemon.instances = {
            foreground.key: foreground_instance,
            overlay.key: overlay_instance,
        }
        # Even a corrupt/stale stack entry must not turn a system overlay into
        # the target of an application close animation.
        daemon.foreground_stack = [overlay.key, foreground.key]
        transitions: list[tuple[str, str, int]] = []

        async def emit(phase, selected, *, generation=0, **_payload):
            transitions.append((phase, selected.key, generation))

        daemon._emit_component_transition = emit

        first = await daemon._announce_foreground_closing()
        second = await daemon._announce_foreground_closing()

        self.assertIs(first, foreground_instance)
        self.assertIsNone(second)
        self.assertTrue(foreground_instance.transition_closing)
        self.assertFalse(overlay_instance.transition_closing)
        self.assertEqual(transitions, [("closing", foreground.key, 7)])

        daemon.stopping = False
        daemon.role_registry = types.SimpleNamespace(release_provider=lambda _key: ())

        async def cancel_tasks(_instance, *, include_watch):
            self.assertTrue(include_watch)

        async def terminate(_instance):
            return None

        daemon._cancel_instance_tasks = cancel_tasks
        daemon._terminate_instance_process = terminate
        await daemon._stop_component_locked(foreground.key)

        self.assertEqual(
            transitions,
            [
                ("closing", foreground.key, 7),
                ("closed", foreground.key, 7),
            ],
        )

    async def test_manual_app_crash_notifies_once_and_never_restarts(self) -> None:
        class ExitedProcess:
            returncode = 23
            pid = 8123

            def poll(self):
                return self.returncode

        component = app()
        component.restart = "on-failure"
        instance = Instance(
            component=component,
            generation=9,
            process=ExitedProcess(),  # type: ignore[arg-type]
            state="ready",
            ready=True,
        )
        daemon = object.__new__(Msysd)
        daemon.components = {component.key: component}
        daemon.instances = {component.key: instance}
        daemon.foreground_stack = [component.key]
        daemon.backgrounded_components = set()
        daemon.stopping = False
        daemon.role_registry = types.SimpleNamespace(
            release_provider=lambda _key: None
        )
        daemon._begin_unplanned_display_failure = lambda *_args, **_kwargs: None
        events: list[tuple[str, dict, str]] = []

        async def broadcast(topic, payload, source):
            events.append((topic, payload, source))

        daemon.broadcast = broadcast

        first = await daemon._finalize_exited_instance(
            instance, 23, include_watch=True
        )
        second = await daemon._finalize_exited_instance(
            instance, 23, include_watch=True
        )

        self.assertTrue(first)
        self.assertFalse(second)
        notifications = [
            payload for topic, payload, source in events
            if topic == "msys.notification.post" and source == "msys.core"
        ]
        self.assertEqual(len(notifications), 1)
        self.assertEqual(notifications[0]["schema"], "msys.application-crash.v1")
        self.assertEqual(notifications[0]["component"], component.key)
        self.assertEqual(notifications[0]["generation"], 9)
        self.assertEqual(notifications[0]["returncode"], 23)
        self.assertEqual(
            notifications[0]["reason"], "unexpected-process-exit"
        )
        self.assertFalse(daemon._should_restart(instance, 23))


if __name__ == "__main__":
    unittest.main()
