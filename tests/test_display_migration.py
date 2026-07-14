from __future__ import annotations

import asyncio
import time
import unittest
from typing import Any
from unittest.mock import patch

from msys_core.manifest import Component, Provide
from msys_core.msysd import (
    DISPLAY_MIGRATION_TOPIC,
    DISPLAY_OUTPUT_RECOVERED_SCHEMA,
    DISPLAY_OUTPUT_RECOVERED_TOPIC,
    DISPLAY_OUTPUT_ROLE,
    Instance,
    Msysd,
)
from msys_core.roles import RoleRegistry


OLD = "org.example.display:spi"
NEW = "org.example.display:hdmi"
NEXT = "org.example.display:virtual"
POLICY = "org.example.shell:policy"
SHELL = "org.example.shell:chrome"
APP = "org.example.apps:viewer"
CALLER = "org.example.apps:settings"
EXPLICIT = "org.example.apps:legacy"


def component(
    key: str,
    *,
    lifecycle: str = "background",
    display: str = "inherit",
    mode: str = "background",
) -> Component:
    package, identifier = key.split(":", 1)
    return Component(
        package_id=package,
        package_version="1.0.0",
        id=identifier,
        exec=["unused"],
        lifecycle=lifecycle,
        readiness_mode="mipc-ready",
        windowing={
            "system": "x11",
            "display": display,
            "mode": mode,
            "title": identifier,
            "identity": {
                "app_id": key.replace(":", "."),
                "x11_wm_class": key.replace(":", "."),
            },
        },
    )


def display_provider(key: str, display: str) -> Component:
    result = component(key, display=display, mode="display-provider")
    result.env = {"DISPLAY_ID": display}
    result.provides = [Provide("role", DISPLAY_OUTPUT_ROLE, exclusive=True)]
    return result


class MigrationDaemon(Msysd):
    def __init__(self, *, include_next: bool = False) -> None:
        providers = [display_provider(OLD, ":24"), display_provider(NEW, ":0")]
        if include_next:
            providers.append(display_provider(NEXT, ":9"))
        consumers = [
            component(POLICY),
            component(SHELL),
            component(APP, lifecycle="manual", mode="window"),
            component(CALLER, lifecycle="manual", mode="window"),
            component(EXPLICIT, lifecycle="manual", display=":77", mode="window"),
        ]
        next(item for item in consumers if item.key == CALLER).permissions = [
            "mipc.call:msys.core.select_role"
        ]
        self.components = {item.key: item for item in [*providers, *consumers]}
        self.profile = {
            "roles": {DISPLAY_OUTPUT_ROLE: [item.key for item in providers]},
            "startup": [OLD, POLICY, SHELL],
            "env": {},
        }
        self.role_registry = RoleRegistry.from_profile(self.components, self.profile)
        self.role_registry.acquire(DISPLAY_OUTPUT_ROLE, OLD, holder="generation:1")
        self.role_preference_overrides: dict[str, str] = {}
        self.instances: dict[str, Instance] = {}
        self.generations: dict[str, int] = {}
        for key in (OLD, POLICY, SHELL, APP, CALLER, EXPLICIT):
            self.instances[key] = self._new_instance(key)
        self.foreground_stack = [CALLER, APP, EXPLICIT]
        self.catalog_epoch = 1
        self.catalog_lock = asyncio.Lock()
        self.reload_lock = asyncio.Lock()
        self.role_locks: dict[str, asyncio.Lock] = {}
        self.supervisor_tasks: set[asyncio.Task[Any]] = set()
        self.failure_history: dict[str, list[float]] = {}
        self.spawn_backoff_until: dict[str, float] = {}
        self.spawn_retry_tasks: dict[str, asyncio.Task[Any]] = {}
        self.quarantined: set[str] = set()
        self.stop_requests: set[str] = set()
        self.start_locks: dict[str, asyncio.Lock] = {}
        self.stopping = False
        self.next_display_migration_id = 1
        self.display_migrations: dict[int, dict[str, Any]] = {}
        self.display_migration_active: int | None = None
        self.display_migration_tasks: dict[int, asyncio.Task[Any]] = {}
        self.actions: list[tuple[str, str, str | None]] = []
        self.events: list[tuple[str, dict[str, Any]]] = []
        self.persisted: list[dict[str, str]] = []
        self.fail_on: set[tuple[str, str]] = set()
        self.fail_once_on: set[tuple[str, str]] = set()
        self.fail_provider: set[str] = set()
        self.start_gates: dict[str, asyncio.Event] = {}
        self.fail_persist_once = False
        self.replace_once_on_stop: set[str] = set()
        self.replace_generation_on_ensure: set[str] = set()

    def _new_instance(self, key: str, *, ready: bool = True) -> Instance:
        generation = self.generations.get(key, 0) + 1
        self.generations[key] = generation
        return Instance(
            component=self.components[key],
            generation=generation,
            state="ready" if ready else "failed",
            ready=ready,
        )

    async def ensure_ready(self, key: str, activation=None) -> Instance:
        current = self.instances.get(key)
        if key in self.replace_generation_on_ensure:
            self.replace_generation_on_ensure.remove(key)
            current = self._new_instance(key)
            self.instances[key] = current
        if current is not None and current.ready:
            return current
        display = self._session_display()
        self.actions.append(("start", key, display))
        gate = self.start_gates.get(key)
        if gate is not None:
            await gate.wait()
        if key in self.fail_provider:
            failed = self._new_instance(key, ready=False)
            self.instances[key] = failed
            raise RuntimeError(f"provider failed: {key}")
        if (key, display) in self.fail_on:
            raise RuntimeError(f"consumer failed on {display}: {key}")
        if (key, display) in self.fail_once_on:
            self.fail_once_on.remove((key, display))
            raise RuntimeError(f"consumer failed once on {display}: {key}")
        instance = self._new_instance(key)
        self.instances[key] = instance
        self._lease_preferred_roles(instance)
        if self._is_foreground_app(instance.component):
            self._mark_foreground(key)
        return instance

    async def stop_component(self, key: str, *, expected=None) -> None:
        self.actions.append(("stop", key, self._session_display()))
        current = self.instances.get(key)
        if key in self.replace_once_on_stop and current is expected:
            self.replace_once_on_stop.remove(key)
            self.instances[key] = self._new_instance(key)
            current = self.instances[key]
        if current is None or (expected is not None and current is not expected):
            return
        self.instances.pop(key, None)
        current.ready = False
        current.finalized = True
        self.role_registry.release_provider(key)
        self.foreground_stack = [item for item in self.foreground_stack if item != key]

    async def broadcast(self, topic: str, payload: Any, source: str) -> None:
        self.events.append((topic, dict(payload)))

    def _persist_role_preferences(self) -> None:
        if self.fail_persist_once:
            self.fail_persist_once = False
            raise OSError("preference store unavailable")
        self.persisted.append(dict(self.role_preference_overrides))

    async def _reactivate_foreground(self) -> None:
        top = self.foreground_stack[0] if self.foreground_stack else ""
        self.actions.append(("activate", top, self._session_display()))


async def wait_for_migration(daemon: MigrationDaemon, migration_id: int) -> dict[str, Any]:
    for _attempt in range(100):
        record = daemon.display_migrations[migration_id]
        if record["phase"] in {"succeeded", "rolled-back"}:
            return record
        await asyncio.sleep(0)
    raise AssertionError("display migration did not complete")


class DisplayMigrationTests(unittest.IsolatedAsyncioTestCase):
    @staticmethod
    def use_same_display(daemon: MigrationDaemon) -> None:
        daemon.components[NEW].env = {"DISPLAY_ID": ":24"}
        daemon.components[NEW].windowing["display"] = ":24"

    async def test_catalog_display_replacement_captures_and_recovers_consumers(self) -> None:
        daemon = MigrationDaemon()
        outage = daemon._begin_catalog_display_outage({OLD})

        self.assertIsNotNone(outage)
        assert outage is not None
        self.assertIn(APP, outage["consumers"])
        self.assertIn(CALLER, outage["consumers"])
        self.assertNotIn(EXPLICIT, outage["consumers"])

        await daemon._suspend_display_consumers(outage)
        await daemon.stop_component(OLD)
        replacement = daemon._new_instance(OLD)
        daemon.instances[OLD] = replacement
        daemon.role_registry.acquire(DISPLAY_OUTPUT_ROLE, OLD, holder="replacement")

        await daemon._start_profile_components()

        self.assertIsNone(daemon.display_outage)
        self.assertIn(APP, daemon.instances)
        self.assertIn(CALLER, daemon.instances)
        self.assertIn(SHELL, daemon.instances)
        self.assertIn(POLICY, daemon.instances)

    async def test_unrelated_catalog_change_does_not_capture_display(self) -> None:
        daemon = MigrationDaemon()

        outage = daemon._begin_catalog_display_outage({SHELL})

        self.assertIsNone(outage)
        self.assertIsNone(getattr(daemon, "display_outage", None))

    async def test_explicit_active_display_stop_suspends_visual_session(self) -> None:
        daemon = MigrationDaemon()

        await Msysd.stop_component(daemon, OLD)

        self.assertIsNotNone(daemon.display_outage)
        self.assertNotIn(OLD, daemon.instances)
        for key in (POLICY, SHELL, APP, CALLER):
            self.assertNotIn(key, daemon.instances)
        # A client with an explicit unrelated DISPLAY is outside the failure
        # domain and remains available while :24 is stopped.
        self.assertIn(EXPLICIT, daemon.instances)

    async def test_component_call_reply_is_sent_before_requesting_ui_is_restarted(self) -> None:
        daemon = MigrationDaemon()
        caller = daemon.instances[CALLER]
        caller.sock = object()  # send_packet is patched; only channel presence matters.
        replies: list[dict[str, Any]] = []

        with patch("msys_core.msysd.send_packet", side_effect=lambda _sock, msg: replies.append(msg)):
            await daemon._dispatch_component_call(caller, {
                "type": "call",
                "id": 6,
                "target": "msys.core",
                "method": "select_role",
                "payload": {"role": DISPLAY_OUTPUT_ROLE, "provider": NEW},
            })

        self.assertEqual(len(replies), 1)
        migration = replies[0]["payload"]["migration"]
        self.assertEqual(migration["phase"], "planned")
        self.assertIs(daemon.instances[CALLER], caller)
        self.assertFalse(any(action[:2] == ("stop", CALLER) for action in daemon.actions))

        record = await wait_for_migration(daemon, migration["id"])
        self.assertEqual(record["phase"], "succeeded")
        self.assertIsNot(daemon.instances[CALLER], caller)

    async def test_success_restarts_consumers_in_profile_order_then_stops_old_provider(self) -> None:
        daemon = MigrationDaemon()
        caller_instance = daemon.instances[CALLER]
        response = await daemon._core_call(
            {
                "type": "call",
                "id": 7,
                "method": "select_role",
                "payload": {"role": DISPLAY_OUTPUT_ROLE, "provider": NEW},
            },
            source=CALLER,
        )
        migration = response["payload"]["migration"]
        self.assertEqual(migration["phase"], "planned")
        # The migration task cannot run until this core-call response has been
        # returned to _dispatch_component_call and written to the caller.
        self.assertIs(daemon.instances[CALLER], caller_instance)

        record = await wait_for_migration(daemon, migration["id"])
        self.assertEqual(record["phase"], "succeeded")
        self.assertEqual(record["restarted"], [POLICY, SHELL, APP, CALLER])
        self.assertEqual(daemon.role_registry.active_provider(DISPLAY_OUTPUT_ROLE), NEW)
        self.assertEqual(daemon._session_display(), ":0")
        self.assertNotIn(OLD, daemon.instances)
        self.assertIn(EXPLICIT, daemon.instances)
        self.assertEqual(daemon.foreground_stack[:3], [CALLER, APP, EXPLICIT])
        self.assertEqual(
            daemon.persisted,
            [{DISPLAY_OUTPUT_ROLE: NEW}],
        )

        new_start = daemon.actions.index(("start", NEW, ":24"))
        old_stop = daemon.actions.index(("stop", OLD, ":0"))
        consumer_starts = [
            action
            for action in daemon.actions
            if action[0] == "start" and action[1] in {POLICY, SHELL, APP, CALLER}
        ]
        self.assertEqual([action[1] for action in consumer_starts], [POLICY, SHELL, APP, CALLER])
        self.assertTrue(all(action[2] == ":0" for action in consumer_starts))
        self.assertLess(new_start, old_stop)
        self.assertLess(max(daemon.actions.index(action) for action in consumer_starts), old_stop)
        self.assertNotIn(("stop", EXPLICIT, ":0"), daemon.actions)
        self.assertTrue(all(topic == DISPLAY_MIGRATION_TOPIC for topic, _ in daemon.events))
        self.assertEqual(
            [payload["phase"] for _topic, payload in daemon.events],
            ["planned", "switching", "succeeded"],
        )
        self.assertEqual(daemon.events[-1][1]["phase"], "succeeded")

    async def test_same_display_provider_change_invalidates_and_restarts_session(self) -> None:
        daemon = MigrationDaemon()
        self.use_same_display(daemon)

        planned = await daemon._queue_display_migration(
            NEW,
            preference_mode="select",
            source="public",
        )
        record = await wait_for_migration(daemon, planned["id"])

        self.assertEqual(record["phase"], "succeeded")
        self.assertTrue(record["session_invalidated"])
        self.assertEqual(record["from_display"], ":24")
        self.assertEqual(record["to_display"], ":24")
        self.assertEqual(record["restarted"], [POLICY, SHELL, APP, CALLER])
        self.assertEqual(record["consumers"], [POLICY, SHELL, APP, CALLER])
        self.assertNotIn(OLD, daemon.instances)
        self.assertIn(NEW, daemon.instances)
        self.assertFalse(any(
            action[0] == "stop" and action[1] == NEW
            for action in daemon.actions
        ))
        starts = [
            action
            for action in daemon.actions
            if action[0] == "start" and action[1] in record["consumers"]
        ]
        self.assertEqual([action[1] for action in starts], record["consumers"])
        self.assertTrue(all(action[2] == ":24" for action in starts))

    async def test_same_display_consumer_failure_restores_old_session(self) -> None:
        daemon = MigrationDaemon()
        self.use_same_display(daemon)
        daemon.fail_once_on.add((APP, ":24"))

        planned = await daemon._queue_display_migration(
            NEW,
            preference_mode="select",
            source="public",
        )
        record = await wait_for_migration(daemon, planned["id"])

        self.assertEqual(record["phase"], "rolled-back")
        self.assertTrue(record["rollback_complete"])
        self.assertEqual(record["error"]["details"]["rollback_failures"], [])
        self.assertEqual(
            daemon.role_registry.active_provider(DISPLAY_OUTPUT_ROLE),
            OLD,
        )
        self.assertEqual(daemon._session_display(), ":24")
        self.assertIn(OLD, daemon.instances)
        self.assertNotIn(NEW, daemon.instances)
        for key in (POLICY, SHELL, APP, CALLER, EXPLICIT):
            self.assertTrue(daemon.instances[key].ready, key)
        self.assertEqual(daemon.foreground_stack[:3], [CALLER, APP, EXPLICIT])

    async def test_same_display_recreates_manual_windows_back_to_front(self) -> None:
        daemon = MigrationDaemon()
        self.use_same_display(daemon)
        daemon.foreground_stack = [APP, CALLER, EXPLICIT]

        planned = await daemon._queue_display_migration(
            NEW,
            preference_mode="select",
            source="public",
        )
        record = await wait_for_migration(daemon, planned["id"])

        self.assertEqual(record["phase"], "succeeded")
        self.assertEqual(record["restarted"], [POLICY, SHELL, CALLER, APP])
        starts = [
            action[1]
            for action in daemon.actions
            if action[0] == "start" and action[1] in record["consumers"]
        ]
        self.assertEqual(starts, [POLICY, SHELL, CALLER, APP])
        self.assertEqual(daemon.foreground_stack[:3], [APP, CALLER, EXPLICIT])

    async def test_same_provider_new_generation_invalidates_session(self) -> None:
        daemon = MigrationDaemon()
        daemon.replace_generation_on_ensure.add(OLD)

        planned = await daemon._queue_display_migration(
            OLD,
            preference_mode="select",
            source="public",
        )
        record = await wait_for_migration(daemon, planned["id"])

        self.assertEqual(record["phase"], "succeeded")
        self.assertTrue(record["session_invalidated"])
        self.assertEqual(record["from_display"], ":24")
        self.assertEqual(record["to_display"], ":24")
        self.assertEqual(record["from_generation"], 1)
        self.assertEqual(record["to_generation"], 2)
        self.assertEqual(record["restarted"], [POLICY, SHELL, APP, CALLER])

    async def test_consumer_failure_rolls_back_role_display_processes_and_foreground(self) -> None:
        daemon = MigrationDaemon()
        daemon.fail_on.add((APP, ":0"))
        original_caller = daemon.instances[CALLER]
        pending = await daemon._queue_display_migration(
            NEW,
            preference_mode="select",
            source=CALLER,
        )
        record = await wait_for_migration(daemon, pending["id"])

        self.assertEqual(record["phase"], "rolled-back")
        self.assertTrue(record["rollback_complete"])
        self.assertEqual(daemon.role_registry.active_provider(DISPLAY_OUTPUT_ROLE), OLD)
        self.assertEqual(daemon.role_registry.preferred_provider(DISPLAY_OUTPUT_ROLE), OLD)
        self.assertEqual(daemon._session_display(), ":24")
        self.assertIn(OLD, daemon.instances)
        self.assertNotIn(NEW, daemon.instances)
        self.assertIs(daemon.instances[CALLER], original_caller)
        for key in (POLICY, SHELL, APP, CALLER, EXPLICIT):
            self.assertTrue(daemon.instances[key].ready, key)
        self.assertEqual(daemon.foreground_stack[:3], [CALLER, APP, EXPLICIT])
        restored_starts = [
            action
            for action in daemon.actions
            if action[0] == "start" and action[2] == ":24" and action[1] in {POLICY, SHELL, APP}
        ]
        self.assertEqual([action[1] for action in restored_starts], [POLICY, SHELL, APP])
        self.assertEqual(record["error"]["details"]["rollback_failures"], [])
        self.assertEqual(daemon.persisted, [{}])
        self.assertEqual(daemon.events[-1][1]["phase"], "rolled-back")

    async def test_new_provider_readiness_failure_never_disconnects_old_session(self) -> None:
        daemon = MigrationDaemon()
        daemon.fail_provider.add(NEW)
        originals = dict(daemon.instances)
        pending = await daemon._queue_display_migration(
            NEW,
            preference_mode="select",
            source="public",
        )
        record = await wait_for_migration(daemon, pending["id"])

        self.assertEqual(record["phase"], "rolled-back")
        self.assertTrue(record["rollback_complete"])
        self.assertEqual(daemon.role_registry.active_provider(DISPLAY_OUTPUT_ROLE), OLD)
        self.assertEqual(daemon._session_display(), ":24")
        self.assertNotIn(NEW, daemon.instances)
        for key, instance in originals.items():
            self.assertIs(daemon.instances[key], instance)
        self.assertFalse(any(action[0] == "stop" and action[1] == OLD for action in daemon.actions))

    async def test_rollback_health_reports_a_consumer_that_cannot_be_restored(self) -> None:
        daemon = MigrationDaemon()
        daemon.fail_on.update({(APP, ":0"), (POLICY, ":24")})
        planned = await daemon._queue_display_migration(
            NEW,
            preference_mode="select",
            source="public",
        )
        record = await wait_for_migration(daemon, planned["id"])

        self.assertEqual(record["phase"], "rolled-back")
        self.assertFalse(record["rollback_complete"])
        self.assertEqual(daemon.role_registry.active_provider(DISPLAY_OUTPUT_ROLE), OLD)
        self.assertEqual(daemon._session_display(), ":24")
        failures = record["error"]["details"]["rollback_failures"]
        self.assertTrue(
            any(item["step"] == f"restore-consumer:{POLICY}" for item in failures)
        )

    async def test_preference_commit_failure_rolls_back_after_consumer_health_gate(self) -> None:
        daemon = MigrationDaemon()
        daemon.fail_persist_once = True
        pending = await daemon._queue_display_migration(
            NEW,
            preference_mode="select",
            source="public",
        )
        record = await wait_for_migration(daemon, pending["id"])
        self.assertEqual(record["phase"], "rolled-back")
        self.assertTrue(record["rollback_complete"])
        self.assertEqual(daemon.role_registry.active_provider(DISPLAY_OUTPUT_ROLE), OLD)
        self.assertEqual(daemon._session_display(), ":24")
        self.assertNotIn(NEW, daemon.instances)
        self.assertEqual(daemon.persisted, [{}])
        for key in (POLICY, SHELL, APP, CALLER):
            starts = [
                action for action in daemon.actions
                if action[0] == "start" and action[1] == key
            ]
            self.assertEqual([action[2] for action in starts], [":0", ":24"])

    async def test_concurrent_requests_are_queued_and_serialized(self) -> None:
        daemon = MigrationDaemon(include_next=True)
        gate = asyncio.Event()
        daemon.start_gates[NEW] = gate
        first = await daemon._queue_display_migration(
            NEW,
            preference_mode="select",
            source="first",
        )
        await asyncio.sleep(0)
        self.assertEqual(daemon.display_migration_active, first["id"])
        second = await daemon._queue_display_migration(
            NEXT,
            preference_mode="select",
            source="second",
        )
        await asyncio.sleep(0)
        self.assertTrue(daemon.display_migrations[second["id"]]["queued"])
        self.assertFalse(any(action[0] == "start" and action[1] == NEXT for action in daemon.actions))

        gate.set()
        first_record = await wait_for_migration(daemon, first["id"])
        second_record = await wait_for_migration(daemon, second["id"])
        self.assertEqual(first_record["phase"], "succeeded")
        self.assertEqual(second_record["phase"], "succeeded")
        self.assertEqual(second_record["from_provider"], NEW)
        self.assertEqual(daemon.role_registry.active_provider(DISPLAY_OUTPUT_ROLE), NEXT)
        self.assertEqual(daemon._session_display(), ":9")

    async def test_rollback_preserves_a_target_provider_that_was_already_running(self) -> None:
        daemon = MigrationDaemon()
        preexisting_target = daemon._new_instance(NEW)
        daemon.instances[NEW] = preexisting_target
        daemon.fail_on.add((APP, ":0"))

        planned = await daemon._queue_display_migration(
            NEW,
            preference_mode="select",
            source="public",
        )
        record = await wait_for_migration(daemon, planned["id"])

        self.assertEqual(record["phase"], "rolled-back")
        self.assertIs(daemon.instances[NEW], preexisting_target)
        self.assertTrue(preexisting_target.ready)
        self.assertEqual(daemon.role_registry.active_provider(DISPLAY_OUTPUT_ROLE), OLD)
        self.assertFalse(
            any(action[0] == "stop" and action[1] == NEW for action in daemon.actions)
        )

    async def test_success_retires_a_replacement_generation_of_the_old_provider(self) -> None:
        daemon = MigrationDaemon()
        daemon.replace_once_on_stop.add(OLD)
        planned = await daemon._queue_display_migration(
            NEW,
            preference_mode="select",
            source="public",
        )
        record = await wait_for_migration(daemon, planned["id"])

        self.assertEqual(record["phase"], "succeeded")
        self.assertNotIn(OLD, daemon.instances)
        old_stop_attempts = [
            action for action in daemon.actions
            if action[0] == "stop" and action[1] == OLD
        ]
        self.assertEqual(len(old_stop_attempts), 2)

    async def test_reset_role_migrates_back_to_profile_default_and_clears_override(self) -> None:
        daemon = MigrationDaemon()
        for lease in daemon.role_registry.active_leases(DISPLAY_OUTPUT_ROLE):
            daemon.role_registry.release(lease)
        daemon.role_registry.select_preferred(DISPLAY_OUTPUT_ROLE, NEW)
        daemon.role_preference_overrides[DISPLAY_OUTPUT_ROLE] = NEW
        new_instance = daemon._new_instance(NEW)
        daemon.instances[NEW] = new_instance
        daemon.role_registry.acquire(
            DISPLAY_OUTPUT_ROLE,
            NEW,
            holder=f"generation:{new_instance.generation}",
        )

        response = await daemon._core_call({
            "type": "call",
            "id": 11,
            "method": "reset_role",
            "payload": {"role": DISPLAY_OUTPUT_ROLE},
        })
        pending = response["payload"]["migration"]
        record = await wait_for_migration(daemon, pending["id"])
        self.assertEqual(record["phase"], "succeeded")
        self.assertEqual(daemon.role_registry.active_provider(DISPLAY_OUTPUT_ROLE), OLD)
        self.assertEqual(daemon.role_registry.preferred_provider(DISPLAY_OUTPUT_ROLE), OLD)
        self.assertNotIn(DISPLAY_OUTPUT_ROLE, daemon.role_preference_overrides)
        self.assertNotIn(NEW, daemon.instances)
        self.assertEqual(daemon._session_display(), ":24")

    async def test_status_query_and_bad_id_are_structured(self) -> None:
        daemon = MigrationDaemon()
        idle = await daemon._core_call({
            "type": "call",
            "id": 1,
            "method": "display_migration_status",
            "payload": {},
        })
        self.assertEqual(idle["payload"]["migration"]["phase"], "idle")
        bad = await daemon._core_call({
            "type": "call",
            "id": 2,
            "method": "display_migration_status",
            "payload": {"id": True},
        })
        self.assertEqual(bad["code"], "BAD_PAYLOAD")

    async def test_non_display_role_keeps_existing_synchronous_switch_path(self) -> None:
        class OtherRoleDaemon:
            role_locks: dict[str, asyncio.Lock] = {}

            async def _switch_role(self, role, provider, *, preference_mode):
                self.switched = (role, provider, preference_mode)
                return {"role": role, "active": provider}

            async def _queue_display_migration(self, *_args, **_kwargs):
                raise AssertionError("display migration path used for another role")

        daemon = OtherRoleDaemon()
        response = await Msysd._core_call(daemon, {
            "type": "call",
            "id": 3,
            "method": "select_role",
            "payload": {"role": "launcher", "provider": "org.example:launcher"},
        })
        self.assertEqual(response["payload"]["active"], "org.example:launcher")
        self.assertEqual(
            daemon.switched,
            ("launcher", "org.example:launcher", "select"),
        )


class DisplayProviderRecoveryTests(unittest.IsolatedAsyncioTestCase):
    async def crash_active_provider(self, daemon: MigrationDaemon) -> None:
        await daemon._finalize_exited_instance(
            daemon.instances[OLD],
            1,
            include_watch=True,
        )

    async def fail_backup_migration(
        self,
        daemon: MigrationDaemon,
    ) -> dict[str, Any]:
        daemon.fail_once_on.add((SHELL, ":0"))
        planned = await daemon._queue_display_migration(
            NEW,
            preference_mode="select",
            source="public",
        )
        return await wait_for_migration(daemon, planned["id"])

    async def test_provider_crash_waits_for_delayed_generation_then_recovers_shell(self) -> None:
        daemon = MigrationDaemon()
        daemon.failure_history[SHELL] = [1.0, 2.0]
        failed_provider = daemon.instances[OLD]

        await daemon._finalize_exited_instance(
            failed_provider,
            1,
            include_watch=True,
        )

        self.assertIsNotNone(daemon.display_outage)
        self.assertEqual(
            daemon.display_outage["consumers"],
            [POLICY, SHELL],
        )
        self.assertEqual(
            daemon.display_outage["dropped_applications"],
            [APP, CALLER],
        )
        for key in (POLICY, SHELL, APP, CALLER):
            self.assertNotIn(key, daemon.instances)
            self.assertNotIn(key, daemon.quarantined)
        self.assertIn(EXPLICIT, daemon.instances)
        self.assertFalse(any(action[0] == "start" for action in daemon.actions))

        # Client failures observed while X is absent do not consume their own
        # supervision budget.  The prior, unrelated budget remains intact.
        for _attempt in range(8):
            self.assertIsNone(daemon._record_component_failure(SHELL))
        self.assertEqual(daemon.failure_history[SHELL], [1.0, 2.0])

        await asyncio.sleep(0)
        replacement = daemon._new_instance(OLD)
        daemon.instances[OLD] = replacement
        recovery = daemon._component_became_ready(replacement)
        self.assertIsNotNone(recovery)
        await recovery

        self.assertIsNone(daemon.display_outage)
        self.assertEqual(
            daemon.role_registry.active_provider(DISPLAY_OUTPUT_ROLE),
            OLD,
        )
        starts = [
            action[1]
            for action in daemon.actions
            if action[0] == "start"
        ]
        self.assertEqual(starts, [POLICY, SHELL])
        for key in (POLICY, SHELL, EXPLICIT):
            self.assertTrue(daemon.instances[key].ready, key)
        for key in (APP, CALLER):
            self.assertNotIn(key, daemon.instances)
        self.assertEqual(daemon.failure_history[SHELL], [1.0, 2.0])
        self.assertEqual(daemon.foreground_stack, [EXPLICIT])
        topic, payload = daemon.events[-1]
        self.assertEqual(topic, DISPLAY_OUTPUT_RECOVERED_TOPIC)
        self.assertEqual(payload["schema"], DISPLAY_OUTPUT_RECOVERED_SCHEMA)
        self.assertEqual(payload["fault"], "display-session-lost")
        self.assertFalse(payload["session_preserved"])
        self.assertFalse(payload["applications_reopened"])
        self.assertEqual(payload["restarted_system_ui"], [POLICY, SHELL])
        self.assertEqual(payload["dropped_applications"], [APP, CALLER])

    async def test_late_provider_detection_recovers_recent_visual_quarantine(self) -> None:
        daemon = MigrationDaemon()
        now = time.monotonic()
        recent = [now - 4.0, now - 3.0, now - 2.0, now - 1.0, now]
        daemon.failure_history[SHELL] = list(recent)
        daemon.quarantined.add(SHELL)
        daemon.quarantine_times = {SHELL: now}

        await daemon._finalize_exited_instance(
            daemon.instances[OLD],
            1,
            include_watch=True,
        )

        self.assertNotIn(SHELL, daemon.quarantined)
        self.assertEqual(daemon.display_outage["failure_history"][SHELL], [])
        replacement = daemon._new_instance(OLD)
        daemon.instances[OLD] = replacement
        recovery = daemon._component_became_ready(replacement)
        self.assertIsNotNone(recovery)
        await recovery
        self.assertTrue(daemon.instances[SHELL].ready)
        self.assertNotIn(SHELL, daemon.failure_history)

    async def test_planned_provider_stop_keeps_recent_visual_quarantine(self) -> None:
        daemon = MigrationDaemon()
        now = time.monotonic()
        daemon.failure_history[SHELL] = [now]
        daemon.quarantined.add(SHELL)
        daemon.quarantine_times = {SHELL: now}

        outage = daemon._begin_display_outage(daemon.instances[OLD])

        self.assertIsNotNone(outage)
        self.assertIn(SHELL, daemon.quarantined)
        self.assertIn(SHELL, outage["preexisting_quarantine"])
        self.assertEqual(outage["failure_history"][SHELL], [now])

    async def test_persistent_provider_failure_keeps_consumers_suspended(self) -> None:
        daemon = MigrationDaemon()
        # Model an operator quarantine that predates the display fault.  It
        # must remain distinct from the display recovery budget.
        daemon.quarantined.add(POLICY)
        failed_provider = daemon.instances[OLD]

        await daemon._finalize_exited_instance(
            failed_provider,
            1,
            include_watch=True,
        )

        for _attempt in range(8):
            self.assertIsNone(daemon._record_component_failure(SHELL))
        for _attempt in range(5):
            daemon._record_component_failure(OLD)
            daemon._record_component_failure(EXPLICIT)

        self.assertIsNotNone(daemon.display_outage)
        self.assertIn(OLD, daemon.quarantined)
        self.assertIn(POLICY, daemon.quarantined)
        self.assertIn(EXPLICIT, daemon.quarantined)
        self.assertNotIn(SHELL, daemon.quarantined)
        self.assertEqual(daemon.failure_history.get(SHELL), None)
        self.assertFalse(any(action[0] == "start" for action in daemon.actions))
        for key in (POLICY, SHELL, APP, CALLER):
            self.assertNotIn(key, daemon.instances)

        failed_replacement = daemon._new_instance(OLD, ready=False)
        daemon.instances[OLD] = failed_replacement
        self.assertIsNone(daemon._schedule_display_recovery(failed_replacement))
        await asyncio.sleep(0)
        self.assertIsNotNone(daemon.display_outage)

    async def test_outage_switch_to_backup_adopts_saved_visual_session(self) -> None:
        daemon = MigrationDaemon()
        await self.crash_active_provider(daemon)
        saved_foreground = list(daemon.display_outage["foreground"])

        planned = await daemon._queue_display_migration(
            NEW,
            preference_mode="select",
            source="public",
        )
        record = await wait_for_migration(daemon, planned["id"])

        self.assertEqual(record["phase"], "succeeded")
        self.assertTrue(record["recovering_outage"])
        self.assertEqual(record["consumers"], [POLICY, SHELL])
        self.assertEqual(record["restarted"], [POLICY, SHELL])
        self.assertIsNone(daemon.display_outage)
        self.assertEqual(
            daemon.role_registry.active_provider(DISPLAY_OUTPUT_ROLE),
            NEW,
        )
        self.assertNotIn(OLD, daemon.instances)
        starts = [
            action
            for action in daemon.actions
            if action[0] == "start" and action[1] in record["consumers"]
        ]
        self.assertEqual(
            [action[1] for action in starts],
            [POLICY, SHELL],
        )
        self.assertTrue(all(action[2] == ":0" for action in starts))
        self.assertEqual(saved_foreground, [CALLER, APP, EXPLICIT])
        self.assertEqual(daemon.foreground_stack, [EXPLICIT])
        self.assertNotIn(APP, daemon.instances)
        self.assertNotIn(CALLER, daemon.instances)

    async def test_outage_switch_failure_preserves_snapshot_and_stopped_clients(self) -> None:
        daemon = MigrationDaemon()
        await self.crash_active_provider(daemon)
        saved = daemon._clone_display_outage(daemon.display_outage)

        record = await self.fail_backup_migration(daemon)

        self.assertEqual(record["phase"], "rolled-back")
        self.assertTrue(record["rollback_complete"])
        self.assertIsNotNone(daemon.display_outage)
        self.assertEqual(daemon.display_outage["id"], saved["id"])
        self.assertEqual(daemon.display_outage["consumers"], saved["consumers"])
        self.assertEqual(daemon.display_outage["foreground"], saved["foreground"])
        self.assertEqual(
            daemon.role_registry.preferred_provider(DISPLAY_OUTPUT_ROLE),
            OLD,
        )
        self.assertIsNone(
            daemon.role_registry.active_provider(DISPLAY_OUTPUT_ROLE)
        )
        self.assertNotIn(NEW, daemon.instances)
        for key in (POLICY, SHELL, APP, CALLER):
            self.assertNotIn(key, daemon.instances)
            self.assertNotIn(key, daemon.quarantined)
        old_display_starts = [
            action
            for action in daemon.actions
            if action[0] == "start"
            and action[1] in saved["consumers"]
            and action[2] == ":24"
        ]
        self.assertEqual(old_display_starts, [])

    async def test_outage_backup_readiness_failure_keeps_original_waiting(self) -> None:
        daemon = MigrationDaemon()
        await self.crash_active_provider(daemon)
        saved = daemon._clone_display_outage(daemon.display_outage)
        daemon.fail_provider.add(NEW)

        planned = await daemon._queue_display_migration(
            NEW,
            preference_mode="select",
            source="public",
        )
        record = await wait_for_migration(daemon, planned["id"])

        self.assertEqual(record["phase"], "rolled-back")
        self.assertTrue(record["rollback_complete"])
        self.assertEqual(daemon.display_outage["id"], saved["id"])
        self.assertEqual(daemon.display_outage["consumers"], saved["consumers"])
        self.assertNotIn(NEW, daemon.instances)
        self.assertIsNone(
            daemon.role_registry.active_provider(DISPLAY_OUTPUT_ROLE)
        )
        for key in saved["consumers"]:
            self.assertNotIn(key, daemon.instances)
        self.assertFalse(any(
            action[0] == "start" and action[1] in saved["consumers"]
            for action in daemon.actions
        ))

    async def test_outage_rollback_recovers_once_when_original_is_late_ready(self) -> None:
        daemon = MigrationDaemon()
        await self.crash_active_provider(daemon)
        record = await self.fail_backup_migration(daemon)
        self.assertEqual(record["phase"], "rolled-back")
        self.assertIsNotNone(daemon.display_outage)

        action_boundary = len(daemon.actions)
        replacement = daemon._new_instance(OLD)
        daemon.instances[OLD] = replacement
        recovery = daemon._component_became_ready(replacement)
        self.assertIsNotNone(recovery)
        await recovery

        self.assertIsNone(daemon.display_outage)
        self.assertEqual(
            daemon.role_registry.active_provider(DISPLAY_OUTPUT_ROLE),
            OLD,
        )
        recovery_starts = [
            action[1]
            for action in daemon.actions[action_boundary:]
            if action[0] == "start"
        ]
        self.assertEqual(recovery_starts, [POLICY, SHELL])
        live_consumers = {
            key: daemon.instances[key]
            for key in (POLICY, SHELL)
        }
        self.assertIsNone(daemon._component_became_ready(replacement))
        await asyncio.sleep(0)
        self.assertEqual(
            {key: daemon.instances[key] for key in live_consumers},
            live_consumers,
        )

    async def test_old_provider_late_ready_after_backup_success_does_not_double_start(self) -> None:
        daemon = MigrationDaemon()
        await self.crash_active_provider(daemon)
        planned = await daemon._queue_display_migration(
            NEW,
            preference_mode="select",
            source="public",
        )
        record = await wait_for_migration(daemon, planned["id"])
        self.assertEqual(record["phase"], "succeeded")
        live_consumers = {
            key: daemon.instances[key]
            for key in (POLICY, SHELL)
        }
        start_count = sum(
            action[0] == "start" and action[1] in live_consumers
            for action in daemon.actions
        )

        late_old = daemon._new_instance(OLD)
        daemon.instances[OLD] = late_old
        self.assertIsNone(daemon._component_became_ready(late_old))
        await asyncio.sleep(0)

        self.assertIsNone(daemon.display_outage)
        self.assertEqual(
            daemon.role_registry.active_provider(DISPLAY_OUTPUT_ROLE),
            NEW,
        )
        self.assertEqual(
            sum(
                action[0] == "start" and action[1] in live_consumers
                for action in daemon.actions
            ),
            start_count,
        )
        self.assertEqual(
            {key: daemon.instances[key] for key in live_consumers},
            live_consumers,
        )

    async def test_old_ready_queued_during_backup_switch_is_fenced(self) -> None:
        daemon = MigrationDaemon()
        await self.crash_active_provider(daemon)
        target_gate = asyncio.Event()
        daemon.start_gates[NEW] = target_gate

        planned = await daemon._queue_display_migration(
            NEW,
            preference_mode="select",
            source="public",
        )
        await asyncio.sleep(0)
        self.assertEqual(
            daemon.display_migrations[planned["id"]]["phase"],
            "switching",
        )

        late_old = daemon._new_instance(OLD)
        daemon.instances[OLD] = late_old
        stale_recovery = daemon._component_became_ready(late_old)
        self.assertIsNotNone(stale_recovery)
        await asyncio.sleep(0)
        self.assertFalse(stale_recovery.done())

        target_gate.set()
        record = await wait_for_migration(daemon, planned["id"])
        await stale_recovery

        self.assertEqual(record["phase"], "succeeded")
        self.assertIsNone(daemon.display_outage)
        self.assertEqual(
            daemon.role_registry.active_provider(DISPLAY_OUTPUT_ROLE),
            NEW,
        )
        consumer_starts = [
            action[1]
            for action in daemon.actions
            if action[0] == "start"
            and action[1] in {POLICY, SHELL, APP, CALLER}
        ]
        self.assertEqual(consumer_starts, [POLICY, SHELL])


if __name__ == "__main__":
    unittest.main()
