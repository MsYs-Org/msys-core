from __future__ import annotations

import json
import socket
import struct
import types
import unittest
from unittest.mock import AsyncMock, patch

from msys_core.manifest import Component, Provide
from msys_core.mipc_acl import (
    allows_call,
    allows_event,
    call_permission_candidates,
    subscription_covers,
)
from msys_core.msysd import Msysd, PeerCredentials


class CaptureSocket:
    def __init__(self) -> None:
        self.packets: list[dict] = []

    def sendall(self, data: bytes) -> None:
        self.packets.append(json.loads(data.decode("utf-8")))


def make_instance(*permissions: str, identifier: str = "caller"):
    component = Component(
        package_id="org.example.acl",
        package_version="1.0.0",
        id=identifier,
        exec=[],
        lifecycle="background",
        permissions=list(permissions),
    )
    return types.SimpleNamespace(
        component=component,
        sock=CaptureSocket(),
        subscriptions=set(),
    )


def make_daemon(instance=None):
    daemon = object.__new__(Msysd)
    daemon.instances = {}
    daemon.components = {}
    if instance is not None:
        daemon.instances[instance.component.key] = instance
    return daemon


class PublicReader:
    def __init__(self, message: dict) -> None:
        self.data = (json.dumps(message) + "\n").encode("utf-8")

    async def readline(self) -> bytes:
        return self.data


class PublicWriter:
    def __init__(self) -> None:
        self.writes: list[bytes] = []
        self.closed = False

    def write(self, data: bytes) -> None:
        self.writes.append(data)

    async def drain(self) -> None:
        return None

    def close(self) -> None:
        self.closed = True

    async def wait_closed(self) -> None:
        return None

    def response(self) -> dict:
        return json.loads(self.writes[-1].decode("utf-8"))


class PermissionMatchingTests(unittest.TestCase):
    def test_core_target_and_method_grants_are_exact(self) -> None:
        self.assertTrue(
            allows_call(["mipc.call:msys.core.discover"], "msys.core", "discover")
        )
        self.assertFalse(
            allows_call(["mipc.call:msys.core.discover"], "msys.core", "start")
        )
        self.assertTrue(allows_call(["mipc.call:msys.core"], "msys.core", "start"))
        self.assertFalse(
            allows_call(["mipc.call:msys.corex"], "msys.core", "discover")
        )

    def test_role_interface_and_component_targets_do_not_prefix_match(self) -> None:
        self.assertTrue(
            allows_call(["mipc.call:role:launcher"], "role:launcher", "open")
        )
        self.assertFalse(
            allows_call(["mipc.call:role:launch"], "role:launcher", "open")
        )
        self.assertTrue(
            allows_call(
                ["mipc.call:interface:org.example.inventory.v1"],
                "interface:org.example.inventory.v1",
                "list",
            )
        )
        self.assertTrue(
            allows_call(
                ["mipc.call:org.example.inventory.v1"],
                "interface:org.example.inventory.v1",
                "list",
            )
        )
        self.assertTrue(
            allows_call(
                ["mipc.call:component:org.example.provider:main"],
                "component:org.example.provider:main",
                "probe",
            )
        )
        self.assertFalse(
            allows_call(
                ["mipc.call:component:org.example.provider:main"],
                "component:org.example.provider:main-extra",
                "probe",
            )
        )

    def test_any_target_grant_is_explicit_and_method_grants_are_exact(self) -> None:
        self.assertTrue(allows_call(["mipc.call:*"], "role:any", "mutate"))
        self.assertTrue(
            allows_call(
                ["mipc.call:role:window-manager.get_layout"],
                "role:window-manager",
                "get_layout",
            )
        )
        self.assertFalse(
            allows_call(
                ["mipc.call:role:window-manager.get_layout"],
                "role:window-manager",
                "set_layout",
            )
        )
        self.assertTrue(allows_call(
            ["mipc.call:org.msys.hal.manager.v1.inventory"],
            "interface:org.msys.hal.manager.v1",
            "inventory",
        ))
        self.assertTrue(allows_call(
            ["mipc.call:component:org.example.provider:main.probe"],
            "component:org.example.provider:main",
            "probe",
        ))
        candidates = call_permission_candidates("msys.core", "discover")
        self.assertEqual(
            candidates,
            ("mipc.call:msys.core.discover", "mipc.call:msys.core"),
        )

    def test_event_grants_only_use_a_trailing_wildcard(self) -> None:
        self.assertTrue(
            allows_event(
                ["mipc.event:publish:msys.hal.*"],
                "publish",
                "msys.hal.changed",
            )
        )
        self.assertFalse(
            allows_event(
                ["mipc.event:publish:msys.*.changed"],
                "publish",
                "msys.hal.changed",
            )
        )
        self.assertTrue(subscription_covers("msys.hal.*", "msys.hal.power.*"))
        self.assertTrue(subscription_covers("msys.hal.*", "msys.hal.changed"))
        self.assertFalse(subscription_covers("msys.hal.changed", "msys.hal.*"))
        self.assertFalse(subscription_covers("msys.hal.*", "msys.power.changed"))


class EnforcementTests(unittest.IsolatedAsyncioTestCase):
    async def test_interface_grant_authorizes_exact_catalog_provider_call(self) -> None:
        instance = make_instance("mipc.call:org.example.inventory.v1")
        daemon = make_daemon(instance)
        provider = Component(
            package_id="org.example.provider",
            package_version="1.0.0",
            id="main",
            exec=[],
            lifecycle="on-demand",
            provides=[Provide(kind="interface", name="org.example.inventory.v1")],
        )
        daemon.components[provider.key] = provider
        daemon.dispatch_call = AsyncMock(
            return_value={"type": "return", "id": 91, "payload": {"ok": True}}
        )
        message = {
            "type": "call",
            "id": 91,
            "target": f"component:{provider.key}",
            "method": "describe",
        }

        await Msysd._dispatch_component_call(daemon, instance, message)

        daemon.dispatch_call.assert_awaited_once_with(
            message,
            source=instance.component.key,
        )
        self.assertEqual(instance.sock.packets[0]["type"], "return")

    async def test_interface_grant_does_not_cover_non_provider_or_other_method(self) -> None:
        instance = make_instance("mipc.call:org.example.inventory.v1.describe")
        daemon = make_daemon(instance)
        provider = Component(
            package_id="org.example.provider",
            package_version="1.0.0",
            id="main",
            exec=[],
            lifecycle="on-demand",
            provides=[Provide(kind="interface", name="org.example.other.v1")],
        )
        daemon.components[provider.key] = provider

        wrong_interface = Msysd._authorize_component_call(daemon, instance, {
            "type": "call",
            "id": 92,
            "target": f"component:{provider.key}",
            "method": "describe",
        })
        provider.provides = [
            Provide(kind="interface", name="org.example.inventory.v1")
        ]
        wrong_method = Msysd._authorize_component_call(daemon, instance, {
            "type": "call",
            "id": 93,
            "target": f"component:{provider.key}",
            "method": "set_state",
        })

        self.assertEqual(wrong_interface["code"], "ACCESS_DENIED")
        self.assertEqual(wrong_method["code"], "ACCESS_DENIED")

    async def test_denied_call_returns_access_denied_without_dispatch(self) -> None:
        instance = make_instance()
        daemon = make_daemon(instance)
        daemon.dispatch_call = AsyncMock()
        message = {
            "type": "call",
            "id": 41,
            "target": "role:window-manager",
            "method": "close_active",
        }

        with patch("builtins.print") as output:
            await Msysd._dispatch_component_call(daemon, instance, message)

        daemon.dispatch_call.assert_not_awaited()
        self.assertEqual(len(instance.sock.packets), 1)
        denial = instance.sock.packets[0]
        self.assertEqual(denial["type"], "error")
        self.assertEqual(denial["id"], 41)
        self.assertEqual(denial["code"], "ACCESS_DENIED")
        self.assertEqual(denial["payload"]["operation"], "call")
        self.assertIn("access denied", output.call_args_list[0].args[0])

    async def test_allowed_call_is_dispatched_and_replied(self) -> None:
        instance = make_instance("mipc.call:role:window-manager")
        daemon = make_daemon(instance)
        daemon.dispatch_call = AsyncMock(
            return_value={"type": "return", "id": 7, "payload": {"ok": True}}
        )
        message = {
            "type": "call",
            "id": 7,
            "target": "role:window-manager",
            "method": "home",
        }

        await Msysd._dispatch_component_call(daemon, instance, message)

        daemon.dispatch_call.assert_awaited_once_with(
            message,
            source=instance.component.key,
        )
        self.assertEqual(instance.sock.packets[0]["type"], "return")

    async def test_denied_subscribe_without_id_is_observable_and_not_installed(self) -> None:
        instance = make_instance()
        daemon = make_daemon(instance)

        await Msysd._handle_component_message(
            daemon,
            instance,
            {"type": "subscribe", "topic": "msys.secret.changed"},
        )

        self.assertEqual(instance.subscriptions, set())
        self.assertEqual(instance.sock.packets[0]["type"], "error")
        self.assertEqual(instance.sock.packets[0]["id"], 0)
        self.assertEqual(instance.sock.packets[0]["code"], "ACCESS_DENIED")

    async def test_subscribe_with_id_has_ack_and_wildcard_cannot_escalate(self) -> None:
        instance = make_instance("mipc.event:subscribe:msys.hal.changed")
        daemon = make_daemon(instance)

        await Msysd._handle_component_message(
            daemon,
            instance,
            {"type": "subscribe", "id": 8, "topic": "msys.hal.changed"},
        )
        await Msysd._handle_component_message(
            daemon,
            instance,
            {"type": "subscribe", "id": 9, "topic": "msys.hal.*"},
        )

        self.assertEqual(instance.subscriptions, {"msys.hal.changed"})
        self.assertEqual(instance.sock.packets[0], {
            "type": "return",
            "id": 8,
            "payload": {"subscribed": "msys.hal.changed"},
        })
        self.assertEqual(instance.sock.packets[1]["id"], 9)
        self.assertEqual(instance.sock.packets[1]["code"], "ACCESS_DENIED")

    async def test_legacy_successful_subscribe_remains_fire_and_forget(self) -> None:
        instance = make_instance("mipc.event:subscribe:msys.hal.*")
        daemon = make_daemon(instance)

        await Msysd._handle_component_message(
            daemon,
            instance,
            {"type": "subscribe", "topic": "msys.hal.changed"},
        )

        self.assertEqual(instance.subscriptions, {"msys.hal.changed"})
        self.assertEqual(instance.sock.packets, [])

    async def test_denied_publish_is_not_broadcast(self) -> None:
        instance = make_instance("mipc.event:publish:msys.public.*")
        daemon = make_daemon(instance)
        daemon.broadcast = AsyncMock()

        await Msysd._handle_component_message(
            daemon,
            instance,
            {
                "type": "event",
                "id": 12,
                "topic": "msys.secret.changed",
                "payload": {"leak": True},
            },
        )

        daemon.broadcast.assert_not_awaited()
        self.assertEqual(instance.sock.packets[0]["code"], "ACCESS_DENIED")
        self.assertEqual(instance.sock.packets[0]["id"], 12)

    async def test_allowed_publish_is_broadcast_with_authenticated_source(self) -> None:
        instance = make_instance("mipc.event:publish:msys.public.*")
        daemon = make_daemon(instance)
        daemon.broadcast = AsyncMock()
        message = {
            "type": "event",
            "topic": "msys.public.changed",
            "payload": {"ok": True},
        }

        await Msysd._handle_component_message(daemon, instance, message)

        daemon.broadcast.assert_awaited_once_with(
            "msys.public.changed",
            {"ok": True},
            source=instance.component.key,
        )
        self.assertEqual(instance.sock.packets, [])

    async def test_public_and_core_dispatch_remain_administrator_paths(self) -> None:
        daemon = object.__new__(Msysd)
        daemon._core_call = AsyncMock(
            return_value={"type": "return", "id": 1, "payload": {"ok": True}}
        )
        message = {
            "type": "call",
            "id": 1,
            "target": "msys.core",
            "method": "list_components",
        }

        public = await Msysd.dispatch_call(daemon, message, source="public")
        internal = await Msysd.dispatch_call(daemon, message, source="msys.core")

        self.assertEqual(public["type"], "return")
        self.assertEqual(internal["type"], "return")
        self.assertEqual(daemon._core_call.await_count, 2)

    async def test_core_internal_event_does_not_require_publish_permission(self) -> None:
        receiver = make_instance(
            "mipc.event:subscribe:msys.lifecycle.transition",
            identifier="receiver",
        )
        receiver.ready = True
        receiver.subscriptions.add("msys.lifecycle.transition")
        daemon = make_daemon(receiver)

        await Msysd.broadcast(
            daemon,
            "msys.lifecycle.transition",
            {"phase": "launched"},
            source="msys.core",
        )

        self.assertEqual(len(receiver.sock.packets), 1)
        self.assertEqual(receiver.sock.packets[0]["source"], "msys.core")


class PublicSocketAuthorizationTests(unittest.IsolatedAsyncioTestCase):
    MESSAGE = {
        "type": "call",
        "id": 55,
        "target": "msys.core",
        "method": "list_components",
        "payload": {},
    }

    async def invoke(self, daemon, peer, managed):
        reader = PublicReader(self.MESSAGE)
        writer = PublicWriter()
        daemon._public_peer_credentials = lambda _writer: peer
        daemon._managed_instance_for_peer = lambda _pid: managed
        await Msysd._handle_public_client(daemon, reader, writer)
        self.assertTrue(writer.closed)
        self.assertEqual(json.loads(writer.writes[0]), {
            "type": "welcome",
            "component": "public",
            "generation": 0,
        })
        return writer.response()

    async def test_managed_public_peer_uses_component_acl_when_allowed(self) -> None:
        instance = make_instance("mipc.call:msys.core")
        daemon = make_daemon(instance)
        daemon.dispatch_call = AsyncMock(
            return_value={"type": "return", "id": 55, "payload": {"ok": True}}
        )

        response = await self.invoke(
            daemon,
            PeerCredentials(pid=7001, uid=0, gid=0),
            instance,
        )

        self.assertEqual(response["type"], "return")
        daemon.dispatch_call.assert_awaited_once_with(
            self.MESSAGE,
            source=instance.component.key,
        )

    async def test_managed_root_public_peer_is_denied_without_permission(self) -> None:
        instance = make_instance()
        daemon = make_daemon(instance)
        daemon.dispatch_call = AsyncMock()

        response = await self.invoke(
            daemon,
            PeerCredentials(pid=7002, uid=0, gid=0),
            instance,
        )

        self.assertEqual(response["code"], "ACCESS_DENIED")
        self.assertEqual(response["id"], 55)
        daemon.dispatch_call.assert_not_awaited()

    async def test_unmanaged_non_root_public_peer_is_denied(self) -> None:
        daemon = make_daemon()
        daemon.dispatch_call = AsyncMock()

        response = await self.invoke(
            daemon,
            PeerCredentials(pid=7003, uid=1000, gid=1000),
            None,
        )

        self.assertEqual(response["code"], "ACCESS_DENIED")
        self.assertEqual(
            response["payload"]["reason"],
            "unmanaged-peer-is-not-root",
        )
        daemon.dispatch_call.assert_not_awaited()

    async def test_unmanaged_root_public_peer_is_operator_admin(self) -> None:
        daemon = make_daemon()
        daemon.dispatch_call = AsyncMock(
            return_value={"type": "return", "id": 55, "payload": {"ok": True}}
        )

        response = await self.invoke(
            daemon,
            PeerCredentials(pid=7004, uid=0, gid=0),
            None,
        )

        self.assertEqual(response["type"], "return")
        daemon.dispatch_call.assert_awaited_once_with(self.MESSAGE, source="public")


class PeerAttributionTests(unittest.TestCase):
    def test_so_peercred_record_is_decoded_exactly(self) -> None:
        class PeerSocket:
            def getsockopt(self, level, option, size):
                self.arguments = (level, option, size)
                return struct.pack("3i", 8123, 0, 27)

        peer_socket = PeerSocket()
        writer = types.SimpleNamespace(
            get_extra_info=lambda name: peer_socket if name == "socket" else None
        )
        with patch.object(socket, "SO_PEERCRED", 17, create=True):
            credentials = Msysd._public_peer_credentials(writer)

        self.assertEqual(credentials, PeerCredentials(pid=8123, uid=0, gid=27))
        self.assertEqual(peer_socket.arguments[2], struct.calcsize("3i"))

    def test_direct_component_pid_matches_even_if_process_already_exited(self) -> None:
        instance = make_instance()
        instance.process = types.SimpleNamespace(pid=8124)
        daemon = make_daemon(instance)

        with patch("msys_core.msysd.os.getpgid", side_effect=ProcessLookupError):
            matched = Msysd._managed_instance_for_peer(daemon, 8124)

        self.assertIs(matched, instance)

    def test_descendant_process_group_and_session_match_component_leader(self) -> None:
        instance = make_instance()
        instance.process = types.SimpleNamespace(pid=8125)
        daemon = make_daemon(instance)

        with (
            patch("msys_core.msysd.os.getpgid", return_value=8125),
            patch("msys_core.msysd.os.getsid", return_value=9000),
        ):
            group_match = Msysd._managed_instance_for_peer(daemon, 8126)
        with (
            patch("msys_core.msysd.os.getpgid", return_value=9000),
            patch("msys_core.msysd.os.getsid", return_value=8125),
        ):
            session_match = Msysd._managed_instance_for_peer(daemon, 8127)

        self.assertIs(group_match, instance)
        self.assertIs(session_match, instance)


if __name__ == "__main__":
    unittest.main()
