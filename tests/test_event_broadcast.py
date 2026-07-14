from __future__ import annotations

import json
import types
import unittest

from msys_core.manifest import Component
from msys_core.msysd import (
    MAX_SUBSCRIPTIONS,
    Msysd,
    subscription_matches,
    valid_event_topic,
    valid_subscription,
)


class CaptureSocket:
    def __init__(self) -> None:
        self.packets: list[dict] = []

    def sendall(self, data: bytes) -> None:
        self.packets.append(json.loads(data.decode("utf-8")))


def component(identifier: str, permissions: list[str]) -> Component:
    return Component(
        package_id="org.example.events",
        package_version="1.0.0",
        id=identifier,
        exec=[],
        lifecycle="background",
        permissions=permissions,
    )


class EventSubscriptionTests(unittest.IsolatedAsyncioTestCase):
    def test_topic_and_prefix_pattern_grammar_is_bounded(self) -> None:
        self.assertTrue(valid_event_topic("msys.hal.changed"))
        self.assertFalse(valid_event_topic("msys.hal.*"))
        self.assertFalse(valid_event_topic(""))
        self.assertFalse(valid_event_topic(" bad"))
        self.assertFalse(valid_event_topic("a" * 129))
        self.assertTrue(valid_subscription("msys.hal.*"))
        self.assertTrue(valid_subscription("*"))
        self.assertFalse(valid_subscription("msys.*.changed"))
        self.assertFalse(valid_subscription("prefix**"))

    def test_matching_is_exact_or_prefix_only(self) -> None:
        self.assertTrue(subscription_matches("msys.hal.*", "msys.hal.changed"))
        self.assertFalse(subscription_matches("msys.hal.*", "msys.power.changed"))
        self.assertTrue(subscription_matches("*", "third.party.event"))
        self.assertTrue(subscription_matches("exact.event", "exact.event"))
        self.assertFalse(subscription_matches("exact.event", "exact.event.child"))

    async def test_broadcast_delivers_to_exact_prefix_and_global_subscribers(self) -> None:
        exact, prefix, global_subscriber, unrelated = (
            CaptureSocket(), CaptureSocket(), CaptureSocket(), CaptureSocket()
        )
        daemon = object.__new__(Msysd)
        daemon.instances = {
            "exact": types.SimpleNamespace(
                component=component("exact", ["mipc.event:subscribe:msys.hal.changed"]),
                subscriptions={"msys.hal.changed"}, sock=exact, ready=True
            ),
            "prefix": types.SimpleNamespace(
                component=component("prefix", ["mipc.event:subscribe:msys.hal.*"]),
                subscriptions={"msys.hal.*"}, sock=prefix, ready=True
            ),
            "global": types.SimpleNamespace(
                component=component("global", ["mipc.event:subscribe:*"]),
                subscriptions={"*"}, sock=global_subscriber, ready=True
            ),
            "unrelated": types.SimpleNamespace(
                component=component("unrelated", ["mipc.event:subscribe:msys.window.*"]),
                subscriptions={"msys.window.*"}, sock=unrelated, ready=True
            ),
        }

        await Msysd.broadcast(
            daemon,
            "msys.hal.changed",
            {"domain": "power"},
            source="org.example:provider",
        )

        self.assertEqual(len(exact.packets), 1)
        self.assertEqual(len(prefix.packets), 1)
        self.assertEqual(len(global_subscriber.packets), 1)
        self.assertEqual(unrelated.packets, [])
        self.assertEqual(prefix.packets[0]["source"], "org.example:provider")

    async def test_subscribe_rejects_invalid_and_bounds_component_state(self) -> None:
        daemon = object.__new__(Msysd)
        capture = CaptureSocket()
        instance = types.SimpleNamespace(
            component=component("bounded", ["mipc.event:subscribe:*"]),
            subscriptions=set(),
            sock=capture,
        )
        for index in range(MAX_SUBSCRIPTIONS + 10):
            await Msysd._handle_component_message(
                daemon,
                instance,
                {"type": "subscribe", "topic": f"example.topic{index}"},
            )
        await Msysd._handle_component_message(
            daemon,
            instance,
            {"type": "subscribe", "topic": "invalid.*.pattern"},
        )
        self.assertEqual(len(instance.subscriptions), MAX_SUBSCRIPTIONS)
        self.assertNotIn("invalid.*.pattern", instance.subscriptions)


if __name__ == "__main__":
    unittest.main()
