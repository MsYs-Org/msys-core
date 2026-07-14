from __future__ import annotations

import unittest

from msys_core.manifest import Component
from msys_core.msysd import Msysd, normalize_intent_request


def handler(component_id: str, intent: dict, *, priority: int = 0) -> Component:
    value = dict(intent)
    value["priority"] = priority
    return Component(
        package_id="org.msys.handlers",
        package_version="1.0.0",
        id=component_id,
        exec=["true"],
        lifecycle="manual",
        activation={"launchable": True, "intents": [value]},
        raw={"name": component_id},
    )


class IntentResolutionTests(unittest.TestCase):
    def test_conventional_fields_infer_standard_action(self) -> None:
        self.assertEqual(
            normalize_intent_request({"uri": "demo://item"})["action"],
            "open-uri",
        )
        self.assertEqual(
            normalize_intent_request({"mime": "text/plain"})["action"],
            "open-mime",
        )
        self.assertEqual(
            normalize_intent_request({"name": "network"})["action"],
            "settings-panel",
        )
        explicit = normalize_intent_request({"action": "share", "uri": "demo://item"})
        self.assertEqual(explicit["action"], "share")

    def daemon_with(self, *components: Component) -> Msysd:
        daemon = object.__new__(Msysd)
        daemon.components = {component.key: component for component in components}
        return daemon

    def test_uri_scheme_and_priority(self) -> None:
        low = handler("low", {"action": "open-uri", "schemes": ["demo"]}, priority=1)
        high = handler("high", {"action": "open-uri", "schemes": ["demo"]}, priority=20)
        daemon = self.daemon_with(low, high)
        result = daemon._intent_candidates({"action": "open-uri", "uri": "demo://item/1"})
        self.assertEqual([item["component"] for item in result], [high.key, low.key])

    def test_mime_wildcard(self) -> None:
        text = handler("text", {"action": "open-mime", "mime": ["text/*"]})
        daemon = self.daemon_with(text)
        self.assertEqual(
            daemon._intent_candidates({"action": "open-mime", "mime": "text/plain"})[0]["component"],
            text.key,
        )
        self.assertEqual(daemon._intent_candidates({"action": "open-mime", "mime": "image/png"}), [])


class IntentChoiceErrorTests(unittest.IsolatedAsyncioTestCase):
    async def test_graphical_cancel_is_preserved_for_original_caller(self) -> None:
        class FakeDaemon:
            components = {"org.example:first": object(), "org.example:second": object()}

            def _intent_candidates(self, _request):
                return [
                    {"component": "org.example:first"},
                    {"component": "org.example:second"},
                ]

            async def dispatch_call(self, _message, source):
                self.source = source
                return {
                    "type": "error",
                    "code": "CHOICE_CANCELLED",
                    "message": "cancelled by Back",
                }

        daemon = FakeDaemon()
        response = await Msysd._core_call(
            daemon,
            {
                "type": "call",
                "id": 7,
                "method": "activate",
                "payload": {"uri": "demo://item"},
            },
        )
        self.assertEqual(response["id"], 7)
        self.assertEqual(response["code"], "CHOICE_CANCELLED")
        self.assertEqual(daemon.source, "msys.core")


if __name__ == "__main__":
    unittest.main()
