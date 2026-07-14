"""Manifest-backed authorization helpers for the private mIPC channel.

The inherited ``MSYS_CONTROL_FD`` proves which supervised component is
speaking.  These helpers deliberately implement a small, exact policy
language so a manifest cannot accidentally acquire authority through a fuzzy
match.
"""

from __future__ import annotations

from collections.abc import Iterable


MAX_TOPIC_LENGTH = 128


def valid_event_topic(topic: object) -> bool:
    """Return whether *topic* is a concrete, language-neutral event name."""

    if not isinstance(topic, str) or not 1 <= len(topic) <= MAX_TOPIC_LENGTH:
        return False
    if not topic[0].isalnum() or not topic[0].isascii():
        return False
    return all(
        character.isascii()
        and (character.isalnum() or character in "._:-")
        for character in topic
    )


def valid_subscription(pattern: object) -> bool:
    """Accept exact topics, ``prefix*`` patterns, or the global ``*``."""

    if pattern == "*":
        return True
    if not isinstance(pattern, str) or not 1 <= len(pattern) <= MAX_TOPIC_LENGTH:
        return False
    if pattern.endswith("*"):
        prefix = pattern[:-1]
        return bool(prefix) and valid_event_topic(prefix)
    return valid_event_topic(pattern)


def subscription_matches(pattern: str, topic: str) -> bool:
    if pattern == "*":
        return True
    if pattern.endswith("*"):
        return topic.startswith(pattern[:-1])
    return pattern == topic


def subscription_covers(grant: str, requested: str) -> bool:
    """Return whether subscription *grant* contains all of *requested*.

    This is stricter than checking one sample topic.  For example an exact
    ``msys.hal.changed`` grant cannot authorize a ``msys.hal.*`` subscription,
    while the reverse is safe.
    """

    if not valid_subscription(grant) or not valid_subscription(requested):
        return False
    if grant == "*":
        return True
    if not grant.endswith("*"):
        return grant == requested
    grant_prefix = grant[:-1]
    requested_prefix = requested[:-1] if requested.endswith("*") else requested
    return requested_prefix.startswith(grant_prefix)


def _permission_set(permissions: Iterable[object]) -> frozenset[str]:
    return frozenset(item for item in permissions if isinstance(item, str))


def call_permission_candidates(target: str, method: str) -> tuple[str, ...]:
    """Return the exact permissions which may authorize one call.

    ``interface:<name>`` has a compatibility alias because v1 manifests have
    historically used ``mipc.call:<name>``.  New manifests may spell the
    target explicitly. Appending ``.<method>`` narrows any target grant; all
    comparisons are complete-string equality rather than prefix matching.
    """

    resources: list[str] = []
    if method:
        resources.append(f"{target}.{method}")
    resources.append(target)
    if target.startswith("interface:"):
        interface = target.split(":", 1)[1]
        if interface:
            if method:
                resources.append(f"{interface}.{method}")
            resources.append(interface)
    return tuple(f"mipc.call:{resource}" for resource in dict.fromkeys(resources))


def allows_call(permissions: Iterable[object], target: str, method: str) -> bool:
    declared = _permission_set(permissions)
    if "mipc.call:*" in declared:
        return True
    return any(
        permission in declared
        for permission in call_permission_candidates(target, method)
    )


def event_permission(action: str, pattern: str) -> str:
    return f"mipc.event:{action}:{pattern}"


def allows_event(
    permissions: Iterable[object],
    action: str,
    requested: str,
) -> bool:
    """Authorize an event publish or subscription.

    Event grants are exact or contain one wildcard at the final character.
    A subscribe grant must cover the entire requested subscription pattern,
    not merely one event which happens to match it.
    """

    if action not in {"publish", "subscribe"}:
        return False
    if action == "publish" and not valid_event_topic(requested):
        return False
    if action == "subscribe" and not valid_subscription(requested):
        return False
    prefix = f"mipc.event:{action}:"
    for permission in _permission_set(permissions):
        if not permission.startswith(prefix):
            continue
        grant = permission[len(prefix):]
        if subscription_covers(grant, requested):
            return True
    return False
