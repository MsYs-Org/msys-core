"""Zero-dependency validator for the public ``msys.profile.v1`` contract."""

from __future__ import annotations

import json
import math
import re
from pathlib import Path
from typing import Any


class ProfileContractError(ValueError):
    """A profile does not satisfy the language-neutral v1 contract."""


_PROFILE_ID = re.compile(r"^[a-z][a-z0-9.-]*$")
_ROLE = re.compile(r"^[a-z][a-z0-9.-]*$")
_COMPONENT_REF = re.compile(
    r"^(?:[a-z0-9][a-z0-9_-]*(?:\.[a-z0-9][a-z0-9_-]*)+:)?"
    r"[a-z][a-z0-9._-]*$"
)
_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_EXTENSION = re.compile(r"^x-[a-z0-9][a-z0-9._-]*$")


def _fail(path: str, message: str) -> None:
    raise ProfileContractError(f"{path}: {message}")


def _object(value: object, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        _fail(path, "must be an object")
    return value


def _array(value: object, path: str) -> list[Any]:
    if not isinstance(value, list):
        _fail(path, "must be an array")
    return value


def _string(
    value: object,
    path: str,
    *,
    minimum: int = 1,
    maximum: int | None = None,
    pattern: re.Pattern[str] | None = None,
) -> str:
    if not isinstance(value, str):
        _fail(path, "must be a string")
    if len(value) < minimum:
        _fail(path, f"must contain at least {minimum} character(s)")
    if maximum is not None and len(value) > maximum:
        _fail(path, f"must contain at most {maximum} character(s)")
    if "\0" in value:
        _fail(path, "must not contain NUL")
    if pattern is not None and pattern.fullmatch(value) is None:
        _fail(path, f"has invalid format: {value!r}")
    return value


def _keys(
    value: dict[str, Any],
    path: str,
    *,
    allowed: set[str],
    required: set[str] = frozenset(),
) -> None:
    missing = sorted(required - value.keys())
    if missing:
        _fail(path, f"missing required field(s): {', '.join(missing)}")
    for key, extension_value in value.items():
        if not isinstance(key, str):
            _fail(path, "field names must be strings")
        if key not in allowed and _EXTENSION.fullmatch(key) is None:
            _fail(path, f"unknown field {key!r}; extensions must start with x-")
        if key not in allowed:
            _json_value(extension_value, f"{path}.{key}")


def _json_value(value: object, path: str, depth: int = 0) -> None:
    """Reject Python-only values when the validator is called without JSON."""

    if depth > 64:
        _fail(path, "JSON nesting exceeds 64 levels")
    if value is None or isinstance(value, (str, bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            _fail(path, "must be a finite JSON number")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _json_value(item, f"{path}[{index}]", depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                _fail(path, "JSON object field names must be strings")
            _json_value(item, f"{path}.{key}", depth + 1)
        return
    _fail(path, f"contains a non-JSON value of type {type(value).__name__}")


def _unique_strings(
    value: object,
    path: str,
    *,
    pattern: re.Pattern[str],
    maximum_items: int,
) -> list[str]:
    items = _array(value, path)
    if len(items) > maximum_items:
        _fail(path, f"must contain at most {maximum_items} items")
    result: list[str] = []
    seen: set[str] = set()
    for index, raw in enumerate(items):
        item = _string(raw, f"{path}[{index}]", maximum=255, pattern=pattern)
        if item in seen:
            _fail(path, f"contains duplicate value {item!r}")
        seen.add(item)
        result.append(item)
    return result


def validate_profile_id(value: object, path: str = "$.id") -> str:
    return _string(value, path, maximum=128, pattern=_PROFILE_ID)


def validate_profile(
    data: object,
    *,
    expected_id: str | None = None,
) -> dict[str, Any]:
    """Validate and return one ``msys.profile.v1`` mapping.

    Component references are checked syntactically, not against the current
    component catalog: profiles intentionally may name optional providers that
    are installed later.
    """

    profile = _object(data, "$")
    _keys(
        profile,
        "$",
        allowed={
            "schema",
            "id",
            "roles",
            "disabled_roles",
            "startup",
            "env",
            "state_dir",
            "isolation",
            "settings",
        },
        required={"schema", "id", "roles", "startup"},
    )
    if profile["schema"] != "msys.profile.v1":
        _fail("$.schema", "must equal 'msys.profile.v1'")
    profile_id = validate_profile_id(profile["id"])
    if expected_id is not None:
        requested = validate_profile_id(expected_id, "$requested_profile")
        if profile_id != requested:
            _fail("$.id", f"must match requested profile {requested!r}")

    roles = _object(profile["roles"], "$.roles")
    if len(roles) > 256:
        _fail("$.roles", "must contain at most 256 roles")
    for raw_role, candidates in roles.items():
        role = _string(raw_role, "$.roles.<name>", maximum=128, pattern=_ROLE)
        _unique_strings(
            candidates,
            f"$.roles.{role}",
            pattern=_COMPONENT_REF,
            maximum_items=64,
        )

    disabled = _unique_strings(
        profile.get("disabled_roles", []),
        "$.disabled_roles",
        pattern=_ROLE,
        maximum_items=256,
    )
    conflicts = sorted(set(roles).intersection(disabled))
    if conflicts:
        _fail(
            "$",
            "roles and disabled_roles conflict for: " + ", ".join(conflicts),
        )

    _unique_strings(
        profile["startup"],
        "$.startup",
        pattern=_COMPONENT_REF,
        maximum_items=1024,
    )

    env = _object(profile.get("env", {}), "$.env")
    if len(env) > 1024:
        _fail("$.env", "must contain at most 1024 variables")
    for raw_name, raw_value in env.items():
        name = _string(raw_name, "$.env.<name>", maximum=255, pattern=_ENV_NAME)
        _string(raw_value, f"$.env.{name}", minimum=0, maximum=32768)

    if "state_dir" in profile:
        state_dir = _string(profile["state_dir"], "$.state_dir", maximum=4096)
        if not state_dir.startswith("/"):
            _fail("$.state_dir", "must be an absolute Linux path")

    isolation = _object(profile.get("isolation", {}), "$.isolation")
    _keys(isolation, "$.isolation", allowed={"seccomp_helper"})
    if "seccomp_helper" in isolation:
        _string(
            isolation["seccomp_helper"],
            "$.isolation.seccomp_helper",
            maximum=4096,
        )

    settings = _object(profile.get("settings", {}), "$.settings")
    _json_value(settings, "$.settings")
    return profile


def _reject_duplicate_fields(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ProfileContractError(f"duplicate JSON object field {key!r}")
        result[key] = value
    return result


def _reject_non_finite(value: str) -> None:
    raise ProfileContractError(f"non-finite JSON number {value!r} is not allowed")


def load_profile_document(path: Path, *, expected_id: str) -> dict[str, Any]:
    """Decode a profile file strictly and validate it before supervisor use."""

    try:
        text = path.read_text(encoding="utf-8-sig")
        data = json.loads(
            text,
            object_pairs_hook=_reject_duplicate_fields,
            parse_constant=_reject_non_finite,
        )
        return validate_profile(data, expected_id=expected_id)
    except ProfileContractError as exc:
        raise ProfileContractError(f"{path}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ProfileContractError(
            f"{path}: invalid JSON at line {exc.lineno}, column {exc.colno}: {exc.msg}"
        ) from exc


__all__ = [
    "ProfileContractError",
    "load_profile_document",
    "validate_profile",
    "validate_profile_id",
]

