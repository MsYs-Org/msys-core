#!/usr/bin/env python3
"""Compile strict JSON into the dependency-free native-lite runtime plan."""

from __future__ import annotations

import argparse
import heapq
import json
import os
from pathlib import Path
import re
import tempfile
from typing import AbstractSet, Any


SCHEMA = "msys.native-lite-plan.source.v1"
HEADER = "MSYS_NATIVE_LITE_PLAN\t1"
SCHEMA_V2 = "msys.native-runtime.source.v2"
HEADER_V2 = "MSYS_NATIVE_LITE_PLAN\t2"
MAX_BYTES = 1024 * 1024
MAX_COMPONENTS = 64
ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$")
ENV_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
RESERVED_ENV = {
    "MSYS_READY_FD",
    "MSYS_CONTROL_FD",
    "MSYS_COMPONENT_ID",
    "MSYS_GENERATION",
    "MSYS_RUNTIME_DIR",
    "MSYS_PACKAGE_ID",
    "MSYS_PACKAGE_VERSION",
    "MSYS_WINDOW_TITLE",
    "MSYS_APP_ID",
    "MSYS_WINDOW_IDENTITY",
    "MSYS_X11_WM_INSTANCE",
}


class PlanError(ValueError):
    pass


def object_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PlanError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def closed_object(
    value: Any,
    path: str,
    *,
    allowed: AbstractSet[str],
    required: AbstractSet[str] = frozenset(),
) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise PlanError(f"{path} must be an object")
    unknown = sorted(set(value) - allowed)
    missing = sorted(required - set(value))
    if unknown:
        raise PlanError(f"{path} has unknown field {unknown[0]!r}")
    if missing:
        raise PlanError(f"{path} is missing field {missing[0]!r}")
    return value


def integer(value: Any, path: str, minimum: int, maximum: int) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not minimum <= value <= maximum:
        raise PlanError(f"{path} must be an integer in {minimum}..{maximum}")
    return value


def enum_string(value: Any, path: str, allowed: AbstractSet[str]) -> str:
    if not isinstance(value, str) or value not in allowed:
        raise PlanError(f"{path} is invalid")
    return value


def bounded_string(value: Any, path: str, maximum_bytes: int, *, nonempty: bool = False) -> str:
    if not isinstance(value, str) or "\0" in value:
        raise PlanError(f"{path} must be a NUL-free string")
    size = len(value.encode("utf-8"))
    if (nonempty and not value) or size > maximum_bytes:
        raise PlanError(f"{path} has invalid encoded length")
    return value


def normalize_component(raw: Any, index: int) -> dict[str, Any]:
    path = f"$.components[{index}]"
    item = closed_object(
        raw,
        path,
        allowed={
            "id", "kind", "critical", "restart", "readiness", "backoff",
            "exec", "after", "env",
        },
        required={"id", "kind", "critical", "restart", "readiness", "exec"},
    )
    component_id = bounded_string(item["id"], f"{path}.id", 128, nonempty=True)
    if ID_RE.fullmatch(component_id) is None:
        raise PlanError(f"{path}.id is invalid")
    kind = enum_string(
        item["kind"], f"{path}.kind", {"display", "window", "shell", "other"}
    )
    critical = item["critical"]
    if not isinstance(critical, bool):
        raise PlanError(f"{path}.critical must be boolean")
    restart = enum_string(
        item["restart"], f"{path}.restart", {"never", "on-failure", "always"}
    )

    readiness = closed_object(
        item["readiness"],
        f"{path}.readiness",
        allowed={"mode", "timeout_ms"},
        required={"mode", "timeout_ms"},
    )
    readiness_mode = enum_string(
        readiness["mode"], f"{path}.readiness.mode", {"exec", "fd", "mipc-ready"}
    )
    readiness_timeout = integer(
        readiness["timeout_ms"], f"{path}.readiness.timeout_ms", 1, 300_000
    )

    backoff = closed_object(
        item.get("backoff", {}),
        f"{path}.backoff",
        allowed={"initial_ms", "max_ms", "limit"},
    )
    initial_ms = integer(backoff.get("initial_ms", 250), f"{path}.backoff.initial_ms", 1, 60_000)
    max_ms = integer(backoff.get("max_ms", 30_000), f"{path}.backoff.max_ms", initial_ms, 300_000)
    limit = integer(backoff.get("limit", 8), f"{path}.backoff.limit", 0, 1000)

    argv_raw = item["exec"]
    if not isinstance(argv_raw, list) or not 1 <= len(argv_raw) <= 64:
        raise PlanError(f"{path}.exec must contain 1..64 arguments")
    argv = [bounded_string(value, f"{path}.exec[{offset}]", 4096) for offset, value in enumerate(argv_raw)]
    if not argv[0] or not argv[0].startswith("/"):
        raise PlanError(f"{path}.exec[0] must be absolute")

    after_raw = item.get("after", [])
    if not isinstance(after_raw, list) or len(after_raw) > 32:
        raise PlanError(f"{path}.after must contain at most 32 ids")
    after: list[str] = []
    for offset, value in enumerate(after_raw):
        dependency = bounded_string(value, f"{path}.after[{offset}]", 128, nonempty=True)
        if ID_RE.fullmatch(dependency) is None:
            raise PlanError(f"{path}.after[{offset}] is invalid")
        after.append(dependency)
    if len(set(after)) != len(after):
        raise PlanError(f"{path}.after contains duplicates")

    environment_raw = item.get("env", {})
    if not isinstance(environment_raw, dict) or len(environment_raw) > 64:
        raise PlanError(f"{path}.env must contain at most 64 entries")
    environment: list[tuple[str, str]] = []
    for key in sorted(environment_raw):
        if ENV_RE.fullmatch(key) is None or key in RESERVED_ENV:
            raise PlanError(f"{path}.env has invalid or reserved key {key!r}")
        value = bounded_string(environment_raw[key], f"{path}.env.{key}", 4096)
        environment.append((key, value))

    return {
        "id": component_id,
        "kind": kind,
        "critical": critical,
        "restart": restart,
        "readiness_mode": readiness_mode,
        "readiness_timeout_ms": readiness_timeout,
        "initial_ms": initial_ms,
        "max_ms": max_ms,
        "limit": limit,
        "argv": argv,
        "after": sorted(after),
        "environment": environment,
    }


def topological_components(components: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_id = {item["id"]: item for item in components}
    if len(by_id) != len(components):
        raise PlanError("component ids must be unique")
    if not any(item["critical"] for item in components):
        raise PlanError("at least one component must be critical")
    dependents: dict[str, list[str]] = {name: [] for name in by_id}
    indegree: dict[str, int] = {name: 0 for name in by_id}
    for item in components:
        for dependency in item["after"]:
            if dependency not in by_id:
                raise PlanError(f"{item['id']} references missing dependency {dependency}")
            if dependency == item["id"]:
                raise PlanError(f"{item['id']} depends on itself")
            dependents[dependency].append(item["id"])
            indegree[item["id"]] += 1
    ready = [name for name, count in indegree.items() if count == 0]
    heapq.heapify(ready)
    ordered: list[dict[str, Any]] = []
    while ready:
        name = heapq.heappop(ready)
        ordered.append(by_id[name])
        for dependent in sorted(dependents[name]):
            indegree[dependent] -= 1
            if indegree[dependent] == 0:
                heapq.heappush(ready, dependent)
    if len(ordered) != len(components):
        raise PlanError("dependency graph contains a cycle")
    return ordered


def encoded(value: str) -> str:
    return value.encode("utf-8").hex()


def normalize_v2_component(raw: Any, index: int) -> dict[str, Any]:
    path = f"$.components[{index}]"
    item = closed_object(
        raw,
        path,
        allowed={
            "id", "kind", "critical", "lifecycle", "idle_timeout_ms",
            "restart", "readiness", "backoff", "exec", "after", "env",
            "provides", "permissions", "package", "name", "summary", "icon",
            "windowing", "launchable",
        },
        required={
            "id", "kind", "critical", "lifecycle", "restart", "readiness",
            "exec", "package", "name",
        },
    )
    component_id = bounded_string(item["id"], f"{path}.id", 128, nonempty=True)
    if ID_RE.fullmatch(component_id) is None:
        raise PlanError(f"{path}.id is invalid")
    kind = enum_string(item["kind"], f"{path}.kind", {"display", "window", "shell", "other"})
    critical = item["critical"]
    if not isinstance(critical, bool):
        raise PlanError(f"{path}.critical must be boolean")
    lifecycle = enum_string(
        item["lifecycle"], f"{path}.lifecycle", {"background", "on-demand", "manual"}
    )
    idle_timeout_ms = integer(item.get("idle_timeout_ms", 0), f"{path}.idle_timeout_ms", 0, 3_600_000)
    if lifecycle == "on-demand" and idle_timeout_ms < 100:
        raise PlanError(f"{path}.idle_timeout_ms must be at least 100 for on-demand")
    if lifecycle != "on-demand" and idle_timeout_ms != 0:
        raise PlanError(f"{path}.idle_timeout_ms is only valid for on-demand")
    restart = enum_string(item["restart"], f"{path}.restart", {"never", "on-failure", "always"})
    readiness = closed_object(
        item["readiness"], f"{path}.readiness",
        allowed={"mode", "timeout_ms"}, required={"mode", "timeout_ms"},
    )
    readiness_mode = enum_string(
        readiness["mode"], f"{path}.readiness.mode",
        {"exec", "fd", "mipc-ready", "x11-display"},
    )
    readiness_timeout = integer(
        readiness["timeout_ms"], f"{path}.readiness.timeout_ms", 1, 300_000
    )
    backoff = closed_object(
        item.get("backoff", {}), f"{path}.backoff",
        allowed={"initial_ms", "max_ms", "limit"},
    )
    initial_ms = integer(backoff.get("initial_ms", 250), f"{path}.backoff.initial_ms", 1, 60_000)
    max_ms = integer(backoff.get("max_ms", 30_000), f"{path}.backoff.max_ms", initial_ms, 300_000)
    limit = integer(backoff.get("limit", 8), f"{path}.backoff.limit", 0, 1000)

    argv_raw = item["exec"]
    if not isinstance(argv_raw, list) or not 1 <= len(argv_raw) <= 64:
        raise PlanError(f"{path}.exec must contain 1..64 arguments")
    argv = [bounded_string(value, f"{path}.exec[{offset}]", 4096) for offset, value in enumerate(argv_raw)]
    if not argv[0].startswith("/"):
        raise PlanError(f"{path}.exec[0] must be absolute")

    after_raw = item.get("after", [])
    if not isinstance(after_raw, list) or len(after_raw) > 32:
        raise PlanError(f"{path}.after must contain at most 32 ids")
    after = [bounded_string(value, f"{path}.after[{offset}]", 128, nonempty=True)
             for offset, value in enumerate(after_raw)]
    if any(ID_RE.fullmatch(value) is None for value in after) or len(set(after)) != len(after):
        raise PlanError(f"{path}.after contains invalid or duplicate ids")

    environment_raw = item.get("env", {})
    if not isinstance(environment_raw, dict) or len(environment_raw) > 64:
        raise PlanError(f"{path}.env must contain at most 64 entries")
    environment: list[tuple[str, str]] = []
    for key in sorted(environment_raw):
        if ENV_RE.fullmatch(key) is None or key in RESERVED_ENV:
            raise PlanError(f"{path}.env has invalid or reserved key {key!r}")
        environment.append((key, bounded_string(environment_raw[key], f"{path}.env.{key}", 4096)))

    provides_raw = item.get("provides", [])
    if not isinstance(provides_raw, list) or len(provides_raw) > 32:
        raise PlanError(f"{path}.provides must contain at most 32 entries")
    provides: list[tuple[str, str, bool, int]] = []
    provided_keys: set[tuple[str, str]] = set()
    for offset, raw_provide in enumerate(provides_raw):
        provide_path = f"{path}.provides[{offset}]"
        provide = closed_object(
            raw_provide, provide_path,
            allowed={"role", "interface", "capability", "exclusive", "priority"},
        )
        kinds = [name for name in ("role", "interface", "capability") if name in provide]
        if len(kinds) != 1:
            raise PlanError(f"{provide_path} must declare exactly one provide kind")
        provide_kind = kinds[0]
        provide_name = bounded_string(provide[provide_kind], f"{provide_path}.{provide_kind}", 128, nonempty=True)
        if ID_RE.fullmatch(provide_name) is None:
            raise PlanError(f"{provide_path} name is invalid")
        exclusive = provide.get("exclusive", False)
        if not isinstance(exclusive, bool):
            raise PlanError(f"{provide_path}.exclusive must be boolean")
        priority = integer(provide.get("priority", 0), f"{provide_path}.priority", 0, 1_000_000)
        if (provide_kind, provide_name) in provided_keys:
            raise PlanError(f"{provide_path} duplicates a provide")
        provided_keys.add((provide_kind, provide_name))
        provides.append((provide_kind, provide_name, exclusive, priority))

    permissions_raw = item.get("permissions", [])
    if not isinstance(permissions_raw, list) or len(permissions_raw) > 128:
        raise PlanError(f"{path}.permissions must contain at most 128 entries")
    permissions = [bounded_string(value, f"{path}.permissions[{offset}]", 256, nonempty=True)
                   for offset, value in enumerate(permissions_raw)]
    if len(set(permissions)) != len(permissions):
        raise PlanError(f"{path}.permissions contains duplicates")

    package = closed_object(
        item["package"], f"{path}.package",
        allowed={"id", "name", "version", "kind"},
        required={"id", "name", "version", "kind"},
    )
    package_id = bounded_string(package["id"], f"{path}.package.id", 128, nonempty=True)
    if ID_RE.fullmatch(package_id) is None:
        raise PlanError(f"{path}.package.id is invalid")
    package_name = bounded_string(package["name"], f"{path}.package.name", 256)
    package_version = bounded_string(package["version"], f"{path}.package.version", 64)
    package_kind = bounded_string(package["kind"], f"{path}.package.kind", 64)
    name = bounded_string(item["name"], f"{path}.name", 256, nonempty=True)
    summary = bounded_string(item.get("summary", ""), f"{path}.summary", 1024)
    icon = bounded_string(item.get("icon", ""), f"{path}.icon", 4096)
    launchable = item.get("launchable", False)
    if not isinstance(launchable, bool):
        raise PlanError(f"{path}.launchable must be boolean")

    window_raw = item.get("windowing", {})
    window = closed_object(
        window_raw, f"{path}.windowing",
        allowed={"system", "display", "mode", "title", "app_id", "wm_class", "wm_instance"},
    )
    window_limits = {
        "system": 32, "display": 64, "mode": 64, "title": 256,
        "app_id": 256, "wm_class": 256, "wm_instance": 256,
    }
    normalized_window = {
        key: bounded_string(window.get(key, ""), f"{path}.windowing.{key}", limit)
        for key, limit in window_limits.items()
    }
    return {
        "id": component_id, "kind": kind, "critical": critical,
        "lifecycle": lifecycle, "idle_timeout_ms": idle_timeout_ms,
        "restart": restart, "readiness_mode": readiness_mode,
        "readiness_timeout_ms": readiness_timeout, "initial_ms": initial_ms,
        "max_ms": max_ms, "limit": limit, "argv": argv, "after": sorted(after),
        "environment": environment, "provides": provides, "permissions": sorted(permissions),
        "package_id": package_id, "package_name": package_name,
        "package_version": package_version, "package_kind": package_kind,
        "name": name, "summary": summary, "icon": icon, "launchable": launchable,
        "window": normalized_window,
    }


def compile_document_v2(document: Any) -> str:
    root = closed_object(
        document, "$", allowed={"schema", "stop_grace_ms", "profile", "components"},
        required={"schema", "profile", "components"},
    )
    stop_grace = integer(root.get("stop_grace_ms", 2000), "$.stop_grace_ms", 100, 60_000)
    profile = closed_object(
        root["profile"], "$.profile", allowed={"id", "display", "roles", "startup", "env"},
        required={"id", "roles", "startup"},
    )
    profile_id = bounded_string(profile["id"], "$.profile.id", 128, nonempty=True)
    if ID_RE.fullmatch(profile_id) is None:
        raise PlanError("$.profile.id is invalid")
    display = bounded_string(profile.get("display", ""), "$.profile.display", 63)
    roles_raw = profile["roles"]
    if not isinstance(roles_raw, dict) or len(roles_raw) > 64:
        raise PlanError("$.profile.roles must contain at most 64 roles")
    roles: list[tuple[str, list[str]]] = []
    for role in sorted(roles_raw):
        if ID_RE.fullmatch(role) is None:
            raise PlanError(f"$.profile.roles has invalid role {role!r}")
        providers_raw = roles_raw[role]
        if not isinstance(providers_raw, list) or not 1 <= len(providers_raw) <= MAX_COMPONENTS:
            raise PlanError(f"$.profile.roles.{role} must contain 1..64 providers")
        providers = [bounded_string(value, f"$.profile.roles.{role}[{offset}]", 128, nonempty=True)
                     for offset, value in enumerate(providers_raw)]
        if any(ID_RE.fullmatch(value) is None for value in providers) or len(set(providers)) != len(providers):
            raise PlanError(f"$.profile.roles.{role} contains invalid or duplicate providers")
        roles.append((role, providers))
    startup_raw = profile["startup"]
    if not isinstance(startup_raw, list) or len(startup_raw) > MAX_COMPONENTS:
        raise PlanError("$.profile.startup must contain at most 64 components")
    startup = [bounded_string(value, f"$.profile.startup[{offset}]", 128, nonempty=True)
               for offset, value in enumerate(startup_raw)]
    if any(ID_RE.fullmatch(value) is None for value in startup) or len(set(startup)) != len(startup):
        raise PlanError("$.profile.startup contains invalid or duplicate components")
    environment_raw = profile.get("env", {})
    if not isinstance(environment_raw, dict) or len(environment_raw) > 64:
        raise PlanError("$.profile.env must contain at most 64 entries")
    profile_environment: list[tuple[str, str]] = []
    for key in sorted(environment_raw):
        if ENV_RE.fullmatch(key) is None or key in RESERVED_ENV:
            raise PlanError(f"$.profile.env has invalid or reserved key {key!r}")
        profile_environment.append((key, bounded_string(environment_raw[key], f"$.profile.env.{key}", 4096)))

    raw_components = root["components"]
    if not isinstance(raw_components, list) or not 1 <= len(raw_components) <= MAX_COMPONENTS:
        raise PlanError("$.components must contain 1..64 entries")
    components = topological_components(
        [normalize_v2_component(item, index) for index, item in enumerate(raw_components)]
    )
    ids = {item["id"] for item in components}
    for component in startup:
        if component not in ids:
            raise PlanError(f"$.profile.startup references missing component {component}")
    for role, providers in roles:
        for provider in providers:
            if provider not in ids:
                raise PlanError(f"$.profile.roles.{role} references missing component {provider}")
            if not any(kind == "role" and name == role for kind, name, _exclusive, _priority in
                       next(item for item in components if item["id"] == provider)["provides"]):
                raise PlanError(f"{provider} does not provide preferred role {role}")

    lines = [HEADER_V2, f"stop_grace_ms\t{stop_grace}"]
    lines.append("\t".join((
        "profile", encoded(profile_id), encoded(display), str(len(roles)),
        str(len(profile_environment)), str(len(startup)),
    )))
    for role, providers in roles:
        lines.append(f"role\t{encoded(role)}\t{len(providers)}")
        lines.extend(f"provider\t{provider}" for provider in providers)
    lines.extend(f"profile-env\t{encoded(key)}\t{encoded(value)}" for key, value in profile_environment)
    lines.extend(f"startup\t{value}" for value in startup)
    for item in components:
        lines.append("\t".join((
            "component", item["id"], item["kind"], "1" if item["critical"] else "0",
            item["restart"], item["readiness_mode"], str(item["readiness_timeout_ms"]),
            str(item["initial_ms"]), str(item["max_ms"]), str(item["limit"]),
            str(len(item["argv"])), str(len(item["after"])), str(len(item["environment"])),
            item["lifecycle"], str(item["idle_timeout_ms"]), str(len(item["provides"])),
            str(len(item["permissions"])), "1" if item["launchable"] else "0",
        )))
        lines.extend(f"arg\t{encoded(value)}" for value in item["argv"])
        lines.extend(f"after\t{value}" for value in item["after"])
        lines.extend(f"env\t{encoded(key)}\t{encoded(value)}" for key, value in item["environment"])
        lines.extend(
            f"provide\t{kind}\t{encoded(name)}\t{'1' if exclusive else '0'}\t{priority}"
            for kind, name, exclusive, priority in item["provides"]
        )
        lines.extend(f"permission\t{encoded(value)}" for value in item["permissions"])
        lines.append("\t".join((
            "package", encoded(item["package_id"]), encoded(item["package_name"]),
            encoded(item["package_version"]), encoded(item["package_kind"]),
        )))
        lines.append("\t".join((
            "metadata", encoded(item["name"]), encoded(item["summary"]), encoded(item["icon"]),
        )))
        window = item["window"]
        lines.append("\t".join((
            "window", encoded(window["system"]), encoded(window["display"]), encoded(window["mode"]),
            encoded(window["title"]), encoded(window["app_id"]), encoded(window["wm_class"]),
            encoded(window["wm_instance"]),
        )))
        lines.append("end")
    result = "\n".join(lines) + "\n"
    if len(result.encode("utf-8")) > MAX_BYTES:
        raise PlanError("compiled plan exceeds 1 MiB")
    return result


def compile_document(document: Any) -> str:
    if isinstance(document, dict) and document.get("schema") == SCHEMA_V2:
        return compile_document_v2(document)
    root = closed_object(
        document,
        "$",
        allowed={"schema", "stop_grace_ms", "components"},
        required={"schema", "components"},
    )
    if root["schema"] != SCHEMA:
        raise PlanError(f"$.schema must equal {SCHEMA!r}")
    stop_grace = integer(root.get("stop_grace_ms", 2000), "$.stop_grace_ms", 100, 60_000)
    raw_components = root["components"]
    if not isinstance(raw_components, list) or not 1 <= len(raw_components) <= MAX_COMPONENTS:
        raise PlanError("$.components must contain 1..64 entries")
    components = topological_components(
        [normalize_component(item, index) for index, item in enumerate(raw_components)]
    )
    lines = [HEADER, f"stop_grace_ms\t{stop_grace}"]
    for item in components:
        lines.append(
            "\t".join(
                (
                    "component",
                    item["id"],
                    item["kind"],
                    "1" if item["critical"] else "0",
                    item["restart"],
                    item["readiness_mode"],
                    str(item["readiness_timeout_ms"]),
                    str(item["initial_ms"]),
                    str(item["max_ms"]),
                    str(item["limit"]),
                    str(len(item["argv"])),
                    str(len(item["after"])),
                    str(len(item["environment"])),
                )
            )
        )
        lines.extend(f"arg\t{encoded(value)}" for value in item["argv"])
        lines.extend(f"after\t{value}" for value in item["after"])
        lines.extend(
            f"env\t{encoded(key)}\t{encoded(value)}"
            for key, value in item["environment"]
        )
        lines.append("end")
    result = "\n".join(lines) + "\n"
    if len(result.encode("utf-8")) > MAX_BYTES:
        raise PlanError("compiled plan exceeds 1 MiB")
    return result


def load_json(path: Path) -> Any:
    raw = path.read_bytes()
    if not 1 <= len(raw) <= MAX_BYTES:
        raise PlanError("source plan size must be 1..1048576 bytes")
    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=object_no_duplicates)
    except UnicodeDecodeError as error:
        raise PlanError("source plan is not UTF-8") from error
    except json.JSONDecodeError as error:
        raise PlanError(f"invalid JSON: {error.msg}") from error


def write_atomic(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", newline="\n", dir=path.parent,
        prefix=f".{path.name}.", suffix=".tmp", delete=False,
    ) as temporary:
        temporary.write(content)
        temporary.flush()
        os.fsync(temporary.fileno())
        temporary_path = Path(temporary.name)
    try:
        os.chmod(temporary_path, 0o644)
        os.replace(temporary_path, path)
    finally:
        temporary_path.unlink(missing_ok=True)


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(
        description=(
            "Compile msys.native-lite-plan.source.v1 JSON into the strict "
            "MSYS_NATIVE_LITE_PLAN v1 line protocol. No package lookup, shell "
            "expansion, or target-side Python is involved."
        )
    )
    command.add_argument("source", type=Path)
    command.add_argument("-o", "--output", type=Path)
    command.add_argument("--check", action="store_true", help="validate without writing")
    return command


def main(argv: list[str] | None = None) -> int:
    arguments = parser().parse_args(argv)
    try:
        result = compile_document(load_json(arguments.source))
        if arguments.check:
            print("native-lite plan: ok")
        elif arguments.output is None:
            print(result, end="")
        else:
            write_atomic(arguments.output, result)
            print(f"native-lite plan: wrote {arguments.output}")
        return 0
    except (OSError, PlanError) as error:
        print(f"native-lite plan: {error}", file=__import__("sys").stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
