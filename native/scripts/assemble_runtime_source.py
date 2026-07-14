#!/usr/bin/env python3
"""Assemble installed package manifests into a strict native runtime v2 source.

This is a development/build-host tool. The target consumes only the compiled
line plan and therefore needs neither Python nor a JSON/package scanner.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import tempfile
from typing import Any


SCHEMA = "msys.native-runtime.source.v2"
MAX_BYTES = 1024 * 1024


class AssemblyError(ValueError):
    pass


def no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise AssemblyError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_json(path: Path) -> dict[str, Any]:
    raw = path.read_bytes()
    if not 1 <= len(raw) <= MAX_BYTES:
        raise AssemblyError(f"{path}: size is outside 1..1048576 bytes")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=no_duplicates)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AssemblyError(f"{path}: invalid UTF-8 JSON: {error}") from error
    if not isinstance(value, dict):
        raise AssemblyError(f"{path}: root must be an object")
    return value


def package_path(value: str, root: Path) -> str:
    if value == "@package":
        return str(root)
    if value.startswith("@package/"):
        return str(root / value[len("@package/"):])
    return value


def resolve_exec(argv: Any, root: Path, commands: dict[str, str], component: str) -> list[str]:
    if not isinstance(argv, list) or not argv or not all(isinstance(value, str) for value in argv):
        raise AssemblyError(f"{component}: exec must be a non-empty string array")
    result = [package_path(value, root) for value in argv]
    if not result[0].startswith("/"):
        replacement = commands.get(result[0])
        if replacement is None:
            raise AssemblyError(
                f"{component}: bare executable {result[0]!r} needs --command NAME=/absolute/path"
            )
        result[0] = replacement
    return result


def first_icon(component: dict[str, Any], package: dict[str, Any], root: Path) -> str:
    icons = component.get("icons") or package.get("icons") or []
    if not isinstance(icons, list):
        return ""
    candidates = [entry for entry in icons if isinstance(entry, dict) and isinstance(entry.get("path"), str)]
    if not candidates:
        return ""
    candidates.sort(key=lambda entry: int(entry.get("size", 0)), reverse=True)
    return package_path(str(candidates[0]["path"]), root)


def component_kind(provides: list[dict[str, Any]]) -> str:
    roles = {str(entry.get("role", "")) for entry in provides if isinstance(entry, dict)}
    if "display-output" in roles:
        return "display"
    if roles & {"window-manager", "window-policy"}:
        return "window"
    if roles & {"launcher", "system-chrome", "navigation-bar"}:
        return "shell"
    return "other"


def assemble(
    profile_path: Path,
    package_roots: list[tuple[Path, Path]],
    commands: dict[str, str],
) -> dict[str, Any]:
    profile = load_json(profile_path)
    if profile.get("schema") != "msys.profile.v1":
        raise AssemblyError("profile schema must be msys.profile.v1")
    profile_id = profile.get("id")
    roles = profile.get("roles", {})
    startup = profile.get("startup", [])
    profile_env = profile.get("env", {})
    settings = profile.get("settings", {})
    if not isinstance(profile_id, str) or not isinstance(roles, dict):
        raise AssemblyError("profile id/roles are invalid")
    if not isinstance(startup, list) or not isinstance(profile_env, dict) or not isinstance(settings, dict):
        raise AssemblyError("profile startup/env/settings are invalid")

    components: list[dict[str, Any]] = []
    known: set[str] = set()
    for source_value, target_value in package_roots:
        source_root = source_value.resolve()
        target_root = target_value
        manifest_path = source_root / "manifest.json"
        manifest = load_json(manifest_path)
        if manifest.get("schema") != "msys.manifest.v1":
            raise AssemblyError(f"{manifest_path}: schema must be msys.manifest.v1")
        package = manifest.get("package")
        raw_components = manifest.get("components")
        if not isinstance(package, dict) or not isinstance(raw_components, list):
            raise AssemblyError(f"{manifest_path}: package/components are invalid")
        package_id = package.get("id")
        if not isinstance(package_id, str):
            raise AssemblyError(f"{manifest_path}: package.id is invalid")
        package_metadata = {
            "id": package_id,
            "name": str(package.get("name", package_id)),
            "version": str(package.get("version", "")),
            "kind": str(package.get("kind", "system")),
        }
        for raw_component in raw_components:
            if not isinstance(raw_component, dict) or not isinstance(raw_component.get("id"), str):
                raise AssemblyError(f"{manifest_path}: invalid component")
            local_id = str(raw_component["id"])
            key = f"{package_id}:{local_id}"
            if key in known:
                raise AssemblyError(f"duplicate component {key}")
            known.add(key)
            provides = raw_component.get("provides", [])
            permissions = raw_component.get("permissions", [])
            environment = raw_component.get("env", {})
            readiness = raw_component.get("readiness", {"mode": "exec", "timeout_ms": 5000})
            windowing = raw_component.get("windowing", {})
            activation = raw_component.get("activation", {})
            if not isinstance(provides, list) or not isinstance(permissions, list):
                raise AssemblyError(f"{key}: provides/permissions are invalid")
            if not isinstance(environment, dict) or not isinstance(readiness, dict):
                raise AssemblyError(f"{key}: env/readiness are invalid")
            if not isinstance(windowing, dict) or not isinstance(activation, dict):
                raise AssemblyError(f"{key}: windowing/activation are invalid")
            identity = windowing.get("identity", {})
            if isinstance(identity, str):
                identity = {"app_id": identity, "x11_wm_class": identity}
            if not isinstance(identity, dict):
                identity = {}
            lifecycle = str(raw_component.get("lifecycle", "manual"))
            idle_timeout = int(raw_component.get("idle_timeout_ms", 30_000)) if lifecycle == "on-demand" else 0
            native_provides: list[dict[str, Any]] = []
            for provided in provides:
                if not isinstance(provided, dict):
                    raise AssemblyError(f"{key}: invalid provide entry")
                kinds = [name for name in ("role", "interface", "capability") if name in provided]
                if len(kinds) != 1:
                    raise AssemblyError(f"{key}: provide entry needs exactly one kind")
                provide_kind = kinds[0]
                native_provides.append({
                    provide_kind: str(provided[provide_kind]),
                    "exclusive": bool(provided.get("exclusive", False)),
                    "priority": int(provided.get("priority", 0)),
                })
            components.append({
                "id": key,
                "kind": component_kind(provides),
                "critical": key in startup,
                "lifecycle": lifecycle,
                "idle_timeout_ms": idle_timeout,
                "restart": str(raw_component.get("restart", "never")),
                "readiness": {
                    "mode": str(readiness.get("mode", "exec")),
                    "timeout_ms": int(readiness.get("timeout_ms", 5000)),
                },
                "exec": resolve_exec(raw_component.get("exec"), target_root, commands, key),
                "after": [str(value) for value in raw_component.get("after", [])],
                "env": {str(name): str(value) for name, value in environment.items()},
                "provides": native_provides,
                "permissions": [str(value) for value in permissions],
                "package": package_metadata,
                "name": str(raw_component.get("name", package_metadata["name"])),
                "summary": str(raw_component.get("summary", package.get("summary", ""))),
                "icon": first_icon(raw_component, package, target_root),
                "launchable": bool(activation.get("launchable", False)),
                "windowing": {
                    "system": str(windowing.get("system", "")),
                    "display": str(windowing.get("display", "")),
                    "mode": str(windowing.get("mode", "")),
                    "title": str(windowing.get("title", "")),
                    "app_id": str(identity.get("app_id", "")),
                    "wm_class": str(identity.get("x11_wm_class", identity.get("app_id", ""))),
                    "wm_instance": str(identity.get("x11_wm_instance", "")),
                },
            })

    # `after` is ordering-only. Omit alternatives not present in this closed
    # catalog instead of turning them into accidental hard dependencies.
    for component in components:
        component["after"] = [value for value in component["after"] if value in known]
    native_roles: dict[str, list[str]] = {}
    for role, providers in roles.items():
        if not isinstance(role, str) or not isinstance(providers, list):
            raise AssemblyError("profile roles must map strings to arrays")
        present = [str(value) for value in providers if str(value) in known]
        if present:
            native_roles[role] = present
    native_startup = [str(value) for value in startup if str(value) in known]
    if not native_startup:
        raise AssemblyError("profile has no startup component in the supplied catalog")
    return {
        "schema": SCHEMA,
        "stop_grace_ms": 2000,
        "profile": {
            "id": profile_id,
            "display": str(settings.get("display", "")),
            "roles": native_roles,
            "startup": native_startup,
            "env": {str(name): str(value) for name, value in profile_env.items()},
        },
        "components": components,
    }


def write_atomic(path: Path, document: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    content = json.dumps(document, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
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


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Assemble manifest/profile data for native Core v2")
    parser.add_argument("--profile", type=Path, required=True)
    parser.add_argument(
        "--package-root",
        action="append",
        required=True,
        metavar="SOURCE[=TARGET]",
        help="manifest source root and optional absolute target package root",
    )
    parser.add_argument("--command", action="append", default=[])
    parser.add_argument("-o", "--output", type=Path, required=True)
    args = parser.parse_args(argv)
    commands = {
        "python": "/opt/msys-dev/.runtime/python/bin/python3",
        "python3": "/opt/msys-dev/.runtime/python/bin/python3",
        "bash": "/bin/bash",
        "sh": "/bin/sh",
    }
    try:
        for assignment in args.command:
            name, separator, value = assignment.partition("=")
            if not separator or not name or not value.startswith("/"):
                raise AssemblyError("--command must be NAME=/absolute/path")
            commands[name] = value
        package_roots: list[tuple[Path, Path]] = []
        for declaration in args.package_root:
            source, separator, target = declaration.partition("=")
            source_path = Path(source)
            target_path = Path(target) if separator else source_path.resolve()
            if separator and not target_path.is_absolute():
                raise AssemblyError("--package-root target must be absolute")
            package_roots.append((source_path, target_path))
        document = assemble(args.profile, package_roots, commands)
        write_atomic(args.output, document)
        print(f"native runtime source: wrote {args.output}")
        return 0
    except (OSError, AssemblyError, ValueError) as error:
        print(f"native runtime source: {error}", file=__import__("sys").stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
