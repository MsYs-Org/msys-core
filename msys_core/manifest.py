from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Mapping
import json

from .isolation import IsolationSpec, parse_isolation
from .profile_contract import load_profile_document, validate_profile_id


MIN_IDLE_TIMEOUT_MS = 1_000
MAX_IDLE_TIMEOUT_MS = 86_400_000


@dataclass(slots=True)
class Provide:
    kind: str
    name: str
    exclusive: bool = False
    priority: int = 0


@dataclass(slots=True)
class Component:
    package_id: str
    package_version: str
    id: str
    exec: list[str]
    lifecycle: str
    package_kind: str = "application"
    package_name: str = ""
    package_icons: list[dict[str, Any]] = field(default_factory=list)
    runtime: str = "custom"
    restart: str = "never"
    idle_timeout_ms: int | None = None
    cwd: str | None = None
    env: dict[str, str] = field(default_factory=dict)
    readiness_mode: str = "exec"
    readiness_timeout_ms: int = 5000
    provides: list[Provide] = field(default_factory=list)
    requires: list[str] = field(default_factory=list)
    wants: list[str] = field(default_factory=list)
    after: list[str] = field(default_factory=list)
    windowing: dict[str, Any] = field(default_factory=dict)
    activation: dict[str, Any] = field(default_factory=dict)
    permissions: list[str] = field(default_factory=list)
    isolation: IsolationSpec = field(default_factory=IsolationSpec)
    raw: dict[str, Any] = field(default_factory=dict)
    manifest_path: Path | None = None
    # Appended fields preserve the positional layout of the original internal
    # Component constructor for embedders that have not moved to keywords yet.
    package_summary: str = ""
    package_i18n: object = None

    @property
    def key(self) -> str:
        return f"{self.package_id}:{self.id}"


def _provide(raw: dict[str, Any]) -> Provide:
    if "role" in raw:
        return Provide(
            kind="role",
            name=str(raw["role"]),
            exclusive=bool(raw.get("exclusive", True)),
            priority=int(raw.get("priority", 0)),
        )
    if "interface" in raw:
        return Provide(
            kind="interface",
            name=str(raw["interface"]),
            exclusive=bool(raw.get("exclusive", False)),
            priority=int(raw.get("priority", 0)),
        )
    if "capability" in raw:
        return Provide(
            kind="capability",
            name=str(raw["capability"]),
            exclusive=bool(raw.get("exclusive", False)),
            priority=int(raw.get("priority", 0)),
        )
    raise ValueError(f"unknown provide entry: {raw!r}")


def _component_reference(package_id: str, value: object) -> str:
    """Normalize manifest-local references to their global component id."""

    reference = str(value)
    return reference if ":" in reference else f"{package_id}:{reference}"


def _idle_timeout(path: Path, raw: dict[str, Any], lifecycle: str) -> int | None:
    if "idle_timeout_ms" not in raw:
        return None
    value = raw["idle_timeout_ms"]
    component_id = str(raw.get("id", ""))
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(
            f"{path}: component {component_id} idle_timeout_ms must be an integer"
        )
    if not MIN_IDLE_TIMEOUT_MS <= value <= MAX_IDLE_TIMEOUT_MS:
        raise ValueError(
            f"{path}: component {component_id} idle_timeout_ms must be between "
            f"{MIN_IDLE_TIMEOUT_MS} and {MAX_IDLE_TIMEOUT_MS}"
        )
    if lifecycle != "on-demand":
        raise ValueError(
            f"{path}: component {component_id} idle_timeout_ms requires "
            "lifecycle=on-demand"
        )
    return value


def load_manifest(path: Path) -> list[Component]:
    data = json.loads(path.read_text(encoding="utf-8-sig"))
    if data.get("schema") != "msys.manifest.v1":
        raise ValueError(f"{path} is not an MSYS v1 manifest")
    pkg = data["package"]
    package_id = str(pkg["id"])
    package_version = str(pkg.get("version", "0.0.0"))
    package_kind = str(pkg.get("kind", "application"))
    package_name = str(pkg.get("name") or package_id)
    package_summary = (
        pkg.get("summary", "") if isinstance(pkg.get("summary", ""), str) else ""
    )
    package_i18n = pkg.get("x-msys-i18n")
    components: list[Component] = []
    for raw in data.get("components", []):
        readiness = raw.get("readiness", {})
        lifecycle = str(raw.get("lifecycle", "manual"))
        if "isolation" in raw and "x-msys-isolation" in raw:
            raise ValueError(f"{path}: component {raw.get('id', '')} declares isolation twice")
        isolation = parse_isolation(raw.get("isolation", raw.get("x-msys-isolation")))
        components.append(
            Component(
                package_id=package_id,
                package_version=package_version,
                package_kind=package_kind,
                package_name=package_name,
                package_summary=package_summary,
                package_i18n=(
                    dict(package_i18n) if isinstance(package_i18n, dict) else package_i18n
                ),
                package_icons=[
                    dict(icon)
                    for icon in pkg.get("icons", [])
                    if isinstance(icon, dict)
                ],
                id=str(raw["id"]),
                exec=[str(x) for x in raw["exec"]],
                lifecycle=lifecycle,
                runtime=str(raw.get("runtime", "custom")),
                restart=str(raw.get("restart", "never")),
                idle_timeout_ms=_idle_timeout(path, raw, lifecycle),
                cwd=str(raw["cwd"]) if raw.get("cwd") else None,
                env={str(k): str(v) for k, v in raw.get("env", {}).items()},
                readiness_mode=str(readiness.get("mode", "exec")),
                readiness_timeout_ms=int(readiness.get("timeout_ms", 5000)),
                provides=[_provide(x) for x in raw.get("provides", [])],
                requires=[
                    _component_reference(package_id, x)
                    for x in raw.get("requires", [])
                ],
                wants=[
                    _component_reference(package_id, x)
                    for x in raw.get("wants", [])
                ],
                after=[
                    _component_reference(package_id, x)
                    for x in raw.get("after", [])
                ],
                windowing=dict(raw.get("windowing", {})),
                activation=dict(raw.get("activation", {})),
                permissions=[str(x) for x in raw.get("permissions", [])],
                isolation=isolation,
                raw=raw,
                manifest_path=path,
            )
        )
    return components


def load_manifests(config_dir: Path) -> dict[str, Component]:
    manifests = sorted(config_dir.glob("manifests/**/*.json"))
    manifests += sorted(config_dir.glob("manifests/*.json"))
    result: dict[str, Component] = {}
    for path in dict.fromkeys(manifests):
        for component in load_manifest(path):
            if component.key in result:
                raise ValueError(f"duplicate component id {component.key}")
            result[component.key] = component
    return result


def load_manifest_paths(paths: Iterable[Path]) -> dict[str, Component]:
    """Load explicitly selected canonical manifests.

    Each path is loaded at most once. Different files may not declare the same
    component identity; package-level replacement is applied separately by
    :func:`replace_package_components`.
    """

    result: dict[str, Component] = {}
    for path in dict.fromkeys(Path(item).resolve() for item in paths):
        if not path.is_file():
            raise ValueError(f"canonical manifest is not a file: {path}")
        for component in load_manifest(path):
            if component.key in result:
                raise ValueError(f"duplicate canonical component id {component.key}")
            result[component.key] = component
    return result


def replace_package_components(
    base: Mapping[str, Component],
    replacements: Mapping[str, Component],
) -> dict[str, Component]:
    """Atomically replace complete package component sets.

    A package update is an atomic unit. If its new manifest removes a component,
    that old component must not survive from a built-in or development fallback.
    """

    package_ids = {component.package_id for component in replacements.values()}
    result = {
        key: component
        for key, component in base.items()
        if component.package_id not in package_ids
    }
    result.update(replacements)
    return result


def load_installed_manifests(
    state_dir: Path,
    *,
    recover_pending: bool = True,
) -> dict[str, Component]:
    registry = state_dir / "registry" / "installed.json"
    if not registry.exists():
        return {}
    data = json.loads(registry.read_text(encoding="utf-8-sig"))
    packages = data.get("packages", [])
    transaction_path = state_dir / "registry" / "install-transaction.json"
    if recover_pending and transaction_path.exists():
        transaction = json.loads(transaction_path.read_text(encoding="utf-8-sig"))
        if (
            transaction.get("schema") == "msys.install-transaction.v1"
            and transaction.get("phase") in {"health_pending", "rolling_back"}
        ):
            package_id = str(transaction.get("package", ""))
            packages = [
                package
                for package in packages
                if not isinstance(package, dict) or package.get("package") != package_id
            ]
            restore_current = transaction.get("restore_current")
            if isinstance(restore_current, dict):
                packages.append(restore_current)
    result: dict[str, Component] = {}
    for package in packages:
        root = Path(str(package.get("path", "")))
        manifest = root / "manifest.json"
        if not manifest.exists():
            continue
        for component in load_manifest(manifest):
            if component.cwd is None:
                component.cwd = str(root)
            if component.key in result:
                raise ValueError(f"duplicate installed component id {component.key}")
            result[component.key] = component
    return result


def load_profile(config_dir: Path, profile_id: str) -> dict[str, Any]:
    safe_id = validate_profile_id(profile_id, "$requested_profile")
    path = config_dir / "profiles" / f"{safe_id}.json"
    return load_profile_document(path, expected_id=safe_id)
