from __future__ import annotations

import ctypes
import errno
import json
import os
import re
import shutil
import sys
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Callable

try:
    import resource
except ImportError:  # pragma: no cover - MSYS executes on Linux
    resource = None  # type: ignore[assignment]


FAIL_CLOSED = "fail-closed"
BEST_EFFORT = "best-effort"
FAILURE_POLICIES = frozenset({FAIL_CLOSED, BEST_EFFORT})
NAMESPACE_ORDER = ("user", "mount", "ipc", "uts", "network")
NAMESPACE_FLAGS = {
    "user": 0x10000000,      # CLONE_NEWUSER
    "mount": 0x00020000,     # CLONE_NEWNS
    "ipc": 0x08000000,       # CLONE_NEWIPC
    "uts": 0x04000000,       # CLONE_NEWUTS
    "network": 0x40000000,   # CLONE_NEWNET
}
NAMESPACE_PROC_NAMES = {
    "user": "user",
    "mount": "mnt",
    "ipc": "ipc",
    "uts": "uts",
    "network": "net",
}
RLIMIT_RESOURCES = {
    name: getattr(resource, constant)
    for name, constant in {
        "as": "RLIMIT_AS",
        "core": "RLIMIT_CORE",
        "cpu": "RLIMIT_CPU",
        "data": "RLIMIT_DATA",
        "fsize": "RLIMIT_FSIZE",
        "memlock": "RLIMIT_MEMLOCK",
        "nofile": "RLIMIT_NOFILE",
        "nproc": "RLIMIT_NPROC",
        "stack": "RLIMIT_STACK",
    }.items()
    if resource is not None and hasattr(resource, constant)
}

PR_SET_DUMPABLE = 4
PR_SET_NO_NEW_PRIVS = 38
MS_PRIVATE = 1 << 18
MS_REC = 1 << 14


class IsolationConfigurationError(ValueError):
    pass


class IsolationUnavailable(RuntimeError):
    pass


class PartialIsolationError(RuntimeError):
    """An irreversible isolation step succeeded before its setup failed."""


@dataclass(frozen=True, slots=True)
class RlimitSpec:
    soft: int
    hard: int


@dataclass(frozen=True, slots=True)
class SeccompSpec:
    mode: str = "off"
    profile: str = "default"


@dataclass(frozen=True, slots=True)
class IsolationSpec:
    profile: str = "none"
    failure: str = BEST_EFFORT
    namespaces: tuple[str, ...] = ()
    no_new_privs: bool = False
    dumpable: bool | None = None
    rlimits: dict[str, RlimitSpec] = field(default_factory=dict)
    seccomp: SeccompSpec = field(default_factory=SeccompSpec)

    @property
    def requested(self) -> bool:
        return bool(
            self.profile != "none"
            or self.namespaces
            or self.no_new_privs
            or self.dumpable is not None
            or self.rlimits
            or self.seccomp.mode != "off"
        )


def describe_isolation(spec: IsolationSpec) -> dict[str, Any]:
    return {
        "profile": spec.profile,
        "failure": spec.failure,
        "requested": spec.requested,
        "namespaces": list(spec.namespaces),
        "no_new_privs": spec.no_new_privs,
        "dumpable": spec.dumpable,
        "rlimits": {
            name: {"soft": limit.soft, "hard": limit.hard}
            for name, limit in sorted(spec.rlimits.items())
        },
        "seccomp": {
            "mode": spec.seccomp.mode,
            "profile": spec.seccomp.profile,
        },
        "security_boundary": "partial-not-a-filesystem-sandbox",
    }


PROFILE_DEFAULTS: dict[str, dict[str, Any]] = {
    "none": {},
    "baseline": {
        "no_new_privs": True,
        "dumpable": False,
        "rlimits": {
            "core": 0,
            "nofile": 1024,
        },
    },
    # This is deliberately named "namespaced", not "sandbox". These
    # namespaces reduce kernel-global reach but do not hide the host rootfs.
    "namespaced": {
        "namespaces": list(NAMESPACE_ORDER),
        "no_new_privs": True,
        "dumpable": False,
        "rlimits": {
            "core": 0,
            "nofile": 512,
            "nproc": 256,
        },
    },
    "custom": {},
}


def _boolean(raw: dict[str, Any], name: str, default: bool | None) -> bool | None:
    value = raw.get(name, default)
    if value is not None and not isinstance(value, bool):
        raise IsolationConfigurationError(f"isolation.{name} must be boolean")
    return value


def _limit_value(value: Any, field_name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise IsolationConfigurationError(f"{field_name} must be a non-negative integer")
    return value


def _parse_rlimit(name: str, value: Any) -> RlimitSpec:
    if name not in RLIMIT_RESOURCES:
        raise IsolationConfigurationError(f"unsupported rlimit {name}")
    if isinstance(value, int) and not isinstance(value, bool):
        limit = _limit_value(value, f"isolation.rlimits.{name}")
        return RlimitSpec(limit, limit)
    if not isinstance(value, dict):
        raise IsolationConfigurationError(
            f"isolation.rlimits.{name} must be an integer or soft/hard object"
        )
    unknown = set(value).difference({"soft", "hard"})
    if unknown:
        raise IsolationConfigurationError(f"unknown rlimit fields: {', '.join(sorted(unknown))}")
    if "soft" not in value and "hard" not in value:
        raise IsolationConfigurationError(f"isolation.rlimits.{name} is empty")
    hard = _limit_value(value.get("hard", value.get("soft")), f"isolation.rlimits.{name}.hard")
    soft = _limit_value(value.get("soft", hard), f"isolation.rlimits.{name}.soft")
    if soft > hard:
        raise IsolationConfigurationError(f"isolation.rlimits.{name}.soft exceeds hard")
    return RlimitSpec(soft, hard)


def _parse_seccomp(value: Any) -> SeccompSpec:
    if value is None or value == "off":
        return SeccompSpec()
    if value == "helper":
        return SeccompSpec(mode="helper")
    if not isinstance(value, dict):
        raise IsolationConfigurationError("isolation.seccomp must be off, helper, or an object")
    unknown = set(value).difference({"mode", "profile"})
    if unknown:
        raise IsolationConfigurationError(f"unknown seccomp fields: {', '.join(sorted(unknown))}")
    mode = str(value.get("mode", "off"))
    if mode not in {"off", "helper"}:
        raise IsolationConfigurationError(f"unsupported seccomp mode {mode}")
    profile = str(value.get("profile", "default"))
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", profile):
        raise IsolationConfigurationError("invalid seccomp helper profile")
    return SeccompSpec(mode=mode, profile=profile)


def parse_isolation(value: Any) -> IsolationSpec:
    """Parse a component isolation declaration without changing defaults."""

    if value is None:
        return IsolationSpec()
    if isinstance(value, str):
        raw: dict[str, Any] = {"profile": value}
    elif isinstance(value, dict):
        raw = dict(value)
    else:
        raise IsolationConfigurationError("component isolation must be a profile string or object")

    allowed = {
        "profile",
        "failure",
        "namespaces",
        "no_new_privs",
        "dumpable",
        "rlimits",
        "seccomp",
    }
    unknown = set(raw).difference(allowed)
    if unknown:
        raise IsolationConfigurationError(f"unknown isolation fields: {', '.join(sorted(unknown))}")
    profile = str(raw.get("profile", "custom"))
    if profile not in PROFILE_DEFAULTS:
        raise IsolationConfigurationError(f"unknown isolation profile {profile}")
    defaults = PROFILE_DEFAULTS[profile]
    # Absence of the whole isolation declaration is the compatibility path.
    # Once a component opts in, an omitted policy must not silently weaken it.
    failure = str(raw.get("failure", FAIL_CLOSED))
    if failure not in FAILURE_POLICIES:
        raise IsolationConfigurationError(f"invalid isolation failure policy {failure}")

    namespace_values = raw.get("namespaces", defaults.get("namespaces", []))
    if not isinstance(namespace_values, list) or any(not isinstance(item, str) for item in namespace_values):
        raise IsolationConfigurationError("isolation.namespaces must be an array of names")
    namespaces = tuple(dict.fromkeys(namespace_values))
    unsupported = set(namespaces).difference(NAMESPACE_FLAGS)
    if unsupported:
        detail = ", ".join(sorted(unsupported))
        if "pid" in unsupported:
            detail += " (pid needs a double-fork/helper and is not implemented)"
        raise IsolationConfigurationError(f"unsupported namespaces: {detail}")

    no_new_privs = _boolean(raw, "no_new_privs", bool(defaults.get("no_new_privs", False)))
    dumpable = _boolean(raw, "dumpable", defaults.get("dumpable"))
    assert isinstance(no_new_privs, bool)

    raw_limits = dict(defaults.get("rlimits", {}))
    overrides = raw.get("rlimits", {})
    if not isinstance(overrides, dict):
        raise IsolationConfigurationError("isolation.rlimits must be an object")
    for name, limit in overrides.items():
        if limit is None:
            raw_limits.pop(str(name), None)
        else:
            raw_limits[str(name)] = limit
    limits = {name: _parse_rlimit(name, limit) for name, limit in raw_limits.items()}
    seccomp = _parse_seccomp(raw.get("seccomp", defaults.get("seccomp", "off")))
    if seccomp.mode == "helper" and not no_new_privs:
        raise IsolationConfigurationError("seccomp helper requires no_new_privs=true")
    return IsolationSpec(
        profile=profile,
        failure=failure,
        namespaces=namespaces,
        no_new_privs=no_new_privs,
        dumpable=dumpable,
        rlimits=limits,
        seccomp=seccomp,
    )


@dataclass(frozen=True, slots=True)
class IsolationCapabilities:
    linux: bool
    prctl: bool
    unshare: bool
    namespaces: frozenset[str]
    rlimits: frozenset[str]
    seccomp_helper: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "linux": self.linux,
            "no_new_privs": self.prctl,
            "dumpable": self.prctl,
            "unshare_api": self.unshare,
            "namespaces": {name: name in self.namespaces for name in NAMESPACE_ORDER},
            "rlimits": sorted(self.rlimits),
            "seccomp": {
                "mode": "optional-helper",
                "helper": self.seccomp_helper,
                "available": self.seccomp_helper is not None,
            },
            "permission_probe": "deferred-to-child",
            "security_boundary": "partial-not-a-filesystem-sandbox",
        }


def resolve_executable(command: str | None) -> str | None:
    if not command:
        return None
    if os.path.isabs(command) or os.sep in command:
        path = Path(command)
        return str(path.resolve()) if path.is_file() and os.access(path, os.X_OK) else None
    return shutil.which(command)


def detect_capabilities(seccomp_helper: str | None = None) -> IsolationCapabilities:
    linux = sys.platform.startswith("linux")
    prctl = False
    unshare = False
    if linux:
        try:
            libc = ctypes.CDLL(None)
            prctl = hasattr(libc, "prctl")
            unshare = hasattr(libc, "unshare")
        except OSError:
            pass
    namespaces = frozenset(
        name
        for name, proc_name in NAMESPACE_PROC_NAMES.items()
        if unshare and Path(f"/proc/self/ns/{proc_name}").exists()
    )
    return IsolationCapabilities(
        linux=linux,
        prctl=prctl,
        unshare=unshare,
        namespaces=namespaces,
        rlimits=frozenset(RLIMIT_RESOURCES) if linux else frozenset(),
        seccomp_helper=resolve_executable(seccomp_helper) if linux else None,
    )


class LinuxIsolationBackend:
    def __init__(self) -> None:
        self.libc = ctypes.CDLL(None, use_errno=True)

    def _check(self, result: int, operation: str) -> None:
        if result != 0:
            error = ctypes.get_errno() or errno.EPERM
            raise OSError(error, f"{operation}: {os.strerror(error)}")

    def unshare(self, namespace: str) -> None:
        self._check(int(self.libc.unshare(NAMESPACE_FLAGS[namespace])), f"unshare({namespace})")

    @staticmethod
    def _write_mapping(path: str, value: str, *, optional: bool = False) -> None:
        try:
            with open(path, "w", encoding="ascii") as stream:
                stream.write(value)
        except FileNotFoundError:
            if not optional:
                raise

    def enter_user_namespace(self) -> None:
        uid = os.getuid()
        gid = os.getgid()
        self.unshare("user")
        try:
            self._write_mapping("/proc/self/setgroups", "deny\n", optional=True)
            self._write_mapping("/proc/self/uid_map", f"0 {uid} 1\n")
            self._write_mapping("/proc/self/gid_map", f"0 {gid} 1\n")
        except Exception as exc:
            # The namespace transition cannot be rolled back in this child.
            raise PartialIsolationError(f"user namespace mapping failed: {exc}") from exc

    def make_mounts_private(self) -> None:
        result = self.libc.mount(None, b"/", None, MS_REC | MS_PRIVATE, None)
        self._check(int(result), "mount(/, MS_PRIVATE|MS_REC)")

    def set_no_new_privs(self) -> None:
        self._check(int(self.libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)), "prctl(NO_NEW_PRIVS)")

    def set_dumpable(self, enabled: bool) -> None:
        self._check(int(self.libc.prctl(PR_SET_DUMPABLE, int(enabled), 0, 0, 0)), "prctl(DUMPABLE)")

    def set_rlimit(self, name: str, limit: RlimitSpec) -> None:
        if resource is None:
            raise OSError(errno.ENOSYS, "setrlimit is unavailable")
        resource.setrlimit(RLIMIT_RESOURCES[name], (limit.soft, limit.hard))


class IsolationPreexec:
    """Small child-side operation set; never called in the supervisor parent."""

    def __init__(self, spec: IsolationSpec, backend: Any | None = None) -> None:
        self.spec = spec
        self.backend = backend or LinuxIsolationBackend()

    @staticmethod
    def _diagnostic(disposition: str, label: str, exc: Exception) -> None:
        message = f"msys-isolation: {disposition} {label}: {exc}\n".encode(
            "utf-8", errors="replace"
        )
        try:
            os.write(2, message[:2048])
        except OSError:
            pass

    @classmethod
    def _warn(cls, label: str, exc: Exception) -> None:
        cls._diagnostic("best-effort skipped", label, exc)

    @classmethod
    def _abort(cls, label: str, exc: Exception) -> None:
        cls._diagnostic("aborting", label, exc)

    def _apply(self, label: str, operation: Callable[[], None]) -> bool:
        try:
            operation()
            return True
        except PartialIsolationError as exc:
            # Continuing after a half-configured user namespace is neither
            # compatible nor safe, even under best-effort policy.
            self._abort(label, exc)
            raise
        except Exception as exc:
            if self.spec.failure == FAIL_CLOSED:
                self._abort(label, exc)
                raise IsolationUnavailable(f"{label} failed: {exc}") from exc
            self._warn(label, exc)
            return False

    def __call__(self) -> None:
        if "user" in self.spec.namespaces:
            self._apply("namespace:user", self.backend.enter_user_namespace)
        for namespace in NAMESPACE_ORDER:
            if namespace == "user" or namespace not in self.spec.namespaces:
                continue
            entered = self._apply(
                f"namespace:{namespace}",
                lambda value=namespace: self.backend.unshare(value),
            )
            if namespace == "mount" and entered:
                self._apply("mount-propagation-private", self.backend.make_mounts_private)
        if self.spec.no_new_privs:
            self._apply("no_new_privs", self.backend.set_no_new_privs)
        if self.spec.dumpable is not None:
            self._apply("dumpable", lambda: self.backend.set_dumpable(bool(self.spec.dumpable)))
        for name, limit in sorted(self.spec.rlimits.items()):
            self._apply(f"rlimit:{name}", lambda n=name, value=limit: self.backend.set_rlimit(n, value))


@dataclass(slots=True)
class IsolationLaunchPlan:
    argv: list[str]
    preexec_fn: Callable[[], None] | None
    spec: IsolationSpec
    effective: IsolationSpec
    skipped: list[str] = field(default_factory=list)
    seccomp_helper: str | None = None

    def summary(self) -> dict[str, Any]:
        return {
            "profile": self.spec.profile,
            "failure": self.spec.failure,
            "requested": self.spec.requested,
            "namespaces": list(self.effective.namespaces),
            "no_new_privs": self.effective.no_new_privs,
            "dumpable": self.effective.dumpable,
            "rlimits": {
                name: {"soft": limit.soft, "hard": limit.hard}
                for name, limit in sorted(self.effective.rlimits.items())
            },
            "seccomp": {
                "mode": self.effective.seccomp.mode,
                "profile": self.effective.seccomp.profile,
                "helper": self.seccomp_helper,
            },
            "degraded": bool(self.skipped),
            "skipped": list(self.skipped),
            "security_boundary": "partial-not-a-filesystem-sandbox",
        }

    def environment(self) -> dict[str, str]:
        summary = self.summary()
        return {
            "MSYS_ISOLATION_PROFILE": self.spec.profile,
            "MSYS_ISOLATION_FAILURE_POLICY": self.spec.failure,
            "MSYS_ISOLATION_DEGRADED": "1" if self.skipped else "0",
            "MSYS_ISOLATION_JSON": json.dumps(
                summary, ensure_ascii=False, separators=(",", ":")
            ),
        }


def prepare_isolation_launch(
    spec: IsolationSpec,
    argv: list[str],
    *,
    seccomp_helper: str | None = None,
    capabilities: IsolationCapabilities | None = None,
    backend_factory: Callable[[], Any] = LinuxIsolationBackend,
) -> IsolationLaunchPlan:
    """Preflight a launch and implement explicit fail-closed/degrade policy."""

    capabilities = capabilities or detect_capabilities(seccomp_helper)
    skipped: list[str] = []

    def unavailable(feature: str) -> None:
        if spec.failure == FAIL_CLOSED:
            raise IsolationUnavailable(f"isolation capability unavailable: {feature}")
        skipped.append(feature)

    effective_namespaces: list[str] = []
    for namespace in spec.namespaces:
        if capabilities.linux and capabilities.unshare and namespace in capabilities.namespaces:
            effective_namespaces.append(namespace)
        else:
            unavailable(f"namespace:{namespace}")

    no_new_privs = spec.no_new_privs
    if no_new_privs and not (capabilities.linux and capabilities.prctl):
        unavailable("no_new_privs")
        no_new_privs = False
    dumpable = spec.dumpable
    if dumpable is not None and not (capabilities.linux and capabilities.prctl):
        unavailable("dumpable")
        dumpable = None

    effective_limits: dict[str, RlimitSpec] = {}
    for name, limit in spec.rlimits.items():
        if capabilities.linux and name in capabilities.rlimits:
            effective_limits[name] = limit
        else:
            unavailable(f"rlimit:{name}")

    effective_seccomp = spec.seccomp
    helper = capabilities.seccomp_helper
    launch_argv = list(argv)
    if spec.seccomp.mode == "helper":
        if not capabilities.linux or helper is None:
            unavailable("seccomp:helper")
            effective_seccomp = SeccompSpec()
            helper = None
        else:
            launch_argv = [helper, "--profile", spec.seccomp.profile, "--", *launch_argv]

    effective = replace(
        spec,
        namespaces=tuple(effective_namespaces),
        no_new_privs=no_new_privs,
        dumpable=dumpable,
        rlimits=effective_limits,
        seccomp=effective_seccomp,
    )
    needs_preexec = bool(
        effective.namespaces
        or effective.no_new_privs
        or effective.dumpable is not None
        or effective.rlimits
    )
    preexec = IsolationPreexec(effective, backend_factory()) if needs_preexec else None
    return IsolationLaunchPlan(
        argv=launch_argv,
        preexec_fn=preexec,
        spec=spec,
        effective=effective,
        skipped=skipped,
        seccomp_helper=helper if effective_seccomp.mode == "helper" else None,
    )
