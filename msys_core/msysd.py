from __future__ import annotations

import argparse
import asyncio
import fcntl
import fnmatch
import heapq
import json
import os
import re
import signal
import socket
import stat
import struct
import subprocess
import sys
import time
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import Any

from .isolation import describe_isolation, detect_capabilities, prepare_isolation_launch
from .manifest import (
    Component,
    load_installed_manifests,
    load_manifest_paths,
    load_manifests,
    load_profile,
    replace_package_components,
)
from .mipc_acl import (
    MAX_TOPIC_LENGTH,
    allows_call,
    allows_event,
    call_permission_candidates,
    event_permission,
    subscription_matches,
    valid_event_topic,
    valid_subscription,
)
from .protocol import MAX_PACKET, ProtocolError, decode, send_packet
from .presentation_i18n import PresentationCatalogCache
from .roles import RoleRegistry
from .services import ServiceCatalog


ROLE_RETRY_SAFE_METHODS = {
    "list_windows",
    "recents",
    "list",
    "status",
    "capabilities",
}
ROLE_NO_START_NOOPS = frozenset({
    ("input-method", "hide"),
    ("notification-center", "hide"),
})
ROLE_LIVENESS_ERRORS = {
    "CALL_TIMEOUT",
    "CALL_SEND_FAILED",
    "NO_PROVIDER_SOCKET",
    "PROVIDER_EXITED",
    "PROVIDER_STOPPED",
}
MAX_FORWARD_TIMEOUT_SECONDS = 300.0
CALL_DEADLINE_EXPIRED_MESSAGE = "call deadline already expired"
ROLE_SWITCH_CLEANUP_BUDGET_SECONDS = 0.025
PROCESS_EXIT_FALLBACK_POLL_SECONDS = 0.02
X11_READINESS_POLL_SECONDS = 0.02
TRANSITION_PHASES = frozenset({"launching", "launched", "closing", "closed", "failed"})
MAX_SUBSCRIPTIONS = 128
DEFAULT_X11_DISPLAY = ":0"
DISPLAY_MIGRATION_TOPIC = "msys.display.migration"
DISPLAY_MIGRATION_SCHEMA = "msys.display-migration.v1"
DISPLAY_OUTPUT_RECOVERED_TOPIC = "msys.display.output_recovered"
DISPLAY_OUTPUT_RECOVERED_SCHEMA = "msys.display-output-recovered.v1"
DISPLAY_OUTPUT_ROLE = "display-output"
DISPLAY_FAILURE_QUARANTINE_GRACE_SECONDS = 15.0
ACCESS_DENIED = "ACCESS_DENIED"
DEFAULT_MEMINFO_PATH = Path("/proc/meminfo")
DEFAULT_PROC_ROOT = Path("/proc")
CATALOG_TRANSACTION_SCHEMA = "msys.catalog-transaction.v1"
APPLICATION_NAVIGATION_INTERFACE = "org.msys.application-navigation.v1"
APPLICATION_CRASH_SCHEMA = "msys.application-crash.v1"
APPLICATION_CRASH_TOPIC = "msys.notification.post"
SESSION_PREFERENCES_SCHEMA = "msys.session-preferences.v1"
SESSION_PREFERENCES_TOPIC = "msys.session.preferences.changed"
PROCESS_LIST_SCHEMA = "msys.process-list.v1"
DEFAULT_SYSTEM_PROCESS_LIMIT = 64
MAX_SYSTEM_PROCESS_LIMIT = 128
MAX_LOGICAL_TARGET_LENGTH = 192
LOGICAL_TARGET_PATTERN = re.compile(
    rf"^(?:role|interface|component):[A-Za-z0-9][A-Za-z0-9._:-]{{0,{MAX_LOGICAL_TARGET_LENGTH - 2}}}$"
)
MAX_MANAGED_PROCESS_RESULTS = 128
MAX_PROCESS_NAME_LENGTH = 64

_LINUX_PROCESS_STATES = {
    "R": "running",
    "S": "sleeping",
    "D": "disk-sleep",
    "Z": "zombie",
    "T": "stopped",
    "t": "tracing-stop",
    "X": "dead",
    "x": "dead",
    "I": "idle",
    "P": "parked",
}

# Locale values are part of the visual-session contract, not application
# configuration.  Keep the list deliberately small and POSIX-compatible:
# SDK applications consume MSYS_LOCALE first, while native and toolkit
# applications still consume LANG/LC_* directly.
I18N_LOCALE_PRECEDENCE = ("MSYS_LOCALE", "LC_ALL", "LC_MESSAGES", "LANG")
_I18N_LOCALE_NAME = re.compile(
    r"^[a-z]{2,8}(?:-[A-Z][a-z]{3})?"
    r"(?:-(?:[A-Z]{2}|[0-9]{3}))?"
    r"(?:-(?:[a-z0-9]{5,8}|[0-9][a-z0-9]{3}))*$"
)


def _process_group_members(
    leader_pid: int,
    proc_root: Path = DEFAULT_PROC_ROOT,
) -> list[int]:
    """Return one component session's process group from bounded proc metadata."""

    if leader_pid <= 0:
        return []
    members: list[int] = []
    try:
        entries = list(proc_root.iterdir())
    except OSError:
        return []
    for entry in entries:
        if not entry.name.isdigit():
            continue
        try:
            text = (entry / "stat").read_text(encoding="ascii", errors="replace")
            fields = text[text.rindex(")") + 1 :].split()
            process_group = int(fields[2])
        except (OSError, ValueError, IndexError):
            continue
        if process_group == leader_pid:
            members.append(int(entry.name))
    return sorted(set(members))


def _memory_values(path: Path) -> tuple[int | None, int | None]:
    try:
        text = path.read_text(encoding="ascii", errors="replace")
    except OSError:
        return None, None
    values: dict[str, int] = {}
    for name in ("Rss", "Pss"):
        match = re.search(rf"(?m)^{name}:\s+([0-9]+)\s+kB\s*$", text)
        if match is not None:
            values[name] = int(match.group(1))
    return values.get("Rss"), values.get("Pss")


def _status_rss(path: Path) -> int | None:
    try:
        text = path.read_text(encoding="ascii", errors="replace")
    except OSError:
        return None
    match = re.search(r"(?m)^VmRSS:\s+([0-9]+)\s+kB\s*$", text)
    return int(match.group(1)) if match is not None else None


def process_memory_snapshot(
    leader_pid: int,
    proc_root: Path = DEFAULT_PROC_ROOT,
) -> dict[str, Any]:
    """Sample RSS/PSS once for an explicitly requested component snapshot."""

    members = _process_group_members(leader_pid, proc_root)
    rss_values: list[int] = []
    pss_values: list[int] = []
    for pid in members:
        rss, pss = _memory_values(proc_root / str(pid) / "smaps_rollup")
        if rss is None:
            rss = _status_rss(proc_root / str(pid) / "status")
        if rss is not None:
            rss_values.append(rss)
        if pss is not None:
            pss_values.append(pss)
    rss_complete = bool(members) and len(rss_values) == len(members)
    pss_complete = rss_complete and len(pss_values) == len(members)
    return {
        "schema": "msys.process-memory.v1",
        "scope": "process-group",
        "unit": "KiB",
        "leader_pid": leader_pid,
        "member_count": len(members),
        "available": rss_complete,
        "rss_kib": sum(rss_values) if rss_complete else None,
        "pss_available": pss_complete,
        "pss_kib": sum(pss_values) if pss_complete else None,
        "reason": (
            None
            if pss_complete
            else "pss-unavailable" if rss_complete else "memory-unavailable"
        ),
    }


def _bounded_process_name(value: object, fallback: str) -> str:
    """Return a single-line proc name with a fixed response-size bound."""

    text = "".join(
        character if character.isprintable() and character not in "\r\n\0" else "?"
        for character in str(value)
    ).strip()
    if not text:
        text = fallback
    return text[:MAX_PROCESS_NAME_LENGTH]


def _proc_process_record(
    pid: int,
    proc_root: Path = DEFAULT_PROC_ROOT,
) -> dict[str, Any] | None:
    """Read one bounded Linux process record directly from procfs.

    ``stat`` is authoritative for identity and parent/group/session metadata;
    ``status`` supplies the real UID and leader RSS when available.  A process
    that exits during either read is simply omitted from the snapshot.
    """

    if pid <= 0:
        return None
    directory = proc_root / str(pid)
    try:
        stat_text = (directory / "stat").read_text(
            encoding="ascii", errors="replace"
        )
        opening = stat_text.index("(")
        closing = stat_text.rindex(")")
        fields = stat_text[closing + 1 :].split()
        if len(fields) < 4:
            return None
        state_code = fields[0]
        ppid = int(fields[1])
        process_group = int(fields[2])
        session = int(fields[3])
        name = _bounded_process_name(stat_text[opening + 1 : closing], str(pid))
    except (OSError, ValueError, IndexError):
        return None

    uid: int | None = None
    rss_kib: int | None = None
    try:
        status_text = (directory / "status").read_text(
            encoding="ascii", errors="replace"
        )
    except OSError:
        status_text = ""
    uid_match = re.search(r"(?m)^Uid:\s+([0-9]+)(?:\s|$)", status_text)
    if uid_match is not None:
        uid = int(uid_match.group(1))
    rss_match = re.search(r"(?m)^VmRSS:\s+([0-9]+)\s+kB\s*$", status_text)
    if rss_match is not None:
        rss_kib = int(rss_match.group(1))
    return {
        "pid": pid,
        "ppid": ppid,
        "process_group": process_group,
        "session": session,
        "uid": uid,
        "name": name,
        "state": _LINUX_PROCESS_STATES.get(state_code, "unknown"),
        "rss_kib": rss_kib,
    }


def _public_process_record(
    record: dict[str, Any],
    *,
    source: str,
    msys_owned: bool,
    component: str | None = None,
    component_state: str | None = None,
    runtime: str | None = None,
    lifecycle: str | None = None,
    generation: int | None = None,
) -> dict[str, Any]:
    """Project internal proc metadata onto the closed public v1 fields."""

    return {
        "pid": int(record["pid"]),
        "ppid": record.get("ppid"),
        "uid": record.get("uid"),
        "name": str(record["name"]),
        "state": str(record["state"]),
        "rss_kib": record.get("rss_kib"),
        "source": source,
        "msys_owned": msys_owned,
        "component": component,
        "component_state": component_state,
        "runtime": runtime,
        "lifecycle": lifecycle,
        "generation": generation,
    }


def system_process_snapshot(
    managed_leader_pids: set[int],
    *,
    proc_root: Path = DEFAULT_PROC_ROOT,
    limit: int = DEFAULT_SYSTEM_PROCESS_LIMIT,
    supervisor_pid: int | None = None,
) -> tuple[list[dict[str, Any]], bool]:
    """Return a bounded, PID-ordered non-MSYS Linux process snapshot.

    The scan retains only ``limit`` records in memory.  Component descendants
    are excluded by their process-group or session leader, matching Core's
    supervised ``start_new_session`` process boundary.
    """

    if not 1 <= limit <= MAX_SYSTEM_PROCESS_LIMIT:
        raise ValueError("system process limit is out of range")
    if supervisor_pid is None:
        supervisor_pid = os.getpid()
    heap: list[tuple[int, int, int, dict[str, Any]]] = []
    eligible_count = 0
    try:
        entries = os.scandir(proc_root)
    except OSError:
        return [], False
    with entries:
        for entry in entries:
            if not entry.name.isdigit():
                continue
            pid = int(entry.name)
            record = _proc_process_record(pid, proc_root)
            if record is None:
                continue
            if (
                pid == supervisor_pid
                or pid in managed_leader_pids
                or record["process_group"] in managed_leader_pids
                or record["session"] in managed_leader_pids
            ):
                continue
            if record["rss_kib"] is None and (
                pid == 2 or record["ppid"] == 2
            ):
                # Linux kernel threads have no userspace RSS and are normally
                # parented by kthreadd. They are not actionable in Settings
                # and must not consume the bounded userspace result budget.
                continue
            eligible_count += 1
            rss_kib = record["rss_kib"]
            item = (
                1 if rss_kib is not None else 0,
                int(rss_kib or 0),
                -pid,
                record,
            )
            if len(heap) < limit:
                heapq.heappush(heap, item)
            elif item[:3] > heap[0][:3]:
                heapq.heapreplace(heap, item)
    selected = sorted(
        (item[3] for item in heap),
        key=lambda item: (
            item["rss_kib"] is None,
            -int(item["rss_kib"] or 0),
            item["pid"],
        ),
    )
    return [
        _public_process_record(
            record,
            source="procfs",
            msys_owned=False,
        )
        for record in selected
    ], eligible_count > limit


def _is_i18n_environment_name(name: str) -> bool:
    """Return whether *name* participates in the process locale contract."""

    return name == "MSYS_LOCALE" or name == "LANG" or name.startswith("LC_")


def _normalize_msys_locale(value: object) -> str | None:
    """Normalize a common POSIX/BCP-47 locale for ``MSYS_LOCALE``.

    This intentionally mirrors the small public SDK locale grammar without
    importing the SDK into Core.  A C/POSIX locale deliberately returns
    ``None``: leaving ``MSYS_LOCALE`` absent preserves the SDK's documented
    fallback-to-catalog-default behavior.
    """

    raw = str(value).strip()
    if not raw or raw.upper() in {"C", "POSIX", "C.UTF-8", "C.UTF8"}:
        return None
    # POSIX spelling can include an encoding and an optional modifier.  The
    # language tag, rather than those libc implementation details, is the
    # stable MSYS application contract.
    tag = raw.split("@", 1)[0].split(".", 1)[0].replace("_", "-")
    parts = tag.split("-")
    if not parts or not parts[0].isalpha() or not 2 <= len(parts[0]) <= 8:
        return None
    canonical = [parts[0].lower()]
    for index, part in enumerate(parts[1:], start=1):
        if not part or not part.isalnum():
            return None
        if index == 1 and len(part) == 4 and part.isalpha():
            canonical.append(part.title())
        elif len(part) == 2 and part.isalpha():
            canonical.append(part.upper())
        elif len(part) == 3 and part.isdigit():
            canonical.append(part)
        else:
            canonical.append(part.lower())
    normalized = "-".join(canonical)
    return normalized if _I18N_LOCALE_NAME.fullmatch(normalized) is not None else None


def _supervisor_locale_environment(environment: dict[str, str]) -> dict[str, str]:
    """Capture Core-owned locale variables and derive ``MSYS_LOCALE``.

    The input is the inherited environment after trusted profile overrides but
    before an untrusted package manifest can add its own ``env`` fields.  All
    POSIX ``LC_*`` variables are retained so toolkit and C applications keep
    their normal locale behavior.  A valid highest-precedence locale also gets
    a canonical ``MSYS_LOCALE`` spelling for SDK consumers.
    """

    locale_environment = {
        name: value
        for name, value in environment.items()
        if _is_i18n_environment_name(name)
    }
    for name in I18N_LOCALE_PRECEDENCE:
        raw = locale_environment.get(name)
        if raw is None or not str(raw).strip():
            continue
        normalized = _normalize_msys_locale(raw)
        if normalized is not None:
            locale_environment["MSYS_LOCALE"] = normalized
        # Stop even if the value is C/POSIX or malformed.  This matches the
        # documented SDK precedence and avoids silently defeating LC_ALL.
        break
    return locale_environment


@dataclass(frozen=True, slots=True)
class MemoryReclaimPolicy:
    enabled: bool = False
    available_kib: int = 49152
    poll_ms: int = 2000
    min_app_age_ms: int = 15000

    @classmethod
    def from_profile(cls, profile: dict[str, Any]) -> "MemoryReclaimPolicy":
        settings = profile.get("settings", {})
        raw = settings.get("memory_reclaim", {}) if isinstance(settings, dict) else {}
        if raw in ({}, None):
            return cls()
        if not isinstance(raw, dict):
            raise ValueError("profile settings.memory_reclaim must be an object")
        allowed = {"enabled", "available_kib", "poll_ms", "min_app_age_ms"}
        unknown = sorted(set(raw) - allowed)
        if unknown:
            raise ValueError(
                "profile settings.memory_reclaim has unknown fields: "
                + ", ".join(unknown)
            )
        enabled = raw.get("enabled", True)
        if not isinstance(enabled, bool):
            raise ValueError("profile memory_reclaim.enabled must be a boolean")

        def bounded(name: str, default: int, minimum: int, maximum: int) -> int:
            value = raw.get(name, default)
            if isinstance(value, bool) or not isinstance(value, int):
                raise ValueError(f"profile memory_reclaim.{name} must be an integer")
            if not minimum <= value <= maximum:
                raise ValueError(
                    f"profile memory_reclaim.{name} must be between "
                    f"{minimum} and {maximum}"
                )
            return value

        return cls(
            enabled=enabled,
            available_kib=bounded("available_kib", 49152, 8192, 1048576),
            poll_ms=bounded("poll_ms", 2000, 500, 60000),
            min_app_age_ms=bounded("min_app_age_ms", 15000, 0, 3600000),
        )


def read_mem_available_kib(path: Path = DEFAULT_MEMINFO_PATH) -> int | None:
    """Read Linux's kernel-computed available memory without external tools."""

    try:
        lines = path.read_text(encoding="ascii", errors="strict").splitlines()
    except (OSError, UnicodeError):
        return None
    for line in lines:
        name, separator, value = line.partition(":")
        if name != "MemAvailable" or not separator:
            continue
        fields = value.split()
        if len(fields) != 2 or fields[1] != "kB" or not fields[0].isascii():
            return None
        try:
            amount = int(fields[0], 10)
        except ValueError:
            return None
        return amount if amount >= 0 else None
    return None


class CatalogTransactionError(RuntimeError):
    """Typed catalog failure safe to return over mIPC."""

    code = "CATALOG_TRANSACTION_FAILED"

    def __init__(
        self,
        message: str,
        *,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}


class CatalogPreflightError(CatalogTransactionError):
    code = "CATALOG_PREFLIGHT_FAILED"


class CatalogReloadError(CatalogTransactionError):
    code = "CATALOG_RELOAD_FAILED"


class CatalogHealthError(CatalogTransactionError):
    code = "CATALOG_HEALTH_FAILED"


def _catalog_transaction_request(value: object) -> dict[str, Any] | None:
    """Validate the installer's runtime-switch proof request."""

    if value is None:
        return None
    if not isinstance(value, dict):
        raise ValueError("transaction must be an object")
    if value.get("schema") != CATALOG_TRANSACTION_SCHEMA:
        raise ValueError("transaction schema is unsupported")
    package = value.get("package")
    if (
        not isinstance(package, str)
        or not package
        or len(package) > 128
        or "\0" in package
    ):
        raise ValueError("transaction package is invalid")
    removed = value.get("removed")
    if not isinstance(removed, bool):
        raise ValueError("transaction removed must be a boolean")
    request: dict[str, Any] = {
        "schema": CATALOG_TRANSACTION_SCHEMA,
        "package": package,
        "removed": removed,
    }
    if not removed:
        version = value.get("version")
        path = value.get("path")
        if (
            not isinstance(version, str)
            or not version
            or len(version) > 128
            or "\0" in version
        ):
            raise ValueError("transaction version is invalid")
        if (
            not isinstance(path, str)
            or not path
            or len(path) > 4096
            or "\0" in path
            or not Path(path).is_absolute()
        ):
            raise ValueError("transaction path must be an absolute path")
        request["version"] = version
        request["path"] = path
    resume = value.get("resume_components", [])
    if not isinstance(resume, list) or len(resume) > 256:
        raise ValueError("transaction resume_components must be a bounded array")
    normalized_resume: set[str] = set()
    for component in resume:
        if (
            not isinstance(component, str)
            or not component
            or len(component) > 257
            or "\0" in component
        ):
            raise ValueError("transaction resume component is invalid")
        normalized_resume.add(component)
    if normalized_resume:
        request["resume_components"] = sorted(normalized_resume)
    return request


class RuntimeOwnershipError(RuntimeError):
    """Raised when another msysd owns the requested runtime directory."""


class DisplayMigrationError(RuntimeError):
    """A visual-session migration failed and requires transactional rollback."""

    code = "DISPLAY_MIGRATION_FAILED"

    def __init__(
        self,
        message: str,
        *,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}


def forwarded_timeout_seconds(message: dict[str, Any], default: float = 5.0) -> float:
    """Return the caller's bounded remaining monotonic deadline."""

    raw = message.get("deadline_ms")
    if isinstance(raw, bool) or not isinstance(raw, (int, float)):
        return min(MAX_FORWARD_TIMEOUT_SECONDS, max(0.001, default))
    remaining = float(raw) / 1000.0 - time.monotonic()
    return min(MAX_FORWARD_TIMEOUT_SECONDS, max(0.0, remaining))


def _expired_before_provider_delivery(response: dict[str, Any]) -> bool:
    """Distinguish cold-start deadline expiry from a live provider timeout."""

    return (
        response.get("type") == "error"
        and response.get("code") == "CALL_TIMEOUT"
        and response.get("message") == CALL_DEADLINE_EXPIRED_MESSAGE
    )


def normalize_intent_request(payload: object) -> dict[str, Any]:
    request = dict(payload) if isinstance(payload, dict) else {}
    if not str(request.get("action", "")).strip():
        if request.get("uri"):
            request["action"] = "open-uri"
        elif request.get("mime"):
            request["action"] = "open-mime"
        elif request.get("name"):
            request["action"] = "settings-panel"
    return request


@dataclass
class Instance:
    component: Component
    generation: int
    process: subprocess.Popen[bytes] | None = None
    sock: socket.socket | None = None
    state: str = "declared"
    ready: bool = False
    started_at: float = 0.0
    started_wallclock: float = 0.0
    failures: list[float] = field(default_factory=list)
    subscriptions: set[str] = field(default_factory=set)
    pending_calls: dict[int, asyncio.Future[dict[str, Any]]] = field(default_factory=dict)
    in_flight_calls: int = 0
    idle_task: asyncio.Task[None] | None = field(default=None, repr=False)
    watch_task: asyncio.Task[None] | None = field(default=None, repr=False)
    reader_task: asyncio.Task[None] | None = field(default=None, repr=False)
    readiness_task: asyncio.Task[None] | None = field(default=None, repr=False)
    ready_event: asyncio.Event = field(default_factory=asyncio.Event, repr=False)
    finalized: bool = False
    backoff_until: float = 0.0
    isolation: dict[str, Any] = field(default_factory=dict)
    transition_launched: bool = False
    transition_closing: bool = False


@dataclass(frozen=True, slots=True)
class PeerCredentials:
    pid: int
    uid: int
    gid: int


class Msysd:
    def __init__(
        self,
        config: Path,
        runtime_dir: Path,
        profile_id: str,
        manifest_paths: tuple[Path, ...] = (),
    ) -> None:
        self.config = config
        self.runtime_dir = runtime_dir
        self.profile_id = profile_id
        fallback_components = load_manifests(config)
        canonical_components = load_manifest_paths(manifest_paths)
        self.builtin_components = replace_package_components(
            fallback_components,
            canonical_components,
        )
        self.components = dict(self.builtin_components)
        self.profile = load_profile(config, profile_id)
        self.state_dir = Path(str(self.profile.get("state_dir") or os.environ.get("MSYS_STATE_DIR", "/opt/msys-state")))
        self.session_language = "system"
        self._load_session_preferences()
        installed_components = load_installed_manifests(self.state_dir)
        # A committed version replaces its complete built-in package. This also
        # removes components deleted by an update; the immutable built-in stays
        # available as an uninstall/rollback fallback on the next reload.
        self.components = replace_package_components(
            self.components,
            installed_components,
        )
        self._validate_dependency_graph(self.components)
        self.instances: dict[str, Instance] = {}
        self.generations: dict[str, int] = {}
        self.public_server: asyncio.AbstractServer | None = None
        self.role_registry = RoleRegistry.from_profile(self.components, self.profile)
        self.service_catalog = ServiceCatalog(self.components)
        self.role_preference_overrides: dict[str, str] = {}
        self._load_role_preferences()
        self.role_map: dict[str, list[str]] = {
            role: list(self.role_registry.candidate_ids(role))
            for role in self.role_registry.list_roles()
        }
        self.pending_calls: dict[int, asyncio.Future[dict[str, Any]]] = {}
        self.failure_history: dict[str, list[float]] = {}
        self.spawn_backoff_until: dict[str, float] = {}
        self.spawn_retry_tasks: dict[str, asyncio.Task[Any]] = {}
        self.quarantined: set[str] = set()
        self.quarantine_times: dict[str, float] = {}
        self.next_request_id = 1
        self.stopping = False
        self.foreground_stack: list[str] = []
        self.backgrounded_components: set[str] = set()
        self.start_locks: dict[str, asyncio.Lock] = {}
        self.catalog_lock = asyncio.Lock()
        self.reload_lock = asyncio.Lock()
        self.catalog_epoch = 0
        self.role_locks: dict[str, asyncio.Lock] = {}
        self.next_display_migration_id = 1
        self.display_migrations: dict[int, dict[str, Any]] = {}
        self.display_migration_active: int | None = None
        self.display_migration_tasks: dict[int, asyncio.Task[Any]] = {}
        # Transport reconnects remain inside the long-lived display provider.
        # If that provider itself exits, its X stack is no longer adoptable;
        # the outage record fences client restart budgets and retains only the
        # small automatic system-UI set needed for recovery.
        self.display_outage: dict[str, Any] | None = None
        self.next_display_outage_id = 1
        # Unexpected provider exits are intentionally separate from requested
        # display migrations so manual applications are never fake-restored.
        self.display_fault: dict[str, Any] | None = None
        self.next_display_fault_id = 1
        self.stop_requests: set[str] = set()
        self.supervisor_tasks: set[asyncio.Task[Any]] = set()
        self._runtime_lock_fd: int | None = None
        self.memory_reclaim_policy = MemoryReclaimPolicy.from_profile(self.profile)
        self.meminfo_path = DEFAULT_MEMINFO_PATH
        self.proc_root = DEFAULT_PROC_ROOT
        self._presentation_catalogs = PresentationCatalogCache()

    def _track_task(self, coro: Any) -> asyncio.Task[Any]:
        task = asyncio.create_task(coro)
        self.supervisor_tasks.add(task)
        task.add_done_callback(self.supervisor_tasks.discard)
        return task

    def _memory_reclaim_candidate(self, now: float | None = None) -> Instance | None:
        """Return the oldest live background ordinary App, never the front App."""

        if now is None:
            now = time.monotonic()
        minimum_age = self.memory_reclaim_policy.min_app_age_ms / 1000.0
        backgrounded = getattr(self, "backgrounded_components", set())
        foreground = (
            self.foreground_stack[0]
            if self.foreground_stack and self.foreground_stack[0] not in backgrounded
            else None
        )
        for key in reversed(self.foreground_stack):
            if key == foreground:
                continue
            instance = self.instances.get(key)
            if (
                instance is None
                or instance.finalized
                or not instance.process
                or instance.process.poll() is not None
                or not self._is_foreground_app(instance.component)
                or now - instance.started_at < minimum_age
            ):
                continue
            return instance
        return None

    async def _reclaim_one_background_app(self, available_kib: int) -> str | None:
        candidate = self._memory_reclaim_candidate()
        if candidate is None:
            return None
        key = candidate.component.key
        generation = candidate.generation
        print(
            "msysd: memory pressure reclaim "
            f"component={key} gen={generation} available_kib={available_kib} "
            f"threshold_kib={self.memory_reclaim_policy.available_kib}",
            flush=True,
        )
        await self.stop_component(key, expected=candidate)
        return key

    async def _memory_reclaim_loop(self) -> None:
        policy = self.memory_reclaim_policy
        while not self.stopping:
            await asyncio.sleep(policy.poll_ms / 1000.0)
            available = read_mem_available_kib(self.meminfo_path)
            if available is None or available >= policy.available_kib:
                continue
            try:
                await self._reclaim_one_background_app(available)
            except Exception as exc:
                print(f"msysd: memory reclaim failed: {exc}", flush=True)

    @staticmethod
    def _idle_timeout_seconds(instance: Instance) -> float | None:
        component = instance.component
        timeout_ms = component.idle_timeout_ms
        if (
            component.lifecycle != "on-demand"
            or timeout_ms is None
            or isinstance(timeout_ms, bool)
            or not isinstance(timeout_ms, int)
        ):
            return None
        return timeout_ms / 1000.0

    @staticmethod
    def _cancel_idle_task(instance: Instance) -> None:
        task = instance.idle_task
        # Clear ownership synchronously. A call may finish before cancellation
        # is delivered to the sleeping task and must be able to arm a fresh
        # full timeout immediately.
        instance.idle_task = None
        if task is not None and not task.done():
            task.cancel()

    def _schedule_idle_task(self, instance: Instance) -> asyncio.Task[None] | None:
        delay = self._idle_timeout_seconds(instance)
        instances = getattr(self, "instances", None)
        if (
            delay is None
            or instance.in_flight_calls != 0
            or not instance.ready
            or instance.finalized
            or (instances is not None and instances.get(instance.component.key) is not instance)
            or getattr(self, "stopping", False)
            or instance.component.key in getattr(self, "stop_requests", set())
        ):
            return None
        existing = instance.idle_task
        if existing is not None and not existing.done():
            return existing
        task = asyncio.create_task(self._idle_stop_after(instance, delay))
        instance.idle_task = task
        return task

    def _begin_forward_call(self, instance: Instance) -> None:
        # Increment before cancelling. If an expired timer is runnable in the
        # same event-loop turn, its generation/in-flight recheck will see the
        # reservation and cannot stop this provider underneath the call.
        instance.in_flight_calls += 1
        self._cancel_idle_task(instance)

    def _finish_forward_call(self, instance: Instance) -> None:
        if instance.in_flight_calls <= 0:
            print(
                f"msysd: idle accounting underflow {instance.component.key} "
                f"gen={instance.generation}",
                flush=True,
            )
            instance.in_flight_calls = 0
            return
        instance.in_flight_calls -= 1
        if instance.in_flight_calls == 0:
            self._schedule_idle_task(instance)

    async def _idle_stop_after(self, instance: Instance, delay: float) -> None:
        current_task = asyncio.current_task()
        try:
            await asyncio.sleep(delay)
            instances = getattr(self, "instances", None)
            if (
                instance.idle_task is not current_task
                or instance.in_flight_calls != 0
                or not instance.ready
                or instance.finalized
                or (instances is not None and instances.get(instance.component.key) is not instance)
                or getattr(self, "stopping", False)
                or instance.component.key in getattr(self, "stop_requests", set())
            ):
                return
            print(
                f"msysd: idle stop {instance.component.key} "
                f"gen={instance.generation} timeout_ms={instance.component.idle_timeout_ms}",
                flush=True,
            )
            await self.stop_component(instance.component.key, expected=instance)
        except asyncio.CancelledError:
            return
        finally:
            if instance.idle_task is current_task:
                instance.idle_task = None

    @staticmethod
    def _optional_request_id(message: dict[str, Any]) -> int | None:
        request_id = message.get("id")
        if isinstance(request_id, int) and not isinstance(request_id, bool):
            return request_id
        return None

    def _component_error(
        self,
        instance: Instance,
        message: dict[str, Any],
        *,
        code: str,
        operation: str,
        detail: str,
        required: str | None = None,
    ) -> dict[str, Any]:
        """Build and log one stable component-channel policy error."""

        request_id = self._optional_request_id(message)
        payload = {
            "operation": operation,
            "component": instance.component.key,
            "resource": detail,
        }
        if required:
            payload["required"] = required
        label = "access denied" if code == ACCESS_DENIED else "ipc request rejected"
        print(
            f"msysd: {label} component={instance.component.key} "
            f"operation={operation} resource={detail} code={code}",
            flush=True,
        )
        return {
            "type": "error",
            # Fire-and-forget subscribe/event frames historically have no id.
            # id=0 makes a denial observable without colliding with normal SDK
            # calls, whose allocator starts at 1.
            "id": request_id if request_id is not None else 0,
            "code": code,
            "message": f"component is not permitted to {operation}",
            "payload": payload,
        }

    def _access_denied(
        self,
        instance: Instance,
        message: dict[str, Any],
        *,
        operation: str,
        detail: str,
        required: str,
    ) -> dict[str, Any]:
        return self._component_error(
            instance,
            message,
            code=ACCESS_DENIED,
            operation=operation,
            detail=detail,
            required=required,
        )

    def _authorize_component_call(
        self,
        instance: Instance,
        message: dict[str, Any],
    ) -> dict[str, Any] | None:
        target = str(message.get("target", ""))
        method = str(message.get("method", ""))
        if allows_call(instance.component.permissions, target, method):
            return None
        # A manager commonly discovers every provider of an interface and
        # then addresses one exact component in order to probe, compare, or
        # configure it. Keep that operation least-privilege: an interface
        # grant covers the direct call only when the current catalog declares
        # that exact target as a provider of the granted interface.
        if target.startswith("component:"):
            component_key = target.split(":", 1)[1]
            component = getattr(self, "components", {}).get(component_key)
            if component is not None:
                for provide in component.provides:
                    if provide.kind != "interface":
                        continue
                    if allows_call(
                        instance.component.permissions,
                        f"interface:{provide.name}",
                        method,
                    ):
                        return None
        candidates = call_permission_candidates(target, method)
        return self._access_denied(
            instance,
            message,
            operation="call",
            detail=f"{target}.{method}" if method else target,
            required=candidates[0] if candidates else f"mipc.call:{target}",
        )

    @staticmethod
    def _public_peer_credentials(writer: asyncio.StreamWriter) -> PeerCredentials:
        try:
            peer_socket = writer.get_extra_info("socket")
            if peer_socket is None or not hasattr(socket, "SO_PEERCRED"):
                raise OSError("SO_PEERCRED is unavailable")
            size = struct.calcsize("3i")
            raw = peer_socket.getsockopt(
                socket.SOL_SOCKET,
                socket.SO_PEERCRED,
                size,
            )
            if not isinstance(raw, (bytes, bytearray)) or len(raw) != size:
                raise OSError("SO_PEERCRED returned an invalid record")
            pid, uid, gid = struct.unpack("3i", raw)
        except OSError:
            raise
        except (AttributeError, TypeError, ValueError, struct.error) as exc:
            raise OSError(f"SO_PEERCRED lookup failed: {exc}") from exc
        if pid <= 0 or uid < 0 or gid < 0:
            raise OSError("SO_PEERCRED returned invalid credentials")
        return PeerCredentials(pid=pid, uid=uid, gid=gid)

    def _managed_instance_for_peer(self, peer_pid: int) -> Instance | None:
        """Match a public peer to a supervised process/session generation.

        Components are launched with ``start_new_session=True``. Their PID is
        therefore also the process-group and session leader. Descendants such
        as UI/native helpers remain attributable even when they are not the
        manifest's direct process.
        """

        instances = list(self.instances.values())
        for instance in instances:
            process = instance.process
            leader = getattr(process, "pid", None)
            if not isinstance(leader, int) or isinstance(leader, bool) or leader <= 0:
                continue
            if peer_pid == leader:
                return instance
        try:
            peer_pgid = os.getpgid(peer_pid)
            peer_sid = os.getsid(peer_pid)
        except OSError:
            return None
        for instance in instances:
            process = instance.process
            leader = getattr(process, "pid", None)
            if not isinstance(leader, int) or isinstance(leader, bool) or leader <= 0:
                continue
            if peer_pgid == leader or peer_sid == leader:
                return instance
        return None

    def _public_access_denied(
        self,
        message: dict[str, Any],
        peer: PeerCredentials | None,
        reason: str,
    ) -> dict[str, Any]:
        request_id = self._optional_request_id(message)
        identity = (
            f"pid={peer.pid} uid={peer.uid} gid={peer.gid}"
            if peer is not None
            else "peer=unknown"
        )
        print(
            f"msysd: access denied public {identity} operation=call reason={reason}",
            flush=True,
        )
        return {
            "type": "error",
            "id": request_id if request_id is not None else 0,
            "code": ACCESS_DENIED,
            "message": "public control access requires an unmanaged root operator",
            "payload": {"operation": "call", "reason": reason},
        }

    @staticmethod
    def _send_component_response(
        instance: Instance,
        response: dict[str, Any],
        *,
        context: str,
    ) -> None:
        if not instance.sock:
            return
        try:
            send_packet(instance.sock, response)
        except OSError as exc:
            print(
                f"msysd: component {context} reply failed "
                f"{instance.component.key}: {exc}",
                flush=True,
            )

    def _selected_display(self) -> str | None:
        """Return the display exported by the selected display-output provider.

        An active lease describes the display session that is actually in use;
        before that lease exists, the profile-selected provider is the source
        of truth.  DISPLAY_ID is the provider-facing canonical spelling while
        DISPLAY remains supported for older manifests.
        """

        registry = getattr(self, "role_registry", None)
        if registry is None:
            return None
        try:
            provider_id = (
                registry.active_provider(DISPLAY_OUTPUT_ROLE)
                or registry.preferred_provider(DISPLAY_OUTPUT_ROLE)
            )
        except KeyError:
            return None
        provider = getattr(self, "components", {}).get(provider_id)
        if provider is None:
            return None
        for name in ("DISPLAY_ID", "DISPLAY"):
            value = str(provider.env.get(name, "")).strip()
            if value:
                return value
        return None

    def _session_display(self) -> str:
        """Resolve the X11 session default without board-specific constants."""

        selected = self._selected_display()
        if selected:
            return selected
        profile = getattr(self, "profile", {})
        profile_env = profile.get("env", {}) if isinstance(profile, dict) else {}
        configured = profile_env.get("DISPLAY") if isinstance(profile_env, dict) else None
        return str(configured or os.environ.get("DISPLAY") or DEFAULT_X11_DISPLAY)

    def _component_environment(self, component: Component) -> dict[str, str]:
        """Build a component environment with the selected visual session.

        The display provider overrides an inherited or legacy profile DISPLAY;
        a component-level DISPLAY is applied last and is therefore an explicit
        per-component override.  Locale values differ: they belong to the
        selected MSYS session and are deliberately re-applied after manifest
        environment overrides so every package sees one language baseline.
        """

        env = os.environ.copy()
        profile = getattr(self, "profile", {})
        profile_env = profile.get("env", {}) if isinstance(profile, dict) else {}
        if isinstance(profile_env, dict):
            env.update({str(key): str(value) for key, value in profile_env.items()})
        locale_environment = _supervisor_locale_environment(env)
        session_language = getattr(self, "session_language", "system")
        if session_language != "system":
            locale_environment["MSYS_LOCALE"] = session_language
        env["DISPLAY"] = self._session_display()
        env.update(component.env)
        # Package manifests are not a global language preference mechanism.
        # Remove any values they supplied and restore the inherited/profile
        # session locale, including every LC_* category.  This is also done
        # before application-private HOME/XDG/Python isolation is applied.
        for name in tuple(env):
            if _is_i18n_environment_name(name):
                env.pop(name, None)
        env.update(locale_environment)
        return env

    def _apply_component_isolation(self, env: dict[str, str], component: Component) -> None:
        """Give installed packages private state and a clean language runtime."""

        if self.builtin_components.get(component.key) is component:
            return

        app_root = self.state_dir / "apps" / component.package_id
        home = app_root / "home"
        config = app_root / "config"
        data = app_root / "data"
        cache = app_root / "cache"
        runtime = self.runtime_dir / "components" / component.package_id / component.id
        temporary = runtime / "tmp"
        for directory in (home, config, data, cache, runtime, temporary):
            directory.mkdir(parents=True, exist_ok=True, mode=0o700)
            try:
                directory.chmod(0o700)
            except OSError:
                pass

        # Canonical system packages may use the platform Python and its stable
        # mIPC SDK ABI without inheriting Core, Tools, or arbitrary host
        # site-packages. The path is selected by the trusted supervisor
        # environment, never by component manifest env. Development launchers
        # can omit the explicit variable: the one inherited PYTHONPATH entry
        # containing the actual msys_sdk package is selected narrowly.
        platform_pythonpath = ""
        if component.package_kind == "system":
            configured = os.environ.get("MSYS_PLATFORM_PYTHONPATH", "")
            inherited = os.environ.get("PYTHONPATH", "")
            candidates = configured.split(os.pathsep) if configured else inherited.split(os.pathsep)
            approved: list[str] = []
            for value in candidates:
                if not value:
                    continue
                candidate = Path(value)
                try:
                    resolved = candidate.resolve(strict=True)
                except OSError:
                    continue
                if not resolved.is_dir():
                    continue
                if not (resolved / "msys_sdk" / "__init__.py").is_file():
                    continue
                approved.append(str(resolved))
            platform_pythonpath = os.pathsep.join(dict.fromkeys(approved))

        for name in (
            "PYTHONPATH",
            "PYTHONHOME",
            "PYTHONSTARTUP",
            "PYTHONUSERBASE",
            "VIRTUAL_ENV",
            "MSYS_PLATFORM_PYTHONPATH",
        ):
            env.pop(name, None)
        env.update({
            "HOME": str(home),
            "XDG_CONFIG_HOME": str(config),
            "XDG_DATA_HOME": str(data),
            "XDG_CACHE_HOME": str(cache),
            "XDG_RUNTIME_DIR": str(runtime),
            "TMPDIR": str(temporary),
            "PYTHONNOUSERSITE": "1",
            # Installed versions are immutable package content. Root can
            # bypass mode bits, so Python must not create __pycache__ there.
            "PYTHONDONTWRITEBYTECODE": "1",
            "MSYS_APP_STATE_DIR": str(app_root),
            "MSYS_APP_RUNTIME_DIR": str(runtime),
        })
        if platform_pythonpath:
            env["MSYS_PLATFORM_PYTHONPATH"] = platform_pythonpath
            env["PYTHONPATH"] = platform_pythonpath

    def _seccomp_helper(self) -> str | None:
        settings = self.profile.get("isolation", {})
        configured = settings.get("seccomp_helper") if isinstance(settings, dict) else None
        value = configured or os.environ.get("MSYS_SECCOMP_HELPER")
        return str(value) if value else None

    @staticmethod
    def _validate_dependency_graph(components: dict[str, Component]) -> None:
        for key, component in components.items():
            missing = [dependency for dependency in component.requires if dependency not in components]
            if missing:
                raise ValueError(f"component {key} requires missing components: {', '.join(missing)}")

        visiting: set[str] = set()
        visited: set[str] = set()

        def visit(key: str, path: list[str]) -> None:
            if key in visiting:
                cycle_start = path.index(key) if key in path else 0
                cycle = path[cycle_start:] + [key]
                raise ValueError(f"component dependency cycle: {' -> '.join(cycle)}")
            if key in visited:
                return
            visiting.add(key)
            path.append(key)
            ordering_dependencies = list(components[key].requires)
            ordering_dependencies.extend(
                dependency
                for dependency in components[key].after
                if dependency in components
            )
            for dependency in ordering_dependencies:
                visit(dependency, path)
            path.pop()
            visiting.remove(key)
            visited.add(key)

        for key in components:
            visit(key, [])

    def preflight_installed_candidate(
        self,
        package_id: str,
        package_path: Path,
    ) -> dict[str, Any]:
        """Validate the complete prospective catalog before pointer commit."""

        try:
            target = Path(package_path).resolve(strict=True)
            packages_root = (self.state_dir / "packages").resolve()
            relative = target.relative_to(packages_root)
            if (
                len(relative.parts) != 3
                or relative.parts[0] != package_id
                or relative.parts[1] != "versions"
            ):
                raise ValueError("candidate is outside its managed package version root")
            manifest = target / "manifest.json"
            candidate = load_manifest_paths((manifest,))
            if not candidate:
                raise ValueError("candidate manifest has no components")
            declared_packages = {component.package_id for component in candidate.values()}
            if declared_packages != {package_id}:
                raise ValueError("candidate manifest package identity mismatch")

            installed = load_installed_manifests(self.state_dir)
            prospective_installed = replace_package_components(installed, candidate)
            prospective = replace_package_components(
                self.builtin_components,
                prospective_installed,
            )
            self._validate_dependency_graph(prospective)
            # Construct both catalogs during preflight. This catches malformed
            # role/service declarations before any current pointer can move.
            prospective_roles = RoleRegistry.from_profile(prospective, self.profile)
            ServiceCatalog(prospective)
            removed_startup = sorted(
                component
                for component in self.profile.get("startup", [])
                if component in self.components and component not in prospective
            )
            if removed_startup:
                raise ValueError(
                    "candidate removes active profile startup components: "
                    + ", ".join(removed_startup)
                )
            lost_roles = sorted(
                role
                for role in self.role_registry.list_roles()
                if self.role_registry.preferred_provider(role) is not None
                and (
                    role not in prospective_roles.list_roles()
                    or prospective_roles.preferred_provider(role) is None
                )
            )
            if lost_roles:
                raise ValueError(
                    "candidate leaves enabled roles without providers: "
                    + ", ".join(lost_roles)
                )
        except CatalogTransactionError:
            raise
        except Exception as exc:
            raise CatalogPreflightError(
                "prospective MSYS catalog is invalid",
                details={
                    "package": package_id,
                    "path": str(package_path),
                    "reason": str(exc)[:512],
                },
            ) from exc
        return {
            "package": package_id,
            "path": str(target),
            "components": sorted(candidate),
            "catalog_components": len(prospective),
        }

    def preflight_installed_removal(self, package_id: str) -> dict[str, Any]:
        """Validate the complete catalog that would remain after uninstall.

        The installer holds its state lock and calls this read-only gate before
        moving current or registry pointers. Built-in fallbacks reappear here
        exactly as they will during the post-commit registry reload.
        """

        try:
            if not package_id:
                raise ValueError("package id is required")
            installed = load_installed_manifests(self.state_dir)
            removed = sorted(
                key
                for key, component in installed.items()
                if component.package_id == package_id
            )
            if not removed:
                raise ValueError("package is not present in the installed catalog")
            prospective_installed = {
                key: component
                for key, component in installed.items()
                if component.package_id != package_id
            }
            prospective = replace_package_components(
                self.builtin_components,
                prospective_installed,
            )
            self._validate_dependency_graph(prospective)
            prospective_roles = RoleRegistry.from_profile(prospective, self.profile)
            ServiceCatalog(prospective)
            removed_startup = sorted(
                component
                for component in self.profile.get("startup", [])
                if component in self.components and component not in prospective
            )
            if removed_startup:
                raise ValueError(
                    "removal deletes active profile startup components: "
                    + ", ".join(removed_startup)
                )
            lost_roles = sorted(
                role
                for role in self.role_registry.list_roles()
                if self.role_registry.preferred_provider(role) is not None
                and (
                    role not in prospective_roles.list_roles()
                    or prospective_roles.preferred_provider(role) is None
                )
            )
            if lost_roles:
                raise ValueError(
                    "removal leaves enabled roles without providers: "
                    + ", ".join(lost_roles)
                )
        except CatalogTransactionError:
            raise
        except Exception as exc:
            raise CatalogPreflightError(
                "prospective MSYS catalog removal is invalid",
                details={
                    "package": package_id,
                    "reason": str(exc)[:512],
                },
            ) from exc
        return {
            "package": package_id,
            "components": removed,
            "catalog_components": len(prospective),
        }

    @property
    def _role_preferences_path(self) -> Path:
        return self.state_dir / "preferences" / "roles.json"

    @property
    def _session_preferences_path(self) -> Path:
        return self.state_dir / "preferences" / "session.json"

    @staticmethod
    def _validate_session_language(value: object) -> str:
        language = str(value).strip()
        if language == "system":
            return language
        normalized = _normalize_msys_locale(language)
        if normalized is None or normalized != language:
            raise ValueError("language must be system or a canonical locale")
        return normalized

    def _load_session_preferences(self) -> None:
        try:
            data = json.loads(self._session_preferences_path.read_text(encoding="utf-8"))
        except (FileNotFoundError, OSError, UnicodeError, json.JSONDecodeError):
            return
        if not isinstance(data, dict) or data.get("schema") != SESSION_PREFERENCES_SCHEMA:
            return
        try:
            self.session_language = self._validate_session_language(
                data.get("language", "system")
            )
        except ValueError as exc:
            print(f"msysd: ignored session language: {exc}", flush=True)

    def _persist_session_preferences(self) -> None:
        path = self._session_preferences_path
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
        document = {
            "schema": SESSION_PREFERENCES_SCHEMA,
            "language": self.session_language,
        }
        descriptor = -1
        try:
            descriptor = os.open(
                temporary,
                os.O_WRONLY | os.O_CREAT | os.O_TRUNC,
                0o600,
            )
            with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
                descriptor = -1
                json.dump(document, stream, ensure_ascii=False, separators=(",", ":"))
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            try:
                temporary.unlink()
            except FileNotFoundError:
                pass

    def _profile_session_locale(self) -> str | None:
        environment = os.environ.copy()
        profile = getattr(self, "profile", {})
        profile_environment = profile.get("env", {}) if isinstance(profile, dict) else {}
        if isinstance(profile_environment, dict):
            environment.update(
                {str(key): str(value) for key, value in profile_environment.items()}
            )
        return _supervisor_locale_environment(environment).get("MSYS_LOCALE")

    def _session_preferences_payload(self) -> dict[str, Any]:
        language = getattr(self, "session_language", "system")
        resolved = self._profile_session_locale() if language == "system" else language
        return {
            "schema": SESSION_PREFERENCES_SCHEMA,
            "language": language,
            "resolved_language": resolved or "",
        }

    def _load_role_preferences(self) -> None:
        try:
            data = json.loads(self._role_preferences_path.read_text(encoding="utf-8"))
        except (FileNotFoundError, OSError, json.JSONDecodeError):
            return
        for role, provider in dict(data.get("roles", {})).items():
            try:
                self.role_registry.select_preferred(str(role), str(provider))
                self.role_preference_overrides[str(role)] = str(provider)
            except Exception as exc:
                print(f"msysd: ignored role preference role={role}: {exc}", flush=True)

    def _persist_role_preferences(self) -> None:
        path = self._role_preferences_path
        path.parent.mkdir(parents=True, exist_ok=True)
        temporary = path.with_suffix(".tmp")
        temporary.write_text(
            json.dumps({"schema": "msys.role-preferences.v1", "roles": self.role_preference_overrides}, indent=2) + "\n",
            encoding="utf-8",
        )
        os.replace(temporary, path)

    def _preferred_exclusive_roles(self, key: str) -> tuple[str, ...]:
        return tuple(
            info.name
            for info in self.role_registry.list_role_info()
            if info.exclusive and info.preferred_provider == key
        )

    def _exclusive_candidate_roles(self, key: str) -> tuple[str, ...]:
        return tuple(
            info.name
            for info in self.role_registry.list_role_info()
            if info.exclusive and any(candidate.provider_id == key for candidate in info.candidates)
        )

    def _enabled_candidate_roles(self, key: str) -> tuple[str, ...]:
        return tuple(
            info.name
            for info in self.role_registry.list_role_info()
            if any(candidate.provider_id == key for candidate in info.candidates)
        )

    def _is_eager_role_provider(self, key: str) -> bool:
        component = self.components.get(key)
        if component and component.raw.get("x-msys-role-activation") == "always":
            return True
        declared_roles = {
            provide.name
            for provide in component.provides
            if provide.kind == "role"
        } if component else set()
        if declared_roles and not self._enabled_candidate_roles(key):
            # A profile can omit an entire system job, not merely its UI.
            # Providers whose every role is disabled must stay dormant even
            # when their component lifecycle is background/session.
            return False
        candidate_roles = self._exclusive_candidate_roles(key)
        if not candidate_roles:
            return True
        # A process may implement several roles.  It only needs one selected
        # exclusive role to be started, but receives leases solely for roles
        # that actually selected it.
        return bool(self._preferred_exclusive_roles(key))

    async def run(self) -> None:
        self.runtime_dir.mkdir(parents=True, exist_ok=True)
        os.environ["MSYS_RUNTIME_DIR"] = str(self.runtime_dir)
        self._acquire_runtime_ownership()
        try:
            await self._start_public_socket()
            await self._start_profile_components()
            if self.memory_reclaim_policy.enabled:
                self._track_task(self._memory_reclaim_loop())
            await self._wait_for_shutdown()
        finally:
            self._release_runtime_ownership()

    @property
    def _runtime_lock_path(self) -> Path:
        return self.runtime_dir / ".msysd.lock"

    def _acquire_runtime_ownership(self) -> None:
        """Atomically claim a runtime directory for this supervisor process."""

        if self._runtime_lock_fd is not None:
            return
        self.runtime_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(
            self._runtime_lock_path,
            os.O_RDWR
            | os.O_CREAT
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0),
            0o600,
        )
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            os.close(fd)
            raise RuntimeOwnershipError(
                f"MSYS runtime is already owned: {self.runtime_dir}"
            ) from exc
        try:
            os.fchmod(fd, 0o600)
            os.ftruncate(fd, 0)
            os.write(fd, f"{os.getpid()}\n".encode("ascii"))
            os.fsync(fd)
        except BaseException:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)
            raise
        self._runtime_lock_fd = fd

    def _release_runtime_ownership(self) -> None:
        fd = self._runtime_lock_fd
        if fd is None:
            return
        self._runtime_lock_fd = None
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
        finally:
            os.close(fd)

    async def _start_public_socket(self) -> None:
        path = self.runtime_dir / "control.sock"
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        self.public_server = await asyncio.start_unix_server(self._handle_public_client, path=str(path))
        os.chmod(path, 0o600)
        print(f"msysd: public control socket {path}", flush=True)

    async def _start_profile_components(self) -> None:
        startup = [
            str(x)
            for x in self.profile.get("startup", [])
            if self._is_eager_role_provider(str(x))
        ]
        eager = [
            key for key, c in self.components.items()
            if (c.lifecycle in {"session", "background"} or key in startup)
            and self._is_eager_role_provider(key)
        ]
        for key in dict.fromkeys(startup + eager):
            if key in self.components:
                try:
                    instance = await self.ensure_ready(key)
                    # A planned catalog replacement can intentionally stop
                    # the active display provider. Once its replacement is
                    # ready, finish recreating the captured visual session
                    # before starting any later profile entries.
                    if (
                        self.display_outage is not None
                        and self._provides_display_output(instance.component)
                    ):
                        await self._recover_display_consumers(instance)
                except Exception as exc:
                    print(f"msysd: startup failed {key}: {exc}", flush=True)

    def _begin_catalog_display_outage(
        self,
        affected: set[str],
    ) -> dict[str, Any] | None:
        """Capture consumers before a catalog update replaces active X11."""

        try:
            provider_key = self.role_registry.active_provider(DISPLAY_OUTPUT_ROLE)
        except KeyError:
            return None
        if not provider_key or provider_key not in affected:
            return None
        provider = self.instances.get(provider_key)
        if provider is None or not provider.ready:
            return None
        return self._begin_display_outage(provider)

    def _catalog_health_targets(self, affected: set[str]) -> list[str]:
        targets = {
            key
            for key in affected
            if key in self.components
            and self.components[key].lifecycle in {"background", "session"}
            and self._is_eager_role_provider(key)
        }
        for role in self.role_registry.list_roles():
            provider = self.role_registry.preferred_provider(role)
            if provider in affected:
                targets.add(provider)
        return sorted(targets)

    def _validate_catalog_transaction_pointer(
        self,
        transaction: dict[str, Any],
    ) -> dict[str, Any]:
        """Prove the committed registry points at the requested immutable tree."""

        package_id = str(transaction["package"])
        try:
            registry_path = self.state_dir / "registry" / "installed.json"
            document = json.loads(registry_path.read_text(encoding="utf-8-sig"))
            packages = document.get("packages")
            if document.get("schema") != "msys.installed.v1" or not isinstance(
                packages, list
            ):
                raise ValueError("installed registry has an invalid schema")
            matches = [
                pointer
                for pointer in packages
                if isinstance(pointer, dict) and pointer.get("package") == package_id
            ]
            if transaction["removed"]:
                if matches:
                    raise ValueError("removed package is still present in the registry")
                return {
                    "schema": CATALOG_TRANSACTION_SCHEMA,
                    "package": package_id,
                    "removed": True,
                }
            if len(matches) != 1:
                raise ValueError(
                    "installed registry must contain exactly one requested package"
                )
            pointer = matches[0]
            version = str(transaction["version"])
            if pointer.get("version") != version:
                raise ValueError(
                    f"installed version is {pointer.get('version')!r}, expected {version!r}"
                )
            expected_path = Path(str(transaction["path"])).resolve(strict=True)
            actual_path = Path(str(pointer.get("path", ""))).resolve(strict=True)
            if actual_path != expected_path:
                raise ValueError(
                    f"installed path is {actual_path}, expected {expected_path}"
                )
            manifest = actual_path / "manifest.json"
            if not manifest.is_file():
                raise ValueError("installed package manifest is unavailable")
            manifest_document = json.loads(manifest.read_text(encoding="utf-8-sig"))
            manifest_package = (
                manifest_document.get("package")
                if isinstance(manifest_document, dict)
                else None
            )
            if not isinstance(manifest_package, dict):
                raise ValueError("installed package manifest has no package identity")
            if manifest_package.get("id") != package_id:
                raise ValueError(
                    "installed package manifest id is "
                    f"{manifest_package.get('id')!r}, expected {package_id!r}"
                )
            if manifest_package.get("version") != version:
                raise ValueError(
                    "installed package manifest version is "
                    f"{manifest_package.get('version')!r}, expected {version!r}"
                )
        except CatalogTransactionError:
            raise
        except Exception as exc:
            raise CatalogReloadError(
                "committed package pointer does not match the reload transaction",
                details={
                    "package": package_id,
                    "removed": bool(transaction["removed"]),
                    "reason": str(exc)[:512],
                },
            ) from exc
        return {
            "schema": CATALOG_TRANSACTION_SCHEMA,
            "package": package_id,
            "version": version,
            "path": str(actual_path),
            "removed": False,
        }

    @staticmethod
    def _catalog_instance_is_active(instance: Instance) -> bool:
        if instance.finalized:
            return False
        if instance.ready:
            return True
        return bool(
            instance.process is not None and instance.process.poll() is None
        )

    async def _verify_catalog_health(
        self,
        targets: list[str],
        *,
        generation_floor: dict[str, int] | None = None,
    ) -> list[dict[str, Any]]:
        failures: list[dict[str, Any]] = []
        verified: list[dict[str, Any]] = []
        floors = generation_floor or {}
        for key in targets:
            try:
                instance = await self.ensure_ready(key)
                if not instance.ready or instance.state != "ready":
                    raise RuntimeError(f"component state is {instance.state}")
                current = self.components.get(key)
                if current is None or instance.component is not current:
                    raise RuntimeError("ready instance belongs to the previous catalog")
                floor = floors.get(key)
                if floor is not None and instance.generation <= floor:
                    raise RuntimeError(
                        f"ready generation {instance.generation} did not replace {floor}"
                    )
                package_root = (
                    str(current.manifest_path.parent.resolve())
                    if current.manifest_path is not None
                    else None
                )
                verified.append({
                    "component": key,
                    "generation": instance.generation,
                    "package_version": current.package_version,
                    "package_root": package_root,
                })
            except Exception as exc:
                failure: dict[str, Any] = {
                    "component": key,
                    "message": str(exc)[:512],
                }
                if key in floors:
                    failure["required_generation_gt"] = floors[key]
                failures.append(failure)
        if failures:
            raise CatalogHealthError(
                "critical catalog components did not become ready",
                details={"failures": failures, "targets": targets},
            )
        return verified

    async def reload_installed_components(
        self,
        *,
        verify_health: bool = True,
        transaction: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        async with self.reload_lock:
            return await self._reload_installed_components_locked(
                verify_health=verify_health,
                transaction=transaction,
            )

    async def _reload_installed_components_locked(
        self,
        *,
        verify_health: bool = True,
        transaction: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Atomically refresh the committed package registry at runtime."""
        transaction_result = (
            self._validate_catalog_transaction_pointer(transaction)
            if transaction is not None
            else None
        )
        installed = load_installed_manifests(
            self.state_dir,
            recover_pending=False,
        )
        replacement = replace_package_components(self.builtin_components, installed)
        self._validate_dependency_graph(replacement)
        planned_display_outage: dict[str, Any] | None = None
        async with self.catalog_lock:
            previous = self.components
            for key in set(previous).intersection(replacement):
                candidate = replacement[key]
                current = previous[key]
                if (
                    current.package_version == candidate.package_version
                    and current.raw == candidate.raw
                    and current.manifest_path == candidate.manifest_path
                ):
                    # Preserve object identity so a running unchanged installed
                    # component remains valid in the new catalog epoch.
                    replacement[key] = current
            removed = sorted(set(previous).difference(replacement))
            changed = sorted(
                key
                for key in set(previous).intersection(replacement)
                if previous[key] is not replacement[key]
            )
            added = sorted(set(replacement).difference(previous))

            changed_or_removed = set(changed + removed)
            transaction_affected: set[str] = set()
            requested_resume: set[str] = set()
            if transaction is not None:
                package_id = str(transaction["package"])
                transaction_affected = {
                    key
                    for key, component in previous.items()
                    if component.package_id == package_id
                } | {
                    key
                    for key, component in replacement.items()
                    if component.package_id == package_id
                }
                requested_resume = set(transaction.get("resume_components", []))
                invalid_resume = sorted(
                    key
                    for key in requested_resume
                    if key not in replacement
                    or replacement[key].package_id != package_id
                )
                if invalid_resume:
                    raise CatalogReloadError(
                        "runtime restore request is outside the package transaction",
                        details={
                            "package": package_id,
                            "invalid_components": invalid_resume,
                        },
                    )

            # Preserve exactly the affected live set.  Background/session jobs
            # will also be selected by profile policy, while a manual App is
            # resumed only when it was actually running before this switch (or
            # when rollback explicitly carries that saved running set).
            runtime_before = {
                key
                for key in changed_or_removed
                if (
                    (instance := self.instances.get(key)) is not None
                    and self._catalog_instance_is_active(instance)
                )
            }
            restart_targets = {
                key for key in runtime_before if key in replacement
            } | requested_resume
            generation_floor: dict[str, int] = {}
            for key in restart_targets:
                if key not in set(changed + added):
                    continue
                instance = self.instances.get(key)
                generation_floor[key] = max(
                    self.generations.get(key, 0),
                    instance.generation if instance is not None else 0,
                )
            rollback_resume = sorted(runtime_before | requested_resume)

            # Snapshot the old session while the old catalog, role lease, and
            # provider generation are still authoritative. Explicit stops
            # remove those facts before the process exits, so waiting for the
            # normal crash path would be too late.
            planned_display_outage = self._begin_catalog_display_outage(
                set(removed + changed)
            )

            old_registry = self.role_registry
            old_active = {
                role: old_registry.active_providers(role)
                for role in old_registry.list_roles()
            }
            old_preferred = {
                role: old_registry.preferred_provider(role)
                for role in old_registry.list_roles()
            }
            registry = RoleRegistry.from_profile(replacement, self.profile)
            valid_overrides: dict[str, str] = {}
            for role, provider in self.role_preference_overrides.items():
                try:
                    registry.select_preferred(role, provider)
                    valid_overrides[role] = provider
                except Exception:
                    print(f"msysd: removed stale role preference role={role} provider={provider}", flush=True)

            for role, providers in old_active.items():
                for provider in providers:
                    instance = self.instances.get(provider)
                    if (
                        instance
                        and instance.ready
                        and replacement.get(provider) is instance.component
                        and role in registry.list_roles()
                        and registry.is_candidate(role, provider)
                    ):
                        try:
                            registry.acquire(
                                role,
                                provider,
                                holder=f"generation:{instance.generation}",
                            )
                        except Exception:
                            pass

            role_transition_targets = {
                provider
                for role in registry.list_roles()
                if (
                    (provider := registry.preferred_provider(role)) is not None
                    and old_preferred.get(role) != provider
                )
            }

            self.components = replacement
            self.role_preference_overrides = valid_overrides
            self.role_registry = registry
            self.service_catalog = ServiceCatalog(replacement)
            self.role_map = {
                role: list(registry.candidate_ids(role))
                for role in registry.list_roles()
            }
            self.catalog_epoch += 1
            stop_targets = {
                key: self.instances[key]
                for key in removed + changed
                if key in self.instances
            }
            retry_targets: list[asyncio.Task[Any]] = []
            for key in changed + added:
                self.failure_history.pop(key, None)
                self.quarantined.discard(key)
                self.quarantine_times.pop(key, None)
                self.spawn_backoff_until.pop(key, None)
                retry_task = self.spawn_retry_tasks.pop(key, None)
                if retry_task and not retry_task.done():
                    retry_targets.append(retry_task)

        try:
            for task in retry_targets:
                task.cancel()
            if retry_targets:
                await asyncio.gather(*retry_targets, return_exceptions=True)
            if planned_display_outage is not None:
                await self._suspend_display_consumers(planned_display_outage)
            for key, instance in stop_targets.items():
                await self.stop_component(key, expected=instance)

            for instance in list(self.instances.values()):
                if instance.ready and self.components.get(instance.component.key) is instance.component:
                    self._lease_preferred_roles(instance)
            await self._start_profile_components()
            health_targets = sorted(
                set(self._catalog_health_targets(set(changed + added)))
                | role_transition_targets
                | restart_targets
                | {
                    key
                    for key in (
                        planned_display_outage["consumers"]
                        if planned_display_outage is not None
                        else []
                    )
                    if key in self.components
                }
            )
            verified_runtime: list[dict[str, Any]] = []
            if verify_health:
                verified_runtime = await self._verify_catalog_health(
                    health_targets,
                    generation_floor=generation_floor,
                )
            self._persist_role_preferences()
        except CatalogTransactionError as exc:
            if transaction is not None:
                exc.details.setdefault("resume_components", rollback_resume)
                exc.details.setdefault("package", transaction["package"])
            raise
        except Exception as exc:
            details: dict[str, Any] = {"reason": str(exc)[:512]}
            if transaction is not None:
                details["package"] = transaction["package"]
                details["resume_components"] = rollback_resume
            raise CatalogReloadError(
                "installed catalog runtime switch failed",
                details=details,
            ) from exc
        result = {
            "added": added,
            "changed": changed,
            "removed": removed,
            "health_checked": health_targets if verify_health else [],
        }
        if transaction_result is not None:
            verified_by_component = {
                record["component"]: record for record in verified_runtime
            }
            restarted = []
            for key, floor in sorted(generation_floor.items()):
                record = verified_by_component.get(key)
                if record is None:
                    continue
                restarted.append({
                    **record,
                    "from_generation": floor,
                    "to_generation": record["generation"],
                })
            transaction_result.update({
                "catalog_epoch": self.catalog_epoch,
                "affected_components": sorted(transaction_affected),
                "running_before": sorted(runtime_before),
                "resumed_components": sorted(restart_targets),
                "restarted_components": restarted,
                "generation_verified": bool(verify_health),
            })
            result["transaction"] = transaction_result
        print(f"msysd: registry reloaded {result}", flush=True)
        return result

    async def _wait_for_shutdown(self) -> None:
        loop = asyncio.get_running_loop()
        stop_event = asyncio.Event()
        for sig in (signal.SIGINT, signal.SIGTERM):
            try:
                loop.add_signal_handler(sig, stop_event.set)
            except NotImplementedError:
                pass
        await stop_event.wait()
        self.stopping = True
        print("msysd: stopping", flush=True)
        if self.public_server:
            self.public_server.close()
            await self.public_server.wait_closed()
        tasks = [task for task in self.supervisor_tasks if not task.done()]
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        await asyncio.gather(*(self.stop_component(k) for k in list(self.instances)), return_exceptions=True)

    async def ensure_started(self, key: str, activation: dict[str, Any] | None = None) -> Instance:
        if self.stopping:
            raise RuntimeError("msysd is stopping")
        if key in self.stop_requests:
            raise RuntimeError(f"component stop is in progress: {key}")
        lock = self.start_locks.setdefault(key, asyncio.Lock())
        async with lock:
            return await self._ensure_started_locked(key, activation=activation)

    async def _ensure_started_locked(self, key: str, activation: dict[str, Any] | None = None) -> Instance:
        if self.stopping or key in self.stop_requests:
            raise RuntimeError(f"component start cancelled: {key}")
        if key not in self.components:
            raise KeyError(f"unknown component {key}")
        if key in self.quarantined:
            raise RuntimeError(f"component is quarantined: {key}")
        component = self.components[key]
        existing = self.instances.get(key)
        # An outage fences new X11 generations, not RPC delivery to a
        # generation which this daemon has already made ready.  In particular,
        # window-policy becomes ready before later visual consumers finish
        # their deliberately ordered recovery and must remain callable during
        # that interval.  Keep every stale, exited and handshaking instance on
        # the fenced path below.
        if (
            existing is not None
            and existing.component is component
            and existing.generation
            == self.generations.get(key, existing.generation)
            and existing.ready
            and existing.state == "ready"
            and not existing.finalized
            and existing.process is not None
            and existing.process.poll() is None
        ):
            return existing
        if self._display_outage_blocks(component):
            raise RuntimeError(
                f"display-output is unavailable; component start deferred: {key}"
            )
        spawn_remaining = self.spawn_backoff_until.get(key, 0.0) - time.monotonic()
        if spawn_remaining > 0:
            await asyncio.sleep(spawn_remaining)
            if self.stopping or key in self.stop_requests:
                raise RuntimeError(f"component start cancelled: {key}")
        existing = self.instances.get(key)
        if existing and existing.process and existing.process.poll() is None:
            if self.components.get(key) is existing.component:
                return existing
            await self._stop_component_locked(key)
            existing = None
        if existing and existing.process and existing.process.poll() is not None:
            if not existing.finalized:
                await self._finalize_exited_instance(
                    existing,
                    existing.process.returncode or 0,
                    include_watch=True,
                )
                if self._should_restart(existing, existing.process.returncode or 0):
                    delay = self._record_restart_failure(existing)
                    if delay is None:
                        raise RuntimeError(f"component is quarantined: {key}")
                    existing.state = "backoff"
                    existing.backoff_until = time.monotonic() + delay
            remaining = existing.backoff_until - time.monotonic()
            if remaining > 0:
                await asyncio.sleep(remaining)
            if self.stopping or key in self.stop_requests:
                raise RuntimeError(f"component start cancelled: {key}")

        for dep in component.requires:
            await self.ensure_ready(dep)
        for dep in component.after:
            dependency = self.instances.get(dep)
            if not dependency or dependency.ready or not dependency.process or dependency.process.poll() is not None:
                continue
            try:
                await asyncio.wait_for(
                    dependency.ready_event.wait(),
                    timeout=dependency.component.readiness_timeout_ms / 1000,
                )
            except asyncio.TimeoutError:
                print(f"msysd: ordering dependency not ready {key} after={dep}", flush=True)
        if self.components.get(key) is not component:
            # The installed catalog changed while hard dependencies were being
            # activated.  Re-evaluate against the newly committed manifest
            # before spawning so old code cannot appear after a reload.
            return await self._ensure_started_locked(key, activation=activation)
        if self.stopping or key in self.stop_requests:
            raise RuntimeError(f"component start cancelled: {key}")

        generation = self.generations.get(key, 0) + 1
        self.generations[key] = generation
        if self._is_foreground_app(component):
            await self._emit_component_transition(
                "launching",
                component,
                generation=generation,
            )
        parent_sock, child_sock = socket.socketpair(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        parent_sock.setblocking(False)

        env = self._component_environment(component)
        self._apply_component_isolation(env, component)
        env["MSYS_CONTROL_FD"] = str(child_sock.fileno())
        env["MSYS_COMPONENT_ID"] = component.key
        env["MSYS_GENERATION"] = str(generation)
        env["MSYS_RUNTIME_DIR"] = str(self.runtime_dir)
        env["MSYS_PACKAGE_ID"] = component.package_id
        env["MSYS_PACKAGE_VERSION"] = component.package_version
        env["MSYS_STATE_DIR"] = str(self.state_dir)
        if component.windowing.get("title"):
            env["MSYS_WINDOW_TITLE"] = str(component.windowing["title"])
        identity = component.windowing.get("identity")
        if isinstance(identity, dict):
            app_id = str(identity.get("app_id", ""))
            wm_class = str(identity.get("x11_wm_class") or app_id)
            if app_id:
                env["MSYS_APP_ID"] = app_id
            if wm_class:
                env["MSYS_WINDOW_IDENTITY"] = wm_class
            if identity.get("x11_wm_instance"):
                env["MSYS_X11_WM_INSTANCE"] = str(identity["x11_wm_instance"])
        elif identity:
            # Backward compatibility for early v1 manifests that used a plain
            # string before the identity object was standardized.
            env["MSYS_APP_ID"] = str(identity)
            env["MSYS_WINDOW_IDENTITY"] = str(identity)
        if component.manifest_path:
            env["MSYS_PACKAGE_ROOT"] = str(component.manifest_path.parent.resolve())
        if activation:
            env["MSYS_ACTIVATION_JSON"] = json.dumps(activation, ensure_ascii=False, separators=(",", ":"))

        argv = self._resolve_exec(component)
        try:
            isolation_plan = prepare_isolation_launch(
                component.isolation,
                argv,
                seccomp_helper=self._seccomp_helper(),
            )
            env.update(isolation_plan.environment())
            isolation_summary = isolation_plan.summary()
            if component.isolation.requested:
                print(
                    "msysd: isolation "
                    f"{key} profile={component.isolation.profile} "
                    f"failure={component.isolation.failure} "
                    f"degraded={isolation_summary['degraded']} "
                    f"boundary={isolation_summary['security_boundary']}",
                    flush=True,
                )
            print(f"msysd: starting {key} gen={generation}", flush=True)
            popen_options: dict[str, Any] = {}
            if isolation_plan.preexec_fn is not None:
                popen_options["preexec_fn"] = isolation_plan.preexec_fn
            process = subprocess.Popen(
                isolation_plan.argv,
                cwd=component.cwd,
                env=env,
                pass_fds=(child_sock.fileno(),),
                start_new_session=True,
                **popen_options,
            )
        except Exception as exc:
            child_sock.close()
            parent_sock.close()
            print(f"msysd: spawn failed {key}: {exc}", flush=True)
            if self._is_foreground_app(component):
                await self._emit_component_transition(
                    "failed",
                    component,
                    generation=generation,
                    message=str(exc),
                )
            delay = self._record_component_failure(key)
            if delay is not None:
                self.spawn_backoff_until[key] = time.monotonic() + delay
                if self._component_should_restart(component, 1):
                    self._schedule_spawn_retry(key, delay)
            raise
        child_sock.close()

        instance = Instance(
            component=component,
            generation=generation,
            process=process,
            sock=parent_sock,
            state="handshaking" if component.readiness_mode != "exec" else "ready",
            ready=component.readiness_mode == "exec",
            started_at=time.monotonic(),
            started_wallclock=time.time(),
            isolation=isolation_summary,
        )
        if instance.ready:
            instance.ready_event.set()
        self.instances[key] = instance
        self.spawn_backoff_until.pop(key, None)
        if self._is_foreground_app(component):
            self._mark_foreground(key)
        instance.watch_task = asyncio.create_task(self._watch_process(instance))
        instance.reader_task = asyncio.create_task(self._read_component(instance))
        if component.readiness_mode != "exec":
            instance.readiness_task = asyncio.create_task(self._readiness_probe(instance))
        for dependency in component.wants:
            if dependency in self.components:
                self._track_task(self._start_wanted_component(key, dependency))
        if instance.ready:
            self._component_became_ready(instance)
        return instance

    async def _start_wanted_component(self, source: str, dependency: str) -> None:
        try:
            await self.ensure_ready(dependency)
        except Exception as exc:
            print(f"msysd: wanted dependency unavailable {source} wants={dependency}: {exc}", flush=True)

    @staticmethod
    def _resolve_package_argument(
        component: Component,
        value: str,
    ) -> tuple[Path, Path]:
        """Resolve one strict ``@package/`` reference inside its package root.

        Raw segment checks deliberately happen before ``Path.resolve``.  This
        prevents a path that merely normalizes back inside the package from
        hiding empty, dot, parent, Windows-style, or absolute syntax.  The
        resolved containment check additionally catches symlinked parents
        that leave the immutable package directory.
        """

        manifest_path = component.manifest_path
        if manifest_path is None:
            raise RuntimeError(
                f"component {component.key} uses @package without a manifest"
            )
        relative = "" if value == "@package" else value.removeprefix("@package/")
        if not relative:
            raise RuntimeError(
                f"component {component.key} has an empty @package path"
            )
        if "\0" in relative or "\\" in relative:
            raise RuntimeError(
                f"component {component.key} has an unsafe @package path: {value!r}"
            )
        segments = relative.split("/")
        if any(segment in {"", ".", ".."} for segment in segments):
            raise RuntimeError(
                f"component {component.key} has an unsafe @package path: {value!r}"
            )
        parsed = PurePosixPath(relative)
        if parsed.is_absolute() or not parsed.parts:
            raise RuntimeError(
                f"component {component.key} has an absolute @package path: {value!r}"
            )
        try:
            package_root = manifest_path.parent.resolve(strict=True)
            candidate = package_root.joinpath(*segments)
            resolved = candidate.resolve(strict=False)
            resolved.relative_to(package_root)
        except (OSError, RuntimeError, ValueError) as exc:
            raise RuntimeError(
                f"component {component.key} @package path escapes its package root: "
                f"{value!r}"
            ) from exc
        return candidate, resolved

    @staticmethod
    def _validate_package_executable(
        component: Component,
        declared: str,
        candidate: Path,
        resolved: Path,
    ) -> None:
        """Require a package-owned argv[0] to be a real executable file."""

        try:
            metadata = candidate.lstat()
        except OSError as exc:
            raise RuntimeError(
                f"component {component.key} package executable is unavailable: "
                f"{declared!r}"
            ) from exc
        if stat.S_ISLNK(metadata.st_mode):
            raise RuntimeError(
                f"component {component.key} package executable must not be a symlink: "
                f"{declared!r}"
            )
        if not stat.S_ISREG(metadata.st_mode):
            raise RuntimeError(
                f"component {component.key} package executable is not a regular file: "
                f"{declared!r}"
            )
        if not os.access(resolved, os.X_OK):
            raise RuntimeError(
                f"component {component.key} package executable is not executable: "
                f"{declared!r}"
            )

    def _resolve_exec(self, component: Component) -> list[str]:
        argv: list[str] = []
        for index, value in enumerate(component.exec):
            if value == "@package" or value.startswith("@package/"):
                candidate, resolved = self._resolve_package_argument(
                    component,
                    value,
                )
                if index == 0:
                    self._validate_package_executable(
                        component,
                        value,
                        candidate,
                        resolved,
                    )
                argv.append(str(resolved))
            else:
                # Host commands, absolute host paths, and ordinary relative
                # argv values retain their existing lookup semantics.
                argv.append(value)
        # Built-in reference components share MSYS's isolated Python runtime.
        # Third-party packages can remain fully self-contained by executing
        # @package/files/runtime/bin/python3 (or any native argv[0]).
        if argv and argv[0] in {"python", "@msys-python"}:
            return [sys.executable, *argv[1:]]
        return argv

    def _is_foreground_app(self, component: Component) -> bool:
        if component.lifecycle != "manual":
            return False
        # The full-screen screen-shield provider is controlled through typed
        # visible/hidden state. Merely starting its hidden host must not make
        # it the user's foreground app or cause Back/Home to target it. Other
        # roles can intentionally be foreground surfaces (a replaceable
        # third-party launcher is the important case), so this is exact.
        if any(
            provide.kind == "role" and provide.name == "screen-shield"
            for provide in component.provides
        ):
            return False
        mode = str(component.windowing.get("mode", ""))
        return mode in {"window", "fullscreen"}

    @staticmethod
    def _component_has_gui_window(component: Component) -> bool:
        """Return whether a manifest declares any user-visible window surface."""

        mode = str(component.windowing.get("mode", "")).strip().casefold()
        system = str(component.windowing.get("system", "")).strip().casefold()
        if mode in {"window", "fullscreen", "overlay"}:
            return True
        if system in {"x11", "wayland"} and mode not in {"", "none", "headless"}:
            return True
        role_windows = component.raw.get("x-msys-role-windows")
        return isinstance(role_windows, dict) and bool(role_windows)

    def _process_list_snapshot(
        self,
        *,
        include_system: bool,
        system_limit: int,
    ) -> dict[str, Any]:
        """Build one bounded headless-component and optional procfs snapshot."""

        live: list[tuple[str, Instance, int]] = []
        for key, instance in sorted(self.instances.items()):
            process = instance.process
            if process is None or process.poll() is not None:
                continue
            pid = getattr(process, "pid", None)
            if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
                continue
            live.append((key, instance, pid))

        proc_root = getattr(self, "proc_root", DEFAULT_PROC_ROOT)
        supervisor_pid = os.getpid()
        core_record = _proc_process_record(supervisor_pid, proc_root)
        if core_record is None:
            core_record = {
                "pid": supervisor_pid,
                "ppid": None,
                "uid": None,
                "name": "msysd",
                "state": "unknown",
                "rss_kib": None,
            }
        core_record["name"] = "MSYS Core"
        managed_leaders = {pid for _key, _instance, pid in live}
        managed = [
            _public_process_record(
                core_record,
                source="msys-core",
                msys_owned=True,
                component="msys.core",
                component_state="ready",
                runtime="python",
                lifecycle="supervisor",
            )
        ]
        managed_eligible = 1
        for key, instance, pid in live:
            component = instance.component
            if self._component_has_gui_window(component):
                continue
            managed_eligible += 1
            if len(managed) >= MAX_MANAGED_PROCESS_RESULTS:
                continue
            record = _proc_process_record(pid, proc_root)
            if record is None:
                # The supervisor remains authoritative while poll() reports a
                # live generation. Keep the identity but do not invent procfs
                # fields when permission or an exit race prevents the read.
                record = {
                    "pid": pid,
                    "ppid": None,
                    "uid": None,
                    "name": _bounded_process_name(key, str(pid)),
                    "state": "unknown",
                    "rss_kib": None,
                }
            presentation_name, _summary = self._localized_component_presentation(
                key, component
            )
            record["name"] = _bounded_process_name(presentation_name, key)
            managed.append(
                _public_process_record(
                    record,
                    source="msys-supervisor",
                    msys_owned=True,
                    component=key,
                    component_state=instance.state,
                    runtime=component.runtime,
                    lifecycle=component.lifecycle,
                    generation=instance.generation,
                )
            )

        system: list[dict[str, Any]] = []
        system_truncated = False
        if include_system:
            system, system_truncated = system_process_snapshot(
                managed_leaders,
                proc_root=proc_root,
                limit=system_limit,
                supervisor_pid=supervisor_pid,
            )
        return {
            "schema": PROCESS_LIST_SCHEMA,
            "filter": "headless-msys",
            "include_system": include_system,
            "system_limit": system_limit,
            "managed_count": len(managed),
            "system_count": len(system),
            "managed_truncated": managed_eligible > len(managed),
            "system_truncated": system_truncated,
            "processes": [*managed, *system],
        }

    def _is_launchable(self, component: Component) -> bool:
        explicit = component.activation.get("launchable")
        if explicit is not None:
            return bool(explicit)
        if component.lifecycle not in {"manual", "on-demand"}:
            return False
        if any(provide.kind == "role" for provide in component.provides):
            return False
        return str(component.windowing.get("mode", "")) in {"window", "fullscreen"}

    @staticmethod
    def _safe_icon_declarations(raw: object) -> list[dict[str, Any]]:
        if not isinstance(raw, list):
            return []
        icons: list[dict[str, Any]] = []
        for value in raw[:32]:
            if not isinstance(value, dict):
                continue
            path = value.get("path")
            if not isinstance(path, str) or not path or "\0" in path or len(path) > 1024:
                continue
            relative = path.removeprefix("@package/")
            parsed = PurePosixPath(relative)
            if parsed.is_absolute() or not parsed.parts or ".." in parsed.parts:
                continue
            icon: dict[str, Any] = {"path": path}
            size = value.get("size")
            if isinstance(size, int) and not isinstance(size, bool) and 1 <= size <= 4096:
                icon["size"] = size
            mime = value.get("mime")
            if isinstance(mime, str) and mime and "\0" not in mime and len(mime) <= 128:
                icon["mime"] = mime
            icons.append(icon)
        return icons

    @staticmethod
    def _component_package_root(component: Component) -> str | None:
        manifest_path = component.manifest_path
        if manifest_path is None:
            return None
        try:
            return str(manifest_path.parent.resolve())
        except OSError:
            return None

    @staticmethod
    def _manifest_presentation_text(value: object) -> str | None:
        if not isinstance(value, str) or not value or "\0" in value:
            return None
        return value

    def _presentation_locale(self) -> str | None:
        cached = getattr(self, "_presentation_locale_value", None)
        if isinstance(cached, str) or cached is False:
            return cached if isinstance(cached, str) else None
        session_language = getattr(self, "session_language", "system")
        locale = (
            self._profile_session_locale()
            if session_language == "system"
            else session_language
        )
        # Profile/session locale is immutable for one supervisor generation.
        # Cache the string (or False as an explicit default-locale sentinel) so
        # list_apps does not repeatedly copy the process environment per App.
        self._presentation_locale_value = locale or False
        return locale

    def _localized_component_presentation(
        self,
        key: str,
        component: Component,
    ) -> tuple[str, str | None]:
        component_name = self._manifest_presentation_text(component.raw.get("name"))
        package_name = self._manifest_presentation_text(component.package_name)
        fallback_name = component_name or package_name or key
        component_summary = self._manifest_presentation_text(
            component.raw.get("summary")
        )
        package_summary = self._manifest_presentation_text(component.package_summary)
        fallback_summary = component_summary or package_summary

        # An explicit component declaration is an override, including when it
        # is malformed: malformed package metadata must never silently replace
        # a component identity.  Without an override, package presentation is
        # the normal translation fallback used by single-component apps.
        if "x-msys-i18n" in component.raw:
            declaration = component.raw.get("x-msys-i18n")
        else:
            declaration = component.package_i18n
        if not isinstance(declaration, dict) or component.manifest_path is None:
            return fallback_name, fallback_summary

        catalogs = getattr(self, "_presentation_catalogs", None)
        if not isinstance(catalogs, PresentationCatalogCache):
            catalogs = PresentationCatalogCache()
            self._presentation_catalogs = catalogs
        catalog = catalogs.get(component.manifest_path, declaration.get("catalog"))
        if catalog is None:
            return fallback_name, fallback_summary

        locale = self._presentation_locale()

        def translated(field: str, fallback: str | None) -> str | None:
            message_key = declaration.get(field)
            if (
                not isinstance(message_key, str)
                or not message_key
                or len(message_key) > 160
                or "\0" in message_key
            ):
                return fallback
            return catalog.text(message_key, locale) or fallback

        return (
            translated("name_key", fallback_name) or fallback_name,
            translated("summary_key", fallback_summary),
        )

    def _component_summary(self, key: str, component: Component) -> dict[str, Any]:
        instance = self.instances.get(key)
        component_icons = self._safe_icon_declarations(component.raw.get("icons"))
        icons = component_icons or self._safe_icon_declarations(component.package_icons)
        name, presentation_summary = self._localized_component_presentation(key, component)
        summary = {
            "id": key,
            "package": component.package_id,
            "package_version": component.package_version,
            "package_kind": component.package_kind,
            "name": name,
            "runtime": component.runtime,
            "lifecycle": component.lifecycle,
            "restart": component.restart,
            "idle_timeout_ms": component.idle_timeout_ms,
            "state": instance.state if instance is not None else "declared",
            "foreground": key in {entry["component"] for entry in self._foreground_entries()},
            "launchable": self._is_launchable(component),
            "provides": [
                {"kind": p.kind, "name": p.name, "exclusive": p.exclusive, "priority": p.priority}
                for p in component.provides
            ],
            "windowing": component.windowing,
            "activation": component.activation,
            "isolation": instance.isolation if instance is not None else describe_isolation(component.isolation),
        }
        package_root = self._component_package_root(component)
        if icons:
            summary["icons"] = icons
        if presentation_summary is not None:
            summary["summary"] = presentation_summary
        if package_root is not None:
            summary["package_root"] = package_root
        return summary

    @staticmethod
    def _window_activation_payload(component: Component) -> dict[str, str]:
        identity = component.windowing.get("identity", {})
        if isinstance(identity, dict):
            window_identity = str(
                identity.get("x11_wm_class") or identity.get("app_id") or ""
            )
        else:
            window_identity = str(identity or "")
        title = str(
            component.windowing.get("title")
            or component.raw.get("name")
            or component.package_name
            or component.key
        )
        return {
            "component": component.key,
            "identity": window_identity,
            "title": title,
        }

    def _service_summaries(
        self,
        kind: str | None = None,
        name: str | None = None,
    ) -> list[dict[str, Any]]:
        grouped: dict[tuple[str, str], list[dict[str, Any]]] = {}
        for provider in self.service_catalog.entries(kind):
            if name is not None and provider.name != name:
                continue
            component = self.components[provider.component]
            instance = self.instances.get(provider.component)
            grouped.setdefault((provider.kind, provider.name), []).append({
                "component": provider.component,
                "target": f"component:{provider.component}",
                "priority": provider.priority,
                "exclusive": provider.exclusive,
                "runtime": component.runtime,
                "lifecycle": component.lifecycle,
                "state": instance.state if instance is not None else "declared",
            })
        return [
            {
                "kind": service_kind,
                "name": service_name,
                "target": (
                    f"interface:{service_name}"
                    if service_kind == "interface"
                    else None
                ),
                "providers": providers,
            }
            for (service_kind, service_name), providers in grouped.items()
        ]

    def _intent_candidates(self, request: dict[str, Any]) -> list[dict[str, Any]]:
        action = str(request.get("action", "")).strip()
        if not action:
            return []
        uri = str(request.get("uri", ""))
        scheme = urllib.parse.urlsplit(uri).scheme.lower() if uri else ""
        mime = str(request.get("mime", "")).lower()
        requested_name = str(request.get("name", ""))
        matches: dict[str, dict[str, Any]] = {}
        for key, component in self.components.items():
            for intent in component.activation.get("intents", []) or []:
                if not isinstance(intent, dict) or str(intent.get("action", "")) != action:
                    continue
                if action == "open-uri" and scheme not in {str(value).lower() for value in intent.get("schemes", [])}:
                    continue
                if action == "open-mime":
                    patterns = [str(value).lower() for value in intent.get("mime", [])]
                    if not mime or not any(fnmatch.fnmatchcase(mime, pattern) for pattern in patterns):
                        continue
                if action == "settings-panel" and str(intent.get("name", "")) != requested_name:
                    continue
                priority = int(intent.get("priority", 0))
                previous = matches.get(key)
                if previous is None or priority > int(previous["priority"]):
                    matches[key] = {
                        "component": key,
                        "name": component.raw.get("name") or component.package_name or key,
                        "priority": priority,
                        "runtime": component.runtime,
                    }
        return sorted(matches.values(), key=lambda item: (-int(item["priority"]), str(item["component"])))

    async def _emit_component_transition(
        self,
        phase: str,
        component: Component,
        *,
        generation: int = 0,
        returncode: int | None = None,
        message: str | None = None,
    ) -> None:
        if phase not in TRANSITION_PHASES:
            raise ValueError(f"unknown lifecycle transition phase: {phase}")
        identity = component.windowing.get("identity", {})
        window_identity = ""
        if isinstance(identity, dict):
            window_identity = str(
                identity.get("x11_wm_class") or identity.get("app_id") or ""
            )
        payload: dict[str, Any] = {
            "phase": phase,
            "component": component.key,
            "title": str(
                component.raw.get("name")
                or component.package_name
                or component.windowing.get("title")
                or component.key
            ),
            "identity": window_identity,
            "generation": int(generation),
            "timestamp_ms": int(time.time() * 1000),
        }
        if returncode is not None:
            payload["returncode"] = int(returncode)
        if message:
            payload["message"] = str(message)[:512]
        await self.broadcast(
            "msys.lifecycle.transition",
            payload,
            source="msys.core",
        )

    @staticmethod
    def _is_ordinary_application(component: Component) -> bool:
        return (
            component.package_kind == "application"
            and component.lifecycle in {"manual", "on-demand"}
        )

    async def _emit_application_crash_notification(
        self,
        instance: Instance,
        returncode: int,
        *,
        reason: str = "unexpected-process-exit",
    ) -> None:
        """Publish one structured App failure for notification history."""

        component = instance.component
        title, _summary = self._localized_component_presentation(
            component.key, component
        )
        payload = {
            "schema": APPLICATION_CRASH_SCHEMA,
            "component": component.key,
            "generation": int(instance.generation),
            "returncode": int(returncode),
            "reason": reason,
            "severity": "error",
            "title": title,
            "message": f"{title} exited unexpectedly (code {returncode})",
            "timestamp_ms": int(time.time() * 1000),
        }
        await self.broadcast(
            APPLICATION_CRASH_TOPIC,
            payload,
            source="msys.core",
        )

    def _send_activation_event(self, instance: Instance, activation: dict[str, Any]) -> None:
        if instance.component.readiness_mode != "mipc-ready" or not instance.sock:
            return
        try:
            send_packet(instance.sock, {
                "type": "event",
                "topic": "msys.activation",
                "source": "msys.core",
                "payload": activation,
            })
        except OSError as exc:
            print(f"msysd: activation delivery failed {instance.component.key}: {exc}", flush=True)

    def _mark_foreground(self, key: str) -> None:
        self.foreground_stack = [item for item in self.foreground_stack if item != key]
        self.foreground_stack.insert(0, key)
        backgrounded = getattr(self, "backgrounded_components", None)
        if backgrounded is None:
            self.backgrounded_components = set()
        else:
            backgrounded.discard(key)

    def _forget_foreground(self, key: str) -> None:
        """Remove one dead task without promoting a Home-hidden predecessor."""

        backgrounded = getattr(self, "backgrounded_components", set())
        was_backgrounded = key in backgrounded
        self.foreground_stack = [item for item in self.foreground_stack if item != key]
        backgrounded.discard(key)
        if was_backgrounded and self.foreground_stack:
            backgrounded.add(self.foreground_stack[0])
        self.backgrounded_components = backgrounded

    def _background_foreground(self, key: str) -> tuple[bool, bool]:
        """Mark the current task background while preserving Recents history."""

        backgrounded = getattr(self, "backgrounded_components", set())
        if not self.foreground_stack or self.foreground_stack[0] != key:
            return False, False
        already = key in backgrounded
        backgrounded.add(key)
        self.backgrounded_components = backgrounded
        return True, already

    def _foreground_entries(
        self,
        *,
        include_resources: bool = False,
    ) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        backgrounded = getattr(self, "backgrounded_components", set())
        visible_index = 0
        for key in self.foreground_stack:
            instance = self.instances.get(key)
            if not instance or not instance.process or instance.process.poll() is not None:
                continue
            identity = instance.component.windowing.get("identity", {})
            window_identity = ""
            if isinstance(identity, dict):
                window_identity = str(identity.get("x11_wm_class") or identity.get("app_id") or "")
            is_background = visible_index > 0 or key in backgrounded
            entry: dict[str, Any] = {
                "component": key,
                "title": instance.component.raw.get("name") or key,
                "identity": window_identity,
                "state": "background" if is_background else instance.state,
                "lifecycle": instance.component.lifecycle,
            }
            if include_resources:
                entry["resources"] = process_memory_snapshot(instance.process.pid)
            result.append(entry)
            visible_index += 1
        return result

    async def _announce_foreground_closing(self) -> Instance | None:
        """Publish one pre-close transition for the live foreground generation.

        Native window policy may terminate the client before its role call
        returns.  Marking the instance first makes this race safe and lets the
        normal stop path suppress a duplicate ``closing`` transition.
        """

        for key in list(self.foreground_stack):
            instance = self.instances.get(key)
            if (
                instance is None
                or self.instances.get(key) is not instance
                or key in getattr(self, "backgrounded_components", set())
                or not self._is_foreground_app(instance.component)
                or instance.transition_closing
                or not instance.process
                or instance.process.poll() is not None
            ):
                continue
            instance.transition_closing = True
            await self._emit_component_transition(
                "closing",
                instance.component,
                generation=instance.generation,
            )
            return instance
        return None

    async def ensure_ready(self, key: str, activation: dict[str, Any] | None = None) -> Instance:
        instance = await self.ensure_started(key, activation=activation)
        while True:
            deadline = time.monotonic() + instance.component.readiness_timeout_ms / 1000
            while not instance.ready:
                process_rc = instance.process.poll() if instance.process else None
                if process_rc is not None or self.instances.get(key) is not instance:
                    break
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                # A component that was ready can lose its mIPC channel before
                # the child has fully exited.  Clear that old readiness edge
                # before awaiting the next transition, otherwise Event.wait()
                # would return immediately in a tight loop.
                instance.ready_event.clear()
                try:
                    # Both a successful readiness transition and process
                    # finalization signal this event.  This avoids polling and
                    # lets us distinguish the resulting state below.
                    await asyncio.wait_for(instance.ready_event.wait(), timeout=remaining)
                except asyncio.TimeoutError:
                    break

            if instance.ready and self.instances.get(key) is instance:
                ready_hook = getattr(self, "_component_became_ready", None)
                if ready_hook is not None:
                    ready_hook(instance)
                else:
                    # A few focused adapters exercise ``ensure_ready`` with a
                    # deliberately minimal daemon object.  Preserve the old
                    # hook contract for those embedders.
                    self._lease_preferred_roles(instance)
                if (
                    self._is_foreground_app(instance.component)
                    and not instance.transition_launched
                ):
                    instance.transition_launched = True
                    await self._emit_component_transition(
                        "launched",
                        instance.component,
                        generation=instance.generation,
                    )
                return instance

            replacement = self.instances.get(key)
            if replacement is not None and replacement is not instance:
                instance = replacement
                continue

            if replacement is None:
                # An explicit stop removes the instance before terminating its
                # process.  Never turn a concurrent stop into an accidental
                # restart merely because the old process has now exited.
                raise RuntimeError(f"component did not become ready: {key}")

            process_rc = instance.process.poll() if instance.process else None
            if (
                process_rc is not None
                and not self.stopping
                and key not in self.stop_requests
                and key not in self.quarantined
                and self._should_restart(instance, process_rc)
            ):
                # Let the process watcher own failure accounting and backoff.
                # Calling ensure_started here before _restart_later records its
                # delay could otherwise race past the intended backoff.  Once
                # the watcher returns it has either installed a replacement or
                # quarantined/stopped the component.
                watch_task = instance.watch_task
                if (
                    watch_task is not None
                    and watch_task is not asyncio.current_task()
                    and not watch_task.cancelled()
                ):
                    await asyncio.shield(watch_task)
                    replacement = self.instances.get(key)
                    if replacement is not None and replacement is not instance:
                        instance = replacement
                        continue

                # This fallback is used when a synthetic/partially initialized
                # instance has no watcher, or a concurrent caller already
                # finalized it.  The per-component start lock still prevents a
                # duplicate spawn.
                instance = await self.ensure_started(key, activation=activation)
                if instance.process and instance.process.poll() is not None:
                    raise RuntimeError(f"component did not become ready: {key}")
                continue

            raise RuntimeError(f"component did not become ready: {key}")

    def _lease_preferred_roles(self, instance: Instance) -> None:
        key = instance.component.key
        if self.components.get(key) is not instance.component:
            return
        for info in self.role_registry.list_role_info():
            if info.preferred_provider != key or info.active_provider is not None:
                continue
            try:
                self.role_registry.acquire(
                    info.name,
                    key,
                    holder=f"generation:{instance.generation}",
                )
            except Exception as exc:
                print(f"msysd: role lease failed role={info.name} provider={key}: {exc}", flush=True)

    async def _readiness_probe(self, instance: Instance) -> None:
        component = instance.component
        deadline = time.monotonic() + component.readiness_timeout_ms / 1000
        while time.monotonic() < deadline:
            if self.instances.get(component.key) is not instance:
                return
            if instance.process and instance.process.poll() is not None:
                return
            if component.readiness_mode == "x11-display":
                display = component.env.get("DISPLAY_ID") or component.env.get("DISPLAY") or ":0"
                ready_file = component.env.get("MSYS_X11_READY_FILE")
                display_number = display.removeprefix(":").split(".", 1)[0]
                display_socket_ready = Path(f"/tmp/.X11-unix/X{display_number}").exists()
                x_ready = False
                if ready_file:
                    ready_path = Path(ready_file)
                    try:
                        ready_stat = ready_path.stat()
                        x_ready = ready_stat.st_mtime >= instance.started_wallclock
                    except OSError:
                        x_ready = False
                if display_socket_ready:
                    env = os.environ.copy()
                    env.update({str(k): str(v) for k, v in self.profile.get("env", {}).items()})
                    env.update(component.env)
                    env["DISPLAY"] = display
                    try:
                        result = await asyncio.to_thread(
                            subprocess.run,
                            ["xdpyinfo"],
                            env=env,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                            timeout=1,
                            check=False,
                        )
                        x_ready = x_ready and result.returncode == 0 if ready_file else result.returncode == 0
                    except (FileNotFoundError, subprocess.TimeoutExpired):
                        x_ready = x_ready if ready_file else display_socket_ready
                if x_ready:
                    instance.ready = True
                    instance.state = "ready"
                    instance.ready_event.set()
                    self._component_became_ready(instance)
                    print(f"msysd: ready {component.key} display={display}", flush=True)
                    return
            # This fallback probe only exists while an X server generation is
            # starting.  A 50 ms interval was visible when switching display
            # providers on the small target; 20 ms keeps the stat/xdpyinfo
            # work bounded while removing most of that fixed hand-off delay.
            await asyncio.sleep(X11_READINESS_POLL_SECONDS)
        if instance.ready or self.instances.get(component.key) is not instance:
            return
        print(f"msysd: readiness timeout {component.key}", flush=True)
        await self._terminate_instance_process(instance)

    async def _watch_process(self, instance: Instance) -> None:
        process = instance.process
        if not process:
            return
        await self._wait_for_process_exit(process)
        rc = process.returncode or 0
        if self.instances.get(instance.component.key) is not instance:
            return
        finalized = await self._finalize_exited_instance(instance, rc, include_watch=False)
        if finalized and not self.stopping and self._should_restart(instance, rc):
            if self._display_outage_blocks(instance.component):
                instance.state = "display-wait"
                return
            await self._restart_later(instance)

    @staticmethod
    async def _wait_for_process_exit(process: subprocess.Popen[bytes]) -> None:
        """Wait for one owned child without occupying a worker thread.

        Linux pidfds turn child exit into an epoll-ready descriptor, matching
        the existing C++ native-lite reactor.  Python/old-kernel builds without
        ``pidfd_open`` retain a short non-blocking poll fallback.  ``poll()``
        is still called after the readiness edge so ``Popen.returncode`` is
        populated and the direct child is reaped by its owner.
        """

        if process.poll() is not None:
            return
        pidfd_open = getattr(os, "pidfd_open", None)
        pidfd = -1
        if pidfd_open is not None:
            try:
                pidfd = pidfd_open(process.pid, 0)
            except (OSError, TypeError, ValueError):
                pidfd = -1
        if pidfd >= 0:
            loop = asyncio.get_running_loop()
            exited = asyncio.Event()
            try:
                loop.add_reader(pidfd, exited.set)
                # pidfds are level-triggered: an exit that races between the
                # initial poll and add_reader still makes this await complete.
                if process.poll() is None:
                    await exited.wait()
                process.poll()
                return
            finally:
                loop.remove_reader(pidfd)
                os.close(pidfd)

        while process.poll() is None:
            await asyncio.sleep(PROCESS_EXIT_FALLBACK_POLL_SECONDS)

    async def _finalize_exited_instance(
        self,
        instance: Instance,
        rc: int,
        *,
        include_watch: bool,
    ) -> bool:
        if instance.finalized or self.instances.get(instance.component.key) is not instance:
            return False
        outage = self._begin_unplanned_display_failure(
            instance,
            reason="unexpected-provider-exit",
        )
        instance.finalized = True
        self.role_registry.release_provider(instance.component.key)
        await self._cancel_instance_tasks(instance, include_watch=include_watch)
        self._close_instance_channel(instance, "PROVIDER_EXITED")
        instance.state = "exited" if rc == 0 else "failed"
        instance.ready = False
        instance.ready_event.set()
        self._forget_foreground(instance.component.key)
        print(f"msysd: exited {instance.component.key} rc={rc}", flush=True)
        if self._is_foreground_app(instance.component) and not self.stopping:
            await self._emit_component_transition(
                "closed" if rc == 0 else "failed",
                instance.component,
                generation=instance.generation,
                returncode=rc,
            )
        if (
            rc != 0
            and not self.stopping
            and self._is_ordinary_application(instance.component)
        ):
            await self._emit_application_crash_notification(instance, rc)
        if outage is not None:
            await self._suspend_display_consumers(outage)
        return True

    async def _terminate_instance_process(self, instance: Instance) -> None:
        process = instance.process
        if not process or process.poll() is not None:
            return
        try:
            os.killpg(process.pid, signal.SIGTERM)
        except ProcessLookupError:
            return
        deadline = time.monotonic() + 2.0
        while process.poll() is None and time.monotonic() < deadline:
            await asyncio.sleep(0.02)
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                return
            while process.poll() is None:
                await asyncio.sleep(0.02)

    async def _cancel_instance_tasks(self, instance: Instance, *, include_watch: bool) -> None:
        current = asyncio.current_task()
        idle_task = instance.idle_task
        if idle_task is not current:
            instance.idle_task = None
        tasks = [instance.reader_task, instance.readiness_task, idle_task]
        if include_watch:
            tasks.append(instance.watch_task)
        active = [task for task in tasks if task and task is not current and not task.done()]
        for task in active:
            task.cancel()
        if active:
            await asyncio.gather(*active, return_exceptions=True)

    def _close_instance_channel(self, instance: Instance, code: str) -> None:
        for request_id, future in list(instance.pending_calls.items()):
            if not future.done():
                future.set_result({
                    "type": "error",
                    "id": request_id,
                    "code": code,
                    "message": instance.component.key,
                })
        instance.pending_calls.clear()
        if instance.sock:
            try:
                instance.sock.close()
            except OSError:
                pass
            instance.sock = None

    @staticmethod
    def _is_restartable_system_provider(component: Component) -> bool:
        return (
            component.package_kind == "system"
            and component.lifecycle in {"background", "session"}
            and any(
                provide.kind in {"role", "interface", "capability"}
                for provide in component.provides
            )
        )

    def _component_should_restart(self, component: Component, rc: int) -> bool:
        if not self._is_restartable_system_provider(component):
            return False
        policy = component.restart
        if policy == "always":
            return True
        if policy == "on-failure" and rc != 0:
            return True
        return False

    def _should_restart(self, instance: Instance, rc: int) -> bool:
        return self._component_should_restart(instance.component, rc)

    def _record_restart_failure(self, instance: Instance) -> float | None:
        delay = self._record_component_failure(instance.component.key)
        if delay is None:
            instance.state = (
                "quarantined"
                if instance.component.key in self.quarantined
                else "display-wait"
            )
        return delay

    def _record_component_failure(self, key: str) -> float | None:
        component = self.components.get(key)
        if component is not None and self._display_outage_blocks(component):
            print(
                f"msysd: deferred restart budget while display is unavailable {key}",
                flush=True,
            )
            return None
        now = time.monotonic()
        failures = [x for x in self.failure_history.get(key, []) if now - x < 60]
        failures.append(now)
        self.failure_history[key] = failures
        if len(failures) >= 5:
            self.quarantined.add(key)
            self.quarantine_times[key] = now
            print(f"msysd: quarantined {key}", flush=True)
            return None
        return min(30.0, 0.25 * (2 ** (len(failures) - 1)))

    def _schedule_spawn_retry(self, key: str, delay: float) -> None:
        component = self.components.get(key)
        if component is not None and self._display_outage_blocks(component):
            return
        existing = self.spawn_retry_tasks.get(key)
        if existing and not existing.done() and existing is not asyncio.current_task():
            return

        async def retry() -> None:
            try:
                await asyncio.sleep(delay)
                component = self.components.get(key)
                if (
                    self.stopping
                    or key in self.stop_requests
                    or key in self.quarantined
                    or (
                        component is not None
                        and self._display_outage_blocks(component)
                    )
                ):
                    return
                await self.ensure_ready(key)
            except asyncio.CancelledError:
                raise
            except Exception as exc:
                print(f"msysd: spawn retry failed {key}: {exc}", flush=True)
            finally:
                if self.spawn_retry_tasks.get(key) is asyncio.current_task():
                    self.spawn_retry_tasks.pop(key, None)

        task = self._track_task(retry())
        self.spawn_retry_tasks[key] = task

    async def _restart_later(self, instance: Instance) -> None:
        key = instance.component.key
        if self._display_outage_blocks(instance.component):
            instance.state = "display-wait"
            return
        delay = self._record_restart_failure(instance)
        if delay is None:
            return
        instance.state = "backoff"
        instance.backoff_until = time.monotonic() + delay
        await asyncio.sleep(delay)
        if (
            not self.stopping
            and instance.component.key not in self.stop_requests
            and self.instances.get(instance.component.key) is instance
            and not self._display_outage_blocks(instance.component)
        ):
            await self.ensure_started(key)

    async def _read_component(self, instance: Instance) -> None:
        sock = instance.sock
        if sock is None:
            return
        loop = asyncio.get_running_loop()
        channel_failed = False
        while self.instances.get(instance.component.key) is instance:
            try:
                data = await loop.sock_recv(sock, MAX_PACKET + 1)
            except (OSError, ProtocolError) as exc:
                print(f"msysd: ipc error {instance.component.key}: {exc}", flush=True)
                channel_failed = True
                break
            if not data:
                channel_failed = True
                break
            try:
                msg = decode(data)
            except ProtocolError as exc:
                print(f"msysd: ipc error {instance.component.key}: {exc}", flush=True)
                channel_failed = True
                break
            await self._handle_component_message(instance, msg)
        if (
            channel_failed
            and instance.component.readiness_mode == "mipc-ready"
            and self.instances.get(instance.component.key) is instance
            and not instance.finalized
        ):
            outage = self._begin_unplanned_display_failure(
                instance,
                reason="unexpected-provider-channel-failure",
            )
            instance.ready = False
            instance.state = "channel-failed"
            instance.ready_event.clear()
            self.role_registry.release_provider(instance.component.key)
            self._close_instance_channel(instance, "PROVIDER_CHANNEL_FAILED")
            print(f"msysd: control channel failed {instance.component.key}", flush=True)
            await self._terminate_instance_process(instance)
            if outage is not None:
                await self._suspend_display_consumers(outage)

    async def _handle_component_message(self, instance: Instance, msg: dict[str, Any]) -> None:
        msg_type = msg["type"]
        if msg_type == "hello":
            send_packet(instance.sock, {
                "type": "welcome",
                "component": instance.component.key,
                "generation": instance.generation,
                "runtime_dir": str(self.runtime_dir),
            })
            return
        if msg_type == "ready":
            instance.ready = True
            instance.state = "ready"
            instance.ready_event.set()
            self._component_became_ready(instance)
            print(f"msysd: ready {instance.component.key}", flush=True)
            return
        if msg_type == "subscribe":
            topic = msg.get("topic", "")
            response: dict[str, Any] | None = None
            if not valid_subscription(topic):
                response = self._component_error(
                    instance,
                    msg,
                    code="BAD_SUBSCRIPTION",
                    operation="subscribe",
                    detail=str(topic)[:MAX_TOPIC_LENGTH],
                )
            elif not allows_event(instance.component.permissions, "subscribe", topic):
                response = self._access_denied(
                    instance,
                    msg,
                    operation="subscribe",
                    detail=topic,
                    required=event_permission("subscribe", topic),
                )
            elif (
                topic not in instance.subscriptions
                and len(instance.subscriptions) >= MAX_SUBSCRIPTIONS
            ):
                response = self._component_error(
                    instance,
                    msg,
                    code="SUBSCRIPTION_LIMIT",
                    operation="subscribe",
                    detail=topic,
                )
            else:
                instance.subscriptions.add(topic)
                request_id = self._optional_request_id(msg)
                if request_id is not None:
                    response = {
                        "type": "return",
                        "id": request_id,
                        "payload": {"subscribed": topic},
                    }
            if response is not None:
                self._send_component_response(
                    instance,
                    response,
                    context="subscribe",
                )
            return
        if msg_type == "event":
            topic = msg.get("topic", "")
            if not valid_event_topic(topic):
                self._send_component_response(
                    instance,
                    self._component_error(
                        instance,
                        msg,
                        code="BAD_EVENT_TOPIC",
                        operation="publish",
                        detail=str(topic)[:MAX_TOPIC_LENGTH],
                    ),
                    context="publish",
                )
                return
            if not allows_event(instance.component.permissions, "publish", topic):
                self._send_component_response(
                    instance,
                    self._access_denied(
                        instance,
                        msg,
                        operation="publish",
                        detail=topic,
                        required=event_permission("publish", topic),
                    ),
                    context="publish",
                )
                return
            payload = msg.get("payload", {})
            already_reloaded = (
                isinstance(payload, dict)
                and payload.get("registry_reloaded") is True
            )
            if topic == "msys.install.package_changed" and not already_reloaded:
                try:
                    changes = await self.reload_installed_components()
                    payload = {**dict(payload or {}), "registry_changes": changes}
                except Exception as exc:
                    print(f"msysd: registry reload failed: {exc}", flush=True)
                    payload = {
                        **dict(payload or {}),
                        "registry_error": {
                            "code": getattr(exc, "code", CatalogReloadError.code),
                            "message": str(exc)[:512],
                        },
                    }
            await self.broadcast(topic, payload, source=instance.component.key)
            return
        if msg_type in {"return", "error"} and "id" in msg:
            future = instance.pending_calls.pop(int(msg.get("id", 0)), None)
            if future and not future.done():
                future.set_result(msg)
            return
        if msg_type == "call":
            self._track_task(self._dispatch_component_call(instance, msg))
            return

    async def _dispatch_component_call(self, instance: Instance, msg: dict[str, Any]) -> None:
        """Dispatch provider-originated calls without blocking its packet reader.

        A provider may need to answer an inbound role call while one of its UI
        worker threads calls another role. Keeping the reader free prevents
        cyclic waits such as chooser.choose_intent plus Back.cancel_choice.
        """

        denial = self._authorize_component_call(instance, msg)
        if denial is None:
            response = await self.dispatch_call(msg, source=instance.component.key)
        else:
            response = denial
        if self.instances.get(instance.component.key) is not instance or not instance.sock:
            return
        self._send_component_response(instance, response, context="call")

    async def dispatch_call(self, msg: dict[str, Any], source: str = "public") -> dict[str, Any]:
        request_id = int(msg.get("id", 0))
        target = str(msg.get("target", ""))
        if target.startswith("role:"):
            role = target.split(":", 1)[1]
            method = str(msg.get("method", ""))
            # Home is itself a window-manager call. Its provider asks Core to
            # activate the launcher role, and Core must call back into that
            # same provider's activate_component method before Home can
            # return. Bypass only this authenticated internal callback so the
            # outer per-role lock cannot deadlock the reentrant transaction.
            if (
                role == "window-manager"
                and method == "activate_component"
                and source == "msys.core"
            ):
                return await self._dispatch_role_call(msg, source=source)
            # Apps navigation asks the selected task-switcher to show itself;
            # that provider must synchronously obtain the window-manager's
            # read-only recent snapshot before it can reply. The outer
            # navigation_action still holds the window-manager role lock, so
            # admit only this authenticated active-provider callback without
            # taking the same lock again. Other callers remain serialized.
            if role == "window-manager" and method == "recents":
                try:
                    active_task_switcher = self.role_registry.active_provider(
                        "task-switcher"
                    )
                except KeyError:
                    active_task_switcher = None
                if active_task_switcher is not None and source == active_task_switcher:
                    return await self._dispatch_role_call(msg, source=source)
            # The chooser's long-running choose_intent call must remain
            # cancellable by Back. Serializing cancel_choice behind the same
            # per-role lock would wait until the choice deadline and defeat
            # cancellation. The provider itself protects its active request.
            if role == "chooser" and method == "cancel_choice":
                return await self._dispatch_role_call(msg, source=source)
            lock = self.role_locks.setdefault(role, asyncio.Lock())
            async with lock:
                return await self._dispatch_role_call(msg, source=source)
        if target.startswith("interface:"):
            return await self._dispatch_interface_call(msg, source=source)
        if target.startswith("component:"):
            return await self._dispatch_component_target_call(msg, source=source)
        if target == "msys.core":
            return await self._core_call(msg, source=source)
        return {"type": "error", "id": request_id, "code": "BAD_TARGET", "message": target}

    async def _dispatch_interface_call(self, msg: dict[str, Any], source: str) -> dict[str, Any]:
        request_id = int(msg.get("id", 0))
        interface = str(msg.get("target", "")).split(":", 1)[1]
        method = str(msg.get("method", ""))
        if not interface:
            return {
                "type": "error",
                "id": request_id,
                "code": "BAD_TARGET",
                "message": "interface name is empty",
            }
        retry_safe = bool(msg.get("idempotent")) or method in ROLE_RETRY_SAFE_METHODS
        attempted: set[str] = set()
        last_error: dict[str, Any] | None = None
        while True:
            provider = await self._provider_for_interface(interface, exclude=attempted)
            if provider is None:
                break
            response = await self._forward_call(provider, msg, source=source)
            if response.get("type") != "error":
                return response
            if _expired_before_provider_delivery(response):
                # Provider discovery/readiness consumed the caller's complete
                # deadline. No packet reached this freshly started provider,
                # so stopping it as a liveness failure would manufacture a
                # restart/generation loop on every cold call.
                response["id"] = request_id
                return response
            last_error = response
            code = str(response.get("code", ""))
            print(
                f"msysd: interface provider failed interface={interface} "
                f"provider={provider.component.key} code={code}",
                flush=True,
            )
            if code not in ROLE_LIVENESS_ERRORS:
                response["id"] = request_id
                return response
            attempted.add(provider.component.key)
            await self.stop_component(provider.component.key, expected=provider)
            if not retry_safe and code != "NO_PROVIDER_SOCKET":
                return {
                    "type": "error",
                    "id": request_id,
                    "code": "OUTCOME_UNKNOWN",
                    "message": (
                        f"{interface}.{method} may have been delivered to "
                        f"{provider.component.key}"
                    ),
                }
        if last_error is not None:
            last_error["id"] = request_id
            return last_error
        return {
            "type": "error",
            "id": request_id,
            "code": "NO_INTERFACE_PROVIDER",
            "message": interface,
        }

    async def _dispatch_component_target_call(
        self,
        msg: dict[str, Any],
        source: str,
    ) -> dict[str, Any]:
        request_id = int(msg.get("id", 0))
        component_id = str(msg.get("target", "")).split(":", 1)[1]
        if not component_id or component_id not in self.components:
            return {
                "type": "error",
                "id": request_id,
                "code": "UNKNOWN_COMPONENT",
                "message": component_id,
            }
        try:
            provider = await self.ensure_ready(component_id)
        except Exception as exc:
            return {
                "type": "error",
                "id": request_id,
                "code": "COMPONENT_UNAVAILABLE",
                "message": str(exc),
            }
        return await self._forward_call(provider, msg, source=source)

    def _role_provider_is_running(self, role: str) -> bool:
        """Inspect live role candidates without activating an on-demand one."""

        try:
            candidates = [
                self.role_registry.active_provider(role),
                self.role_registry.preferred_provider(role),
                *self.role_registry.candidate_ids(role),
            ]
        except KeyError:
            return False
        for key in dict.fromkeys(item for item in candidates if item):
            instance = self.instances.get(key)
            if instance is None or getattr(instance, "finalized", False):
                continue
            process = instance.process
            if process is not None and process.poll() is None:
                return True
        return False

    async def _dispatch_role_call(self, msg: dict[str, Any], source: str) -> dict[str, Any]:
        request_id = int(msg.get("id", 0))
        role = str(msg.get("target", "")).split(":", 1)[1]
        method = str(msg.get("method", ""))
        x11_control_fallback = role in {"window-policy", "window-manager"}
        no_start_noop = (role, method) in ROLE_NO_START_NOOPS
        if no_start_noop and not self._role_provider_is_running(role):
            return {
                "type": "return",
                "id": request_id,
                "payload": {
                    "ok": True,
                    "role": role,
                    "visible": False,
                    "already_hidden": True,
                },
            }
        if role == "window-manager" and method == "close_active":
            await self._announce_foreground_closing()
        retry_safe = (
            bool(msg.get("idempotent"))
            or method in ROLE_RETRY_SAFE_METHODS
            or no_start_noop
        )
        attempted: set[str] = set()
        last_error: dict[str, Any] | None = None
        while True:
            provider = await self._provider_for_role(role, exclude=attempted)
            if not provider:
                break
            response = await self._forward_call(provider, msg, source=source)
            if response.get("type") != "error":
                return response
            if _expired_before_provider_delivery(response):
                response["id"] = request_id
                return response
            last_error = response
            code = str(response.get("code", ""))
            print(
                f"msysd: role provider failed role={role} "
                f"provider={provider.component.key} code={code}",
                flush=True,
            )
            if code not in ROLE_LIVENESS_ERRORS:
                if x11_control_fallback:
                    break
                response["id"] = request_id
                return response
            attempted.add(provider.component.key)
            await self.stop_component(provider.component.key, expected=provider)
            if not retry_safe and code != "NO_PROVIDER_SOCKET":
                return {
                    "type": "error",
                    "id": request_id,
                    "code": "OUTCOME_UNKNOWN",
                    "message": f"{role}.{method} may have been delivered to {provider.component.key}",
                }
        if x11_control_fallback:
            direct = await self._x11_window_policy_call(msg)
            if direct is not None:
                print(
                    "msysd: using core X11 control fallback "
                    f"role={role} method={method} display={self._session_display()}",
                    flush=True,
                )
                direct["fallback"] = True
                payload = direct.get("payload")
                if isinstance(payload, dict):
                    payload["fallback"] = True
                return direct
        if last_error is not None:
            last_error["id"] = request_id
            return last_error
        return {"type": "error", "id": request_id, "code": "NO_PROVIDER", "message": role}

    async def _provider_for_role(self, role: str, *, exclude: set[str] | None = None) -> Instance | None:
        excluded = exclude or set()
        for _catalog_attempt in range(3):
            async with self.catalog_lock:
                registry = self.role_registry
                epoch = self.catalog_epoch
                try:
                    active = registry.active_provider(role)
                    candidates = list(registry.candidate_ids(role))
                    preferred = registry.preferred_provider(role)
                except KeyError:
                    return None
            ordered = []
            if active:
                ordered.append(active)
            if preferred:
                ordered.append(preferred)
            ordered.extend(candidates)
            catalog_changed = False
            for key in dict.fromkeys(ordered):
                if key in excluded:
                    continue
                try:
                    instance = await self.ensure_ready(key)
                except Exception as exc:
                    print(f"msysd: failed provider {key} for role {role}: {exc}", flush=True)
                    async with self.catalog_lock:
                        if self.role_registry is registry:
                            registry.release_provider(key)
                    continue
                async with self.catalog_lock:
                    if self.catalog_epoch != epoch or self.role_registry is not registry:
                        catalog_changed = True
                        break
                    current_component = self.components.get(key)
                    if current_component is not instance.component:
                        stale = True
                    else:
                        stale = False
                        if registry.active_provider(role) != key:
                            try:
                                registry.acquire(
                                    role,
                                    key,
                                    holder=f"generation:{instance.generation}",
                                )
                            except Exception as exc:
                                print(f"msysd: role acquire failed role={role} provider={key}: {exc}", flush=True)
                                continue
                if stale:
                    await self.stop_component(key, expected=instance)
                    continue
                return instance
            if not catalog_changed:
                return None
        return None

    async def _provider_for_interface(
        self,
        interface: str,
        *,
        exclude: set[str] | None = None,
    ) -> Instance | None:
        excluded = exclude or set()
        for _catalog_attempt in range(3):
            async with self.catalog_lock:
                catalog = self.service_catalog
                epoch = self.catalog_epoch
                try:
                    candidates = list(catalog.provider_ids("interface", interface))
                except KeyError:
                    return None
            catalog_changed = False
            for key in candidates:
                if key in excluded:
                    continue
                try:
                    instance = await self.ensure_ready(key)
                except Exception as exc:
                    print(
                        f"msysd: failed provider {key} for interface {interface}: {exc}",
                        flush=True,
                    )
                    continue
                async with self.catalog_lock:
                    if self.catalog_epoch != epoch or self.service_catalog is not catalog:
                        catalog_changed = True
                        break
                    stale = self.components.get(key) is not instance.component
                if stale:
                    await self.stop_component(key, expected=instance)
                    continue
                return instance
            if not catalog_changed:
                return None
        return None

    async def _forward_call(self, provider: Instance, msg: dict[str, Any], source: str) -> dict[str, Any]:
        instances = getattr(self, "instances", None)
        if (
            not provider.sock
            or (instances is not None and instances.get(provider.component.key) is not provider)
        ):
            return {"type": "error", "id": msg.get("id", 0), "code": "NO_PROVIDER_SOCKET"}
        self._begin_forward_call(provider)
        request_id: int | None = None
        try:
            public_id = int(msg.get("id", 0))
            request_id = self.next_request_id
            self.next_request_id += 1
            loop = asyncio.get_running_loop()
            future: asyncio.Future[dict[str, Any]] = loop.create_future()
            provider.pending_calls[request_id] = future
            forwarded = {
                "type": "call",
                "id": request_id,
                "target": provider.component.key,
                "method": msg.get("method"),
                "payload": msg.get("payload", {}),
                "source": source,
            }
            logical_target = msg.get("target")
            if (
                isinstance(logical_target, str)
                and len(logical_target) <= MAX_LOGICAL_TARGET_LENGTH
                and LOGICAL_TARGET_PATTERN.fullmatch(logical_target)
            ):
                forwarded["logical_target"] = logical_target
            if "deadline_ms" in msg:
                forwarded["deadline_ms"] = msg["deadline_ms"]
            timeout = forwarded_timeout_seconds(msg)
            if timeout <= 0:
                return {
                    "type": "error",
                    "id": public_id,
                    "code": "CALL_TIMEOUT",
                    "message": CALL_DEADLINE_EXPIRED_MESSAGE,
                }
            try:
                if os.environ.get("MSYS_DEBUG_IPC") == "1":
                    print(
                        f"msysd: forward call id={request_id} public_id={public_id} "
                        f"to={provider.component.key} method={msg.get('method')}",
                        flush=True,
                    )
                send_packet(provider.sock, forwarded)
                response = await asyncio.wait_for(future, timeout=timeout)
            except asyncio.TimeoutError:
                print(
                    f"msysd: forward timeout id={request_id} "
                    f"to={provider.component.key} method={msg.get('method')}",
                    flush=True,
                )
                return {"type": "error", "id": public_id, "code": "CALL_TIMEOUT", "message": provider.component.key}
            except OSError as exc:
                return {"type": "error", "id": public_id, "code": "CALL_SEND_FAILED", "message": str(exc)}
            response["id"] = public_id
            return response
        finally:
            if request_id is not None:
                provider.pending_calls.pop(request_id, None)
            self._finish_forward_call(provider)

    def _role_summary(self, role: str) -> dict[str, Any]:
        info = self.role_registry.info(role)
        return {
            "role": info.name,
            "exclusive": info.exclusive,
            "preferred": info.preferred_provider,
            "active": info.active_provider,
            "active_providers": list(info.active_providers),
            "candidates": [
                {
                    "component": candidate.provider_id,
                    "priority": candidate.priority,
                    "exclusive": candidate.exclusive,
                    "explicit": candidate.explicit,
                    "declared": candidate.declared,
                    "state": (
                        self.instances[candidate.provider_id].state
                        if candidate.provider_id in self.instances
                        else "declared"
                    ),
                }
                for candidate in info.candidates
            ],
        }

    async def _cleanup_switched_role_provider(
        self,
        provider: str,
        instance: Instance,
    ) -> str | None:
        """Retire a provider after its role lease has moved elsewhere."""

        try:
            await self.stop_component(provider, expected=instance)
        except Exception as exc:
            message = str(exc)
            print(
                f"msysd: role switch cleanup failed provider={provider}: {message}",
                flush=True,
            )
            return message
        return None

    async def _switch_role(self, role: str, provider: str, *, preference_mode: str) -> dict[str, Any]:
        for _attempt in range(3):
            async with self.catalog_lock:
                registry = self.role_registry
                epoch = self.catalog_epoch
                registry.get_candidate(role, provider)

            # Candidate activation is deliberately outside the catalog lock.
            # The per-role lock held by the caller serializes competing switch
            # requests, while unrelated roles and registry reads stay live.
            instance = await self.ensure_ready(provider)

            async with self.catalog_lock:
                if self.catalog_epoch != epoch or self.role_registry is not registry:
                    continue
                if self.components.get(provider) is not instance.component or not instance.ready:
                    continue
                registry.get_candidate(role, provider)
                old_leases = registry.active_leases(role)
                old_active = registry.active_provider(role)
                old_preferred = registry.preferred_provider(role)
                old_override_present = role in self.role_preference_overrides
                old_override = self.role_preference_overrides.get(role)
                unchanged = (
                    old_active == provider
                    and old_preferred == provider
                    and (
                        (
                            preference_mode == "select"
                            and old_override_present
                            and old_override == provider
                        )
                        or (
                            preference_mode == "reset"
                            and not old_override_present
                        )
                    )
                )
                if unchanged:
                    # Re-selecting the live provider is a common Settings
                    # action.  Do not rewrite flash or churn leases when the
                    # requested durable state is already exact.
                    return self._role_summary(role)
                try:
                    if preference_mode == "select":
                        registry.select_preferred(role, provider)
                        self.role_preference_overrides[role] = provider
                    elif preference_mode == "reset":
                        default_provider = registry.candidate_ids(role)[0] if registry.candidate_ids(role) else None
                        if default_provider != provider:
                            raise RuntimeError("role default changed during reset")
                        registry.reset_preferred(role)
                        self.role_preference_overrides.pop(role, None)
                    else:
                        raise ValueError(f"unknown preference mode {preference_mode}")

                    if old_active != provider:
                        for lease in registry.active_leases(role):
                            registry.release(lease)
                        registry.acquire(
                            role,
                            provider,
                            holder=f"generation:{instance.generation}",
                        )
                    self._persist_role_preferences()
                    still_active = bool(
                        old_active
                        and any(
                            old_active in registry.active_providers(name)
                            for name in registry.list_roles()
                        )
                    )
                    old_instance = self.instances.get(old_active) if old_active else None
                    summary = self._role_summary(role)
                except Exception:
                    if old_preferred is not None:
                        registry.select_preferred(role, old_preferred)
                    if old_override_present and old_override is not None:
                        self.role_preference_overrides[role] = old_override
                    else:
                        self.role_preference_overrides.pop(role, None)
                    for lease in registry.active_leases(role):
                        registry.release(lease)
                    for lease in old_leases:
                        if registry.is_candidate(role, lease.provider_id):
                            registry.acquire(role, lease.provider_id, holder=lease.holder)
                    raise

            cleanup_error: str | None = None
            cleanup_pending = False
            if (
                old_active
                and old_active != provider
                and not still_active
                and old_instance is not None
            ):
                # The new provider is ready and owns the lease at this point;
                # keeping the control response behind the old provider's full
                # SIGTERM/SIGKILL grace period only makes Settings appear
                # frozen.  Give cooperative exits a tiny inline budget, then
                # finish retiring the exact old generation in the supervisor
                # task set.  Routing cannot return to it because its lease was
                # released before this task was created.
                cleanup_task = self._track_task(
                    self._cleanup_switched_role_provider(old_active, old_instance)
                )
                done, pending = await asyncio.wait(
                    {cleanup_task},
                    timeout=ROLE_SWITCH_CLEANUP_BUDGET_SECONDS,
                )
                if done:
                    cleanup_error = cleanup_task.result()
                else:
                    cleanup_pending = bool(pending)
            async with self.catalog_lock:
                if self.role_registry is registry:
                    summary = self._role_summary(role)
            print(f"msysd: role switched role={role} provider={provider}", flush=True)
            if cleanup_error:
                summary["cleanup_error"] = cleanup_error
            if cleanup_pending:
                summary["cleanup_pending"] = old_active
            return summary
        raise RuntimeError(f"role catalog changed repeatedly while switching {role}")

    def _ensure_display_migration_runtime(self) -> None:
        """Initialize migration bookkeeping for lightweight test daemons too."""

        if not hasattr(self, "next_display_migration_id"):
            self.next_display_migration_id = 1
        if not hasattr(self, "display_migrations"):
            self.display_migrations = {}
        if not hasattr(self, "display_migration_active"):
            self.display_migration_active = None
        if not hasattr(self, "display_migration_tasks"):
            self.display_migration_tasks = {}

    def _ensure_display_recovery_runtime(self) -> None:
        """Initialize display failure-domain state for lightweight test daemons."""

        if not hasattr(self, "display_outage"):
            self.display_outage = None
        if not hasattr(self, "next_display_outage_id"):
            self.next_display_outage_id = 1
        if not hasattr(self, "display_fault"):
            self.display_fault = None
        if not hasattr(self, "next_display_fault_id"):
            self.next_display_fault_id = 1
        if not hasattr(self, "display_recovery_lock"):
            self.display_recovery_lock = asyncio.Lock()
        if not hasattr(self, "supervisor_tasks"):
            self.supervisor_tasks = set()
        if not hasattr(self, "failure_history"):
            self.failure_history = {}
        if not hasattr(self, "spawn_backoff_until"):
            self.spawn_backoff_until = {}
        if not hasattr(self, "spawn_retry_tasks"):
            self.spawn_retry_tasks = {}
        if not hasattr(self, "quarantined"):
            self.quarantined = set()
        if not hasattr(self, "quarantine_times"):
            self.quarantine_times = {}
        if not hasattr(self, "stop_requests"):
            self.stop_requests = set()

    @staticmethod
    def _provides_display_output(component: Component) -> bool:
        return any(
            provide.kind == "role" and provide.name == DISPLAY_OUTPUT_ROLE
            for provide in component.provides
        )

    def _owns_active_display_output(self, instance: Instance) -> bool:
        if not self._provides_display_output(instance.component):
            return False
        if self.instances.get(instance.component.key) is not instance:
            return False
        try:
            return (
                self.role_registry.active_provider(DISPLAY_OUTPUT_ROLE)
                == instance.component.key
            )
        except KeyError:
            return False

    @staticmethod
    def _display_for_provider(component: Component | None) -> str | None:
        if component is None:
            return None
        for name in ("DISPLAY_ID", "DISPLAY"):
            value = str(component.env.get(name, "")).strip()
            if value:
                return value
        return None

    @staticmethod
    def _is_automatic_visual_service(component: Component) -> bool:
        """Return the small system surface set safe to recreate after X loss.

        Lifecycle is the contract here: background/session surfaces are the
        selected window policy, shell, and chrome.  Manual windows are user
        applications (including Settings) and must not be deceptively opened
        again as if their pre-crash state had survived.
        """

        return component.lifecycle in {"background", "session"}

    def _begin_display_fault(
        self,
        provider: Instance,
        *,
        reason: str,
        dropped_applications: list[str] | None = None,
    ) -> dict[str, Any]:
        self._ensure_display_recovery_runtime()
        record = {
            "schema": DISPLAY_OUTPUT_RECOVERED_SCHEMA,
            "id": self.next_display_fault_id,
            "phase": "recovering",
            "fault": "display-session-lost",
            "reason": reason,
            "provider": provider.component.key,
            "failed_generation": provider.generation,
            "generation": None,
            "display": self._display_for_provider(provider.component),
            "session_preserved": False,
            "applications_reopened": False,
            "restarted_system_ui": [],
            "dropped_applications": list(dropped_applications or []),
            "failures": [],
        }
        self.next_display_fault_id += 1
        self.display_fault = record
        print(
            "msysd: display output fault "
            f"fault={record['fault']} provider={record['provider']} "
            f"gen={record['failed_generation']} display={record['display']}",
            flush=True,
        )
        return record

    async def _complete_display_fault(
        self,
        provider: Instance,
        *,
        restarted_system_ui: list[str] | None = None,
        failures: list[dict[str, str]] | None = None,
        fault_id: int | None = None,
    ) -> dict[str, Any] | None:
        self._ensure_display_recovery_runtime()
        record = self.display_fault
        if (
            record is None
            or record.get("phase") != "recovering"
            or (fault_id is not None and record.get("id") != fault_id)
        ):
            return None
        record.update({
            "phase": "recovered",
            "recovery_provider": provider.component.key,
            "generation": provider.generation,
            "restarted_system_ui": list(restarted_system_ui or []),
            "failures": list(failures or []),
        })
        event = self._copy_display_fault(record)
        await self.broadcast(
            DISPLAY_OUTPUT_RECOVERED_TOPIC,
            event,
            source="msys.core",
        )
        print(
            "msysd: display output recovered "
            f"fault={record['fault']} provider={provider.component.key} "
            f"gen={provider.generation} applications_reopened=false",
            flush=True,
        )
        if self.display_fault is record:
            self.display_fault = None
        return event

    @staticmethod
    def _copy_display_fault(record: dict[str, Any]) -> dict[str, Any]:
        return json.loads(json.dumps(record, ensure_ascii=False))

    @staticmethod
    def _inherits_visual_session(component: Component) -> bool:
        windowing = component.windowing
        if (
            str(windowing.get("system", "")) != "x11"
            or str(windowing.get("display", "")) != "inherit"
        ):
            return False
        if str(windowing.get("mode", "")) == "display-provider":
            return False
        return not any(
            provide.kind == "role" and provide.name == DISPLAY_OUTPUT_ROLE
            for provide in component.provides
        )

    def _order_visual_consumer_keys(self, candidates: set[str]) -> list[str]:
        profile_order = [
            str(key)
            for key in self.profile.get("startup", [])
            if str(key) in candidates
        ]
        remaining = candidates - set(profile_order)
        # Recreate manual windows from back to front after profile services;
        # this both preserves the foreground stack and keeps the current caller
        # alive until every lower window has migrated.
        foreground_order = [
            key for key in reversed(self.foreground_stack) if key in remaining
        ]
        remaining -= set(foreground_order)
        return list(dict.fromkeys([
            *profile_order,
            *foreground_order,
            *sorted(remaining),
        ]))

    def _ordered_visual_consumers(self) -> list[str]:
        running = {
            key
            for key, instance in self.instances.items()
            if not instance.finalized
            and self.components.get(key) is instance.component
            and self._inherits_visual_session(instance.component)
        }
        return self._order_visual_consumer_keys(running)

    def _display_outage_blocks(self, component: Component) -> bool:
        """Return whether an inherited X11 client must wait for its provider."""

        self._ensure_display_recovery_runtime()
        outage = self.display_outage
        if outage is None or not self._inherits_visual_session(component):
            return False
        return component.key not in outage["recovery_allowed"]

    @staticmethod
    def _clone_display_outage(outage: dict[str, Any]) -> dict[str, Any]:
        """Copy the mutable parts of an internal outage transaction record."""

        return {
            **outage,
            "consumers": list(outage["consumers"]),
            "dropped_applications": list(outage.get("dropped_applications", [])),
            "foreground": list(outage["foreground"]),
            "failure_history": {
                key: list(values)
                for key, values in outage["failure_history"].items()
            },
            "spawn_backoff": dict(outage["spawn_backoff"]),
            "preexisting_quarantine": set(outage["preexisting_quarantine"]),
            "recovery_allowed": set(outage["recovery_allowed"]),
        }

    def _display_outage_matches(self, snapshot: dict[str, Any]) -> bool:
        outage = self.display_outage
        return bool(
            outage is not None
            and outage["id"] == snapshot["id"]
            and outage["revision"] == snapshot["revision"]
        )

    def _begin_display_outage(
        self,
        provider: Instance,
        *,
        recover_recent_consumer_failures: bool = False,
        automatic_services_only: bool = False,
    ) -> dict[str, Any] | None:
        """Snapshot the visual session before releasing a failed provider lease."""

        self._ensure_display_recovery_runtime()
        if self.stopping or not self._owns_active_display_output(provider):
            return None
        candidates = {
            key
            for key, instance in self.instances.items()
            if key != provider.component.key
            and self._inherits_visual_session(instance.component)
            and key not in self.stop_requests
        }
        if automatic_services_only:
            recovery_candidates = {
                key
                for key in candidates
                if self._is_automatic_visual_service(self.instances[key].component)
            }
            dropped_candidates = candidates - recovery_candidates
        else:
            recovery_candidates = candidates
            dropped_candidates: set[str] = set()
        ordered = self._order_visual_consumer_keys(recovery_candidates)
        dropped = self._order_visual_consumer_keys(dropped_candidates)
        # A detached display provider can notice Xorg's death after its X11
        # clients have already failed and consumed all five independent
        # restart attempts.  Only an unexpected provider/channel exit opts in
        # to this bounded look-back.  Planned catalog changes and operator
        # stops retain every existing quarantine exactly as before.
        failure_cutoff: float | None = None
        if recover_recent_consumer_failures:
            failure_cutoff = (
                time.monotonic() - DISPLAY_FAILURE_QUARANTINE_GRACE_SECONDS
            )
            for key in ordered:
                quarantined_at = self.quarantine_times.get(key)
                if (
                    key in self.quarantined
                    and quarantined_at is not None
                    and quarantined_at >= failure_cutoff
                ):
                    self.quarantined.discard(key)
                    self.quarantine_times.pop(key, None)
        outage = self.display_outage
        if outage is None:
            outage = {
                "id": self.next_display_outage_id,
                "revision": 1,
                "provider": provider.component.key,
                "provider_component": provider.component,
                "failed_generation": provider.generation,
                "consumers": list(ordered),
                "dropped_applications": list(dropped),
                "automatic_services_only": automatic_services_only,
                "foreground": list(self.foreground_stack),
                "failure_history": {
                    key: [
                        failed_at
                        for failed_at in self.failure_history.get(key, [])
                        if failure_cutoff is None or failed_at < failure_cutoff
                    ]
                    for key in ordered
                },
                "spawn_backoff": {
                    key: self.spawn_backoff_until.get(key)
                    for key in ordered
                },
                "preexisting_quarantine": {
                    key for key in ordered if key in self.quarantined
                },
                "recovery_allowed": set(),
            }
            self.next_display_outage_id += 1
            self.display_outage = outage
        else:
            outage["revision"] += 1
            outage["provider"] = provider.component.key
            outage["provider_component"] = provider.component
            outage["failed_generation"] = provider.generation
            outage["recovery_allowed"].clear()
            # A planned migration remains a full-session transaction even if
            # its provider later fails.  Conversely, an unplanned X loss must
            # never grow into reopening manual applications.
            automatic_services_only = bool(
                outage.get("automatic_services_only", automatic_services_only)
            )
            outage["automatic_services_only"] = automatic_services_only
            known = set(outage["consumers"])
            for key in ordered:
                if key in known:
                    continue
                outage["consumers"].append(key)
                outage["failure_history"][key] = list(
                    failed_at
                    for failed_at in self.failure_history.get(key, [])
                    if failure_cutoff is None or failed_at < failure_cutoff
                )
                outage["spawn_backoff"][key] = self.spawn_backoff_until.get(key)
                if key in self.quarantined:
                    outage["preexisting_quarantine"].add(key)
            known_dropped = set(outage.get("dropped_applications", []))
            for key in dropped:
                if key not in known_dropped:
                    outage.setdefault("dropped_applications", []).append(key)
        print(
            "msysd: display unavailable "
            f"provider={provider.component.key} gen={provider.generation} "
            f"consumers={len(outage['consumers'])}",
            flush=True,
        )
        return outage

    def _begin_unplanned_display_failure(
        self,
        provider: Instance,
        *,
        reason: str,
    ) -> dict[str, Any] | None:
        """Classify an unexpected provider failure before touching X clients."""

        self._ensure_display_recovery_runtime()
        if self.stopping or not self._owns_active_display_output(provider):
            return None
        if self.display_outage is not None:
            # A replacement can itself fail while the outage is fenced. Keep
            # the original fault/event identity and advance the same recovery.
            return self._begin_display_outage(
                provider,
                recover_recent_consumer_failures=True,
                automatic_services_only=True,
            )
        outage = self._begin_display_outage(
            provider,
            recover_recent_consumer_failures=True,
            automatic_services_only=True,
        )
        if outage is None:
            return None
        fault = self._begin_display_fault(
            provider,
            reason=reason,
            dropped_applications=outage.get("dropped_applications", []),
        )
        outage["fault_id"] = fault["id"]
        return outage

    async def _suspend_display_consumers(self, outage: dict[str, Any]) -> None:
        """Stop affected X clients and cancel their independent retry loops.

        ``consumers`` are eligible for recovery. ``dropped_applications`` are
        deliberately closed exactly once and never reopened after an
        unexpected X server loss.
        """

        self._ensure_display_recovery_runtime()
        async with self.display_recovery_lock:
            affected = list(dict.fromkeys([
                *outage["consumers"],
                *outage.get("dropped_applications", []),
            ]))
            for key in affected:
                if self.display_outage is not outage:
                    return
                if key not in self.instances:
                    retry = self.spawn_retry_tasks.pop(key, None)
                    if retry and retry is not asyncio.current_task() and not retry.done():
                        retry.cancel()
                        await asyncio.gather(retry, return_exceptions=True)
                    continue
                try:
                    await self.stop_component(key)
                except Exception as exc:
                    print(
                        f"msysd: display outage suspend failed component={key}: {exc}",
                        flush=True,
                    )

    def _restore_outage_failure_budget(
        self,
        outage: dict[str, Any],
        key: str,
    ) -> None:
        baseline = outage["failure_history"].get(key, [])
        if baseline:
            self.failure_history[key] = list(baseline)
        else:
            self.failure_history.pop(key, None)
        old_backoff = outage["spawn_backoff"].get(key)
        if old_backoff is None:
            self.spawn_backoff_until.pop(key, None)
        else:
            self.spawn_backoff_until[key] = old_backoff
        # Quarantines are never cleared generically: one already present when
        # the display failed (or applied by an operator during the outage) is
        # outside this recovery transaction.  Display-induced failures are
        # suppressed before they can add a quarantine in the first place.

    async def _recover_display_consumers(self, provider: Instance) -> None:
        """Recover only the clients authorized by the outage policy."""

        self._ensure_display_recovery_runtime()
        async with self.display_recovery_lock:
            outage = self.display_outage
            if (
                outage is None
                or not provider.ready
                or self.instances.get(provider.component.key) is not provider
                or not self._owns_active_display_output(provider)
            ):
                return
            revision = outage["revision"]
            failures: list[dict[str, str]] = []
            restarted: list[str] = []
            for key in list(outage["consumers"]):
                if (
                    self.display_outage is not outage
                    or outage["revision"] != revision
                    or not self._owns_active_display_output(provider)
                ):
                    return
                component = self.components.get(key)
                if component is None or not self._inherits_visual_session(component):
                    continue
                if (
                    key in outage["preexisting_quarantine"]
                    or key in self.quarantined
                ):
                    continue
                self._restore_outage_failure_budget(outage, key)
                outage["recovery_allowed"].add(key)
                try:
                    replacement = await self.ensure_ready(key)
                    if not replacement.ready or replacement.state != "ready":
                        raise RuntimeError(f"component state is {replacement.state}")
                    restarted.append(key)
                except Exception as exc:
                    failures.append({
                        "component": key,
                        "message": str(exc)[:256],
                    })
                finally:
                    outage["recovery_allowed"].discard(key)

            if (
                self.display_outage is not outage
                or outage["revision"] != revision
                or not self._owns_active_display_output(provider)
            ):
                return
            automatic_services_only = bool(outage.get("automatic_services_only"))
            fault_id = outage.get("fault_id")
            if not automatic_services_only:
                self._restore_foreground(outage["foreground"])
            self.display_outage = None
            if not automatic_services_only:
                try:
                    await self._reactivate_foreground()
                except Exception as exc:
                    failures.append({
                        "component": "foreground",
                        "message": str(exc)[:256],
                    })
            if fault_id is not None:
                await self._complete_display_fault(
                    provider,
                    restarted_system_ui=restarted,
                    failures=failures,
                    fault_id=fault_id,
                )
            if failures:
                print(
                    "msysd: display recovered with consumer failures "
                    f"provider={provider.component.key} gen={provider.generation} "
                    f"failures={failures}",
                    flush=True,
                )
            else:
                print(
                    "msysd: display recovered "
                    f"provider={provider.component.key} gen={provider.generation}",
                    flush=True,
                )

    def _schedule_display_recovery(
        self,
        provider: Instance,
    ) -> asyncio.Task[Any] | None:
        self._ensure_display_recovery_runtime()
        if (
            self.display_outage is None
            or not provider.ready
            or not self._owns_active_display_output(provider)
        ):
            return None
        return self._track_task(self._recover_display_consumers(provider))

    def _component_became_ready(
        self,
        instance: Instance,
    ) -> asyncio.Task[Any] | None:
        self._lease_preferred_roles(instance)
        self._schedule_idle_task(instance)
        if self._provides_display_output(instance.component):
            return self._schedule_display_recovery(instance)
        return None

    @staticmethod
    def _copy_migration_record(record: dict[str, Any]) -> dict[str, Any]:
        # Every migration field is deliberately JSON-compatible. A round trip
        # prevents callers/events from mutating the daemon's live status.
        return json.loads(json.dumps(record, ensure_ascii=False))

    def _display_migration_status(self, migration_id: int | None = None) -> dict[str, Any]:
        self._ensure_display_migration_runtime()
        selected = migration_id
        if selected is None:
            selected = self.display_migration_active
        if selected is None and self.display_migrations:
            selected = max(self.display_migrations)
        if selected is None or selected not in self.display_migrations:
            return {
                "schema": DISPLAY_MIGRATION_SCHEMA,
                "phase": "idle",
                "active": self.display_migration_active,
            }
        record = self._copy_migration_record(self.display_migrations[selected])
        record["active"] = self.display_migration_active
        return record

    async def _publish_display_migration(self, record: dict[str, Any]) -> None:
        await self.broadcast(
            DISPLAY_MIGRATION_TOPIC,
            self._copy_migration_record(record),
            source="msys.core",
        )

    def _prune_display_migrations(self) -> None:
        if len(self.display_migrations) <= 32:
            return
        removable = [
            migration_id
            for migration_id in sorted(self.display_migrations)
            if migration_id != self.display_migration_active
            and migration_id not in self.display_migration_tasks
        ]
        for migration_id in removable[: len(self.display_migrations) - 32]:
            self.display_migrations.pop(migration_id, None)

    async def _queue_display_migration(
        self,
        provider: str,
        *,
        preference_mode: str,
        source: str,
    ) -> dict[str, Any]:
        self._ensure_display_migration_runtime()
        async with self.catalog_lock:
            self.role_registry.get_candidate(DISPLAY_OUTPUT_ROLE, provider)
            if preference_mode == "reset":
                candidates = self.role_registry.candidate_ids(DISPLAY_OUTPUT_ROLE)
                if not candidates or candidates[0] != provider:
                    raise RuntimeError("display-output default changed during reset")
            old_provider = self.role_registry.active_provider(DISPLAY_OUTPUT_ROLE)
            if old_provider is None:
                old_provider = self.role_registry.preferred_provider(DISPLAY_OUTPUT_ROLE)
            old_display = self._display_for_provider(self.components.get(old_provider))
            new_display = self._display_for_provider(self.components.get(provider))
        migration_id = self.next_display_migration_id
        self.next_display_migration_id += 1
        record: dict[str, Any] = {
            "schema": DISPLAY_MIGRATION_SCHEMA,
            "id": migration_id,
            "phase": "planned",
            "queued": True,
            "role": DISPLAY_OUTPUT_ROLE,
            "preference_mode": preference_mode,
            "source": source,
            "from_provider": old_provider,
            "to_provider": provider,
            "from_display": old_display,
            "to_display": new_display,
            "consumers": [],
            "restarted": [],
            "requested_at_unix_ms": int(time.time() * 1000),
        }
        self.display_migrations[migration_id] = record
        await self._publish_display_migration(record)
        task = self._track_task(
            self._execute_display_migration(
                migration_id,
                provider,
                preference_mode=preference_mode,
            )
        )
        self.display_migration_tasks[migration_id] = task

        def completed(done: asyncio.Task[Any]) -> None:
            if self.display_migration_tasks.get(migration_id) is done:
                self.display_migration_tasks.pop(migration_id, None)
            self._prune_display_migrations()

        task.add_done_callback(completed)
        return self._copy_migration_record(record)

    async def _execute_display_migration(
        self,
        migration_id: int,
        provider: str,
        *,
        preference_mode: str,
    ) -> None:
        role_lock = self.role_locks.setdefault(DISPLAY_OUTPUT_ROLE, asyncio.Lock())
        async with role_lock:
            async with self.reload_lock:
                self._ensure_display_recovery_runtime()
                record = self.display_migrations[migration_id]
                self.display_migration_active = migration_id
                record["queued"] = False
                record["started_at_unix_ms"] = int(time.time() * 1000)
                try:
                    # Provider recovery and a user-requested provider switch
                    # consume the same saved visual-session snapshot.  Keep
                    # them mutually exclusive so only one path can recreate
                    # clients or clear an outage.
                    async with self.display_recovery_lock:
                        result = await self._migrate_display_output(
                            provider,
                            preference_mode=preference_mode,
                            record=record,
                        )
                except Exception as exc:
                    details = (
                        dict(exc.details)
                        if isinstance(exc, DisplayMigrationError)
                        else {}
                    )
                    record.update({
                        "phase": "rolled-back",
                        "rollback_complete": not bool(
                            details.get("rollback_failures")
                        ),
                        "completed_at_unix_ms": int(time.time() * 1000),
                        "error": {
                            "code": getattr(exc, "code", DisplayMigrationError.code),
                            "message": str(exc)[:512],
                            **({"details": details} if details else {}),
                        },
                    })
                    print(
                        f"msysd: display migration rolled back id={migration_id} "
                        f"provider={provider}: {exc}",
                        flush=True,
                    )
                else:
                    record.update(result)
                    record.update({
                        "phase": "succeeded",
                        "completed_at_unix_ms": int(time.time() * 1000),
                    })
                    print(
                        f"msysd: display migration succeeded id={migration_id} "
                        f"provider={provider}",
                        flush=True,
                    )
                finally:
                    self.display_migration_active = None
                    await self._publish_display_migration(record)

    def _snapshot_display_role(self, registry: RoleRegistry) -> dict[str, Any]:
        role = DISPLAY_OUTPUT_ROLE
        old_active = registry.active_provider(role)
        old_preferred = registry.preferred_provider(role)
        old_provider = old_active or old_preferred
        old_instance = self.instances.get(old_provider) if old_provider else None
        override_present = role in self.role_preference_overrides
        return {
            "registry": registry,
            "epoch": self.catalog_epoch,
            "leases": registry.active_leases(role),
            "active": old_active,
            "provider": old_provider,
            "preferred": old_preferred,
            "override_present": override_present,
            "override": self.role_preference_overrides.get(role),
            "display": self._session_display(),
            "provider_instance": old_instance,
            # DISPLAY names are reusable endpoints, not visual-session
            # identities.  In particular, two providers may both export
            # ``:24`` while owning different X server generations.  Keep the
            # actual component object and process generation in the private
            # transaction snapshot so consumers are restarted whenever that
            # identity changes, even if the DISPLAY text does not.
            "provider_component": (
                old_instance.component
                if old_instance is not None
                else self.components.get(old_provider)
            ),
            "provider_generation": (
                old_instance.generation if old_instance is not None else None
            ),
            "foreground": list(self.foreground_stack),
        }

    def _apply_display_preference(
        self,
        registry: RoleRegistry,
        provider: str,
        instance: Instance,
        *,
        preference_mode: str,
    ) -> None:
        if preference_mode == "select":
            registry.select_preferred(DISPLAY_OUTPUT_ROLE, provider)
            self.role_preference_overrides[DISPLAY_OUTPUT_ROLE] = provider
        elif preference_mode == "reset":
            candidates = registry.candidate_ids(DISPLAY_OUTPUT_ROLE)
            if not candidates or candidates[0] != provider:
                raise RuntimeError("display-output default changed during migration")
            registry.reset_preferred(DISPLAY_OUTPUT_ROLE)
            self.role_preference_overrides.pop(DISPLAY_OUTPUT_ROLE, None)
        else:
            raise ValueError(f"unknown preference mode {preference_mode}")
        for lease in registry.active_leases(DISPLAY_OUTPUT_ROLE):
            registry.release(lease)
        registry.acquire(
            DISPLAY_OUTPUT_ROLE,
            provider,
            holder=f"generation:{instance.generation}",
        )

    def _restore_display_role(self, snapshot: dict[str, Any]) -> None:
        registry: RoleRegistry = snapshot["registry"]
        if self.role_registry is not registry or self.catalog_epoch != snapshot["epoch"]:
            raise RuntimeError("display role catalog changed during rollback")
        if snapshot["override_present"] and snapshot["override"] is not None:
            registry.select_preferred(DISPLAY_OUTPUT_ROLE, snapshot["override"])
            self.role_preference_overrides[DISPLAY_OUTPUT_ROLE] = snapshot["override"]
        else:
            registry.reset_preferred(DISPLAY_OUTPUT_ROLE)
            self.role_preference_overrides.pop(DISPLAY_OUTPUT_ROLE, None)
        for lease in registry.active_leases(DISPLAY_OUTPUT_ROLE):
            registry.release(lease)
        for lease in snapshot["leases"]:
            if registry.is_candidate(DISPLAY_OUTPUT_ROLE, lease.provider_id):
                instance = self.instances.get(lease.provider_id)
                holder = (
                    f"generation:{instance.generation}"
                    if instance is not None and instance.ready
                    else lease.holder
                )
                registry.acquire(
                    DISPLAY_OUTPUT_ROLE,
                    lease.provider_id,
                    holder=holder,
                )
        self._persist_role_preferences()

    def _provider_active_outside_display(self, provider: str) -> bool:
        return any(
            role != DISPLAY_OUTPUT_ROLE
            and provider in self.role_registry.active_providers(role)
            for role in self.role_registry.list_roles()
        )

    async def _retire_display_provider(self, provider: str) -> None:
        """Stop the current provider generation once it no longer owns a role.

        A supervised provider can fail and replace its generation while a
        migration is restarting consumers.  Retiring only the instance from
        the initial snapshot would then leave that replacement alive after the
        lease moved.  The component start lock makes each attempt atomic; the
        bounded retry follows a concurrently installed generation without ever
        stopping a provider selected for another role.
        """

        for _attempt in range(3):
            if self._provider_active_outside_display(provider):
                return
            current = self.instances.get(provider)
            if current is None:
                return
            await self.stop_component(provider, expected=current)
        if (
            self.instances.get(provider) is not None
            and not self._provider_active_outside_display(provider)
        ):
            raise RuntimeError(
                f"display provider kept replacing its generation: {provider}"
            )

    def _restore_foreground(self, foreground: list[str]) -> None:
        restored = [
            key
            for key in foreground
            if key in self.instances and self.instances[key].ready
        ]
        self.foreground_stack = [
            *restored,
            *(key for key in self.foreground_stack if key not in restored),
        ]

    async def _reactivate_foreground(self) -> None:
        entries = self._foreground_entries()
        if not entries:
            return
        top = entries[0]
        response = await self.dispatch_call({
            "type": "call",
            "id": 0,
            "target": "role:window-manager",
            "method": "activate_component",
            "payload": {
                "component": top["component"],
                "identity": top["identity"],
                "title": top["title"],
            },
            "idempotent": True,
        }, source="msys.core")
        if response.get("type") == "error":
            print(
                "msysd: foreground reactivation after display migration failed "
                f"component={top['component']} code={response.get('code')}",
                flush=True,
            )

    async def _rollback_display_migration(
        self,
        snapshot: dict[str, Any],
        attempted: list[str],
        provider: str,
        new_instance: Instance | None,
    ) -> list[dict[str, str]]:
        failures: list[dict[str, str]] = []
        outage_snapshot: dict[str, Any] | None = snapshot.get("display_outage")
        restored_outage: dict[str, Any] | None = None
        if outage_snapshot is not None:
            # Discard any mutations caused by the attempted provider and put
            # the original unavailable session back in charge.  Consumers
            # remain stopped until that provider obtains a fresh ready lease.
            restored_outage = self._clone_display_outage(outage_snapshot)
            restored_outage["recovery_allowed"].clear()
            self.display_outage = restored_outage
        originals: dict[str, Instance | None] = snapshot.get(
            "consumer_instances", {}
        )
        for key in reversed(attempted):
            current = self.instances.get(key)
            if current is None or current is originals.get(key):
                continue
            try:
                await self.stop_component(key, expected=current)
            except Exception as exc:
                failures.append({"step": f"stop-new-consumer:{key}", "message": str(exc)[:256]})

        old_provider = snapshot.get("provider")
        if old_provider and outage_snapshot is None:
            try:
                await self.ensure_ready(old_provider)
            except Exception as exc:
                failures.append({"step": f"ready-old-provider:{old_provider}", "message": str(exc)[:256]})
        try:
            async with self.catalog_lock:
                self._restore_display_role(snapshot)
                if outage_snapshot is not None and old_provider:
                    old_instance = self.instances.get(old_provider)
                    if (
                        old_instance is not None
                        and old_instance.ready
                        and self.components.get(old_provider)
                        is old_instance.component
                        and self.role_registry.active_provider(
                            DISPLAY_OUTPUT_ROLE
                        )
                        is None
                        and self.role_registry.preferred_provider(
                            DISPLAY_OUTPUT_ROLE
                        )
                        == old_provider
                    ):
                        self.role_registry.acquire(
                            DISPLAY_OUTPUT_ROLE,
                            old_provider,
                            holder=f"generation:{old_instance.generation}",
                        )
        except Exception as exc:
            failures.append({"step": "restore-role", "message": str(exc)[:256]})

        if (
            provider != old_provider
            and snapshot.get("target_provider_instance") is None
            and not self._provider_active_outside_display(provider)
        ):
            try:
                await self._retire_display_provider(provider)
            except Exception as exc:
                failures.append({"step": f"stop-new-provider:{provider}", "message": str(exc)[:256]})

        if restored_outage is not None:
            for key in attempted:
                retry = self.spawn_retry_tasks.pop(key, None)
                if (
                    retry
                    and retry is not asyncio.current_task()
                    and not retry.done()
                ):
                    retry.cancel()
                    await asyncio.gather(retry, return_exceptions=True)
                self._restore_outage_failure_budget(restored_outage, key)
                if key not in restored_outage["preexisting_quarantine"]:
                    self.quarantined.discard(key)
                    self.quarantine_times.pop(key, None)
            if old_provider:
                old_instance = self.instances.get(old_provider)
                if (
                    old_instance is not None
                    and old_instance.ready
                    and self._owns_active_display_output(old_instance)
                ):
                    self._schedule_display_recovery(old_instance)
            return failures

        for key in attempted:
            original = originals.get(key)
            current = self.instances.get(key)
            if current is original and current is not None and current.ready:
                continue
            if current is not None:
                try:
                    await self.stop_component(key, expected=current)
                except Exception as exc:
                    failures.append({"step": f"stop-rollback-consumer:{key}", "message": str(exc)[:256]})
                    continue
            try:
                replacement = await self.ensure_ready(key)
                if not replacement.ready:
                    raise RuntimeError(f"component state is {replacement.state}")
            except Exception as exc:
                failures.append({"step": f"restore-consumer:{key}", "message": str(exc)[:256]})
        self._restore_foreground(snapshot.get("foreground", []))
        try:
            await self._reactivate_foreground()
        except Exception as exc:
            failures.append({"step": "restore-foreground", "message": str(exc)[:256]})
        return failures

    async def _migrate_display_output(
        self,
        provider: str,
        *,
        preference_mode: str,
        record: dict[str, Any],
    ) -> dict[str, Any]:
        async with self.catalog_lock:
            registry = self.role_registry
            registry.get_candidate(DISPLAY_OUTPUT_ROLE, provider)
            snapshot = self._snapshot_display_role(registry)
            snapshot["target_provider_instance"] = self.instances.get(provider)
            outage_snapshot = (
                self._clone_display_outage(self.display_outage)
                if self.display_outage is not None
                else None
            )
            snapshot["display_outage"] = outage_snapshot
            if outage_snapshot is not None:
                # The live foreground list only contains windows that survived
                # the failed X server.  The outage snapshot is the source of
                # truth for the session the replacement must reconstruct.
                snapshot["foreground"] = list(outage_snapshot["foreground"])
        record.update({
            "phase": "switching",
            "from_provider": snapshot["active"] or snapshot["preferred"],
            "from_display": snapshot["display"],
            "to_provider": provider,
            "to_display": self._display_for_provider(self.components.get(provider)),
            "recovering_outage": outage_snapshot is not None,
        })
        await self._publish_display_migration(record)

        new_instance: Instance | None = None
        attempted: list[str] = []
        restarted: list[str] = []
        switched = False
        try:
            new_instance = await self.ensure_ready(provider)
            if not new_instance.ready or new_instance.state != "ready":
                raise DisplayMigrationError(
                    "new display provider did not become ready",
                    details={"provider": provider, "state": new_instance.state},
                )
            async with self.catalog_lock:
                if self.role_registry is not registry or self.catalog_epoch != snapshot["epoch"]:
                    raise DisplayMigrationError("display catalog changed before commit")
                if self.components.get(provider) is not new_instance.component:
                    raise DisplayMigrationError("new display provider became stale")
                running_consumers = set(self._ordered_visual_consumers())
                if outage_snapshot is not None:
                    if not self._display_outage_matches(outage_snapshot):
                        raise DisplayMigrationError(
                            "display outage changed before provider commit"
                        )
                    outage_consumers = [
                        key
                        for key in outage_snapshot["consumers"]
                        if key in self.components
                        and self._inherits_visual_session(self.components[key])
                    ]
                    running_consumers.difference_update(outage_consumers)
                    consumers = list(dict.fromkeys([
                        *outage_consumers,
                        *self._order_visual_consumer_keys(running_consumers),
                    ]))
                else:
                    consumers = self._order_visual_consumer_keys(
                        running_consumers
                    )
                snapshot["consumer_instances"] = {
                    key: self.instances.get(key)
                    for key in consumers
                }
                switched = True
                self._apply_display_preference(
                    registry,
                    provider,
                    new_instance,
                    preference_mode=preference_mode,
                )
                new_display = self._session_display()
                session_invalidated = (
                    snapshot["display"] != new_display
                    or snapshot["provider"] != provider
                    or snapshot["provider_component"] is not new_instance.component
                    or snapshot["provider_generation"] != new_instance.generation
                    or outage_snapshot is not None
                )
            record.update({
                "to_display": new_display,
                "from_generation": snapshot["provider_generation"],
                "to_generation": new_instance.generation,
                "session_invalidated": session_invalidated,
                "consumers": list(consumers),
            })

            if session_invalidated:
                for key in consumers:
                    if (
                        outage_snapshot is not None
                        and not self._display_outage_matches(outage_snapshot)
                    ):
                        raise DisplayMigrationError(
                            "display outage changed while restarting consumers"
                        )
                    old_consumer = snapshot["consumer_instances"].get(key)
                    skip_quarantined = bool(
                        outage_snapshot is not None
                        and (
                            key in outage_snapshot["preexisting_quarantine"]
                            or key in self.quarantined
                        )
                    )
                    if not skip_quarantined:
                        attempted.append(key)
                    if old_consumer is not None:
                        await self.stop_component(key, expected=old_consumer)
                    if skip_quarantined:
                        continue
                    live_outage = self.display_outage
                    if outage_snapshot is not None:
                        self._restore_outage_failure_budget(outage_snapshot, key)
                        if live_outage is None:
                            raise DisplayMigrationError(
                                "display outage disappeared during recovery"
                            )
                        live_outage["recovery_allowed"].add(key)
                    try:
                        replacement = await self.ensure_ready(key)
                    finally:
                        if live_outage is not None:
                            live_outage["recovery_allowed"].discard(key)
                    if not replacement.ready or replacement.state != "ready":
                        raise DisplayMigrationError(
                            "visual consumer did not become ready",
                            details={"component": key, "state": replacement.state},
                        )
                    restarted.append(key)
                    record["restarted"] = list(restarted)

            if (
                self.role_registry is not registry
                or self.components.get(provider) is not new_instance.component
                or not self._owns_active_display_output(new_instance)
            ):
                raise DisplayMigrationError(
                    "new display provider generation changed during migration"
                )

            self._restore_foreground(snapshot["foreground"])
            await self._reactivate_foreground()

            if (
                self.role_registry is not registry
                or not self._owns_active_display_output(new_instance)
            ):
                raise DisplayMigrationError(
                    "new display provider generation changed before commit"
                )

            # The in-memory lease selects the new DISPLAY during restarts, but
            # the durable preference is committed only after every consumer
            # passes readiness. A daemon crash before this point therefore
            # boots back into the last known-good visual session.
            self._persist_role_preferences()

            if (
                outage_snapshot is not None
                and not self._display_outage_matches(outage_snapshot)
            ):
                raise DisplayMigrationError(
                    "display outage changed before migration commit"
                )

            old_provider = snapshot["provider"]
            if (
                old_provider
                and old_provider != provider
                and not self._provider_active_outside_display(old_provider)
            ):
                await self._retire_display_provider(old_provider)
            if outage_snapshot is not None:
                if not self._display_outage_matches(outage_snapshot):
                    raise DisplayMigrationError(
                        "display outage changed during provider retirement"
                    )
                self.display_outage = None
                fault_id = outage_snapshot.get("fault_id")
                if fault_id is not None:
                    await self._complete_display_fault(
                        new_instance,
                        restarted_system_ui=restarted,
                        fault_id=fault_id,
                    )
            async with self.catalog_lock:
                summary = self._role_summary(DISPLAY_OUTPUT_ROLE)
            return {
                "role_summary": summary,
                "consumers": list(consumers),
                "restarted": list(restarted),
                "foreground": list(self.foreground_stack),
                "from_display": snapshot["display"],
                "to_display": new_display,
            }
        except Exception as exc:
            rollback_failures: list[dict[str, str]] = []
            if switched:
                rollback_failures = await self._rollback_display_migration(
                    snapshot,
                    attempted,
                    provider,
                    new_instance,
                )
            elif (
                provider != snapshot["provider"]
                and snapshot.get("target_provider_instance") is None
                and not self._provider_active_outside_display(provider)
            ):
                try:
                    await self._retire_display_provider(provider)
                except Exception as cleanup_exc:
                    rollback_failures.append({
                        "step": f"stop-new-provider:{provider}",
                        "message": str(cleanup_exc)[:256],
                    })
            details = dict(exc.details) if isinstance(exc, DisplayMigrationError) else {}
            details.update({
                "from_provider": snapshot["provider"],
                "to_provider": provider,
                "attempted": list(attempted),
                "restarted": list(restarted),
                "rollback_failures": rollback_failures,
            })
            raise DisplayMigrationError(str(exc), details=details) from exc

    async def _activate_role_call(self, msg: dict[str, Any]) -> dict[str, Any]:
        request_id = msg.get("id", 0)
        payload = msg.get("payload", {})
        if not isinstance(payload, dict):
            return {
                "type": "error",
                "id": request_id,
                "code": "BAD_PAYLOAD",
                "message": "activate_role payload must be an object",
            }
        raw_role = payload.get("role")
        if not isinstance(raw_role, str) or not raw_role.strip():
            return {
                "type": "error",
                "id": request_id,
                "code": "BAD_ROLE",
                "message": "activate_role requires a non-empty role",
            }
        role = raw_role.strip()
        if role == "window-manager":
            return {
                "type": "error",
                "id": request_id,
                "code": "ROLE_ACTIVATION_RECURSION",
                "message": "window-manager cannot activate itself through window-manager",
            }

        role_lock = self.role_locks.setdefault(role, asyncio.Lock())
        instance: Instance | None = None
        provider = ""
        component: Component | None = None
        async with role_lock:
            for _attempt in range(3):
                async with self.catalog_lock:
                    registry = self.role_registry
                    epoch = self.catalog_epoch
                    if role not in registry.list_roles():
                        return {
                            "type": "error",
                            "id": request_id,
                            "code": "UNKNOWN_ROLE",
                            "message": role,
                        }
                    provider = (
                        registry.active_provider(role)
                        or registry.preferred_provider(role)
                        or ""
                    )
                    if not provider:
                        return {
                            "type": "error",
                            "id": request_id,
                            "code": "NO_PROVIDER",
                            "message": role,
                        }
                    component = self.components.get(provider)
                    if component is None:
                        return {
                            "type": "error",
                            "id": request_id,
                            "code": "NO_PROVIDER",
                            "message": provider,
                        }
                try:
                    candidate = await self.ensure_ready(provider)
                except Exception as exc:
                    async with self.catalog_lock:
                        changed = (
                            self.catalog_epoch != epoch
                            or self.role_registry is not registry
                            or self.components.get(provider) is not component
                        )
                    if changed:
                        continue
                    return {
                        "type": "error",
                        "id": request_id,
                        "code": "ROLE_UNAVAILABLE",
                        "message": str(exc)[:512],
                        "payload": {"role": role, "provider": provider},
                    }
                async with self.catalog_lock:
                    if (
                        self.catalog_epoch != epoch
                        or self.role_registry is not registry
                        or self.components.get(provider) is not component
                        or self.instances.get(provider) is not candidate
                    ):
                        continue
                instance = candidate
                break

        if instance is None or component is None:
            return {
                "type": "error",
                "id": request_id,
                "code": "ROLE_CHANGED",
                "message": role,
            }

        if self._is_foreground_app(component):
            self._mark_foreground(provider)
        window = self._window_activation_payload(component)
        activation_call: dict[str, Any] = {
            "type": "call",
            "id": 0,
            "target": "role:window-manager",
            "method": "activate_component",
            "payload": window,
        }
        if "deadline_ms" in msg:
            activation_call["deadline_ms"] = msg["deadline_ms"]
        activation_response = await self.dispatch_call(
            activation_call,
            source="msys.core",
        )
        if activation_response.get("type") != "return":
            return {
                "type": "error",
                "id": request_id,
                "code": "ROLE_ACTIVATION_FAILED",
                "message": str(
                    activation_response.get("message")
                    or activation_response.get("code")
                    or "window activation failed"
                )[:512],
                "payload": {
                    "role": role,
                    "provider": provider,
                    "generation": instance.generation,
                    "activation": activation_response,
                },
            }
        raw_activation = activation_response.get("payload", {})
        activation = dict(raw_activation) if isinstance(raw_activation, dict) else {}
        return {
            "type": "return",
            "id": request_id,
            "payload": {
                "ok": activation.get("ok") is not False,
                "role": role,
                "provider": provider,
                "generation": instance.generation,
                "state": instance.state,
                "activation": activation,
            },
        }

    async def _core_call(
        self,
        msg: dict[str, Any],
        source: str = "public",
    ) -> dict[str, Any]:
        method = msg.get("method")
        if method == "activate_role":
            return await self._activate_role_call(msg)
        if method == "get_session_preferences":
            return {
                "type": "return",
                "id": msg.get("id", 0),
                "payload": self._session_preferences_payload(),
            }
        if method == "set_session_preferences":
            request_id = msg.get("id", 0)
            payload = msg.get("payload", {})
            if not isinstance(payload, dict):
                return {
                    "type": "error",
                    "id": request_id,
                    "code": "BAD_PAYLOAD",
                    "message": "session preferences payload must be an object",
                }
            unknown = sorted(set(payload) - {"language"})
            if unknown or "language" not in payload:
                return {
                    "type": "error",
                    "id": request_id,
                    "code": "BAD_SESSION_PREFERENCES",
                    "message": (
                        "set_session_preferences requires only language"
                        if not unknown
                        else "unknown session preference: " + ", ".join(unknown)
                    ),
                }
            try:
                language = self._validate_session_language(payload["language"])
            except ValueError as exc:
                return {
                    "type": "error",
                    "id": request_id,
                    "code": "BAD_LANGUAGE",
                    "message": str(exc),
                }
            previous = self.session_language
            self.session_language = language
            try:
                self._persist_session_preferences()
            except OSError as exc:
                self.session_language = previous
                return {
                    "type": "error",
                    "id": request_id,
                    "code": "SESSION_PREFERENCES_WRITE_FAILED",
                    "message": str(exc)[:512],
                }
            self.__dict__.pop("_presentation_locale_value", None)
            result = self._session_preferences_payload()
            result.update({"ok": True, "changed": previous != language})
            if previous != language:
                await self.broadcast(
                    SESSION_PREFERENCES_TOPIC,
                    result,
                    source=source,
                )
            return {
                "type": "return",
                "id": request_id,
                "payload": result,
            }
        if method == "navigation_back":
            request_id = msg.get("id", 0)
            entries = self._foreground_entries()
            if not entries or entries[0].get("state") == "background":
                return {
                    "type": "return",
                    "id": request_id,
                    "payload": {
                        "handled": False,
                        "fallback": True,
                        "reason": "no-foreground-application",
                    },
                }
            component_id = str(entries[0].get("component") or "")
            component = self.components.get(component_id)
            supports_navigation = component is not None and any(
                provide.kind == "interface"
                and provide.name == APPLICATION_NAVIGATION_INTERFACE
                for provide in component.provides
            )
            if not supports_navigation:
                return {
                    "type": "return",
                    "id": request_id,
                    "payload": {
                        "handled": False,
                        "fallback": True,
                        "component": component_id,
                        "reason": "interface-not-provided",
                    },
                }
            instance = self.instances.get(component_id)
            if instance is None or not instance.sock or not instance.ready:
                return {
                    "type": "return",
                    "id": request_id,
                    "payload": {
                        "handled": False,
                        "fallback": False,
                        "component": component_id,
                        "reason": "navigation-provider-unavailable",
                    },
                }
            forwarded = {
                "type": "call",
                "id": request_id,
                "target": f"component:{component_id}",
                "method": "navigation_back",
                "payload": {},
            }
            if "deadline_ms" in msg:
                forwarded["deadline_ms"] = msg["deadline_ms"]
            response = await self._forward_call(
                instance,
                forwarded,
                source="msys.core",
            )
            if response.get("type") != "return":
                return {
                    "type": "return",
                    "id": request_id,
                    "payload": {
                        "handled": False,
                        "fallback": False,
                        "component": component_id,
                        "reason": str(response.get("code") or "navigation-call-failed"),
                    },
                }
            result = response.get("payload", {})
            handled = isinstance(result, dict) and result.get("handled") is True
            return {
                "type": "return",
                "id": request_id,
                "payload": {
                    "handled": handled,
                    "fallback": not handled,
                    "component": component_id,
                    "result": result if isinstance(result, dict) else {},
                },
            }
        if method == "background_component":
            request_id = msg.get("id", 0)
            request = msg.get("payload", {})
            if not isinstance(request, dict):
                return {
                    "type": "error",
                    "id": request_id,
                    "code": "BAD_PAYLOAD",
                    "message": "background payload must be an object",
                }
            component_id = request.get("component")
            if not isinstance(component_id, str) or not component_id:
                return {
                    "type": "error",
                    "id": request_id,
                    "code": "BAD_COMPONENT",
                    "message": "background_component requires a component",
                }
            instance = self.instances.get(component_id)
            if (
                instance is None
                or not instance.process
                or instance.process.poll() is not None
                or not self._is_foreground_app(instance.component)
            ):
                return {
                    "type": "error",
                    "id": request_id,
                    "code": "COMPONENT_UNAVAILABLE",
                    "message": component_id,
                }
            accepted, already = self._background_foreground(component_id)
            if not accepted:
                return {
                    "type": "error",
                    "id": request_id,
                    "code": "NOT_FOREGROUND",
                    "message": component_id,
                }
            return {
                "type": "return",
                "id": request_id,
                "payload": {
                    "ok": True,
                    "component": component_id,
                    "state": "background",
                    "already_background": already,
                },
            }
        if method == "discover":
            raw_payload = msg.get("payload", {})
            if not isinstance(raw_payload, dict):
                return {
                    "type": "error",
                    "id": msg.get("id", 0),
                    "code": "BAD_PAYLOAD",
                    "message": "discover payload must be an object",
                }
            raw_kind = str(raw_payload.get("kind", "")).strip()
            kind = raw_kind or None
            if kind not in {None, "interface", "capability"}:
                return {
                    "type": "error",
                    "id": msg.get("id", 0),
                    "code": "BAD_SERVICE_KIND",
                    "message": raw_kind,
                }
            raw_name = str(raw_payload.get("name", "")).strip()
            return {
                "type": "return",
                "id": msg.get("id", 0),
                "payload": {
                    "services": self._service_summaries(kind, raw_name or None),
                },
            }
        if method == "resolve_intent":
            request = normalize_intent_request(msg.get("payload", {}))
            return {
                "type": "return",
                "id": msg.get("id", 0),
                "payload": {"candidates": self._intent_candidates(request)},
            }
        if method == "activate":
            request = normalize_intent_request(msg.get("payload", {}))
            selected = str(request.get("component", ""))
            candidates = self._intent_candidates(request)
            candidate_ids = [str(item["component"]) for item in candidates]
            if selected:
                if selected not in self.components:
                    return {"type": "error", "id": msg.get("id", 0), "code": "UNKNOWN_COMPONENT", "message": selected}
                if candidate_ids and selected not in candidate_ids:
                    return {"type": "error", "id": msg.get("id", 0), "code": "NOT_INTENT_HANDLER", "message": selected}
            elif len(candidates) == 1:
                selected = candidate_ids[0]
            elif len(candidates) > 1:
                choice_deadline = msg.get("deadline_ms")
                if not isinstance(choice_deadline, (int, float)) or isinstance(choice_deadline, bool):
                    choice_deadline = int(time.monotonic() * 1000 + 30_000)
                choice = await self.dispatch_call({
                    "type": "call",
                    "id": 0,
                    "target": "role:chooser",
                    "method": "choose_intent",
                    "payload": {"request": request, "candidates": candidates},
                    "deadline_ms": choice_deadline,
                }, source="msys.core")
                if choice.get("type") == "return":
                    selected = str(choice.get("payload", {}).get("component", ""))
                if selected not in candidate_ids:
                    choice_code = str(choice.get("code", ""))
                    if choice_code in {"CHOICE_CANCELLED", "CHOICE_TIMEOUT", "CHOOSER_UI_ERROR"}:
                        return {
                            "type": "error",
                            "id": msg.get("id", 0),
                            "code": choice_code,
                            "message": str(choice.get("message", "intent choice failed")),
                            "payload": {"candidates": candidates},
                        }
                    return {
                        "type": "error",
                        "id": msg.get("id", 0),
                        "code": "CHOICE_REQUIRED",
                        "message": "multiple intent handlers",
                        "payload": {"candidates": candidates},
                    }
            else:
                return {
                    "type": "error",
                    "id": msg.get("id", 0),
                    "code": "NO_INTENT_HANDLER",
                    "message": str(request.get("action", "")),
                }
            response = await self._core_call({
                "type": "call",
                "id": msg.get("id", 0),
                "method": "start",
                "payload": {"component": selected, "activation": request},
            })
            if response.get("type") == "return":
                response.setdefault("payload", {})["intent"] = {
                    "action": request.get("action"),
                    "component": selected,
                }
            return response
        if method == "list_roles":
            return {
                "type": "return",
                "id": msg.get("id", 0),
                "payload": {
                    "roles": [
                        self._role_summary(role)
                        for role in self.role_registry.list_roles()
                    ]
                },
            }
        if method == "preflight_registry":
            payload = msg.get("payload", {})
            if not isinstance(payload, dict):
                return {
                    "type": "error",
                    "id": msg.get("id", 0),
                    "code": "BAD_PAYLOAD",
                    "message": "preflight_registry payload must be an object",
                }
            try:
                async with self.reload_lock:
                    result = self.preflight_installed_candidate(
                        str(payload.get("package", "")),
                        Path(str(payload.get("path", ""))),
                    )
            except CatalogTransactionError as exc:
                return {
                    "type": "error",
                    "id": msg.get("id", 0),
                    "code": exc.code,
                    "message": exc.message,
                    "payload": exc.details,
                }
            return {"type": "return", "id": msg.get("id", 0), "payload": result}
        if method == "preflight_registry_remove":
            payload = msg.get("payload", {})
            if not isinstance(payload, dict):
                return {
                    "type": "error",
                    "id": msg.get("id", 0),
                    "code": "BAD_PAYLOAD",
                    "message": "preflight_registry_remove payload must be an object",
                }
            try:
                async with self.reload_lock:
                    result = self.preflight_installed_removal(
                        str(payload.get("package", "")),
                    )
            except CatalogTransactionError as exc:
                return {
                    "type": "error",
                    "id": msg.get("id", 0),
                    "code": exc.code,
                    "message": exc.message,
                    "payload": exc.details,
                }
            return {"type": "return", "id": msg.get("id", 0), "payload": result}
        if method == "reload_registry":
            payload = msg.get("payload", {})
            if not isinstance(payload, dict):
                return {
                    "type": "error",
                    "id": msg.get("id", 0),
                    "code": "BAD_PAYLOAD",
                    "message": "reload_registry payload must be an object",
                }
            verify_health = payload.get("verify_health", True)
            if not isinstance(verify_health, bool):
                return {
                    "type": "error",
                    "id": msg.get("id", 0),
                    "code": "BAD_PAYLOAD",
                    "message": "verify_health must be a boolean",
                }
            try:
                transaction = _catalog_transaction_request(
                    payload.get("transaction")
                )
            except ValueError as exc:
                return {
                    "type": "error",
                    "id": msg.get("id", 0),
                    "code": "BAD_PAYLOAD",
                    "message": str(exc),
                }
            try:
                changes = await self.reload_installed_components(
                    verify_health=verify_health,
                    transaction=transaction,
                )
            except CatalogTransactionError as exc:
                return {
                    "type": "error",
                    "id": msg.get("id", 0),
                    "code": exc.code,
                    "message": exc.message,
                    "payload": exc.details,
                }
            except Exception as exc:
                return {
                    "type": "error",
                    "id": msg.get("id", 0),
                    "code": CatalogReloadError.code,
                    "message": "installed catalog reload failed",
                    "payload": {"reason": str(exc)[:512]},
                }
            return {"type": "return", "id": msg.get("id", 0), "payload": changes}
        if method == "select_role":
            payload = msg.get("payload", {})
            role = str(payload.get("role", ""))
            provider = str(payload.get("provider", ""))
            if role == DISPLAY_OUTPUT_ROLE:
                try:
                    migration = await self._queue_display_migration(
                        provider,
                        preference_mode="select",
                        source=source,
                    )
                except Exception as exc:
                    return {
                        "type": "error",
                        "id": msg.get("id", 0),
                        "code": "DISPLAY_MIGRATION_REJECTED",
                        "message": str(exc)[:512],
                    }
                return {
                    "type": "return",
                    "id": msg.get("id", 0),
                    "payload": {"migration": migration},
                }
            role_lock = self.role_locks.setdefault(role, asyncio.Lock())
            async with role_lock:
                selected = await self._switch_role(role, provider, preference_mode="select")
            return {"type": "return", "id": msg.get("id", 0), "payload": selected}
        if method == "reset_role":
            payload = msg.get("payload", {})
            role = str(payload.get("role", ""))
            role_lock = self.role_locks.setdefault(role, asyncio.Lock())
            async with role_lock:
                async with self.catalog_lock:
                    candidates = self.role_registry.candidate_ids(role)
                    provider = candidates[0] if candidates else None
                    if provider is None:
                        return {"type": "error", "id": msg.get("id", 0), "code": "NO_PROVIDER", "message": role}
                if role == DISPLAY_OUTPUT_ROLE:
                    try:
                        migration = await self._queue_display_migration(
                            provider,
                            preference_mode="reset",
                            source=source,
                        )
                    except Exception as exc:
                        return {
                            "type": "error",
                            "id": msg.get("id", 0),
                            "code": "DISPLAY_MIGRATION_REJECTED",
                            "message": str(exc)[:512],
                        }
                    return {
                        "type": "return",
                        "id": msg.get("id", 0),
                        "payload": {"migration": migration},
                    }
                selected = await self._switch_role(role, provider, preference_mode="reset")
            return {"type": "return", "id": msg.get("id", 0), "payload": selected}
        if method in {"display_migration_status", "get_display_migration"}:
            payload = msg.get("payload", {})
            if not isinstance(payload, dict):
                return {
                    "type": "error",
                    "id": msg.get("id", 0),
                    "code": "BAD_PAYLOAD",
                    "message": "display migration status payload must be an object",
                }
            raw_id = payload.get("id")
            if raw_id is not None and (
                isinstance(raw_id, bool) or not isinstance(raw_id, int) or raw_id <= 0
            ):
                return {
                    "type": "error",
                    "id": msg.get("id", 0),
                    "code": "BAD_PAYLOAD",
                    "message": "display migration id must be a positive integer",
                }
            return {
                "type": "return",
                "id": msg.get("id", 0),
                "payload": {
                    "migration": self._display_migration_status(raw_id),
                },
            }
        if method == "list_components":
            return {
                "type": "return",
                "id": msg.get("id", 0),
                "payload": {
                    "components": [self._component_summary(key, c) for key, c in sorted(self.components.items())]
                },
            }
        if method == "list_processes":
            request = msg.get("payload", {})
            if not isinstance(request, dict):
                return {
                    "type": "error",
                    "id": msg.get("id", 0),
                    "code": "BAD_PAYLOAD",
                    "message": "process list payload must be an object",
                }
            unknown = set(request) - {"include_system", "limit"}
            include_system = request.get("include_system", False)
            limit = request.get("limit", DEFAULT_SYSTEM_PROCESS_LIMIT)
            if unknown:
                return {
                    "type": "error",
                    "id": msg.get("id", 0),
                    "code": "BAD_PAYLOAD",
                    "message": "unknown process list field",
                }
            if not isinstance(include_system, bool):
                return {
                    "type": "error",
                    "id": msg.get("id", 0),
                    "code": "BAD_PAYLOAD",
                    "message": "include_system must be boolean",
                }
            if (
                isinstance(limit, bool)
                or not isinstance(limit, int)
                or not 1 <= limit <= MAX_SYSTEM_PROCESS_LIMIT
            ):
                return {
                    "type": "error",
                    "id": msg.get("id", 0),
                    "code": "BAD_PAYLOAD",
                    "message": (
                        "process list limit must be an integer between 1 and "
                        f"{MAX_SYSTEM_PROCESS_LIMIT}"
                    ),
                }
            return {
                "type": "return",
                "id": msg.get("id", 0),
                "payload": self._process_list_snapshot(
                    include_system=include_system,
                    system_limit=limit,
                ),
            }
        if method == "isolation_capabilities":
            capabilities = detect_capabilities(self._seccomp_helper())
            return {
                "type": "return",
                "id": msg.get("id", 0),
                "payload": capabilities.as_dict(),
            }
        if method == "list_apps":
            return {
                "type": "return",
                "id": msg.get("id", 0),
                "payload": {
                    "apps": [
                        self._component_summary(key, component)
                        for key, component in sorted(self.components.items())
                        if self._is_launchable(component)
                    ]
                },
            }
        if method == "start":
            call_payload = msg.get("payload", {})
            key = str(call_payload.get("component", ""))
            raw_activation = call_payload.get("activation")
            if raw_activation is not None and not isinstance(raw_activation, dict):
                return {"type": "error", "id": msg.get("id", 0), "code": "BAD_ACTIVATION"}
            activation = dict(raw_activation) if isinstance(raw_activation, dict) else None
            instance = await self.ensure_ready(key, activation=activation)
            if activation:
                self._send_activation_event(instance, activation)
            result: dict[str, Any] = {"component": key, "state": instance.state}
            if activation:
                result["activation_request"] = activation
            if self._is_foreground_app(instance.component):
                self._mark_foreground(key)
                activation = await self.dispatch_call({
                    "type": "call",
                    "id": 0,
                    "target": "role:window-manager",
                    "method": "activate_component",
                    "payload": self._window_activation_payload(instance.component),
                }, source="msys.core")
                if activation.get("type") == "return":
                    result["activation"] = activation.get("payload", {})
                else:
                    result["activation_error"] = {
                        "code": activation.get("code"),
                        "message": activation.get("message"),
                    }
            return {"type": "return", "id": msg.get("id", 0), "payload": result}
        if method == "stop":
            key = str(msg.get("payload", {}).get("component", ""))
            await self.stop_component(key)
            return {"type": "return", "id": msg.get("id", 0), "payload": {"component": key, "state": "stopped"}}
        if method == "broadcast":
            payload = msg.get("payload", {})
            await self.broadcast(payload.get("topic", ""), payload.get("payload", {}), source="core-call")
            return {"type": "return", "id": msg.get("id", 0), "payload": {"ok": True}}
        if method == "foreground_stack":
            request = msg.get("payload", {})
            include_resources = (
                isinstance(request, dict) and request.get("include_resources") is True
            )
            return {
                "type": "return",
                "id": msg.get("id", 0),
                "payload": {
                    "windows": self._foreground_entries(
                        include_resources=include_resources
                    )
                },
            }
        return {"type": "error", "id": msg.get("id", 0), "code": "NO_METHOD", "message": str(method)}

    async def _x11_window_policy_call(self, msg: dict[str, Any]) -> dict[str, Any] | None:
        method = str(msg.get("method", ""))
        request_id = msg.get("id", 0)
        if method not in {"list_windows", "recents", "close_active", "back", "home"}:
            return None
        if method == "home":
            return await self._core_call({
                "type": "call",
                "id": request_id,
                "method": "activate_role",
                "payload": {"role": "launcher"},
                **(
                    {"deadline_ms": msg["deadline_ms"]}
                    if "deadline_ms" in msg
                    else {}
                ),
            }, source="msys.core")
        display = self._session_display()
        env = os.environ.copy()
        env["DISPLAY"] = display

        def run_x(argv: list[str], timeout: float = 3.0) -> subprocess.CompletedProcess[str]:
            return subprocess.run(argv, env=env, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout)

        def windows_from_tree(text: str) -> list[dict[str, str]]:
            windows: list[dict[str, str]] = []
            system_prefixes = (
                "MSYS Chrome",
                "MSYS Launcher",
                "MSYS Navigation",
                "MSYS Notifications",
                "MSYS Recents",
                "MSYS Screen Shield",
                "msys-notification-host",
                "msys-task-switcher-host",
            )
            for line in text.splitlines():
                stripped = line.strip()
                if not stripped.startswith("0x") or '"' not in stripped:
                    continue
                xid = stripped.split(None, 1)[0]
                title = stripped.split('"', 2)[1]
                if not title or title.startswith("has no name"):
                    continue
                if any(title.startswith(prefix) for prefix in system_prefixes):
                    continue
                windows.append({"id": xid, "title": title})
            return windows

        try:
            tree = await asyncio.to_thread(run_x, ["xwininfo", "-root", "-tree"])
            raw_windows = windows_from_tree(tree.stdout)
            managed = self._foreground_entries()
            if method in {"list_windows", "recents"}:
                managed_titles = {str(item.get("title", "")) for item in managed}
                external = [window for window in raw_windows if window["title"] not in managed_titles]
                return {"type": "return", "id": request_id, "payload": {"windows": [*managed, *external]}}
            if method == "back":
                navigation = await self._core_call({
                    "type": "call",
                    "id": request_id,
                    "method": "navigation_back",
                    "payload": {},
                    **(
                        {"deadline_ms": msg["deadline_ms"]}
                        if "deadline_ms" in msg
                        else {}
                    ),
                }, source="msys.core")
                navigation_payload = navigation.get("payload", {})
                if (
                    navigation.get("type") == "return"
                    and isinstance(navigation_payload, dict)
                    and navigation_payload.get("handled") is True
                ):
                    return {
                        "type": "return",
                        "id": request_id,
                        "payload": {
                            "ok": True,
                            "destination": "application",
                            "application_navigation": navigation_payload,
                        },
                    }
                # Without the selected policy there is no safe in-process X11
                # minimize primitive here. Never regress Back into stop/xkill.
                return {
                    "type": "return",
                    "id": request_id,
                    "payload": {
                        "ok": False,
                        "reason": "window-policy-required-for-safe-back",
                        "application_navigation": navigation_payload,
                    },
                }
            if method == "close_active":
                if managed:
                    key = managed[0]["component"]
                    await self.stop_component(key)
                    return {
                        "type": "return",
                        "id": request_id,
                        "payload": {"ok": True, "closed_component": key},
                    }
                if not raw_windows:
                    return {"type": "return", "id": request_id, "payload": {"ok": False, "reason": "no-user-window"}}
                window = raw_windows[0]
                result = await asyncio.to_thread(run_x, ["xkill", "-id", window["id"]])
                return {
                    "type": "return",
                    "id": request_id,
                    "payload": {
                        "ok": result.returncode == 0,
                        "closed": window["id"],
                        "title": window["title"],
                        "stderr": result.stderr.strip(),
                    },
                }
        except Exception as exc:
            return {"type": "error", "id": request_id, "code": "X11_WINDOW_POLICY_ERROR", "message": str(exc)}
        return None

    async def broadcast(self, topic: str, payload: Any, source: str) -> None:
        if not valid_event_topic(topic):
            return
        delivered = 0
        for instance in list(self.instances.values()):
            if (
                any(subscription_matches(pattern, topic) for pattern in instance.subscriptions)
                and instance.sock
                and instance.ready
            ):
                try:
                    send_packet(instance.sock, {
                        "type": "event",
                        "topic": topic,
                        "source": source,
                        "payload": payload,
                    })
                    delivered += 1
                except OSError:
                    pass
        if os.environ.get("MSYS_DEBUG_IPC") == "1":
            print(f"msysd: broadcast topic={topic} source={source} delivered={delivered}", flush=True)

    async def stop_component(self, key: str, *, expected: Instance | None = None) -> None:
        # An explicit HAL/operator restart of the active display must preserve
        # the same visual-session transaction as a package replacement. Begin
        # the outage while the provider lease and generation are still live,
        # then stop inherited clients cleanly before X11 disappears. If no
        # replacement is started they intentionally remain suspended; the
        # next ready display generation performs normal ordered recovery.
        current = self.instances.get(key)
        planned_display_outage: dict[str, Any] | None = None
        if current is not None and (expected is None or current is expected):
            planned_display_outage = self._begin_display_outage(current)

        self.stop_requests.add(key)
        retry_task = self.spawn_retry_tasks.pop(key, None)
        if retry_task and retry_task is not asyncio.current_task() and not retry_task.done():
            retry_task.cancel()
            await asyncio.gather(retry_task, return_exceptions=True)
        lock = self.start_locks.setdefault(key, asyncio.Lock())
        try:
            if planned_display_outage is not None:
                await self._suspend_display_consumers(planned_display_outage)
            async with lock:
                if expected is not None and self.instances.get(key) is not expected:
                    return
                await self._stop_component_locked(key)
        finally:
            self.stop_requests.discard(key)

    async def _stop_component_locked(self, key: str) -> None:
        instance = self.instances.pop(key, None)
        if not instance:
            return
        animate = self._is_foreground_app(instance.component) and not self.stopping
        if animate and not instance.transition_closing:
            instance.transition_closing = True
            await self._emit_component_transition(
                "closing",
                instance.component,
                generation=instance.generation,
            )
        instance.finalized = True
        self.role_registry.release_provider(key)
        if instance.sock:
            try:
                send_packet(instance.sock, {"type": "shutdown"})
            except OSError:
                pass
        await self._cancel_instance_tasks(instance, include_watch=True)
        self._close_instance_channel(instance, "PROVIDER_STOPPED")
        instance.ready = False
        instance.ready_event.set()
        self._forget_foreground(key)
        await self._terminate_instance_process(instance)
        if animate:
            await self._emit_component_transition(
                "closed",
                instance.component,
                generation=instance.generation,
                returncode=instance.process.returncode if instance.process else None,
            )

    async def _handle_public_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        # Attribute the accepted connection before waiting for client input.
        # This closes the ordinary connect-then-exit race for a supervised
        # process and retains the generation identity throughout this one-shot
        # public request.
        try:
            public_peer = self._public_peer_credentials(writer)
        except OSError as exc:
            public_peer = None
            public_peer_error: OSError | None = exc
            managed_peer = None
        else:
            public_peer_error = None
            managed_peer = self._managed_instance_for_peer(public_peer.pid)
        try:
            writer.write(b'{"type":"welcome","component":"public","generation":0}\n')
            await writer.drain()
            data = await reader.readline()
            if data:
                from .protocol import decode, encode
                msg = decode(data.strip())
                try:
                    if msg.get("type") == "call":
                        if public_peer_error is not None:
                            response = self._public_access_denied(
                                msg,
                                None,
                                f"peer-credentials-unavailable:{public_peer_error}",
                            )
                        else:
                            assert public_peer is not None
                            if managed_peer is not None:
                                denial = self._authorize_component_call(managed_peer, msg)
                                response = (
                                    denial
                                    if denial is not None
                                    else await self.dispatch_call(
                                        msg,
                                        source=managed_peer.component.key,
                                    )
                                )
                            elif public_peer.uid == 0:
                                response = await self.dispatch_call(msg, source="public")
                            else:
                                response = self._public_access_denied(
                                    msg,
                                    public_peer,
                                    "unmanaged-peer-is-not-root",
                                )
                    else:
                        response = {"type": "error", "id": msg.get("id", 0), "code": "BAD_PUBLIC_MESSAGE"}
                except Exception as exc:
                    response = {
                        "type": "error",
                        "id": msg.get("id", 0),
                        "code": "CALL_FAILED",
                        "message": str(exc),
                    }
                writer.write(encode(response) + b"\n")
                await writer.drain()
        except (BrokenPipeError, ConnectionError, OSError):
            return
        finally:
            writer.close()
            try:
                await writer.wait_closed()
            except (BrokenPipeError, ConnectionError, OSError):
                pass


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--foreground", action="store_true")
    parser.add_argument("--config", required=True)
    parser.add_argument(
        "--manifest",
        action="append",
        default=[],
        help="explicit canonical package manifest; may be repeated",
    )
    parser.add_argument("--runtime-dir", required=True)
    parser.add_argument("--profile", required=True)
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    # glibc consumes MALLOC_TRIM_THRESHOLD_ while the interpreter starts. Do
    # not leak this Core-only host-service tuning into supervised components;
    # a component can still declare its own allocator policy in manifest env.
    os.environ.pop("MALLOC_TRIM_THRESHOLD_", None)
    args = parse_args(argv or sys.argv[1:])
    daemon = Msysd(
        Path(args.config),
        Path(args.runtime_dir),
        args.profile,
        tuple(Path(path) for path in args.manifest),
    )
    try:
        asyncio.run(daemon.run())
    except RuntimeOwnershipError as exc:
        print(f"msysd: {exc}", file=sys.stderr, flush=True)
        return 73
    except KeyboardInterrupt:
        return 130
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
