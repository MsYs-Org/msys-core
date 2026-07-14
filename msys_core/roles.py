"""Pure-data role candidate selection and lease tracking.

This module deliberately knows nothing about processes, IPC transports, or the
host service manager.  A supervisor can use :class:`RoleRegistry` to decide
which component should provide a role, then perform process activation itself.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from .manifest import Component


class RoleError(Exception):
    """Base class for role registry errors."""


class UnknownRoleError(KeyError, RoleError):
    """Raised when a role is not present in the registry."""


class UnknownCandidateError(ValueError, RoleError):
    """Raised when a component is not a candidate for a role."""


class NoCandidateError(LookupError, RoleError):
    """Raised when a role has no currently installed candidate."""


class LeaseConflictError(RuntimeError, RoleError):
    """Raised when an exclusive role already has an active lease."""


class UnknownLeaseError(KeyError, RoleError):
    """Raised when attempting to release a lease that is not active."""


@dataclass(frozen=True, slots=True)
class RoleCandidate:
    """One installed component that may fill a role.

    ``profile_rank`` is zero-based for explicitly configured candidates and is
    ``None`` for candidates discovered only from component ``provides``.
    """

    role: str
    provider_id: str
    priority: int
    exclusive: bool
    profile_rank: int | None = None
    declared: bool = True

    @property
    def explicit(self) -> bool:
        return self.profile_rank is not None


@dataclass(frozen=True, slots=True)
class RoleLease:
    """An immutable grant returned by :meth:`RoleRegistry.acquire`."""

    token: int
    role: str
    provider_id: str
    holder: str | None = None


@dataclass(frozen=True, slots=True)
class RoleInfo:
    """A point-in-time, immutable view of one role."""

    name: str
    exclusive: bool
    candidates: tuple[RoleCandidate, ...]
    preferred_provider: str | None
    active_provider: str | None
    active_providers: tuple[str, ...]
    lease_count: int


@dataclass(slots=True)
class _RoleState:
    candidates: tuple[RoleCandidate, ...]
    exclusive: bool


def _profile_candidate_ids(value: object) -> list[str]:
    """Normalize one profile role value without treating strings as iterables."""

    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if not isinstance(value, Sequence):
        raise TypeError("profile role candidates must be a sequence of component ids")
    return [str(item) for item in value]


class RoleRegistry:
    """Candidate catalog, preference store, and active lease registry.

    Candidate order is deterministic:

    1. installed providers explicitly listed by the profile, in profile order;
    2. all remaining declared providers, by descending ``provide.priority``;
    3. provider id as the stable tie-breaker.

    Missing profile entries are ignored so a profile may include optional or
    not-yet-installed fallback packages.  A known component explicitly named
    by a profile remains a candidate even if an older manifest omitted its
    matching ``provides`` entry; ``RoleCandidate.declared`` exposes that fact.
    """

    def __init__(
        self,
        components: Mapping[str, Component],
        profile_roles: Mapping[str, object] | None = None,
        disabled_roles: Sequence[str] | None = None,
    ) -> None:
        self._components = dict(components)
        self._profile_roles = dict(profile_roles or {})
        self._disabled_roles = frozenset(str(role) for role in (disabled_roles or ()))
        self._roles = self._build_roles()
        self._preferred: dict[str, str] = {}
        self._leases: dict[int, RoleLease] = {}
        self._role_leases: dict[str, list[int]] = {
            role: [] for role in self._roles
        }
        self._next_lease_token = 1

    @classmethod
    def from_profile(
        cls,
        components: Mapping[str, Component],
        profile: Mapping[str, Any],
    ) -> "RoleRegistry":
        """Build a registry from a complete MSYS profile mapping."""

        roles = profile.get("roles", {})
        if not isinstance(roles, Mapping):
            raise TypeError("profile 'roles' must be a mapping")
        disabled = profile.get("disabled_roles", ())
        if isinstance(disabled, str) or not isinstance(disabled, Sequence):
            raise TypeError("profile 'disabled_roles' must be a sequence of role names")
        return cls(components, roles, [str(role) for role in disabled])

    def _build_roles(self) -> dict[str, _RoleState]:
        # Fold duplicate provides from the same component into a single entry.
        # The highest priority wins, while exclusivity is deliberately strict.
        declared: dict[str, dict[str, tuple[int, bool]]] = {}
        for provider_id, component in self._components.items():
            for provide in component.provides:
                if provide.kind != "role":
                    continue
                role = str(provide.name)
                if role in self._disabled_roles:
                    continue
                per_role = declared.setdefault(role, {})
                previous = per_role.get(provider_id)
                if previous is None:
                    per_role[provider_id] = (
                        int(provide.priority),
                        bool(provide.exclusive),
                    )
                else:
                    per_role[provider_id] = (
                        max(previous[0], int(provide.priority)),
                        previous[1] or bool(provide.exclusive),
                    )

        role_names = [
            str(role)
            for role in self._profile_roles
            if str(role) not in self._disabled_roles
        ]
        role_names.extend(sorted(set(declared).difference(role_names)))

        result: dict[str, _RoleState] = {}
        for role in role_names:
            metadata = declared.get(role, {})
            candidates: list[RoleCandidate] = []
            seen: set[str] = set()

            explicit_ids = _profile_candidate_ids(self._profile_roles.get(role))
            for rank, provider_id in enumerate(explicit_ids):
                if provider_id in seen or provider_id not in self._components:
                    continue
                seen.add(provider_id)
                provided = metadata.get(provider_id)
                candidates.append(
                    RoleCandidate(
                        role=role,
                        provider_id=provider_id,
                        priority=provided[0] if provided else 0,
                        # Roles are exclusive by default in the manifest model.
                        exclusive=provided[1] if provided else True,
                        profile_rank=rank,
                        declared=provided is not None,
                    )
                )

            remaining = [
                (provider_id, priority, exclusive)
                for provider_id, (priority, exclusive) in metadata.items()
                if provider_id not in seen
            ]
            remaining.sort(key=lambda item: (-item[1], item[0]))
            candidates.extend(
                RoleCandidate(
                    role=role,
                    provider_id=provider_id,
                    priority=priority,
                    exclusive=exclusive,
                )
                for provider_id, priority, exclusive in remaining
            )

            # Treat inconsistent declarations conservatively: if any candidate
            # says the role is exclusive, no two active leases may coexist.
            exclusive = any(candidate.exclusive for candidate in candidates)
            result[role] = _RoleState(tuple(candidates), exclusive)

        return result

    def _state(self, role: str) -> _RoleState:
        try:
            return self._roles[role]
        except KeyError as exc:
            raise UnknownRoleError(role) from exc

    def list_roles(self) -> tuple[str, ...]:
        """Return role names in deterministic profile/discovery order."""

        return tuple(self._roles)

    def disabled_roles(self) -> tuple[str, ...]:
        """Return profile-disabled roles in deterministic lexical order."""

        return tuple(sorted(self._disabled_roles))

    def list_candidates(self, role: str) -> tuple[RoleCandidate, ...]:
        """Return the immutable ordered candidate list for ``role``."""

        return self._state(role).candidates

    def candidate_ids(self, role: str) -> tuple[str, ...]:
        """Return only provider ids, preserving candidate order."""

        return tuple(c.provider_id for c in self.list_candidates(role))

    def is_candidate(self, role: str, provider_id: str) -> bool:
        """Return whether ``provider_id`` is a known candidate for ``role``."""

        return any(
            candidate.provider_id == provider_id
            for candidate in self.list_candidates(role)
        )

    def get_candidate(self, role: str, provider_id: str) -> RoleCandidate:
        """Return a candidate or raise :class:`UnknownCandidateError`."""

        for candidate in self.list_candidates(role):
            if candidate.provider_id == provider_id:
                return candidate
        raise UnknownCandidateError(
            f"{provider_id!r} is not a candidate for role {role!r}"
        )

    def preferred_provider(self, role: str) -> str | None:
        """Return the selected provider, or the catalog default when reset."""

        state = self._state(role)
        selected = self._preferred.get(role)
        if selected is not None:
            return selected
        if state.candidates:
            return state.candidates[0].provider_id
        return None

    def select_preferred(self, role: str, provider_id: str) -> str:
        """Select a preferred provider after validating role membership."""

        self.get_candidate(role, provider_id)
        self._preferred[role] = provider_id
        return provider_id

    def reset_preferred(self, role: str) -> str | None:
        """Clear an override and return the profile/catalog default provider."""

        self._state(role)
        self._preferred.pop(role, None)
        return self.preferred_provider(role)

    # Concise aliases are useful for IPC methods named ``select`` and ``reset``.
    select = select_preferred
    reset = reset_preferred

    def resolve_candidate(self, role: str) -> RoleCandidate:
        """Resolve the current preferred candidate or raise if none is present."""

        provider_id = self.preferred_provider(role)
        if provider_id is None:
            raise NoCandidateError(f"role {role!r} has no installed candidate")
        return self.get_candidate(role, provider_id)

    def resolve(self, role: str) -> str:
        """Return the provider id selected for a new activation attempt."""

        return self.resolve_candidate(role).provider_id

    def acquire(
        self,
        role: str,
        provider_id: str | None = None,
        *,
        holder: str | None = None,
    ) -> RoleLease:
        """Grant an active role lease.

        For an exclusive role, an existing active lease always causes
        :class:`LeaseConflictError`, including a second request for the same
        provider.  Callers therefore cannot accidentally lose track of two
        grants represented by one active-provider value.
        """

        state = self._state(role)
        candidate = (
            self.resolve_candidate(role)
            if provider_id is None
            else self.get_candidate(role, provider_id)
        )
        active_tokens = self._role_leases[role]
        if state.exclusive and active_tokens:
            active = self._leases[active_tokens[0]]
            raise LeaseConflictError(
                f"exclusive role {role!r} is leased to {active.provider_id!r}"
            )

        token = self._next_lease_token
        self._next_lease_token += 1
        lease = RoleLease(token, role, candidate.provider_id, holder)
        self._leases[token] = lease
        active_tokens.append(token)
        return lease

    # ``lease`` reads naturally at integration call sites.
    lease = acquire

    def release(self, lease: RoleLease | int) -> RoleLease:
        """Release an active lease and return the stored lease value."""

        token = lease.token if isinstance(lease, RoleLease) else int(lease)
        stored = self._leases.get(token)
        if stored is None or (isinstance(lease, RoleLease) and stored != lease):
            raise UnknownLeaseError(token)
        del self._leases[token]
        self._role_leases[stored.role].remove(token)
        return stored

    def release_provider(self, provider_id: str) -> tuple[RoleLease, ...]:
        """Release every lease held by a stopped/crashed component."""

        matching = tuple(
            lease
            for lease in self._leases.values()
            if lease.provider_id == provider_id
        )
        for lease in matching:
            self.release(lease)
        return matching

    def active_leases(self, role: str) -> tuple[RoleLease, ...]:
        """Return all active grants for a role in acquisition order."""

        self._state(role)
        return tuple(self._leases[token] for token in self._role_leases[role])

    def active_providers(self, role: str) -> tuple[str, ...]:
        """Return distinct active provider ids in acquisition order."""

        return tuple(
            dict.fromkeys(lease.provider_id for lease in self.active_leases(role))
        )

    def active_provider(self, role: str) -> str | None:
        """Return the primary active provider, if the role has an active lease."""

        providers = self.active_providers(role)
        return providers[0] if providers else None

    def info(self, role: str) -> RoleInfo:
        """Return a point-in-time role summary suitable for an IPC adapter."""

        state = self._state(role)
        leases = self.active_leases(role)
        providers = self.active_providers(role)
        return RoleInfo(
            name=role,
            exclusive=state.exclusive,
            candidates=state.candidates,
            preferred_provider=self.preferred_provider(role),
            active_provider=providers[0] if providers else None,
            active_providers=providers,
            lease_count=len(leases),
        )

    def list_role_info(self) -> tuple[RoleInfo, ...]:
        """Return summaries for all roles."""

        return tuple(self.info(role) for role in self.list_roles())


__all__ = [
    "LeaseConflictError",
    "NoCandidateError",
    "RoleCandidate",
    "RoleError",
    "RoleInfo",
    "RoleLease",
    "RoleRegistry",
    "UnknownCandidateError",
    "UnknownLeaseError",
    "UnknownRoleError",
]
