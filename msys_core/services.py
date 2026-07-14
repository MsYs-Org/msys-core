"""Language-neutral interface and capability discovery.

Roles model replaceable system jobs and therefore have preferences and leases.
Interfaces and capabilities are deliberately simpler:

* an interface is a callable contract implemented by one or more components;
* a capability is discoverable metadata and is never called directly;
* providers are ordered by manifest priority and then stable component id.

Keeping this catalog pure makes registry reloads atomic and lets the process
supervisor decide when an on-demand provider should be started.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass

from .manifest import Component


SERVICE_KINDS = frozenset({"interface", "capability"})


class ServiceError(Exception):
    """Base class for service catalog errors."""


class UnknownServiceError(KeyError, ServiceError):
    """Raised when an interface or capability is not installed."""


class UnknownServiceProviderError(ValueError, ServiceError):
    """Raised when a requested component does not provide a service."""


@dataclass(frozen=True, slots=True)
class ServiceProvider:
    kind: str
    name: str
    component: str
    priority: int
    exclusive: bool


class ServiceCatalog:
    """Immutable-by-replacement catalog built from component manifests."""

    def __init__(self, components: Mapping[str, Component]) -> None:
        self._components = dict(components)
        self._services = self._build()

    def _build(self) -> dict[tuple[str, str], tuple[ServiceProvider, ...]]:
        folded: dict[tuple[str, str], dict[str, ServiceProvider]] = {}
        for component_id, component in self._components.items():
            for provide in component.provides:
                if provide.kind not in SERVICE_KINDS:
                    continue
                key = (provide.kind, str(provide.name))
                per_service = folded.setdefault(key, {})
                candidate = ServiceProvider(
                    kind=provide.kind,
                    name=str(provide.name),
                    component=component_id,
                    priority=int(provide.priority),
                    exclusive=bool(provide.exclusive),
                )
                previous = per_service.get(component_id)
                if previous is None:
                    per_service[component_id] = candidate
                else:
                    per_service[component_id] = ServiceProvider(
                        kind=candidate.kind,
                        name=candidate.name,
                        component=component_id,
                        priority=max(previous.priority, candidate.priority),
                        exclusive=previous.exclusive or candidate.exclusive,
                    )

        result: dict[tuple[str, str], tuple[ServiceProvider, ...]] = {}
        for key, providers in folded.items():
            result[key] = tuple(
                sorted(
                    providers.values(),
                    key=lambda item: (-item.priority, item.component),
                )
            )
        return result

    @staticmethod
    def _checked_kind(kind: str) -> str:
        normalized = str(kind)
        if normalized not in SERVICE_KINDS:
            raise ValueError(f"unsupported service kind: {kind}")
        return normalized

    def names(self, kind: str) -> tuple[str, ...]:
        checked = self._checked_kind(kind)
        return tuple(
            name
            for service_kind, name in sorted(self._services)
            if service_kind == checked
        )

    def providers(self, kind: str, name: str) -> tuple[ServiceProvider, ...]:
        checked = self._checked_kind(kind)
        try:
            return self._services[(checked, str(name))]
        except KeyError as exc:
            raise UnknownServiceError(f"{checked}:{name}") from exc

    def provider_ids(self, kind: str, name: str) -> tuple[str, ...]:
        return tuple(item.component for item in self.providers(kind, name))

    def get_provider(
        self,
        kind: str,
        name: str,
        component: str | None = None,
    ) -> ServiceProvider:
        providers = self.providers(kind, name)
        if component is None:
            return providers[0]
        for provider in providers:
            if provider.component == component:
                return provider
        raise UnknownServiceProviderError(
            f"{component!r} does not provide {kind}:{name}"
        )

    def entries(self, kind: str | None = None) -> tuple[ServiceProvider, ...]:
        if kind is not None:
            checked = self._checked_kind(kind)
        else:
            checked = None
        entries: list[ServiceProvider] = []
        for (service_kind, _name), providers in sorted(self._services.items()):
            if checked is None or service_kind == checked:
                entries.extend(providers)
        return tuple(entries)


__all__ = [
    "SERVICE_KINDS",
    "ServiceCatalog",
    "ServiceError",
    "ServiceProvider",
    "UnknownServiceError",
    "UnknownServiceProviderError",
]
