"""Small, dependency-free i18n reader for Core presentation metadata.

Core only needs to resolve manifest ``name_key`` and ``summary_key`` values.
Keeping this reader local avoids making the supervisor depend on the optional
Python SDK while retaining the same locale-first parent fallback rule.
"""

from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass
import json
from pathlib import Path
import re
import stat
from typing import Any, Mapping


CATALOG_SCHEMA = "msys.i18n.catalog.v1"
MAX_CATALOG_BYTES = 2 * 1024 * 1024
DEFAULT_CACHE_ENTRIES = 16

_PACKAGE_RELATIVE_PATH = re.compile(
    r"^[A-Za-z0-9][A-Za-z0-9._-]*(?:/[A-Za-z0-9][A-Za-z0-9._-]*)*$"
)
_CANONICAL_LOCALE = re.compile(
    r"^[a-z]{2,8}(?:-[A-Z][a-z]{3})?"
    r"(?:-(?:[A-Z]{2}|[0-9]{3}))?"
    r"(?:-(?:[a-z0-9]{5,8}|[0-9][a-z0-9]{3}))*$"
)


class PresentationCatalogError(ValueError):
    """A recoverable malformed or inaccessible presentation catalog."""


def _strict_object(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PresentationCatalogError(f"duplicate JSON member {key!r}")
        result[key] = value
    return result


def _normalized_locale(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    raw = value.strip()
    if not raw:
        return None
    without_modifier = raw.split("@", 1)[0]
    without_encoding = without_modifier.split(".", 1)[0]
    if without_encoding.upper() in {"C", "POSIX"}:
        return None
    parts = without_encoding.replace("_", "-").split("-")
    if not parts or not 2 <= len(parts[0]) <= 8 or not parts[0].isalpha():
        return None
    canonical = [parts[0].lower()]
    index = 1
    if index < len(parts) and len(parts[index]) == 4 and parts[index].isalpha():
        canonical.append(parts[index].title())
        index += 1
    if index < len(parts) and (
        (len(parts[index]) == 2 and parts[index].isalpha())
        or (len(parts[index]) == 3 and parts[index].isdigit())
    ):
        canonical.append(parts[index].upper())
        index += 1
    for part in parts[index:]:
        if not part.isascii() or not part.isalnum():
            return None
        if not (5 <= len(part) <= 8 or (len(part) == 4 and part[0].isdigit())):
            return None
        canonical.append(part.lower())
    normalized = "-".join(canonical)
    if _CANONICAL_LOCALE.fullmatch(normalized) is None:
        return None
    return normalized


def _locale_chain(requested: str | None, default_locale: str) -> tuple[str, ...]:
    normalized = _normalized_locale(requested) if requested is not None else None
    current = normalized or default_locale
    result: list[str] = []
    while current:
        if current not in result:
            result.append(current)
        current = current.rpartition("-")[0]
    if default_locale not in result:
        result.append(default_locale)
    return tuple(result)


@dataclass(frozen=True, slots=True)
class PresentationCatalog:
    default_locale: str
    messages: Mapping[str, Mapping[str, str]]

    @classmethod
    def load(cls, path: Path) -> "PresentationCatalog":
        try:
            metadata = path.stat()
            if not stat.S_ISREG(metadata.st_mode):
                raise PresentationCatalogError("catalog is not a regular file")
            if metadata.st_size > MAX_CATALOG_BYTES:
                raise PresentationCatalogError("catalog exceeds the 2 MiB limit")
            raw = path.read_bytes()
            if len(raw) > MAX_CATALOG_BYTES:
                raise PresentationCatalogError("catalog exceeds the 2 MiB limit")
            document = json.loads(
                raw.decode("utf-8"),
                object_pairs_hook=_strict_object,
                parse_constant=lambda value: (_ for _ in ()).throw(
                    PresentationCatalogError(f"non-JSON number {value}")
                ),
            )
        except PresentationCatalogError:
            raise
        except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as exc:
            raise PresentationCatalogError(str(exc)) from exc

        if not isinstance(document, dict):
            raise PresentationCatalogError("catalog root must be an object")
        if document.get("schema") != CATALOG_SCHEMA:
            raise PresentationCatalogError("unsupported catalog schema")
        default_locale = document.get("default_locale")
        messages = document.get("messages")
        if (
            not isinstance(default_locale, str)
            or _normalized_locale(default_locale) != default_locale
            or not isinstance(messages, dict)
            or not messages
            or len(messages) > 128
            or default_locale not in messages
        ):
            raise PresentationCatalogError("invalid locale catalog metadata")

        copied: dict[str, dict[str, str]] = {}
        for locale, values in messages.items():
            if (
                not isinstance(locale, str)
                or _normalized_locale(locale) != locale
                or not isinstance(values, dict)
                or len(values) > 20_000
            ):
                raise PresentationCatalogError("invalid locale message map")
            locale_messages: dict[str, str] = {}
            for key, value in values.items():
                if (
                    not isinstance(key, str)
                    or not key
                    or len(key) > 160
                    or not isinstance(value, str)
                    or len(value) > 16_384
                    or "\0" in value
                ):
                    raise PresentationCatalogError("invalid presentation message")
                locale_messages[key] = value
            copied[locale] = locale_messages
        return cls(default_locale=default_locale, messages=copied)

    def text(self, key: str, locale: str | None) -> str | None:
        for candidate in _locale_chain(locale, self.default_locale):
            value = self.messages.get(candidate, {}).get(key)
            if isinstance(value, str) and value:
                return value
        return None


class PresentationCatalogCache:
    """Bounded positive and negative cache for immutable package catalogs."""

    def __init__(self, limit: int = DEFAULT_CACHE_ENTRIES) -> None:
        self.limit = max(1, int(limit))
        self._entries: OrderedDict[
            tuple[str, str], PresentationCatalog | None
        ] = OrderedDict()

    def get(self, manifest_path: Path, relative_path: object) -> PresentationCatalog | None:
        if (
            not isinstance(relative_path, str)
            or not relative_path
            or len(relative_path) > 1024
            or "\0" in relative_path
            or _PACKAGE_RELATIVE_PATH.fullmatch(relative_path) is None
        ):
            return None

        # The manifest path and catalog declaration belong to an immutable
        # component snapshot.  This key needs no filesystem operation, so a
        # Shell polling list_apps never stats or reopens an already-seen file.
        key = (str(manifest_path.absolute()), relative_path)
        if key in self._entries:
            value = self._entries.pop(key)
            self._entries[key] = value
            return value

        catalog: PresentationCatalog | None = None
        try:
            package_root = manifest_path.parent.resolve(strict=True)
            candidate = package_root.joinpath(*relative_path.split("/"))
            resolved = candidate.resolve(strict=True)
            resolved.relative_to(package_root)
            catalog = PresentationCatalog.load(resolved)
        except (OSError, ValueError, PresentationCatalogError):
            catalog = None

        self._entries[key] = catalog
        while len(self._entries) > self.limit:
            self._entries.popitem(last=False)
        return catalog


__all__ = [
    "PresentationCatalog",
    "PresentationCatalogCache",
    "PresentationCatalogError",
]
