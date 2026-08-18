from __future__ import annotations

import dataclasses
import shutil

from .base import BaseScanner

_REGISTRY: dict[str, type[BaseScanner]] = {}


def register_scanner(name: str):
    def decorator(cls: type[BaseScanner]) -> type[BaseScanner]:
        cls.name = name
        _REGISTRY[name] = cls
        return cls

    return decorator


def get_scanner(name: str) -> BaseScanner:
    return _REGISTRY[name]()


def list_scanners() -> dict[str, BaseScanner]:
    return {name: cls() for name, cls in _REGISTRY.items()}


@dataclasses.dataclass(frozen=True)
class ToolStatus:
    name: str
    binary_name: str
    path: str | None

    @property
    def available(self) -> bool:
        return self.path is not None


def tool_status() -> list[ToolStatus]:
    """Which registered tools are actually installed on this machine."""
    return [
        ToolStatus(
            name=name,
            binary_name=scanner.binary_name,
            path=shutil.which(scanner.binary_name),
        )
        for name, scanner in sorted(list_scanners().items())
    ]


def available_scanners() -> list[str]:
    return [status.name for status in tool_status() if status.available]
