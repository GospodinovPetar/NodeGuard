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


def is_registered(name: str) -> bool:
    """Name-only check, so callers validating a tool name don't have to
    instantiate every scanner to do it."""
    return name in _REGISTRY


@dataclasses.dataclass(frozen=True)
class ToolStatus:
    name: str
    binary_name: str
    path: str | None
    available: bool


def tool_status() -> list[ToolStatus]:
    """Which registered tools are actually usable on this machine.

    Availability is the scanner's own answer rather than a PATH probe: a
    scanner that wraps no binary decides it differently (http-headers runs
    in-process and checks that `requests` imports), and its binary_name only
    exists to give the catalog a path to show. Asking the scanner is what
    keeps the catalog and dashboard agreeing with the trigger, which has
    always gone through is_available().
    """
    return [
        ToolStatus(
            name=name,
            binary_name=scanner.binary_name,
            path=shutil.which(scanner.binary_name),
            available=scanner.is_available(),
        )
        for name, scanner in sorted(list_scanners().items())
    ]
