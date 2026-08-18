from __future__ import annotations

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
