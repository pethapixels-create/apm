"""Commands package for APM CLI."""

from typing import Any

__all__ = ["deps"]


def __getattr__(name: str) -> Any:
    # Lazy: importing any ``apm_cli.commands.<x>`` must not load the whole
    # ``deps`` command group (registry resolver, bundle packer) up front.
    if name == "deps":
        from .deps import deps

        return deps
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
