"""Plugin system for custom patch types.

Simple decorator-based registry. The LLM prompt automatically includes
registered types; apply_modification dispatches to the handler.
"""

from typing import Any, Callable, Dict, List

from pathlib import Path

from apkmorph.models import Modification

CUSTOM_PATCH_HANDLERS: Dict[str, Callable[[Modification, Path], bool]] = {}


def register_custom_patch_type(name: str) -> Callable:
    """Decorator to register a handler for a custom edit_type."""

    def decorator(func: Callable[[Modification, Path], bool]) -> Callable:
        CUSTOM_PATCH_HANDLERS[name] = func
        return func

    return decorator


def list_custom_patch_types() -> List[str]:
    """Return names of all registered custom patch types."""
    return list(CUSTOM_PATCH_HANDLERS.keys())


def apply_custom_patch(mod: Modification, decompiled_dir: Path) -> bool:
    """Dispatch to the registered handler for a custom edit_type."""
    handler = CUSTOM_PATCH_HANDLERS.get(mod.edit_type)
    if not handler:
        return False
    try:
        return handler(mod, decompiled_dir)
    except Exception:
        return False
