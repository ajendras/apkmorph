"""Simple plugin API for custom patch types.

Users register handlers (via decorator) for new edit_type strings.
The handler is called by SmaliEditor.apply_modification with a
Modification instance and the decompiled directory Path.

Example usage (theme injector):

    from apkmorph.plugins import register_custom_patch_type
    from apkmorph.models import Modification
    from pathlib import Path

    @register_custom_patch_type("theme_injector")
    def inject_theme(mod: Modification, decompiled_dir: Path) -> bool:
        color = mod.params.get("primary_color", "#2196F3")
        styles = decompiled_dir / "res/values/styles.xml"
        if not styles.exists():
            return False
        content = styles.read_text(encoding="utf-8")
        content = content.replace(
            'colorPrimary">#000000',
            f'colorPrimary">{color}'
        )
        styles.write_text(content, encoding="utf-8")
        return True
"""

from typing import Any, Callable, Dict
from pathlib import Path

from apkmorph.models import Modification


_custom_patch_handlers: Dict[str, Callable[[Modification, Path], bool]] = {}


def register_custom_patch_type(name: str) -> Callable:
    """Decorator to register a function that implements a custom patch type.

    The decorated callable must have signature (Modification, Path) -> bool.
    It should edit files inside decompiled_dir and return True on success.
    """
    if not name or not isinstance(name, str):
        raise ValueError("Plugin name must be a non-empty string")

    def decorator(func: Callable[[Modification, Path], bool]) -> Callable:
        if name in _custom_patch_handlers:
            raise ValueError(f"Patch type '{name}' is already registered")
        _custom_patch_handlers[name] = func
        return func

    return decorator


def get_custom_patch_handler(name: str) -> Callable[[Modification, Path], bool] | None:
    """Return the registered handler for a custom patch type, or None."""
    return _custom_patch_handlers.get(name)


def list_custom_patch_types() -> list[str]:
    """Return a list of all currently registered custom patch type names."""
    return list(_custom_patch_handlers.keys())
