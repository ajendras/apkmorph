"""Plugin system for custom patch types.

Simple decorator-based registration of handlers for arbitrary edit_type
values. The SmaliEditor (and PatchGenerator) dispatch to these handlers
when a Modification carries a matching edit_type.

Extended to allow each custom patch type to supply its own LLM prompt
fragment. These fragments are automatically collected and injected into
the system prompt used by LLMClient, giving the model richer,
domain-specific guidance so it selects the correct edit_type and
supplies appropriate parameters.
"""

from collections.abc import Callable
from pathlib import Path
from typing import Dict

from apkmorph.models import Modification

# Global registries (populated by the decorator)
_custom_patch_handlers: Dict[str, Callable[[Modification, Path], bool]] = {}
_custom_prompt_fragments: Dict[str, str] = {}


def register_custom_patch_type(
    edit_type: str, prompt_fragment: str | None = None
) -> Callable:
    """Decorator to register a custom patch handler and optional LLM guidance.

    The prompt_fragment is a concise natural-language instruction that
    tells the LLM exactly when this edit_type is appropriate and what
    parameters it should emit. If omitted a generic fallback is used.

    Registered fragments are automatically included by LLMClient when
    building the patch-generation prompt.

    Args:
        edit_type: Unique string identifier (e.g. "theme_injector").
        prompt_fragment: Optional domain-specific guidance for the LLM.

    Returns:
        The original function (decorator pattern).

    Example:
        @register_custom_patch_type(
            "theme_injector",
            prompt_fragment=(
                "Use when the user asks for color changes, dark mode or "
                "full theme overlays. Provide params: primary_color, "
                "accent_color, night_mode (bool). Produces coherent "
                "updates across styles.xml, drawables and manifest."
            )
        )
        def inject_theme(mod: Modification, decompiled_dir: Path) -> bool:
            ...
    """
    def decorator(func: Callable[[Modification, Path], bool]) -> Callable:
        _custom_patch_handlers[edit_type] = func
        if prompt_fragment and prompt_fragment.strip():
            _custom_prompt_fragments[edit_type] = prompt_fragment.strip()
        else:
            _custom_prompt_fragments[edit_type] = (
                f"Use edit_type='{edit_type}' for specialized {edit_type} "
                "modifications. Include relevant parameters inside the "
                "params dictionary."
            )
        return func

    return decorator


def get_custom_patch_handler(edit_type: str) -> Callable[[Modification, Path], bool] | None:
    """Return the registered handler for an edit_type or None if unregistered."""
    return _custom_patch_handlers.get(edit_type)


def get_custom_prompt_fragments() -> str:
    """Return a formatted block describing all registered custom patch types.

    This string is injected directly into the LLM system prompt by
    LLMClient.generate_patch_plan so the model receives up-to-date,
    domain-specific guidance.
    """
    if not _custom_prompt_fragments:
        return "No custom patch types have been registered."

    lines: list[str] = ["Registered custom patch types (use these edit_type values when they fit the request):"]
    for et in sorted(_custom_prompt_fragments.keys()):
        fragment = _custom_prompt_fragments[et]
        lines.append(f"  - {et}: {fragment}")
    return "\n".join(lines)


def list_custom_patch_types() -> list[str]:
    """Return a list of all registered custom edit_type identifiers."""
    return sorted(_custom_patch_handlers.keys())
