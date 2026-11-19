"""Smali, XML, resource and plugin-based editing.

SmaliEditor applies modifications from a PatchPlan to the decompiled sources.
Supports smali edits by patching method bodies, XML edits via string replace or ET,
resource string updates, and dispatches to registered custom patch plugins.
"""

import re
from pathlib import Path
from typing import Any

import xml.etree.ElementTree as ET

from apkmorph.models import Modification
from apkmorph.plugins import get_custom_patch_handler


class SmaliEditor:
    """Handles application of different edit types (including plugins)."""

    def apply_modification(self, mod: Modification, decompiled_dir: Path) -> bool:
        """Apply one modification based on its edit_type.

        For unknown types, looks up a registered plugin handler.
        Returns True if the edit succeeded.
        """
        if not mod.file_path:
            # Some resource edits operate on the whole tree
            if mod.edit_type == "resource":
                return self._apply_resource(mod, decompiled_dir)
            return False

        target_path = decompiled_dir / mod.file_path
        target_path.parent.mkdir(parents=True, exist_ok=True)

        edit_type = mod.edit_type

        try:
            if edit_type == "smali":
                return self._apply_smali(mod, target_path)
            elif edit_type == "xml":
                return self._apply_xml(mod, target_path)
            elif edit_type == "resource":
                return self._apply_resource(mod, decompiled_dir)
            else:
                handler = get_custom_patch_handler(edit_type)
                if handler:
                    return handler(mod, decompiled_dir)
                raise ValueError(f"Unsupported edit_type: {edit_type}")
        except Exception:
            # In production code this would log; here we treat any error as failure
            return False

    def _apply_smali(self, mod: Modification, file_path: Path) -> bool:
        """Replace a method body or insert a comment using the supplied snippets."""
        if not file_path.exists():
            return False

        content = file_path.read_text(encoding="utf-8")

        if mod.original_snippet and mod.patched_snippet:
            if mod.original_snippet in content:
                content = content.replace(
                    mod.original_snippet, mod.patched_snippet, 1
                )
                file_path.write_text(content, encoding="utf-8")
                return True

        # Fallback: insert a comment near the method
        if mod.method:
            lines = content.splitlines()
            for i, line in enumerate(lines):
                if f".method {mod.method}" in line or mod.method in line:
                    lines.insert(
                        i + 1,
                        f"    # APK Morph patch: {mod.description}",
                    )
                    if mod.patched_snippet:
                        lines.insert(i + 2, mod.patched_snippet)
                    break
            else:
                return False
            file_path.write_text("\n".join(lines), encoding="utf-8")
            return True
        return False

    def _apply_xml(self, mod: Modification, file_path: Path) -> bool:
        """Apply a simple string replacement to XML files (manifests, layouts)."""
        if not file_path.exists():
            return False
        content = file_path.read_text(encoding="utf-8")
        if mod.original_snippet and mod.patched_snippet:
            if mod.original_snippet in content:
                content = content.replace(
                    mod.original_snippet, mod.patched_snippet
                )
                file_path.write_text(content, encoding="utf-8")
                return True
        return False

    def _apply_resource(self, mod: Modification, decompiled_dir: Path) -> bool:
        """Update a string resource across values/*.xml files.

        Uses resource_key (or falls back to method) and new_value/params.
        """
        key = mod.resource_key or mod.params.get("resource_key") or mod.method
        new_val = (
            mod.new_value
            or mod.params.get("new_value")
            or (mod.patched_snippet or "").strip()
        )
        if not key or not new_val:
            return False

        values_dir = decompiled_dir / "res" / "values"
        if not values_dir.exists():
            return False

        for xml_file in values_dir.glob("*.xml"):
            try:
                tree = ET.parse(xml_file)
                root = tree.getroot()
                updated = False
                for elem in root.iter("string"):
                    if elem.get("name") == key:
                        elem.text = new_val
                        updated = True
                        break
                if updated:
                    # Write with declaration to keep Apktool happy
                    tree.write(
                        xml_file,
                        encoding="utf-8",
                        xml_declaration=True,
                    )
                    return True
            except (ET.ParseError, OSError):
                continue
        return False


def read_method(file_path: Path, method_name: str) -> str:
    """Utility to extract a Smali method body by name (used by analyzer/LLM)."""
    if not file_path or not file_path.exists():
        return ""
    content = file_path.read_text(encoding="utf-8", errors="ignore")
    # Match .method ... <method_name> ... .end method
    pattern = rf"(\.method .*?{re.escape(method_name)}.*?\n)(.+?)\n(\.end method)"
    match = re.search(pattern, content, re.DOTALL)
    if match:
        return match.group(0)
    return ""
