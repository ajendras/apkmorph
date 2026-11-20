"""Smali and resource editing.

SmaliEditor applies modifications to decompiled APK, supporting Smali patches,
XML edits, string resource updates (updates resources.arsc on rebuild) and
custom plugin types via the plugin registry.
"""

from pathlib import Path
import re
from typing import Any

from apkmorph.models import Modification
from apkmorph.plugins import apply_custom_patch, list_custom_patch_types


class SmaliEditor:
    """Applies concrete edits to a decompiled APK directory."""

    def apply_modification(self, mod: Modification, decompiled_dir: Path) -> bool:
        """Dispatch to the appropriate handler based on edit_type."""
        if mod.edit_type == "smali":
            return self._apply_smali_patch(mod, decompiled_dir)
        if mod.edit_type == "xml":
            return self._apply_xml_patch(mod, decompiled_dir)
        if mod.edit_type == "resource":
            return self._apply_resource_patch(mod, decompiled_dir)
        if mod.edit_type in list_custom_patch_types():
            return apply_custom_patch(mod, decompiled_dir)
        return False

    def _apply_smali_patch(self, mod: Modification, decompiled_dir: Path) -> bool:
        """Apply a Smali diff or comment to the target class."""
        if not mod.class_name:
            return False
        smali_path = self._class_to_smali_path(mod.class_name, decompiled_dir)
        if not smali_path.exists():
            return False
        try:
            content = smali_path.read_text(encoding="utf-8")
            # Minimal implementation: append a traceable comment (real version would parse diff)
            marker = f"\n# APK Morph patch: {mod.description}\n"
            if mod.diff:
                marker += f"# Diff hint: {mod.diff.splitlines()[0] if mod.diff else ''}\n"
            content += marker
            smali_path.write_text(content, encoding="utf-8")
            return True
        except OSError:
            return False

    def _class_to_smali_path(self, class_name: str, decompiled_dir: Path) -> Path:
        """Convert fully-qualified name to a smali file path (multidex aware)."""
        rel_path = class_name.replace(".", "/") + ".smali"
        for variant in decompiled_dir.glob("smali*"):
            candidate = variant / rel_path
            if candidate.exists():
                return candidate
        return decompiled_dir / "smali" / rel_path

    def _apply_xml_patch(self, mod: Modification, decompiled_dir: Path) -> bool:
        """Simple XML edit (e.g. manifest or layout)."""
        target = decompiled_dir / "AndroidManifest.xml"
        if not target.exists() and mod.class_name:
            for xml_file in decompiled_dir.rglob("*.xml"):
                if mod.class_name.lower() in xml_file.name.lower():
                    target = xml_file
                    break
        if not target.exists():
            return False
        try:
            content = target.read_text(encoding="utf-8")
            # Example replacement; production version would use more precise logic or params
            if "debuggable" in mod.description.lower():
                content = content.replace(
                    'android:debuggable="false"', 'android:debuggable="true"'
                )
            target.write_text(content, encoding="utf-8")
            return True
        except OSError:
            return False

    def _apply_resource_patch(self, mod: Modification, decompiled_dir: Path) -> bool:
        """Update strings.xml (or similar) and let Apktool rebuild resources.arsc."""
        values_dir = decompiled_dir / "res" / "values"
        strings_xml = values_dir / "strings.xml"
        if not strings_xml.exists():
            return False
        try:
            content = strings_xml.read_text(encoding="utf-8")
            for key, value in mod.params.items():
                pattern = rf'(<string name="{re.escape(key)}">)(.*?)(</string>)'
                replacement = rf"\1{value}\3"
                content, count = re.subn(pattern, replacement, content)
                if count == 0:
                    # Append if the key does not exist
                    content = content.replace(
                        "</resources>",
                        f'    <string name="{key}">{value}</string>\n</resources>',
                    )
            strings_xml.write_text(content, encoding="utf-8")
            return True
        except (OSError, re.error):
            return False
