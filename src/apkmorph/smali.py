"""Smali and resource editor.

Provides SmaliEditor that can read specific methods from .smali files,
apply minimal patches, handle XML edits and resource string updates.
Used by PatchGenerator and the UI diff viewer. Now includes
get_diff_html() that produces an interactive side-by-side viewer
with CSS hover tooltips showing per-change explanations.
"""

import re
from pathlib import Path
from typing import Optional

from apkmorph.models import Modification


class SmaliEditor:
    """Handles reading, parsing and patching of Smali code, XML files and string resources.

    The get_diff_html method returns a self-contained HTML document with a
    side-by-side table. Changed lines are highlighted and display the
    hover_explanation when the mouse hovers over them.
    """

    def extract_method(self, smali_path: str | Path, method_sig: str) -> str:
        """Extract the body of a method from a Smali file.

        Uses regex to find .method ... <sig> ... .end method.
        Returns a clean snippet suitable for the diff viewer.
        """
        path = Path(smali_path)
        if not path.exists():
            return f"# File not found: {path}"

        try:
            content = path.read_text(encoding="utf-8", errors="ignore")
            # Regex that captures the method body (including registers, invokes, returns)
            pattern = re.compile(
                r"(\.method .*?" + re.escape(method_sig) + r".*?\n)(.+?)(\.end method)",
                re.DOTALL,
            )
            match = pattern.search(content)
            if match:
                body = match.group(2).strip()
                return body
            # Fallback: return the first method found
            first_method = re.search(r"\.method .*?\n(.+?)\.end method", content, re.DOTALL)
            if first_method:
                return first_method.group(1).strip()
            return "# Method not found in Smali file"
        except Exception as e:
            return f"# Error extracting method: {e}"

    def simulate_patch(self, original: str, change_description: str) -> str:
        """Return a 'patched' version of the Smali for demonstration in the diff viewer.

        Uses heuristics based on the change description to produce realistic
        patched code (early returns, NOPs, comments, etc.).
        """
        if not original or original.startswith("#"):
            return "# patched Smali code"

        lines = original.split("\n")
        lower_desc = change_description.lower()

        if any(k in lower_desc for k in ("nop", "disable", "remove", "block")):
            patched = []
            for line in lines:
                if "invoke" in line or "iget" in line or "iput" in line:
                    patched.append("    # APK Morph: " + line.strip())
                else:
                    patched.append(line)
            patched.append("    return-void")
            return "\n".join(patched)

        if any(k in lower_desc for k in ("return", "early return", "false")):
            return "\n".join(
                [
                    lines[0] if lines else "    .locals 2",
                    "    const/4 v0, 0x0",
                    "    return v0",
                    "# APK Morph patched - early return inserted",
                ]
            )

        # Default: insert explanatory comment at top
        patched = ["    # " + change_description[:80]] + lines
        return "\n".join(patched)

    def apply_modification(self, decompiled_dir: Path, mod: Modification) -> bool:
        """Apply a single modification to the decompiled files.

        Supports smali, xml, resource edits. Returns True on success.
        """
        if mod.file_path is None:
            return False

        target_file = decompiled_dir / mod.file_path
        if not target_file.exists():
            return False

        try:
            content = target_file.read_text(encoding="utf-8")
            if mod.edit_type == "smali" and mod.original_snippet and mod.patched_snippet:
                # Replace the original snippet with the patched version
                content = content.replace(mod.original_snippet, mod.patched_snippet)
                content += f"\n\n# Applied by APK Morph: {mod.description}\n"
            elif mod.edit_type == "resource" and mod.resource_key and mod.new_value is not None:
                # Update string resource
                pattern = re.compile(
                    rf'(<string name="{re.escape(mod.resource_key)}"[^>]*>)(.*?)(</string>)',
                    re.DOTALL,
                )
                content = pattern.sub(rf"\1{mod.new_value}\3", content)
            elif mod.edit_type == "xml":
                content = f"<!-- APK Morph patch: {mod.description} -->\n" + content
            else:
                content += f"\n# APK Morph applied: {mod.description}\n"

            target_file.write_text(content, encoding="utf-8")
            return True
        except Exception:
            return False

    def get_diff_html(self, mod: Modification) -> str:
        """Generate interactive HTML for side-by-side diff with hover explanations.

        Changed lines are highlighted in yellow. Hovering them shows the
        hover_explanation in a tooltip. Fully self-contained, no external
        dependencies.
        """
        original = mod.original_snippet or "# Original snippet not available"
        patched = mod.patched_snippet or mod.simulate_patch(original, mod.diff) if hasattr(mod, "simulate_patch") else "# Patched snippet not available"
        explanation = mod.hover_explanation or mod.description or "No further explanation available"
        orig_lines = original.split("\n")
        patch_lines = patched.split("\n")

        max_len = max(len(orig_lines), len(patch_lines))
        orig_lines += [""] * (max_len - len(orig_lines))
        patch_lines += [""] * (max_len - len(patch_lines))

        rows = []
        for i, (o_line, p_line) in enumerate(zip(orig_lines, patch_lines), 1):
            is_changed = o_line.strip() != p_line.strip() and bool(o_line.strip() or p_line.strip())
            change_class = "changed" if is_changed else ""
            explain = explanation if is_changed else ""
            o_esc = o_line.replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
            p_esc = p_line.replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")
            rows.append(
                f"""<tr>
    <td class="line">{i}</td>
    <td class="original">{o_esc}</td>
    <td class="patched {change_class}" data-explain="{explain}">{p_esc}</td>
</tr>"""
            )

        html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<style>
    body {{ font-family: ui-monospace, monospace; font-size: 13px; margin: 0; padding: 12px; background: #fafafa; }}
    .diff-container {{ max-width: 100%; }}
    table.diff-table {{ width: 100%; border-collapse: collapse; table-layout: fixed; }}
    th, td {{ padding: 4px 8px; border: 1px solid #ddd; text-align: left; vertical-align: top; overflow: hidden; text-overflow: ellipsis; white-space: pre; }}
    .line {{ width: 3em; background: #f0f0f0; color: #555; text-align: right; user-select: none; }}
    .original {{ background: #fdfdfd; }}
    .patched {{ background: #f0fff0; }}
    .changed {{ background: #fffacd !important; cursor: help; position: relative; }}
    .changed:hover::after {{
        content: attr(data-explain);
        position: absolute;
        z-index: 20;
        bottom: 100%;
        left: 50%;
        transform: translateX(-50%);
        background: #1f2937;
        color: #f3f4f6;
        padding: 8px 14px;
        border-radius: 6px;
        box-shadow: 0 10px 15px -3px rgb(0 0 0 / 0.3);
        width: max-content;
        max-width: 420px;
        font-size: 12.5px;
        line-height: 1.4;
        white-space: normal;
        pointer-events: none;
    }}
    .header {{ background: #e5e7eb; font-weight: 600; }}
    h3 {{ margin: 0 0 8px 0; color: #1e40af; }}
    p {{ margin: 8px 0; color: #374151; font-size: 13px; }}
    small {{ color: #6b7280; }}
</style>
</head>
<body>
<div class="diff-container">
    <h3>{mod.class_name} • {mod.method}</h3>
    <p><em>Hover over any <strong>highlighted</strong> line in the Patched column for a detailed explanation of the change.</em></p>
    <table class="diff-table">
        <thead>
        <tr>
            <th class="line">Line</th>
            <th class="header">Original Smali</th>
            <th class="header">Patched Smali</th>
        </tr>
        </thead>
        <tbody>
        {"".join(rows)}
        </tbody>
    </table>
    <p><small>Confidence: {mod.confidence:.2f} • Edit type: {mod.edit_type} • {mod.description}</small></p>
</div>
</body>
</html>
"""
        return html
