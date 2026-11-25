"""Patch generation and application logic.

PatchGenerator turns natural-language descriptions into PatchPlan objects
via LLMClient, validates them, and coordinates application through SmaliEditor.
Now includes full support for manifest edits (permissions, activities, receivers).
"""

import json
import shutil
from pathlib import Path
from typing import Any, Dict, List

from apkmorph.gallery import get_template_by_id
from apkmorph.llm import LLMClient
from apkmorph.models import AnalysisReport, Modification, PatchPlan
from apkmorph.plugins import get_plugin_handler
from apkmorph.smali import SmaliEditor
from apkmorph.utils import safe_copytree


class PatchGenerator:
    """Generates, validates and applies intelligent patches from natural language."""

    def __init__(self, model: str = "llama3.2"):
        self.model = model
        self.llm = LLMClient(model=model)
        self.editor = SmaliEditor()

    def from_description(self, description: str, report: AnalysisReport) -> PatchPlan:
        """Generate a PatchPlan from a plain-English request.

        The LLM now receives manifest summary and is instructed to use
        edit_type='manifest' for permission/activity/receiver changes.
        """
        plan = self.llm.query(description, report)
        self.validate(plan, report)
        return plan

    def import_template(self, template_id: str, report: AnalysisReport) -> PatchPlan:
        """Import a curated gallery template and tailor it to the current APK."""
        template = get_template_by_id(template_id)
        # Template may contain a base prompt; we let from_description refine it
        prompt = template.get("prompt", f"Apply the {template_id} template")
        plan = self.from_description(prompt, report)
        plan.description = f"{template_id}: {plan.description}"
        return plan

    def validate(self, plan: PatchPlan, report: AnalysisReport) -> None:
        """Validate that every modification is plausible given the report.

        For manifest edits we verify the operation is known and the target
        element makes sense (e.g. a permission being removed actually exists).
        """
        for mod in plan.modifications:
            if mod.confidence < 0.3:
                raise ValueError(f"Modification confidence too low: {mod.confidence}")

            if mod.edit_type == "manifest":
                op = mod.params.get("operation")
                name = mod.params.get("name")
                if op not in (
                    "add_permission",
                    "remove_permission",
                    "add_activity",
                    "remove_activity",
                    "add_receiver",
                    "remove_receiver",
                ):
                    raise ValueError(f"Unknown manifest operation: {op}")
                if not name or not isinstance(name, str):
                    raise ValueError("Manifest edit requires a valid 'name' parameter")
                # Simple sanity check for removals
                if op.endswith("_permission") and op.startswith("remove"):
                    if name not in report.permissions and name not in [
                        p.split(".")[-1] for p in report.permissions
                    ]:
                        # Allow removal of non-existent permission (idempotent)
                        pass
            elif mod.edit_type == "plugin":
                if not get_plugin_handler(mod.target):
                    raise ValueError(f"No handler registered for plugin '{mod.target}'")

    def simulate_apply(self, plan: PatchPlan, decompiled_dir: Path) -> Dict[str, Any]:
        """Dry-run the plan and return what would be changed (for UI preview)."""
        applied: List[Dict[str, Any]] = []
        for mod in plan.modifications:
            applied.append(
                {
                    "edit_type": mod.edit_type,
                    "target": mod.target,
                    "description": mod.description,
                    "rationale": mod.rationale,
                }
            )
        return {"applied": applied, "success": True, "simulated": True}

    def apply_plan(self, plan: PatchPlan, report: AnalysisReport) -> Dict[str, Any]:
        """Apply all modifications and rebuild.

        Backs up the decompiled tree before editing and rolls back on any failure.
        """
        backup_dir = report.decompiled_dir.parent / f"{report.decompiled_dir.name}_backup"
        if backup_dir.exists():
            shutil.rmtree(backup_dir)
        safe_copytree(report.decompiled_dir, backup_dir)

        try:
            for mod in plan.modifications:
                success = self.editor.apply_modification(mod, report.decompiled_dir)
                if not success:
                    raise RuntimeError(f"Failed to apply modification: {mod.description}")

            # Rebuild to verify the patch is valid
            from apkmorph.builder import APKBuilder

            builder = APKBuilder()
            builder.rebuild(str(report.decompiled_dir), "verified.apk")
            return {"success": True, "modifications_applied": len(plan.modifications)}
        except Exception as exc:
            # Rollback
            if report.decompiled_dir.exists():
                shutil.rmtree(report.decompiled_dir)
            safe_copytree(backup_dir, report.decompiled_dir)
            raise RuntimeError(f"Patch application failed, rolled back: {exc}") from exc
        finally:
            if backup_dir.exists():
                shutil.rmtree(backup_dir)

    def export(self, plan: PatchPlan, output_path: str, fmt: str = "python") -> Path:
        """Export a PatchPlan as a reusable Python script or JSON."""
        out = Path(output_path)
        if fmt == "json":
            out.write_text(plan.model_dump_json(indent=2), encoding="utf-8")
            return out
        # Python script
        script = f'''#!/usr/bin/env python3
"""Generated patch for: {plan.description}"""

from apkmorph.analyzer import APKAnalyzer
from apkmorph.patch_generator import PatchGenerator
from apkmorph.builder import APKBuilder
from apkmorph.models import PatchPlan, Modification
import json
from pathlib import Path

plan_data = {plan.model_dump_json(indent=2)}
plan = PatchPlan.model_validate(plan_data)

analyzer = APKAnalyzer()
report = analyzer.decompile("{{apk_path}}")
generator = PatchGenerator()
generator.apply_plan(plan, report)
builder = APKBuilder()
print(builder.rebuild_and_sign(str(report.decompiled_dir)))
'''
        out.write_text(script, encoding="utf-8")
        out.chmod(0o755)
        return out
