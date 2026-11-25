"""Patch generation and application orchestration.

PatchGenerator uses LLMClient (which now receives custom plugin prompt
fragments) to turn a natural-language request into a PatchPlan. It can
validate plans, simulate application, apply them (dispatching to
registered plugin handlers when appropriate), export plans, and integrate
with the curated gallery.
"""

import json
import shutil
from pathlib import Path
from typing import Any, Dict

from apkmorph.builder import APKBuilder
from apkmorph.gallery import get_template_by_id
from apkmorph.llm import LLMClient
from apkmorph.models import AnalysisReport, Modification, PatchPlan
from apkmorph.plugins import get_custom_patch_handler
from apkmorph.smali import SmaliEditor
from apkmorph.utils import safe_copytree


class PatchGenerator:
    """Generates, validates and applies intelligent patches.

    The underlying LLMClient automatically incorporates LLM prompt
    fragments supplied by custom patch plugins, producing higher-quality
    domain-specific suggestions.
    """

    def __init__(self, model: str = "llama3.2", temperature: float = 0.15) -> None:
        self.llm = LLMClient(model=model, temperature=temperature)
        self.builder = APKBuilder()
        self.editor = SmaliEditor()

    def from_description(self, description: str, report: AnalysisReport) -> PatchPlan:
        """Generate a PatchPlan from a plain-English request.

        The LLM prompt includes all registered custom patch-type fragments.
        """
        if not description or not description.strip():
            raise ValueError("Description cannot be empty")

        plan = self.llm.generate_patch_plan(description, report)
        self.validate(plan)
        return plan

    def import_template(self, template_id: str, report: AnalysisReport) -> PatchPlan:
        """Load a curated gallery template and generate a tailored plan.

        Templates may contain pre-filled prompt hints that combine with
        any custom plugin fragments.
        """
        template = get_template_by_id(template_id)
        if not template:
            raise ValueError(f"Template {template_id} not found")

        # Combine template prompt with user-visible description
        combined = f"{template['prompt']} for this APK"
        plan = self.from_description(combined, report)
        plan.description = template.get("name", template_id)
        return plan

    def validate(self, plan: PatchPlan) -> None:
        """Basic sanity checks on a PatchPlan."""
        if not plan.modifications:
            return
        for mod in plan.modifications:
            if not mod.edit_type or not mod.target:
                raise ValueError("Every modification must have edit_type and target")
            if mod.confidence < 0.0 or mod.confidence > 1.0:
                mod.confidence = max(0.0, min(1.0, mod.confidence))

    def simulate_apply(self, plan: PatchPlan, decompiled_dir: Path) -> Dict[str, Any]:
        """Dry-run the plan and return a report of what would be changed."""
        self.validate(plan)
        simulated: Dict[str, Any] = {"applied": [], "skipped": []}
        for mod in plan.modifications:
            if get_custom_patch_handler(mod.edit_type) or mod.edit_type in ("smali", "xml", "resource", "manifest"):
                simulated["applied"].append(mod.target)
            else:
                simulated["skipped"].append(mod.target)
        return simulated

    def apply_plan(self, plan: PatchPlan, report: AnalysisReport) -> Dict[str, Any]:
        """Apply all modifications, dispatch custom plugins when registered,
        back up the tree first and roll back on any failure.
        """
        self.validate(plan)
        decompiled = Path(report.decompiled_dir)
        backup_dir = decompiled.parent / f"{decompiled.name}_backup"

        # Backup before any mutation
        if backup_dir.exists():
            shutil.rmtree(backup_dir)
        safe_copytree(decompiled, backup_dir)

        applied_count = 0
        try:
            for mod in plan.modifications:
                handler = get_custom_patch_handler(mod.edit_type)
                if handler:
                    success = handler(mod, decompiled)
                    if not success:
                        raise RuntimeError(f"Custom handler for {mod.edit_type} failed on {mod.target}")
                else:
                    self.editor.apply_modification(mod, decompiled)
                applied_count += 1

            # Rebuild & sign
            final_apk = self.builder.rebuild_and_sign(str(decompiled))
            return {
                "success": True,
                "applied": applied_count,
                "output_apk": str(final_apk),
                "rationale": plan.rationale,
            }
        except Exception as exc:
            # Rollback on any error
            if decompiled.exists():
                shutil.rmtree(decompiled)
            safe_copytree(backup_dir, decompiled)
            raise RuntimeError(f"Patch application failed, changes rolled back: {exc}") from exc
        finally:
            if backup_dir.exists():
                shutil.rmtree(backup_dir)

    def export(self, plan: PatchPlan, output_path: str, fmt: str = "python") -> Path:
        """Export a PatchPlan as a reusable Python script or JSON template."""
        out = Path(output_path)
        if fmt == "json":
            data = plan.model_dump(mode="json")
            out.write_text(json.dumps(data, indent=2), encoding="utf-8")
        else:
            # Self-contained Python script
            script = f'''#!/usr/bin/env python3
"""Generated patch for: {plan.description}"""

from apkmorph.analyzer import APKAnalyzer
from apkmorph.patch_generator import PatchGenerator
from pathlib import Path

def main(apk_path: str, output_dir: str | None = None):
    analyzer = APKAnalyzer()
    report = analyzer.decompile(apk_path)
    generator = PatchGenerator()
    # Re-apply the exact modifications (custom plugin handlers must be registered first)
    plan = PatchPlan(
        description="{plan.description}",
        modifications=[{",".join(repr(m.model_dump()) for m in plan.modifications)}],
        rationale="{plan.rationale}",
        confidence={plan.confidence},
        model_used="{plan.model_used}",
    )
    result = generator.apply_plan(plan, report)
    print("Patch applied successfully:", result)

if __name__ == "__main__":
    import sys
    main(sys.argv[1] if len(sys.argv) > 1 else "sample.apk")
'''
            out.write_text(script, encoding="utf-8")
        return out.resolve()


# Re-export models for convenience
__all__ = ["PatchGenerator", "PatchPlan", "Modification"]
