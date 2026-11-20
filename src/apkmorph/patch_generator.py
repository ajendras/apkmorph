"""Patch plan generation and application using local LLM.

Uses enriched AnalysisReport (with Frida observations and string resources) to generate
minimal patches. Supports simulation, batch processing, and export to reusable scripts.
"""

import json
from pathlib import Path
from typing import Any, Dict, List, Optional

from rich.console import Console

from apkmorph.analyzer import APKAnalyzer
from apkmorph.builder import APKBuilder
from apkmorph.llm import LLMClient
from apkmorph.models import AnalysisReport, PatchPlan, Modification
from apkmorph.smali import SmaliEditor
from apkmorph.plugins import list_custom_patch_types

console = Console()


class PatchGenerator:
    """Generates, validates, simulates, applies and exports patches."""

    def __init__(self, model: str = "llama3.2") -> None:
        self.model = model
        self.llm = LLMClient(model=model)
        self.editor = SmaliEditor()
        self.builder = APKBuilder()

    def from_description(
        self, description: str, report: AnalysisReport
    ) -> PatchPlan:
        """Create a PatchPlan from a natural-language description.

        Automatically enriches the report with runtime observations if missing.
        """
        console.print(f"[blue]Generating patch plan for: {description}[/blue]")

        if not report.runtime_observations:
            analyzer = APKAnalyzer()
            report = analyzer.observe_runtime(report)

        plan = self.llm.query(description, report)
        plan.description = description
        plan = self.validate(plan, report)
        return plan

    def validate(self, plan: PatchPlan, report: AnalysisReport) -> PatchPlan:
        """Sanity-check modifications against the report and adjust confidence."""
        for mod in plan.modifications:
            if (
                mod.edit_type == "smali"
                and mod.class_name not in report.components
                and not any(mod.class_name in c for c in report.components)
            ):
                mod.confidence = max(0.1, mod.confidence * 0.6)
                mod.description += " (target not found in APK)"
            if mod.edit_type not in {"smali", "xml", "resource"} and mod.edit_type not in list_custom_patch_types():
                mod.confidence = max(0.1, mod.confidence * 0.4)

        if plan.modifications:
            plan.confidence = sum(m.confidence for m in plan.modifications) / len(
                plan.modifications
            )
        else:
            plan.confidence = 0.3
            plan.rationale += "\nWarning: no safe modifications identified."

        return plan

    def simulate_apply(
        self, plan: PatchPlan, decompiled_dir: Path
    ) -> Dict[str, Any]:
        """Dry-run simulation returning what would be changed (no filesystem writes)."""
        applied = []
        for mod in plan.modifications:
            applied.append(
                f"{mod.edit_type} on {mod.class_name}: {mod.description} (confidence {mod.confidence:.2f})"
            )
        return {
            "applied": applied,
            "success": True,
            "would_modify": len(applied),
            "rationale": plan.rationale,
        }

    def apply_plan(self, plan: PatchPlan, report: AnalysisReport) -> Path:
        """Apply every modification then rebuild+sign the APK."""
        console.print("[blue]Applying modifications...[/blue]")
        for mod in plan.modifications:
            success = self.editor.apply_modification(mod, report.decompiled_dir)
            if not success:
                console.print(f"[yellow]Skipped {mod.edit_type} edit for {mod.class_name}[/yellow]")

        output = self.builder.rebuild_and_sign(str(report.decompiled_dir))
        console.print(f"[green]Successfully built signed APK: {output}[/green]")
        return output

    def batch(
        self,
        description: str,
        apk_paths: List[str],
        output_dir: Path,
        model: str = "llama3.2",
        observe_runtime: bool = True,
    ) -> List[Dict[str, Any]]:
        """Process many APKs with the same natural-language request."""
        output_dir.mkdir(parents=True, exist_ok=True)
        results: List[Dict[str, Any]] = []
        for apk_str in apk_paths:
            try:
                analyzer = APKAnalyzer()
                report = analyzer.decompile(apk_str)
                if observe_runtime:
                    report = analyzer.observe_runtime(report)
                plan = self.from_description(description, report)
                patched_path = self.apply_plan(plan, report)
                final_path = output_dir / patched_path.name
                if patched_path != final_path:
                    if final_path.exists():
                        final_path.unlink()
                    patched_path.rename(final_path)
                results.append(
                    {
                        "apk": apk_str,
                        "success": True,
                        "plan_id": plan.id,
                        "output": str(final_path),
                        "modifications": len(plan.modifications),
                    }
                )
            except Exception as exc:
                results.append({"apk": apk_str, "success": False, "error": str(exc)})
        return results

    def export(
        self, plan: PatchPlan, output: Optional[Path] = None, fmt: str = "python"
    ) -> Path:
        """Export plan as JSON template or a self-contained Python script.

        The Python script embeds the exact PatchPlan so it runs offline without
        re-querying the LLM.
        """
        if output is None:
            ext = "json" if fmt.lower() == "json" else "py"
            output = Path(f"{plan.id}.{ext}")

        output.parent.mkdir(parents=True, exist_ok=True)

        if fmt.lower() == "json":
            output.write_text(plan.model_dump_json(indent=2), encoding="utf-8")
            return output

        # Python script with embedded plan (no LLM dependency)
        plan_json = plan.model_dump_json(indent=4)
        script = f'''"""
Self-contained APK Morph patch exported from plan {plan.id}.
Run: python {output.name} path/to/app.apk
"""
from pathlib import Path
import sys
from apkmorph.models import PatchPlan
from apkmorph.analyzer import APKAnalyzer
from apkmorph.smali import SmaliEditor
from apkmorph.builder import APKBuilder


PLAN_DATA = {plan_json}


def main(target: str | Path, output_dir: Path | None = None) -> Path:
    plan = PatchPlan.model_validate(PLAN_DATA)
    print("Applying exported plan:", plan.description)
    analyzer = APKAnalyzer()
    report = analyzer.decompile(str(target))
    report = analyzer.observe_runtime(report)
    editor = SmaliEditor()
    for mod in plan.modifications:
        editor.apply_modification(mod, report.decompiled_dir)
    builder = APKBuilder()
    if output_dir:
        builder.build_dir = Path(output_dir)
    signed = builder.rebuild_and_sign(str(report.decompiled_dir))
    print("Signed APK created:", signed)
    return signed


if __name__ == "__main__":
    apk = sys.argv[1] if len(sys.argv) > 1 else "app.apk"
    out_dir = Path(sys.argv[2]) if len(sys.argv) > 2 else None
    main(apk, out_dir)
'''
        output.write_text(script, encoding="utf-8")
        return output
