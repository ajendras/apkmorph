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
            console.print("[dim]No runtime observations found, enriching with simulation...[/dim]")
            analyzer = APKAnalyzer()
            report = analyzer.observe_runtime(report, duration=5)

        plan = self.llm.query(description, report)
        plan = self.validate(plan)
        return plan

    def validate(self, plan: PatchPlan) -> PatchPlan:
        """Validate LLM-generated plan and normalize any invalid fields."""
        custom_types = list_custom_patch_types()
        valid_edit_types = {"smali", "xml", "resource", *custom_types}

        for mod in plan.modifications:
            if mod.edit_type not in valid_edit_types:
                console.print(
                    f"[yellow]Unknown edit_type '{mod.edit_type}', defaulting to smali[/yellow]"
                )
                mod.edit_type = "smali"
            if not mod.class_name.strip():
                mod.class_name = "com.example.Unknown"
            if mod.confidence < 0.0 or mod.confidence > 1.0:
                mod.confidence = 0.65

        if not plan.rationale.strip():
            plan.rationale = (
                "The LLM suggested targeted modifications based on the app's "
                "components, strings and runtime behavior."
            )
        return plan

    def simulate_apply(
        self, plan: PatchPlan, decompiled_dir: Path
    ) -> Dict[str, Any]:
        """Perform a dry-run simulation of applying the patch plan.

        Returns a report of what would be changed without touching the filesystem.
        Used by tests and for UI preview.
        """
        applied: List[Dict[str, Any]] = []
        for mod in plan.modifications:
            applied.append(
                {
                    "edit_type": mod.edit_type,
                    "target": f"{mod.class_name}::{mod.method}" if mod.method else mod.class_name,
                    "description": mod.description,
                    "confidence": mod.confidence,
                    "params": mod.params,
                }
            )

        return {
            "plan_id": plan.id,
            "description": plan.description,
            "applied": applied,
            "success": len(applied) > 0,
            "simulated": True,
            "rationale": plan.rationale,
            "overall_confidence": plan.confidence,
        }

    def apply_plan(
        self,
        plan: PatchPlan,
        report: AnalysisReport,
        output_dir: Optional[Path] = None,
    ) -> Path:
        """Apply the modifications from the plan to the decompiled sources,
        then rebuild, align and sign the APK.
        """
        console.print(f"[blue]Applying {len(plan.modifications)} modification(s) from plan {plan.id}[/blue]")

        decompiled_dir = report.decompiled_dir
        for mod in plan.modifications:
            try:
                success = self.editor.apply_modification(mod, decompiled_dir)
                status = "applied" if success else "failed"
                console.print(f"  [{status}] {mod.edit_type} on {mod.class_name}: {mod.description}")
            except Exception as exc:  # pylint: disable=broad-except
                console.print(f"[red]Error applying mod {mod.description}: {exc}[/red]")

        if output_dir is not None:
            self.builder.build_dir = output_dir

        final_apk = self.builder.rebuild_and_sign(str(decompiled_dir))
        console.print(f"[green]Build completed successfully → {final_apk}[/green]")
        return final_apk

    def batch(
        self,
        description: str,
        apk_paths: List[str],
        output_dir: Path,
        model: str = "llama3.2",
        observe_runtime: bool = True,
    ) -> List[Dict[str, Any]]:
        """Process multiple APKs with the same natural language description.

        Each gets independent analysis, (optional) runtime observation, plan generation,
        patch application and rebuild.
        """
        output_dir.mkdir(parents=True, exist_ok=True)
        results: List[Dict[str, Any]] = []
        analyzer = APKAnalyzer(working_dir=output_dir / "decomp")
        original_llm = self.llm
        if model != self.model:
            self.llm = LLMClient(model=model)
            self.model = model

        for apk_str in apk_paths:
            apk_path = Path(apk_str)
            try:
                console.print(f"[dim]Processing {apk_path.name}...[/dim]")
                report = analyzer.decompile(str(apk_path))
                if observe_runtime:
                    report = analyzer.observe_runtime(report, duration=6)
                plan = self.from_description(description, report)
                final_apk = self.apply_plan(
                    plan, report, output_dir=output_dir / "outputs"
                )
                results.append(
                    {
                        "apk": apk_path.name,
                        "success": True,
                        "plan_id": plan.id,
                        "output_apk": str(final_apk),
                        "mod_count": len(plan.modifications),
                        "confidence": plan.confidence,
                    }
                )
            except Exception as exc:  # pylint: disable=broad-except
                console.print(f"[red]Failed to patch {apk_path.name}: {exc}[/red]")
                results.append(
                    {
                        "apk": apk_path.name,
                        "success": False,
                        "error": str(exc),
                    }
                )

        self.llm = original_llm
        self.model = getattr(original_llm, "model", self.model)
        console.print(
            f"[green]Batch processing finished. "
            f"{sum(1 for r in results if r.get('success'))} successful.[/green]"
        )
        return results

    def export(
        self, plan: PatchPlan, output: Optional[Path] = None, fmt: str = "python"
    ) -> Path:
        """Export a PatchPlan as reusable Python script or JSON template."""
        if output is None:
            suffix = ".py" if fmt.lower() == "python" else ".json"
            output = Path.cwd() / f"{plan.id}{suffix}"

        output = Path(output)
        output.parent.mkdir(parents=True, exist_ok=True)

        if fmt.lower() == "json":
            output.write_text(plan.model_dump_json(indent=2), encoding="utf-8")
            console.print(f"[green]Exported JSON template to {output}[/green]")
            return output

        # Python script with embedded plan (no LLM call needed on reuse)
        plan_json = plan.model_dump_json(indent=2)
        # Escape braces so f-string does not interpret JSON as expressions
        plan_json_escaped = plan_json.replace("{", "{{").replace("}", "}}")

        script = f'''#!/usr/bin/env python3
"""
Standalone patch exported by APK Morph.

Description: {plan.description}
Rationale: {plan.rationale[:80].replace('"', "'")}...

Run with: python {output.name} your_app.apk [--output-dir ./patched]
"""

import sys
from pathlib import Path

from apkmorph.analyzer import APKAnalyzer
from apkmorph.patch_generator import PatchGenerator
from apkmorph.models import PatchPlan


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python {output.name} <path-to-apk> [--output-dir <dir>]")
        sys.exit(1)

    apk_path = sys.argv[1]
    out_dir = Path("patched")
    if "--output-dir" in sys.argv:
        try:
            idx = sys.argv.index("--output-dir")
            out_dir = Path(sys.argv[idx + 1])
        except (IndexError, ValueError):
            pass

    analyzer = APKAnalyzer()
    report = analyzer.decompile(apk_path)

    plan_json = '''{plan_json_escaped}'''
    plan = PatchPlan.model_validate_json(plan_json)

    generator = PatchGenerator()
    final = generator.apply_plan(plan, report, output_dir=out_dir)
    print(f"✅ Patch applied. Signed APK saved to: {{final}}")


if __name__ == "__main__":
    main()
'''
        output.write_text(script, encoding="utf-8")
        try:
            output.chmod(0o755)
        except OSError:
            pass  # e.g. on Windows

        console.print(f"[green]Exported self-contained Python patch to {output}[/green]")
        return output
