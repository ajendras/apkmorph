"""Patch plan generation and application using local LLM.

Uses enriched AnalysisReport (with Frida observations and string resources) to generate
minimal patches. Supports simulation, batch processing, and export to reusable scripts.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from rich.console import Console

from apkmorph.analyzer import APKAnalyzer
from apkmorph.builder import APKBuilder
from apkmorph.llm import LLMClient
from apkmorph.models import AnalysisReport, PatchPlan, Modification
from apkmorph.plugins import list_custom_patch_types
from apkmorph.smali import SmaliEditor

console = Console()


class PatchGenerator:
    """Generates, validates, simulates, applies and exports patches."""

    def __init__(self, model: str = "llama3.2") -> None:
        self.model = model
        self.llm = LLMClient(model=model)
        self.editor = SmaliEditor()
        self.builder = APKBuilder()

    def from_description(
        self, description: str, report: AnalysisReport, observe_runtime: bool = True
    ) -> PatchPlan:
        """Create a PatchPlan from a natural-language description.

        Automatically enriches the report with runtime observations if missing and requested.
        """
        console.print(f"[blue]Generating patch plan for: {description}[/blue]")

        if observe_runtime and len(report.runtime_observations) == 0:
            analyzer = APKAnalyzer(working_dir=report.decompiled_dir.parent)
            report = analyzer.observe_runtime(report)

        plan = self.llm.query(description, report)
        plan = self.validate(plan)
        return plan

    def validate(self, plan: PatchPlan) -> PatchPlan:
        """Validate and sanitize the PatchPlan returned by the LLM."""
        if not plan.id or not plan.id.startswith("plan_"):
            plan.id = f"plan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        for mod in plan.modifications:
            if not mod.edit_type:
                mod.edit_type = "smali"
            if mod.confidence < 0.0 or mod.confidence > 1.0:
                mod.confidence = 0.7
            if not mod.description:
                mod.description = f"Apply {mod.edit_type} edit to {mod.class_name}"

        if plan.confidence < 0.1 and plan.modifications:
            plan.confidence = 0.65
        return plan

    def simulate_apply(
        self, plan: PatchPlan, decompiled_dir: Path
    ) -> Dict[str, Any]:
        """Dry-run the plan without modifying files. Returns stats."""
        applied = []
        for mod in plan.modifications:
            applied.append(
                {
                    "edit_type": mod.edit_type,
                    "target": mod.class_name,
                    "method": mod.method,
                    "description": mod.description,
                }
            )
        return {
            "applied": applied,
            "total": len(plan.modifications),
            "success": True,
            "simulated": True,
        }

    def apply_plan(
        self,
        plan: PatchPlan,
        report: AnalysisReport,
        install: bool = False,
        launch: bool = True,
    ) -> Path:
        """Apply all modifications from the plan to the decompiled APK,
        rebuild and sign it, then optionally install and launch on a connected device.
        """
        console.print("[bold blue]Applying patch plan...[/bold blue]")

        decompiled = report.decompiled_dir
        # Apply each modification
        for mod in plan.modifications:
            success = self.editor.apply_modification(mod, decompiled)
            if not success:
                console.print(
                    f"[yellow]Warning: could not apply {mod.edit_type} to {mod.class_name}[/yellow]"
                )

        # Rebuild and sign
        try:
            output_apk = self.builder.rebuild_and_sign(str(decompiled))
            console.print(f"[green]✓ Rebuilt and signed: {output_apk.name}[/green]")
        except Exception as exc:
            console.print(f"[red]Build failed: {exc}[/red]")
            raise

        if install:
            console.print("[blue]Installing on connected Android device...[/blue]")
            try:
                self.builder.install_on_device(
                    str(output_apk),
                    report.package_name,
                    report.main_activity,
                    launch=launch,
                )
                action = "installed and launched" if launch and report.main_activity else "installed"
                console.print(f"[green]✓ Successfully {action} on device[/green]")
            except Exception as exc:
                console.print(f"[yellow]Device push failed (continuing): {exc}[/yellow]")

        return output_apk

    def batch(
        self,
        description: str,
        apk_paths: List[str],
        output_dir: Path,
        model: Optional[str] = None,
        observe_runtime: bool = True,
        install: bool = False,
        launch: bool = False,
    ) -> List[Dict[str, Any]]:
        """Apply the same description to multiple APKs.

        Returns list of result dicts.
        """
        if model is None:
            model = self.model
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        results: List[Dict[str, Any]] = []
        for i, apk_str in enumerate(apk_paths, 1):
            apk_path = Path(apk_str)
            console.print(f"[dim]Processing {i}/{len(apk_paths)}: {apk_path.name}[/dim]")
            try:
                analyzer = APKAnalyzer()
                report = analyzer.decompile(str(apk_path))
                if observe_runtime:
                    report = analyzer.observe_runtime(report)
                # Use fresh generator with possibly different model? but reuse
                generator = PatchGenerator(model=model) if model != self.model else self
                plan = generator.from_description(
                    description, report, observe_runtime=False  # already done
                )
                output_apk = generator.apply_plan(
                    plan, report, install=install, launch=launch
                )
                # Move to output_dir if not already
                if output_apk.parent != output_dir:
                    target = output_dir / output_apk.name
                    if target.exists():
                        target.unlink()
                    output_apk.rename(target)
                    output_apk = target
                results.append(
                    {
                        "apk": str(apk_path),
                        "success": True,
                        "output": str(output_apk),
                        "plan_id": plan.id,
                        "confidence": plan.confidence,
                    }
                )
                console.print(f"[green]✓ Patched {apk_path.name} → {output_apk.name}[/green]")
            except Exception as exc:
                console.print(f"[red]Failed {apk_path.name}: {exc}[/red]")
                results.append(
                    {"apk": str(apk_path), "success": False, "error": str(exc)}
                )
        return results

    def export(
        self,
        plan: PatchPlan,
        output: Optional[Path] = None,
        fmt: str = "python",
    ) -> Path:
        """Export plan as Python script or JSON."""
        if output is None:
            ext = "py" if fmt.lower() == "python" else "json"
            output = Path(f"{plan.id}.{ext}")

        output = Path(output)
        output.parent.mkdir(parents=True, exist_ok=True)

        if fmt.lower() == "json":
            output.write_text(
                plan.model_dump_json(indent=2), encoding="utf-8"
            )
        else:
            script_content = self._build_exported_script(plan)
            output.write_text(script_content, encoding="utf-8")
        return output.resolve()

    def _build_exported_script(self, plan: PatchPlan) -> str:
        """Generate a standalone Python script that applies the embedded plan."""
        plan_json = plan.model_dump_json(indent=2)
        return f'''#!/usr/bin/env python3
"""Exported APK Morph patch from plan {plan.id}.

Run with: python {plan.id}.py your_app.apk [--output-dir ./patched]

This script is self-contained and applies the exact modifications without LLM.
"""

import sys
from pathlib import Path
from apkmorph.patch_generator import PatchGenerator
from apkmorph.models import PatchPlan
from apkmorph.analyzer import APKAnalyzer


def main():
    if len(sys.argv) < 2:
        print("Usage: python {plan.id}.py <apk_path> [--output-dir DIR]")
        sys.exit(1)

    apk_path = sys.argv[1]
    output_dir = None
    if "--output-dir" in sys.argv:
        idx = sys.argv.index("--output-dir")
        if idx + 1 < len(sys.argv):
            output_dir = Path(sys.argv[idx + 1])

    analyzer = APKAnalyzer()
    report = analyzer.decompile(apk_path)

    # Load the embedded plan
    plan_data = {plan_json}
    plan = PatchPlan.model_validate(plan_data)

    print(plan.summary())
    generator = PatchGenerator()
    output = generator.apply_plan(plan, report, install=False, launch=False)
    if output_dir:
        target = output_dir / output.name
        output.rename(target)
        print("Output moved to:", target)
    else:
        print("Patched APK:", output)


if __name__ == "__main__":
    main()
'''
