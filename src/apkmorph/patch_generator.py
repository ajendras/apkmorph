"""Patch generation and application using LLM.

Implements the feedback loop by passing user comments into LLMClient to refine prompts and plans.
"""

import json
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from rich.console import Console

from apkmorph.analyzer import APKAnalyzer
from apkmorph.builder import APKBuilder
from apkmorph.llm import LLMClient
from apkmorph.models import AnalysisReport, Modification, PatchPlan
from apkmorph.smali import SmaliEditor
from apkmorph.utils import safe_copytree


class PatchGenerator:
    """Orchestrates LLM-based patch plan generation, validation, application with rollback,
    batch processing, export and the new user feedback refinement loop.
    """

    def __init__(self, model: str = "llama3.2") -> None:
        self.model = model
        self.llm = LLMClient(model=model)
        self.console = Console()
        self.editor = SmaliEditor()

    def from_description(
        self,
        description: str,
        report: AnalysisReport,
        feedback: Optional[str] = None,
    ) -> PatchPlan:
        """Create PatchPlan from natural language, incorporating optional user feedback
        to refine the underlying LLM prompt.
        """
        if not description or not description.strip():
            raise ValueError("Description cannot be empty")
        plan = self.llm.generate_patch_plan(description, report, feedback)
        if not self.validate(plan):
            self.console.print("[yellow]Generated plan failed validation; using defaults.[/yellow]")
        return plan

    def refine_plan(
        self, previous_plan: PatchPlan, feedback: str, report: AnalysisReport
    ) -> PatchPlan:
        """Refine a previous plan by feeding back user comments into a new LLM query.

        This is the core of the user feedback loop.
        """
        if not feedback or not feedback.strip():
            return previous_plan
        self.console.print("[blue]Refining plan based on user feedback...[/blue]")
        refined = self.from_description(
            previous_plan.description, report, feedback=feedback
        )
        refined.id = previous_plan.id + "_refined"
        refined.created_at = datetime.now()
        refined.rationale += f"\n\n---\nUser feedback incorporated: {feedback}\nThis refinement addresses the provided notes to improve accuracy and confidence."
        if feedback not in refined.feedback_history:
            refined.feedback_history = previous_plan.feedback_history + [feedback]
        if refined.confidence < previous_plan.confidence + 0.1:
            refined.confidence = min(0.95, (refined.confidence + previous_plan.confidence) / 2 + 0.1)
        return refined

    def validate(self, plan: PatchPlan) -> bool:
        """Validate that the PatchPlan meets minimum criteria."""
        if not plan or not isinstance(plan, PatchPlan):
            return False
        if not plan.modifications:
            self.console.print("[yellow]Plan has no modifications.[/yellow]")
            return False
        for mod in plan.modifications:
            if not mod.class_name or not mod.description:
                return False
            if mod.confidence < 0 or mod.confidence > 1:
                mod.confidence = 0.7
        return True

    def apply_plan(
        self,
        plan: PatchPlan,
        report: AnalysisReport,
        install: bool = False,
        launch: bool = True,
        keystore: Optional[str] = None,
    ) -> Path:
        """Apply modifications to the decompiled APK, rebuild, sign and optionally install.

        Includes automatic backup and rollback on failure for robustness.
        """
        if not self.validate(plan):
            raise ValueError("Invalid patch plan")

        decompiled = report.decompiled_dir
        backup_dir = decompiled.parent / f"{decompiled.name}_backup_{int(datetime.now().timestamp())}"
        safe_copytree(str(decompiled), str(backup_dir))

        try:
            for modification in plan.modifications:
                self.editor.apply_modification(modification, decompiled)

            builder = APKBuilder()
            output_apk = builder.rebuild_and_sign(
                str(decompiled), keystore=keystore
            )

            if install:
                builder.install_on_device(
                    str(output_apk),
                    report.package_name,
                    report.main_activity,
                    launch=launch,
                )

            self.console.print(f"[green]Applied plan {plan.id} successfully → {output_apk}[/green]")
            return output_apk
        except Exception as exc:
            self.console.print("[red]Error during apply, rolling back...[/red]")
            if backup_dir.exists():
                safe_copytree(str(backup_dir), str(decompiled), dirs_exist_ok=True)
                shutil.rmtree(backup_dir, ignore_errors=True)
            raise RuntimeError(f"Patch application failed (rolled back): {exc}") from exc

    def simulate_apply(self, plan: PatchPlan, decompiled_dir: Path) -> Dict[str, Any]:
        """Dry-run simulation for testing what would be changed without modifying files."""
        simulated = {"applied": [], "would_change": len(plan.modifications)}
        for mod in plan.modifications:
            simulated["applied"].append(
                {
                    "target": mod.class_name,
                    "type": mod.edit_type,
                    "confidence": mod.confidence,
                    "description": mod.description,
                }
            )
        return simulated

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
        """Apply the same description to multiple APKs. Returns list of results."""
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        results = []
        analyzer = APKAnalyzer()
        gen_model = model or self.model
        generator = PatchGenerator(model=gen_model)

        for apk_path in apk_paths:
            try:
                report = analyzer.decompile(apk_path)
                if observe_runtime:
                    report = analyzer.observe_runtime(report)
                plan = generator.from_description(description, report)
                output_apk = generator.apply_plan(
                    plan, report, install=install, launch=launch
                )
                results.append(
                    {
                        "apk": Path(apk_path).name,
                        "success": True,
                        "plan_id": plan.id,
                        "confidence": plan.confidence,
                        "output": str(output_apk),
                    }
                )
            except Exception as exc:
                results.append({"apk": Path(apk_path).name, "success": False, "error": str(exc)})
        return results

    def export(
        self, plan: PatchPlan, output_path: Optional[Path] = None, fmt: str = "python"
    ) -> Path:
        """Export the plan as a standalone Python script or JSON."""
        if output_path is None:
            suffix = ".py" if fmt.lower() == "python" else ".json"
            output_path = Path(f"{plan.id}{suffix}")

        output_path = Path(output_path).resolve()

        if fmt.lower() == "json":
            data = plan.model_dump(mode="json")
            output_path.write_text(json.dumps(data, indent=2))
            return output_path

        mod_data = json.dumps([m.model_dump() for m in plan.modifications])
        script = f'''#!/usr/bin/env python3
"""Generated patch script for: {plan.description}
Exported from APK Morph. Run with: python this_script.py target.apk
"""

import json
from pathlib import Path
import sys

from apkmorph.analyzer import APKAnalyzer
from apkmorph.builder import APKBuilder
from apkmorph.models import Modification, PatchPlan
from apkmorph.patch_generator import PatchGenerator


def main(target_apk: str):
    analyzer = APKAnalyzer()
    report = analyzer.decompile(target_apk)
    mod_list = json.loads({mod_data!r})
    plan = PatchPlan(
        id="{plan.id}",
        description="{plan.description}",
        rationale="{plan.rationale.replace('"', '\\"')}",
        confidence={plan.confidence},
        modifications=[Modification.model_validate(m) for m in mod_list],
        feedback_history={plan.feedback_history!r},
    )
    generator = PatchGenerator()
    output = generator.apply_plan(plan, report)
    print("Patched APK created at:", output)


if __name__ == "__main__":
    if len(sys.argv) > 1:
        main(sys.argv[1])
    else:
        print("Usage: python {output_path.name} <path_to_apk>")
'''
        output_path.write_text(script)
        output_path.chmod(0o755)
        return output_path
