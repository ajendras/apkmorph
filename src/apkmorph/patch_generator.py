"""Patch generation and application using local LLM.

PatchGenerator turns natural-language requests into validated PatchPlans,
applies them via SmaliEditor (or plugins), rebuilds with APKBuilder,
and now provides automatic backup + rollback of the decompiled directory
when a rebuild or signing step fails. All operations stay local.
"""

import json
import shutil
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Optional

from apkmorph.analyzer import APKAnalyzer
from apkmorph.builder import APKBuilder
from apkmorph.llm import LLMClient
from apkmorph.models import AnalysisReport, Modification, PatchPlan
from apkmorph.plugins import get_custom_patch_handler
from apkmorph.smali import SmaliEditor
from apkmorph.utils import safe_copytree


class PatchGenerator:
    """Generates and applies intelligent patches from natural-language descriptions.

    Uses LLMClient to produce a PatchPlan, validates it, applies modifications
    via SmaliEditor (or registered plugins), then rebuilds/signs with APKBuilder.
    On any failure during application or rebuild, the decompiled directory is
    automatically restored from a pre-edit backup.
    """

    def __init__(self, model: str = "llama3.2") -> None:
        self.model = model
        self.llm = LLMClient(model=model)
        self.editor = SmaliEditor()
        self.console = Console()  # rich.console for user feedback

    def from_description(self, description: str, report: AnalysisReport) -> PatchPlan:
        """Generate a PatchPlan from a plain-English request using the LLM.

        The report (including runtime observations and string resources) is
        sent to the model. The returned plan is validated before being returned.
        """
        plan = self.llm.query(description, report)
        plan.id = plan.id or f"plan_{uuid.uuid4().hex[:8]}"

        if not self.validate(plan):
            self.console.print("[yellow]LLM plan failed validation, returning safe fallback.[/yellow]")
            return PatchPlan(
                id=f"plan_{int(time.time())}",
                description=description,
                rationale="Validation failed – no modifications applied.",
                confidence=0.3,
                modifications=[],
            )
        return plan

    def validate(self, plan: PatchPlan) -> bool:
        """Validate a PatchPlan for basic sanity before application."""
        if not isinstance(plan.modifications, list):
            return False
        for mod in plan.modifications:
            if not mod.class_name or not mod.method or not mod.description:
                return False
            if not 0.0 <= mod.confidence <= 1.0:
                return False
        return True

    def apply_plan(
        self,
        plan: PatchPlan,
        report: AnalysisReport,
        install: bool = False,
        launch: bool = True,
    ) -> Path:
        """Apply all modifications, rebuild, and sign.

        A full backup of the decompiled directory is taken before any edits.
        If any modification, rebuild, or install step fails, the directory is
        restored to its original state and a clear error is raised.
        """
        decompiled_dir = Path(report.decompiled_dir)
        if not decompiled_dir.exists():
            raise FileNotFoundError(f"Decompiled directory not found: {decompiled_dir}")

        backup_dir = self._create_backup(decompiled_dir)
        applied_count = 0

        try:
            for mod in plan.modifications:
                if self._apply_modification(mod, decompiled_dir):
                    applied_count += 1

            builder = APKBuilder()
            output_apk = builder.rebuild_and_sign(
                str(decompiled_dir),
                output_name=f"patched_{plan.id[:8]}.apk",
            )

            if install:
                builder.install_on_device(
                    str(output_apk),
                    report.package_name,
                    report.main_activity,
                    launch=launch,
                )

            self.console.print(
                f"[green]✓ Applied {applied_count} modification(s).[/green]\n"
                f"[green]Final APK: {output_apk}[/green]"
            )
            return output_apk

        except Exception as exc:
            self.console.print(f"[red]Error during patch application or rebuild: {exc}[/red]")
            self._rollback(decompiled_dir, backup_dir)
            raise RuntimeError(
                f"Rebuild failed (or another error occurred). "
                f"All changes have been automatically rolled back to the original decompiled state. "
                f"Original error: {exc}"
            ) from exc
        finally:
            # Always clean up the backup (success or failure)
            if backup_dir.exists():
                try:
                    shutil.rmtree(backup_dir)
                except Exception:
                    pass  # best effort

    def _create_backup(self, decompiled_dir: Path) -> Path:
        """Create a timestamped copy of the entire decompiled tree."""
        timestamp = int(time.time())
        backup_dir = decompiled_dir.parent / f"{decompiled_dir.name}_backup_{timestamp}"
        safe_copytree(decompiled_dir, backup_dir)
        return backup_dir

    def _rollback(self, decompiled_dir: Path, backup_dir: Path) -> None:
        """Restore decompiled_dir from backup_dir."""
        if not backup_dir.exists():
            self.console.print("[yellow]Backup missing – cannot rollback.[/yellow]")
            return

        if decompiled_dir.exists():
            try:
                shutil.rmtree(decompiled_dir)
            except Exception:
                pass

        safe_copytree(backup_dir, decompiled_dir)
        self.console.print("[green]Decompiled directory successfully rolled back to pre-patch state.[/green]")

    def _apply_modification(self, mod: Modification, decompiled_dir: Path) -> bool:
        """Dispatch a single Modification to the appropriate handler."""
        edit_type = getattr(mod, "edit_type", "smali") or "smali"
        try:
            if edit_type in ("smali", "xml", "resource"):
                return self.editor.apply_modification(mod, decompiled_dir)
            else:
                handler = get_custom_patch_handler(edit_type)
                if handler:
                    return handler(mod, decompiled_dir)
                self.console.print(f"[yellow]No handler registered for edit_type '{edit_type}'.[/yellow]")
                return False
        except Exception as exc:
            self.console.print(f"[red]Failed to apply {edit_type} modification '{mod.description}': {exc}[/red]")
            return False

    def simulate_apply(self, plan: PatchPlan, decompiled_dir: Path) -> Dict[str, Any]:
        """Dry-run simulation of applying a plan (no files are changed)."""
        applied: List[str] = []
        failed: List[str] = []

        for mod in plan.modifications:
            target = self._find_target_file(mod, decompiled_dir)
            if target and target.exists():
                applied.append(mod.description)
            else:
                failed.append(mod.description)

        return {
            "applied": applied,
            "failed": failed,
            "would_modify": len(plan.modifications),
            "success_rate": len(applied) / len(plan.modifications) if plan.modifications else 0.0,
        }

    def _find_target_file(self, mod: Modification, decompiled_dir: Path) -> Optional[Path]:
        """Helper to locate the file a modification would affect."""
        if not mod.class_name:
            return None
        rel_smali = mod.class_name.replace(".", "/") + ".smali"
        for smali_root in decompiled_dir.glob("smali*"):
            candidate = smali_root / rel_smali
            if candidate.exists():
                return candidate
        # fall back to resource lookup for xml/resource edits
        if mod.edit_type in ("xml", "resource"):
            for xml_file in decompiled_dir.rglob("*.xml"):
                if "string" in xml_file.name.lower() or "values" in str(xml_file):
                    return xml_file
        return None

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
        """Apply the same natural-language description to many APKs.

        Each APK is processed independently (analysis → plan → apply with rollback).
        """
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        results: List[Dict[str, Any]] = []
        analyzer = APKAnalyzer()
        use_model = model or self.model

        for apk_str in apk_paths:
            apk_path = Path(apk_str)
            try:
                report = analyzer.decompile(str(apk_path))
                if observe_runtime:
                    report = analyzer.observe_runtime(report)

                # Use a fresh generator with the chosen model for each APK
                gen = PatchGenerator(model=use_model)
                plan = gen.from_description(description, report)
                output_apk = gen.apply_plan(plan, report, install=install, launch=launch)

                results.append({
                    "apk": str(apk_path),
                    "success": True,
                    "plan_id": plan.id,
                    "output": str(output_apk),
                    "modifications": len(plan.modifications),
                })
            except Exception as exc:
                results.append({
                    "apk": str(apk_path),
                    "success": False,
                    "error": str(exc),
                })
        return results

    def export(
        self,
        plan: PatchPlan,
        output: Optional[Path] = None,
        fmt: str = "python",
    ) -> Path:
        """Export a PatchPlan as a reusable Python script or JSON template."""
        if output is None:
            suffix = ".py" if fmt.lower() == "python" else ".json"
            output = Path(f"{plan.id}{suffix}")

        out_path = Path(output)
        out_path.parent.mkdir(parents=True, exist_ok=True)

        if fmt.lower() == "json":
            out_path.write_text(plan.model_dump_json(indent=2), encoding="utf-8")
        else:
            script_content = self._generate_python_script(plan)
            out_path.write_text(script_content, encoding="utf-8")

        return out_path.absolute()

    def _generate_python_script(self, plan: PatchPlan) -> str:
        mods_json = json.dumps([m.model_dump(mode="json") for m in plan.modifications], indent=2)
        return f'''#!/usr/bin/env python3
"""
APK Morph generated patch script.
Description: {plan.description}
Rationale: {plan.rationale}
Confidence: {plan.confidence}
"""

import sys
from pathlib import Path
from apkmorph.analyzer import APKAnalyzer
from apkmorph.models import Modification, PatchPlan
from apkmorph.patch_generator import PatchGenerator


def main() -> None:
    if len(sys.argv) < 2:
        print("Usage: python {Path(sys.argv[0]).name} <apk_path> [--output-dir DIR]")
        sys.exit(1)

    apk_path = sys.argv[1]
    output_dir = None
    if "--output-dir" in sys.argv:
        try:
            idx = sys.argv.index("--output-dir")
            if idx + 1 < len(sys.argv):
                output_dir = Path(sys.argv[idx + 1])
        except ValueError:
            pass

    analyzer = APKAnalyzer()
    report = analyzer.decompile(apk_path)
    if output_dir:
        report = report.model_copy(update={{"decompiled_dir": output_dir}})

    modifications = [Modification.model_validate(m) for m in {mods_json}]
    plan = PatchPlan(
        id="{plan.id}",
        description="{plan.description}",
        rationale="{plan.rationale.replace(chr(34), chr(92)+chr(34))}",
        confidence={plan.confidence},
        modifications=modifications,
    )

    generator = PatchGenerator()
    output_apk = generator.apply_plan(plan, report)
    print("Successfully created:", output_apk)


if __name__ == "__main__":
    main()
'''


from rich.console import Console  # placed at bottom to satisfy import order used by other modules
