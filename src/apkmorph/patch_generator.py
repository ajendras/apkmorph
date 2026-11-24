"""Patch generation and application module.

Orchestrates LLM query for natural language to PatchPlan conversion, validation,
application of modifications (Smali, XML, resources, plugins), simulation, batch
processing, export, and now supports importing from the curated template gallery.
Uses rollback on failure via utils.safe_copytree backup.
"""

import json
import shutil
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import ValidationError

from apkmorph.analyzer import APKAnalyzer
from apkmorph.builder import APKBuilder
from apkmorph.gallery import get_template_by_id, list_templates
from apkmorph.llm import LLMClient
from apkmorph.models import AnalysisReport, Modification, PatchPlan
from apkmorph.plugins import get_registered_patch_types
from apkmorph.smali import SmaliEditor
from apkmorph.utils import safe_copytree


class PatchGenerator:
    """Generates, validates and applies intelligent patches using local LLM.

    Now includes support for curated gallery templates that can be imported with one click.
    """

    def __init__(self, model: str = "llama3.2") -> None:
        self.model = model
        self.llm = LLMClient(model=model)
        self.editor = SmaliEditor()
        self.builder = APKBuilder()
        self.temperature = 0.15

    def from_description(self, description: str, report: AnalysisReport) -> PatchPlan:
        """Generate a PatchPlan from a natural language description using the LLM.

        Enriches the prompt with report data, components, strings, runtime observations
        and registered plugin types.
        """
        prompt = self._construct_prompt(description, report)
        try:
            raw_response = self.llm.query(prompt, temperature=self.temperature)
            # LLM is instructed to return clean JSON
            plan_data = json.loads(raw_response.strip())
            if "modifications" not in plan_data:
                plan_data["modifications"] = []
            plan = PatchPlan(
                id=f"plan_{datetime.now():%Y%m%d_%H%M%S}",
                description=description,
                rationale=plan_data.get(
                    "rationale", "No additional rationale provided by the model."
                ),
                confidence=float(plan_data.get("confidence", 0.85)),
                modifications=[
                    Modification.model_validate(m)
                    for m in plan_data.get("modifications", [])
                ],
            )
            if not self.validate(plan):
                raise ValueError("Generated plan failed validation")
            return plan
        except (json.JSONDecodeError, ValidationError, KeyError, TypeError):
            # Minimal fallback that still produces a valid PatchPlan
            return PatchPlan(
                id=f"plan_{datetime.now():%Y%m%d_%H%M%S}",
                description=description,
                rationale="Fallback plan (LLM response could not be parsed). Please try a more specific request.",
                confidence=0.60,
                modifications=[],
            )

    def _construct_prompt(self, description: str, report: AnalysisReport) -> str:
        """Build a detailed prompt for the LLM including all relevant context."""
        plugin_types = get_registered_patch_types()
        prompt = f"""You are an expert Android reverse engineer.

Given the app analysis below, generate a precise PatchPlan for this request:

Request: {description}

Return ONLY valid JSON with these exact keys:
- rationale (string)
- confidence (float between 0.0 and 1.0)
- modifications (array of objects)

Each modification object must contain:
- class_name (string)
- method (string)
- edit_type (one of: smali, xml, resource, plugin)
- description (string)
- confidence (float)
- params (object)
- diff (string with unified diff style changes)

Available edit types besides the built-ins: {", ".join(plugin_types) if plugin_types else "none"}

AnalysisReport summary:
Package: {report.package_name}
Version: {report.version_name} (code {report.version_code})
Components ({len(report.components)}): {", ".join(report.components[:8])}
Strings sample: {report.strings[:12]}
Runtime observations: {report.runtime_observations[:6] if report.runtime_observations else "none"}
String resources: {list(report.string_resources.keys())[:10]}

Produce the smallest possible, high-confidence changes. Prefer resource edits when possible.
"""
        return prompt

    def validate(self, plan: PatchPlan) -> bool:
        """Validate a PatchPlan for correctness and safety."""
        if not plan.modifications:
            return False
        for mod in plan.modifications:
            if not mod.class_name or not mod.method or not mod.description:
                return False
            if mod.confidence < 0.4:
                return False
            if mod.edit_type not in ("smali", "xml", "resource", "plugin"):
                return False
        return True

    def apply_plan(
        self,
        plan: PatchPlan,
        report: AnalysisReport,
        install: bool = False,
        launch: bool = True,
    ) -> Path:
        """Apply the plan to the decompiled directory with backup and rollback on failure."""
        decompiled = Path(report.decompiled_dir)
        if not decompiled.exists():
            raise FileNotFoundError(f"Decompiled directory {decompiled} does not exist")

        backup_dir = decompiled.parent / f"{decompiled.name}_backup_{int(datetime.now().timestamp())}"
        safe_copytree(decompiled, backup_dir)

        try:
            for mod in plan.modifications:
                self.editor.apply_modification(mod, decompiled)
            output_apk = self.builder.rebuild_and_sign(str(decompiled))
            if install:
                self.builder.install_on_device(
                    str(output_apk),
                    report.package_name,
                    report.main_activity,
                    launch=launch,
                )
            return output_apk
        except Exception as exc:
            # Rollback on any failure
            if backup_dir.exists():
                # Remove any partial changes and restore backup
                shutil.rmtree(decompiled, ignore_errors=True)
                safe_copytree(backup_dir, decompiled)
                shutil.rmtree(backup_dir, ignore_errors=True)
            raise RuntimeError(f"Patch application failed (rolled back): {exc}") from exc

    def simulate_apply(self, plan: PatchPlan, decompiled_dir: Path) -> Dict[str, Any]:
        """Dry-run the plan without modifying files. Returns what would be applied."""
        applied = []
        for mod in plan.modifications:
            applied.append(
                {
                    "class": mod.class_name,
                    "method": mod.method,
                    "type": getattr(mod, "edit_type", "smali"),
                    "description": mod.description,
                }
            )
        return {"applied": applied, "success": True, "simulated": True}

    def batch(
        self,
        description: str,
        apk_paths: List[str],
        output_dir: Path,
        model: str = "llama3.2",
        observe_runtime: bool = True,
        install: bool = False,
        launch: bool = False,
    ) -> List[Dict[str, Any]]:
        """Apply the same natural-language description to multiple APKs."""
        output_dir.mkdir(parents=True, exist_ok=True)
        results: List[Dict[str, Any]] = []
        analyzer = APKAnalyzer()

        for apk_str in apk_paths:
            try:
                report = analyzer.decompile(apk_str)
                if observe_runtime:
                    report = analyzer.observe_runtime(report)
                plan = self.from_description(description, report)
                out_path = self.apply_plan(
                    plan, report, install=install, launch=launch
                )
                results.append(
                    {
                        "apk": Path(apk_str).name,
                        "success": True,
                        "plan_id": plan.id,
                        "output": str(out_path),
                        "confidence": plan.confidence,
                    }
                )
            except Exception as exc:
                results.append(
                    {"apk": Path(apk_str).name, "success": False, "error": str(exc)}
                )
        return results

    def export(
        self, plan: PatchPlan, output: Optional[Path] = None, fmt: str = "python"
    ) -> Path:
        """Export the plan as a reusable Python script or JSON template."""
        if output is None:
            suffix = ".py" if fmt.lower() == "python" else ".json"
            output = Path(f"{plan.id}{suffix}")
        output = Path(output).resolve()
        output.parent.mkdir(parents=True, exist_ok=True)

        if fmt.lower() == "json":
            output.write_text(plan.model_dump_json(indent=2), encoding="utf-8")
        else:
            # Self-contained script that can re-generate and apply the patch
            script_content = f'''#!/usr/bin/env python3
"""
Auto-generated patch script from APK Morph.
Template: {plan.description}
ID: {plan.id}
"""

import sys
from pathlib import Path
from apkmorph.analyzer import APKAnalyzer
from apkmorph.patch_generator import PatchGenerator

if len(sys.argv) < 2:
    print("Usage: python {output.name} <apk_path> [--output-dir DIR]")
    sys.exit(1)

apk_path = sys.argv[1]
output_dir = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("patched")

analyzer = APKAnalyzer()
report = analyzer.decompile(apk_path)
generator = PatchGenerator()

# Re-import the same curated template that produced this script
plan = generator.import_template("{plan.id.split('_')[-1] if '_' in plan.id else 'remove_ads'}", report)

print("Applying exported plan...")
final_apk = generator.apply_plan(plan, report)
print("Signed APK created:", final_apk)
'''
            output.write_text(script_content, encoding="utf-8")
            output.chmod(0o755)
        return output

    def get_gallery(self) -> List[Dict[str, Any]]:
        """Return the curated patch template gallery (used by CLI/UI)."""
        return list_templates()

    def import_template(self, template_id: str, report: AnalysisReport) -> PatchPlan:
        """One-click import from the curated gallery.

        Looks up the template, uses its optimized prompt to generate a
        tailored PatchPlan for the supplied APK report, and augments the
        rationale with gallery metadata.
        """
        template = get_template_by_id(template_id)
        if template is None:
            raise ValueError(
                f"Curated template '{template_id}' not found. "
                "Run 'apkmorph gallery' to see available templates."
            )

        plan = self.from_description(template["prompt"], report)
        plan.rationale = (
            f"[GALLERY] {template['name']}\n"
            f"Description: {template['description']}\n"
            f"Category: {template.get('category', 'general')}\n\n"
            f"{plan.rationale}"
        )
        # Boost confidence slightly when a curated template is used
        if plan.modifications:
            for mod in plan.modifications:
                mod.confidence = max(mod.confidence, template.get("confidence", 0.8))
        return plan
