"""Patch generation and application.

PatchGenerator orchestrates LLM calls, plan validation, simulation,
application via SmaliEditor (including custom plugins), and final rebuild.
"""

import json
from pathlib import Path
from typing import Any, Dict, List

from apkmorph.analyzer import APKAnalyzer
from apkmorph.builder import APKBuilder
from apkmorph.llm import LLMClient
from apkmorph.models import AnalysisReport, PatchPlan
from apkmorph.plugins import get_custom_patch_handler
from apkmorph.smali import SmaliEditor


class PatchGenerator:
    """Generates, validates and applies intelligent patches using a local LLM."""

    def __init__(self, model: str = "llama3.2") -> None:
        """Initialize with the Ollama model to use for patch generation."""
        self.model = model
        self.llm = LLMClient(model=model)
        self.editor = SmaliEditor()

    def from_description(
        self, description: str, report: AnalysisReport
    ) -> PatchPlan:
        """Translate a natural-language request into a validated PatchPlan.

        Automatically enriches the report with Frida runtime observations
        if none are present. The resulting plan may contain custom plugin
        edit_types if any have been registered.
        """
        if not description or len(description.strip()) < 5:
            raise ValueError("Description must be at least 5 characters")

        analyzer = APKAnalyzer()
        if not report.runtime_observations:
            report = analyzer.observe_runtime(report)

        plan = self.llm.generate_patch(description, report)
        self.validate(plan)
        return plan

    def validate(self, plan: PatchPlan) -> None:
        """Ensure the plan meets minimum quality and safety criteria."""
        if not plan.modifications:
            raise ValueError("PatchPlan contains no modifications")

        for mod in plan.modifications:
            if mod.confidence < 0.5:
                raise ValueError(
                    f"Modification confidence too low ({mod.confidence}): {mod.description}"
                )
            if not mod.description or not mod.diff:
                raise ValueError("Modification missing description or diff")
            # Custom types must have a registered handler or be one of the built-ins
            if mod.edit_type not in ("smali", "xml", "resource"):
                if not get_custom_patch_handler(mod.edit_type):
                    raise ValueError(
                        f"Unknown edit_type '{mod.edit_type}'. "
                        "Register a handler with register_custom_patch_type()"
                    )

        if plan.confidence < 0.6:
            raise ValueError(f"Overall plan confidence too low: {plan.confidence}")

    def simulate_apply(
        self, plan: PatchPlan, decompiled_dir: Path
    ) -> Dict[str, Any]:
        """Dry-run a plan and return a summary of what would be changed.

        No files are modified. Useful for UI preview and tests.
        """
        applied = []
        for mod in plan.modifications:
            handler = get_custom_patch_handler(mod.edit_type)
            applied.append(
                {
                    "id": mod.id,
                    "edit_type": mod.edit_type,
                    "target": str(mod.file_path or mod.class_name),
                    "description": mod.description,
                    "confidence": mod.confidence,
                    "uses_plugin": handler is not None,
                }
            )

        return {
            "plan_id": plan.id,
            "description": plan.description,
            "rationale": plan.rationale,
            "applied": applied,
            "would_modify": len(applied),
            "overall_confidence": plan.confidence,
        }

    def apply_plan(self, plan: PatchPlan, report: AnalysisReport) -> Path:
        """Apply every modification in the plan then rebuild and sign the APK.

        Custom edit_types are dispatched to their registered plugin handlers.
        Returns the final signed APK path.
        """
        decompiled_dir = Path(report.decompiled_dir).resolve()
        if not decompiled_dir.exists():
            raise FileNotFoundError(f"Decompiled directory not found: {decompiled_dir}")

        for mod in plan.modifications:
            success = self.editor.apply_modification(mod, decompiled_dir)
            if not success:
                # For custom plugins we already raised in validate(); here we just warn
                if mod.edit_type not in ("smali", "xml", "resource"):
                    handler = get_custom_patch_handler(mod.edit_type)
                    if handler:
                        # re-try in case of transient error
                        success = handler(mod, decompiled_dir)

        builder = APKBuilder()
        return builder.rebuild_and_sign(str(decompiled_dir))

    def batch(
        self,
        description: str,
        apk_paths: List[str],
        output_dir: Path,
        model: str | None = None,
        observe_runtime: bool = True,
    ) -> List[Dict[str, Any]]:
        """Apply the same natural-language description to many APKs.

        Each APK is processed independently (analysis, optional Frida observation,
        tailored plan, patch application, rebuild). Returns a list of result dicts.
        """
        out_dir = Path(output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

        results: List[Dict[str, Any]] = []
        use_model = model or self.model

        for apk_str in apk_paths:
            try:
                analyzer = APKAnalyzer()
                report = analyzer.decompile(apk_str)
                if observe_runtime:
                    report = analyzer.observe_runtime(report)

                # Use a fresh generator with the chosen model so LLMClient sees it
                gen = PatchGenerator(model=use_model)
                plan = gen.from_description(description, report)
                signed_apk = gen.apply_plan(plan, report)

                final_path = out_dir / signed_apk.name
                if signed_apk != final_path and signed_apk.exists():
                    signed_apk.rename(final_path)
                    signed_apk = final_path

                results.append(
                    {
                        "apk": apk_str,
                        "success": True,
                        "output_apk": str(signed_apk),
                        "plan_id": plan.id,
                        "confidence": plan.confidence,
                        "modifications": len(plan.modifications),
                    }
                )
            except Exception as exc:
                results.append(
                    {
                        "apk": apk_str,
                        "success": False,
                        "error": str(exc),
                    }
                )
        return results
