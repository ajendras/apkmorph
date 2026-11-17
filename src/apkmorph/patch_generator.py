"""Patch plan generation and validation.

Uses the LLMClient to turn natural language into a structured PatchPlan.
Supports validation, simulation of edits for Smali, XML and resource changes.
Integrates runtime observations from Frida to make targeted patches.
"""

from pathlib import Path
from typing import Any, Dict, List

from apkmorph.analyzer import APKAnalyzer
from apkmorph.llm import LLMClient
from apkmorph.models import AnalysisReport, PatchPlan


class PatchGenerator:
    """Generates, validates and simulates intelligent patches for APKs.

    The from_description method enriches the report with Frida observations,
    queries the LLM for a PatchPlan, and returns it.

    validate() ensures the plan is safe and references valid code.

    simulate_apply() shows what changes would be made without touching files.
    Used by tests and the UI for dry-runs covering Smali, XML and resource edits.
    """

    def __init__(self, model: str = "llama3.2") -> None:
        """Initialize with the Ollama model for patch generation.

        Args:
            model: Ollama model tag (must be available locally).
        """
        self.llm = LLMClient(model=model)
        self.model = model

    def from_description(
        self, description: str, report: AnalysisReport
    ) -> PatchPlan:
        """Generate a PatchPlan from a plain-English description.

        If the report has no runtime_observations, enriches it via
        observe_runtime (Frida or simulation fallback). Then uses
        LLMClient to produce a validated PatchPlan.

        Args:
            description: Natural language request (e.g. "disable all analytics")
            report: AnalysisReport produced by APKAnalyzer.decompile()

        Returns:
            PatchPlan containing modifications, rationale and confidence

        Raises:
            ValueError: If description is empty or too short
            RuntimeError: If the LLM fails to return a valid PatchPlan
        """
        if not description or len(description.strip()) < 5:
            raise ValueError("Description must be at least 5 characters")

        enriched_report = report
        if not report.runtime_observations:
            analyzer = APKAnalyzer(working_dir=report.decompiled_dir.parent)
            enriched_report = analyzer.observe_runtime(report, duration=5)

        plan = self.llm.generate_patch(description, enriched_report)
        if not plan.report_summary:
            plan = plan.model_copy(
                update={"report_summary": enriched_report.summary()}
            )
        return plan

    def validate(self, plan: PatchPlan) -> None:
        """Perform safety and semantic validation of a PatchPlan.

        Checks for presence of modifications, reasonable confidence scores,
        valid edit_type values, required fields for resource edits, and
        prevents path-traversal attempts.

        Args:
            plan: PatchPlan to validate

        Raises:
            ValueError: With specific message if any check fails
        """
        if not plan.modifications:
            raise ValueError("Patch plan has no modifications")

        if plan.confidence < 0.4:
            raise ValueError(f"Plan confidence too low: {plan.confidence:.2f}")

        seen_ids: set[str] = set()
        for mod in plan.modifications:
            if mod.id in seen_ids:
                raise ValueError(f"Duplicate modification id: {mod.id}")
            seen_ids.add(mod.id)

            if not mod.description:
                raise ValueError("Modification is missing a description")

            if mod.confidence < 0.2:
                raise ValueError(
                    f"Modification confidence too low: {mod.confidence:.2f}"
                )

            if mod.edit_type not in ("smali", "xml", "resource"):
                raise ValueError(f"Unknown edit_type: {mod.edit_type}")

            if mod.edit_type == "resource" and not mod.resource_key:
                raise ValueError(
                    "Resource modification must provide resource_key"
                )

            if mod.file_path and ".." in str(mod.file_path):
                raise ValueError("file_path must not contain path traversal")

    def simulate_apply(
        self, plan: PatchPlan, decompiled_dir: str | Path
    ) -> Dict[str, Any]:
        """Simulate applying the patches without modifying any files.

        Validates the plan first, then returns a structured summary of
        what would be changed. Supports Smali, XML and resource edits.
        Used by tests and dry-run flows.

        Args:
            plan: PatchPlan to simulate
            decompiled_dir: Root directory of the decompiled APK

        Returns:
            Dict with success status, list of applied modifications,
            list of would-be-modified files, total count, rationale

        Raises:
            FileNotFoundError: If decompiled_dir does not exist
            ValueError: If validation of the plan fails
        """
        decomp_path = Path(decompiled_dir)
        if not decomp_path.exists():
            raise FileNotFoundError(f"Decompiled directory not found: {decomp_path}")

        self.validate(plan)

        applied: List[Dict[str, Any]] = []
        modified_files: List[str] = []

        for mod in plan.modifications:
            mod_dict: Dict[str, Any] = {
                "id": mod.id,
                "edit_type": mod.edit_type,
                "class_name": mod.class_name,
                "method": mod.method or mod.resource_key or "",
                "description": mod.description,
                "confidence": mod.confidence,
                "snippet": mod.patched_snippet or mod.diff,
            }
            applied.append(mod_dict)

            if mod.file_path:
                fpath = str(mod.file_path)
                if fpath not in modified_files:
                    modified_files.append(fpath)

            if mod.edit_type == "resource" and mod.resource_key:
                if "res/values/strings.xml" not in modified_files:
                    modified_files.append("res/values/strings.xml")

            if mod.edit_type == "xml" and "AndroidManifest.xml" not in modified_files:
                modified_files.append("AndroidManifest.xml")

        return {
            "success": True,
            "applied": applied,
            "modified_files": modified_files,
            "total": len(applied),
            "rationale": plan.rationale,
            "confidence": plan.confidence,
        }
