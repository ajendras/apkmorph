"""Patch generation module.

Uses local LLM (via LLMClient) to translate natural-language requests into
a validated PatchPlan containing minimal, targeted modifications. Supports
smali, xml and resource edits. Provides dry-run simulation for tests and
CLI previews. Prioritizes edits based on Frida runtime_observations when
available. Fully consistent with the AnalysisReport and Modification models.
"""

from pathlib import Path
from typing import Any, Dict

from pydantic import ValidationError

from apkmorph.llm import LLMClient
from apkmorph.models import AnalysisReport, PatchPlan, Modification


class PatchGenerator:
    """Generates, validates and simulates APK patches from natural language.

    from_description() builds a rich prompt (including runtime observations),
    obtains a structured PatchPlan from the LLM, and returns it. validate()
    enforces safety rules (confidence thresholds, no destructive changes).
    simulate_apply() returns a detailed dry-run summary without touching
    any files; it exercises all three edit_type values (smali/xml/resource)
    for test coverage and user preview.
    """

    def __init__(self, model: str = "llama3.2") -> None:
        """Initialize generator with selected Ollama model.

        Args:
            model: Ollama model tag (must be available locally).
        """
        self.model = model
        self.llm = LLMClient(model=model)

    def from_description(
        self, description: str, report: AnalysisReport
    ) -> PatchPlan:
        """Translate a natural-language request into a PatchPlan.

        The supplied report should contain runtime_observations (via
        APKAnalyzer.observe_runtime()) for best results; the LLM prompt
        uses them to focus on live code paths.

        Args:
            description: Plain-English change request
            report: Pre-analyzed APK report

        Returns:
            PatchPlan with rationale, confidence and concrete modifications

        Raises:
            ValueError: If description is too short
            RuntimeError: If the LLM does not return valid JSON
        """
        if not description or len(description.strip()) < 5:
            raise ValueError("Description must be at least 5 characters long")

        plan = self.llm.generate_patch(description, report)

        # Ensure report summary is attached for traceability/auditing
        if not plan.report_summary:
            plan = plan.model_copy(update={"report_summary": report.summary()})

        return plan

    def validate(self, plan: PatchPlan) -> None:
        """Validate a PatchPlan for safety, completeness and plausibility.

        Checks overall and per-modification confidence, required fields per
        edit_type, and blocks obviously dangerous operations. Used by CLI
        before any rebuild.

        Args:
            plan: PatchPlan produced by from_description() or loaded from disk

        Raises:
            ValueError: If any validation rule fails
        """
        if not plan.modifications:
            raise ValueError("Patch plan contains no modifications")

        if plan.confidence < 0.4:
            raise ValueError(f"Overall plan confidence too low: {plan.confidence:.2f}")

        # Simple safeguard against destructive suggestions
        dangerous = {"delete", "remove main", "factory reset", "uninstall"}
        if any(word in plan.rationale.lower() for word in dangerous):
            raise ValueError("Plan suggests potentially dangerous changes")

        for mod in plan.modifications:
            if mod.confidence < 0.3:
                raise ValueError(
                    f"Modification {mod.id} confidence too low ({mod.confidence:.2f})"
                )

            if mod.edit_type == "smali":
                if not mod.class_name or not mod.method:
                    raise ValueError("Smali modification must specify class_name and method")
            elif mod.edit_type == "resource":
                if not mod.resource_key or mod.new_value is None:
                    raise ValueError("Resource modification must provide resource_key and new_value")
            elif mod.edit_type == "xml":
                if not mod.file_path:
                    raise ValueError("XML modification must specify file_path")

        # All checks passed
        return

    def simulate_apply(
        self, plan: PatchPlan, decompiled_dir: Path | str
    ) -> Dict[str, Any]:
        """Simulate applying the plan and return a structured summary.

        No files are modified. Exercises smali, xml and resource edit_types
        with before/after style data for tests and dry-run UI previews.

        Args:
            plan: Validated PatchPlan
            decompiled_dir: Root of decompiled sources (used only for path reporting)

        Returns:
            Dictionary with success status, list of applied changes and metadata
        """
        decomp_path = Path(decompiled_dir)
        applied: List[Dict[str, Any]] = []

        for mod in plan.modifications:
            change: Dict[str, Any] = {
                "id": mod.id,
                "edit_type": mod.edit_type,
                "description": mod.description,
                "confidence": mod.confidence,
                "hover_explanation": mod.hover_explanation or mod.description,
            }

            if mod.edit_type == "resource" and mod.resource_key and mod.new_value is not None:
                change.update({
                    "resource_key": mod.resource_key,
                    "old_value": "original placeholder text",
                    "new_value": mod.new_value,
                    "file": "res/values/strings.xml",
                })
            else:
                change.update({
                    "class_name": mod.class_name,
                    "method": mod.method,
                    "file_path": str(mod.file_path) if mod.file_path else None,
                    "diff": mod.diff,
                })

            applied.append(change)

        return {
            "plan_id": plan.id,
            "description": plan.description,
            "rationale": plan.rationale,
            "applied": applied,
            "total_changes": len(applied),
            "success": True,
            "dry_run": True,
            "decompiled_dir": str(decomp_path.absolute()),
        }
