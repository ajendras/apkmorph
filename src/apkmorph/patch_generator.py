"""Patch generation and safety validation.

Translates natural-language requests into a PatchPlan using the local LLM,
then validates each modification for safety and feasibility before application.
Now supports XML and resource (string) edits that affect resources.arsc and
automatically enriches reports with Frida runtime observations before
querying the LLM.
"""

from pathlib import Path
from typing import Any, Dict, List

from apkmorph.llm import LLMClient
from apkmorph.models import AnalysisReport, Modification, PatchPlan
from apkmorph.smali import SmaliEditor
from apkmorph.analyzer import APKAnalyzer


class PatchGenerator:
    """Orchestrates LLM-driven patch plan creation and performs defensive
    validation before any filesystem changes are made. Now supports
    resource.arsc and XML intelligent editing and Frida runtime observation
    to improve patch precision.
    """

    def __init__(self, model: str = "llama3.2") -> None:
        """Initialize with chosen Ollama model and a SmaliEditor helper.

        Args:
            model: Ollama model identifier (must be available locally)
        """
        self.llm = LLMClient(model=model)
        self.smali = SmaliEditor()

    def from_description(
        self, description: str, report: AnalysisReport, observe: bool = True
    ) -> PatchPlan:
        """Generate a PatchPlan from a plain-English request and an AnalysisReport.

        If observe=True (default) the report is automatically enriched with
        Frida runtime observations (real or simulated). The enriched report
        is passed to the LLM which returns a structured PatchPlan. The plan
        is then lightly post-processed.

        Args:
            description: Natural language request
            report: AnalysisReport (may be mutated to a copy with observations)
            observe: Whether to run Frida observation step (default True)

        Returns:
            PatchPlan with modifications, rationale and confidence
        """
        if not description or len(description.strip()) < 5:
            raise ValueError("Description must be meaningful")

        if observe:
            # Use a dedicated analyzer with same working dir base to avoid
            # polluting the report's decompiled_dir
            analyzer = APKAnalyzer(working_dir=report.decompiled_dir.parent)
            report = analyzer.observe_runtime(report, duration=3)

        plan = self.llm.generate_patch(description, report)

        # Since models are frozen we use model_copy to enrich with summary
        plan = plan.model_copy(update={"report_summary": report.summary()})
        return plan

    def validate(self, plan: PatchPlan) -> bool:
        """Perform safety validation on the entire PatchPlan.

        Ensures confidence levels, required fields per edit_type, and that
        the SmaliEditor approves each modification. Raises descriptive
        ValueError for any issue.

        Args:
            plan: The PatchPlan to validate

        Returns:
            True if the plan is valid

        Raises:
            ValueError: If plan is invalid, low confidence or editor rejects
        """
        if len(plan.modifications) == 0:
            raise ValueError("PatchPlan has no modifications to apply")

        for mod in plan.modifications:
            if mod.confidence < 0.65:
                raise ValueError(
                    f"Modification {mod.id} confidence too low: {mod.confidence:.2f}"
                )
            if not self.smali.validate(mod):
                raise ValueError(f"Editor rejected modification {mod.id} ({mod.edit_type})")
            if mod.edit_type == "resource" and mod.new_value is None:
                raise ValueError(f"Resource mod {mod.id} missing new_value")

        return True

    def simulate_apply(
        self, plan: PatchPlan, decompiled_dir: str | Path
    ) -> Dict[str, Any]:
        """Dry-run the patch plan and return structured summary of changes that
        would be made. Does not modify any files. Used by tests and the UI
        preview feature.

        Args:
            plan: PatchPlan to simulate
            decompiled_dir: Path to decompiled sources (for context only)

        Returns:
            Dict with simulation results and list of applied changes
        """
        decomp_path = Path(decompiled_dir)
        simulated: List[Dict[str, Any]] = []

        for mod in plan.modifications:
            change: Dict[str, Any] = {
                "id": mod.id,
                "edit_type": mod.edit_type,
                "target": mod.resource_key or mod.class_name,
                "description": mod.description,
                "confidence": mod.confidence,
            }
            if mod.file_path:
                change["file"] = str(mod.file_path)
            simulated.append(change)

        return {
            "plan_id": plan.id,
            "description": plan.description,
            "rationale": plan.rationale,
            "applied": simulated,
            "success": True,
            "simulated": True,
            "decompiled_dir": str(decomp_path),
        }
