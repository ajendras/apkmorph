"""Patch generation and safety validation.

Translates natural-language requests into a PatchPlan using the local LLM,
then validates each modification for safety and feasibility before application.
Now supports XML and resource (string) edits that affect resources.arsc and
automatically enriches reports with Frida runtime observations before
querying the LLM. Also populates original/patched snippets and hover
explanations used by the interactive diff viewer.
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
    to improve patch precision. Enriches Modification objects with
    snippets for the interactive side-by-side viewer.
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
        Frida runtime observations. The resulting plan is validated and
        enriched with real code snippets for the interactive diff viewer.
        """
        if observe and not report.runtime_observations:
            analyzer = APKAnalyzer()
            report = analyzer.observe_runtime(report)

        plan = self.llm.generate_patch(description, report)
        self.validate(plan)

        # Enrich each modification with real snippets from the decompiled tree.
        # Because models are frozen we create new Modification instances.
        enriched_mods: List[Modification] = []
        for mod in plan.modifications:
            enriched = mod.model_copy()
            if (
                enriched.edit_type == "smali"
                and enriched.file_path
                and report.decompiled_dir
            ):
                try:
                    fp = report.decompiled_dir / str(enriched.file_path)
                    if fp.exists():
                        original = self.smali.extract_method(fp, enriched.method)
                        enriched.original_snippet = original
                        enriched.patched_snippet = self.smali.simulate_patch(
                            original, enriched.diff
                        )
                        enriched.hover_explanation = (
                            f"{enriched.description}\n\n"
                            f"Confidence: {enriched.confidence:.2f}"
                        )
                except Exception:
                    enriched.original_snippet = "# Could not load original method body"
                    enriched.patched_snippet = "# Patch would be applied here"
                    enriched.hover_explanation = enriched.description
            enriched_mods.append(enriched)

        enriched_plan = plan.model_copy(update={"modifications": enriched_mods})
        return enriched_plan

    def validate(self, plan: PatchPlan) -> bool:
        """Perform safety checks on every modification.

        Ensures confidence is high enough and required fields are present
        for the edit type.
        """
        if not plan.modifications:
            raise ValueError("PatchPlan contains no modifications")

        for mod in plan.modifications:
            if mod.confidence < 0.5:
                raise ValueError(
                    f"Modification confidence too low ({mod.confidence}): {mod.description}"
                )
            if mod.edit_type == "smali" and not mod.class_name:
                raise ValueError("Smali modification must specify a class_name")
            if mod.edit_type == "resource" and not mod.resource_key:
                raise ValueError("Resource modification must specify resource_key")

        return True

    def simulate_apply(self, plan: PatchPlan, decompiled_dir: Path) -> Dict[str, Any]:
        """Simulate applying the patches without changing files, return what would happen.

        Returns a dict with the enriched modifications that the UI can display.
        """
        results: Dict[str, Any] = {"applied": [], "failed": []}
        for mod in plan.modifications:
            try:
                if mod.edit_type == "smali" and mod.original_snippet:
                    results["applied"].append(
                        {
                            "mod_id": mod.id,
                            "class_name": mod.class_name,
                            "method": mod.method,
                            "original": mod.original_snippet,
                            "patched": mod.patched_snippet or mod.diff,
                            "explanation": mod.hover_explanation or mod.description,
                            "confidence": mod.confidence,
                        }
                    )
                else:
                    results["applied"].append(
                        {
                            "mod_id": mod.id,
                            "description": mod.description,
                            "edit_type": mod.edit_type,
                        }
                    )
            except Exception as exc:
                results["failed"].append({"mod_id": mod.id, "error": str(exc)})
        return results
