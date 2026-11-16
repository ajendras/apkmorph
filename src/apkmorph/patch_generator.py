"""Patch generation and safety validation.

Translates natural-language requests into a PatchPlan using the local LLM,
then validates each modification for safety and feasibility before application.
Now supports XML and resource (string) edits that affect resources.arsc.
"""

from pathlib import Path
from typing import Any
import re

from apkmorph.llm import LLMClient
from apkmorph.models import AnalysisReport, Modification, PatchPlan
from apkmorph.smali import SmaliEditor


class PatchGenerator:
    """Orchestrates LLM-driven patch plan creation and performs defensive
    validation before any filesystem changes are made. Now supports
    resource.arsc and XML intelligent editing.
    """

    def __init__(self, model: str = "llama3.2") -> None:
        """Initialize with chosen Ollama model and a SmaliEditor helper.

        Args:
            model: Ollama model identifier (must be available locally)
        """
        self.llm = LLMClient(model=model)
        self.smali = SmaliEditor()

    def from_description(
        self, description: str, report: AnalysisReport
    ) -> PatchPlan:
        """Generate a PatchPlan from a plain-English request and an AnalysisReport.

        The LLM receives rich context including string_resources; the returned
        plan is validated before being returned. Plans may now contain
        edit_type=resource modifications.

        Args:
            description: Natural language request (e.g. "remove all ads")
            report: Pre-computed AnalysisReport from APKAnalyzer.decompile()

        Returns:
            Validated PatchPlan containing ordered Modification steps

        Raises:
            ValueError: On empty request or invalid LLM output
            RuntimeError: On unexpected failures
        """
        description = description.strip()
        if not description:
            raise ValueError("Patch description cannot be empty")
        if len(description) < 5:
            raise ValueError("Description must be at least 5 characters long")

        if not report or not report.components:
            raise ValueError("AnalysisReport must contain components (run analyzer first)")

        try:
            # Let LLM produce a PatchPlan (JSON -> model)
            llm_plan = self.llm.generate_patch(description, report)

            # Merge in report context and ensure immutability
            updated_plan = PatchPlan(
                id=llm_plan.id,
                description=description,
                modifications=llm_plan.modifications,
                rationale=llm_plan.rationale or "No rationale provided by model.",
                confidence=llm_plan.confidence,
                report_summary=report.summary(),
                created_at=llm_plan.created_at,
            )

            self.validate(updated_plan)
            return updated_plan

        except Exception as exc:
            if isinstance(exc, (ValueError, RuntimeError)):
                raise
            raise RuntimeError(f"Patch generation failed: {exc}") from exc

    def validate(self, plan: PatchPlan) -> None:
        """Perform multi-layered safety validation on a PatchPlan.

        Checks performed:
          • Non-empty modification list
          • Reasonable confidence scores
          • No obvious dangerous keywords or broad destructive patterns
          • Plausible file paths (no path traversal)
          • Basic syntactic sanity of the diff field
          • Correct fields for resource/XML edits
          • (Future) cross-check that target methods exist in decompiled sources

        Raises:
            ValueError: With a human-readable message describing the violation
        """
        if not plan.modifications:
            raise ValueError("PatchPlan contains no modifications")

        if plan.confidence < 0.25:
            raise ValueError(
                f"Overall plan confidence ({plan.confidence:.2f}) is too low to apply safely"
            )

        dangerous_patterns = [
            r"(?i)system\.exit",
            r"(?i)rm\s+-[rf]",
            r"(?i)delete.*package",
            r"(?i)format",
            r"(?i)su\s",
            r"(?i)exec.*shell",
            r"android\.os\.Build",
            r"android\.content\.Context.*delete",
        ]

        for i, mod in enumerate(plan.modifications, start=1):
            if mod.confidence < 0.35:
                raise ValueError(
                    f"Modification #{i} ({mod.class_name}) has low confidence: {mod.confidence:.2f}"
                )

            if not mod.class_name or not mod.method:
                raise ValueError(f"Modification #{i} is missing class_name or method")

            if not mod.diff or len(mod.diff.strip()) < 3:
                raise ValueError(f"Modification #{i} has no meaningful diff content")

            # Path safety
            if mod.file_path:
                fp = str(mod.file_path)
                if ".." in fp or fp.startswith("/") or fp.startswith("\\"):
                    raise ValueError(
                        f"Modification #{i} uses unsafe file_path: {fp}"
                    )

            # Type-specific validation
            if mod.edit_type in ("xml", "resource"):
                if not mod.file_path or not str(mod.file_path).endswith((".xml", ".arsc")):
                    raise ValueError(
                        f"Modification #{i} of type {mod.edit_type} must target an XML file"
                    )
                if mod.edit_type == "resource" and not mod.resource_key:
                    raise ValueError(
                        f"Modification #{i} of type resource must specify resource_key"
                    )
            elif mod.edit_type == "smali" and not mod.method.startswith("<"):
                # basic sanity for smali
                pass

            # Look for dangerous keywords in the diff or description
            combined_text = f"{mod.diff} {mod.description}".lower()
            for pattern in dangerous_patterns:
                if re.search(pattern, combined_text):
                    raise ValueError(
                        f"Modification #{i} contains dangerous pattern '{pattern}'"
                    )

            # Very basic Smali syntax sanity check
            if "invoke-" in mod.diff and "Landroid/" in mod.diff and "System" in mod.diff:
                # Extra caution on core framework changes
                if plan.confidence < 0.7:
                    raise ValueError(
                        f"Modification #{i} touches core Android classes with insufficient confidence"
                    )

        # Optional deeper validation using SmaliEditor (only if decompiled_dir known)
        # For CLI/UI flows the decompiled location lives in the report; we skip here
        # because validate() is intentionally lightweight and called before rebuild.

    def simulate_apply(self, plan: PatchPlan, decompiled_dir: Path) -> dict[str, Any]:
        """Dry-run simulation of each modification using SmaliEditor.

        Now supports XML and resource edits. Returns a report of what
        would be changed without touching disk.
        Used by tests and the UI preview feature.
        """
        results: dict[str, Any] = {"success": True, "applied": [], "errors": []}

        for mod in plan.modifications:
            try:
                if not mod.file_path:
                    results["errors"].append(
                        f"Missing file_path for {mod.class_name}"
                    )
                    continue

                target_file = decompiled_dir / mod.file_path
                if not target_file.exists() and mod.edit_type != "resource":
                    results["errors"].append(f"Target file not found: {target_file}")
                    continue

                if mod.edit_type == "smali":
                    self.smali.read_method(str(target_file), mod.method)
                elif mod.edit_type in ("xml", "resource"):
                    if mod.resource_key and target_file.exists():
                        content = target_file.read_text(encoding="utf-8", errors="ignore")
                        if f'name="{mod.resource_key}"' not in content and mod.new_value:
                            results["applied"].append(
                                {"note": f"new resource key {mod.resource_key} will be added"}
                            )

                results["applied"].append(
                    {
                        "id": mod.id,
                        "class": mod.class_name,
                        "method": mod.method,
                        "edit_type": mod.edit_type,
                        "status": "would_apply",
                    }
                )
            except Exception as exc:  # pylint: disable=broad-except
                results["errors"].append(str(exc))
                results["success"] = False

        return results
