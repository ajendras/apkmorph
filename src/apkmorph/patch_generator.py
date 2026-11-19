"""Patch generation and application module.

Uses local LLM via LLMClient to turn natural language into PatchPlan.
Supports validation, simulation, and now batch processing of multiple APKs with the same patch description.
The batch mode decompiles each APK, generates a tailored plan, applies the modifications to Smali/XML/resources, then rebuilds.
"""

import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from rich.console import Console
from rich.table import Table

from apkmorph.analyzer import APKAnalyzer
from apkmorph.builder import APKBuilder
from apkmorph.llm import LLMClient
from apkmorph.models import AnalysisReport, Modification, PatchPlan

console = Console()


class PatchGenerator:
    """Generates PatchPlan from natural language using LLM, validates, simulates and applies them.

    Now includes batch mode for multiple APKs using the same description.
    """

    def __init__(self, model: str = "llama3.2") -> None:
        self.model = model
        self.llm = LLMClient(model=model)

    def from_description(
        self, description: str, report: AnalysisReport
    ) -> PatchPlan:
        """Generate a PatchPlan for a single report using LLM."""
        return self.llm.generate_patch(description, report)

    def validate(self, plan: PatchPlan) -> bool:
        """Validate a PatchPlan for safety and completeness."""
        if not plan.modifications:
            raise ValueError("Plan has no modifications")
        if plan.confidence < 0.4:
            console.print("[yellow]Warning: low confidence plan.[/yellow]")
        for mod in plan.modifications:
            if mod.edit_type not in ("smali", "xml", "resource"):
                raise ValueError(f"Unknown edit_type: {mod.edit_type}")
            if not mod.file_path:
                raise ValueError("Modification missing file_path")
            if mod.confidence < 0.3:
                console.print(f"[yellow]Low confidence mod: {mod.description}[/yellow]")
        return True

    def simulate_apply(
        self, plan: PatchPlan, decompiled_dir: Path
    ) -> Dict[str, Any]:
        """Simulate what changes would be made without modifying files."""
        decomp = Path(decompiled_dir)
        simulated = {"applied": [], "skipped": [], "warnings": []}
        for mod in plan.modifications:
            target_file = decomp / str(mod.file_path) if mod.file_path else decomp
            if not target_file.exists():
                simulated["skipped"].append(
                    f"{mod.file_path} not found for {mod.class_name}"
                )
                continue
            simulated["applied"].append(
                {
                    "file": str(mod.file_path),
                    "type": mod.edit_type,
                    "description": mod.description,
                    "snippet": mod.diff,
                }
            )
        return simulated

    def _apply_modifications(
        self, modifications: List[Modification], decompiled_dir: Path
    ) -> List[str]:
        """Apply the modifications to the decompiled files using string replacement
        based on the original_snippet / patched_snippet or resource updates.
        Returns list of applied file paths.
        """
        decomp_path = Path(decompiled_dir)
        applied_files: List[str] = []
        for mod in modifications:
            if not mod.file_path:
                continue
            target = decomp_path / str(mod.file_path)
            if not target.exists():
                # Try to locate the file by class name if path not exact
                if mod.class_name and mod.class_name != "resource":
                    possible = list(
                        decomp_path.rglob(f"*{mod.class_name.split('.')[-1]}*.smali")
                    )
                    if possible:
                        target = possible[0]
                    else:
                        console.print(f"[yellow]Could not find file for {mod.class_name}[/yellow]")
                        continue
            try:
                content = target.read_text(encoding="utf-8", errors="ignore")
                original_content = content

                if (
                    mod.edit_type == "resource"
                    and mod.resource_key
                    and mod.new_value is not None
                ):
                    # Update strings.xml or similar
                    pattern = re.compile(
                        r'(<string\s+name=["\']'
                        + re.escape(mod.resource_key)
                        + r'["\'][^>]*>)(.*?)(</string>)',
                        re.DOTALL | re.IGNORECASE,
                    )
                    replacement = rf"\1{mod.new_value}\3"
                    content, count = pattern.subn(replacement, content)
                    if count == 0:
                        # fallback simple replace
                        content = content.replace(
                            f'name="{mod.resource_key}">',
                            f'name="{mod.resource_key}">{mod.new_value}',
                        )
                elif mod.original_snippet and mod.patched_snippet:
                    # Replace the exact snippet for smali or xml
                    if mod.original_snippet in content:
                        content = content.replace(mod.original_snippet, mod.patched_snippet)
                    else:
                        # fallback to diff description or partial match
                        if "return-void" in mod.diff or "nop" in mod.diff.lower():
                            # simple example for disabling method
                            content = re.sub(
                                r"(\s+)(invoke-.*?\n\s+return-void)",
                                r"\1# APK Morph patch: disabled\n\1return-void",
                                content,
                            )
                elif mod.diff and mod.patched_snippet:
                    content = content.replace(mod.diff, mod.patched_snippet)

                if content != original_content:
                    target.write_text(content, encoding="utf-8")
                    applied_files.append(str(mod.file_path))
                    console.print(f"[green]Applied {mod.edit_type} to {target.name}[/green]")
                else:
                    console.print(f"[yellow]No change applied for {mod.description}[/yellow]")
            except Exception as exc:
                console.print(f"[red]Failed to apply mod to {target}: {exc}[/red]")
        return applied_files

    def apply_plan(self, plan: PatchPlan, report: AnalysisReport) -> Path:
        """Apply a plan to the report's decompiled dir and return the built APK path."""
        self.validate(plan)
        decompiled_dir = report.decompiled_dir
        # Apply the edits
        self._apply_modifications(plan.modifications, decompiled_dir)
        # Rebuild
        builder = APKBuilder()
        signed_apk = builder.rebuild_and_sign(str(decompiled_dir))
        return signed_apk

    def batch(
        self,
        description: str,
        apk_paths: List[str | Path],
        output_dir: str | Path = "batch_output",
        model: Optional[str] = None,
        observe_runtime: bool = True,
    ) -> List[Dict[str, Any]]:
        """Batch mode: apply the same natural-language patch to many APKs.

        Processes each APK independently: decompile -> (optional runtime observe) -> generate
        plan from description -> validate -> apply modifications -> rebuild & sign.

        Returns list of result dicts with success, apk_name, output_path, plan_id, confidence, rationale.
        """
        output_dir = Path(output_dir)
        output_dir.mkdir(parents=True, exist_ok=True)
        results: List[Dict[str, Any]] = []
        analyzer = APKAnalyzer(working_dir=Path("decompiled") / "batch")
        use_model = model or self.model
        generator = PatchGenerator(model=use_model) if model else self
        builder = APKBuilder(build_dir=output_dir)

        for idx, apk_str in enumerate(apk_paths, 1):
            apk_path = Path(apk_str)
            if not apk_path.exists() or not str(apk_path).lower().endswith(".apk"):
                results.append({"success": False, "apk": str(apk_path), "error": "Invalid APK"})
                console.print(f"[red]Skipping invalid APK: {apk_path}[/red]")
                continue

            console.print(
                f"[bold blue][{idx}/{len(apk_paths)}] Processing {apk_path.name} with description:[/bold blue] {description[:60]}..."
            )
            try:
                report = analyzer.decompile(str(apk_path))
                if observe_runtime:
                    report = analyzer.observe_runtime(report)

                plan = generator.from_description(description, report)
                signed_path = generator.apply_plan(plan, report)

                # Ensure output lands in the requested batch directory
                if signed_path.parent != output_dir:
                    final_path = output_dir / signed_path.name
                    if final_path.exists():
                        final_path.unlink()
                    signed_path.rename(final_path)
                    signed_path = final_path

                results.append(
                    {
                        "success": True,
                        "apk": apk_path.name,
                        "output_apk": str(signed_path),
                        "plan_id": plan.id,
                        "confidence": plan.confidence,
                        "num_mods": len(plan.modifications),
                        "rationale": plan.rationale[:100] + "...",
                    }
                )
                console.print(
                    f"[green]✓ Successfully patched {apk_path.name} → {signed_path.name} (confidence {plan.confidence:.2f})[/green]"
                )
            except Exception as exc:
                results.append(
                    {
                        "success": False,
                        "apk": apk_path.name,
                        "error": str(exc)[:80],
                    }
                )
                console.print(f"[red]Failed to process {apk_path.name}: {exc}[/red]")

        # Print summary table
        if results:
            table = Table(title="Batch Patch Summary")
            table.add_column("APK")
            table.add_column("Success")
            table.add_column("Output APK / Error")
            table.add_column("Mods")
            table.add_column("Conf")
            for res in results:
                if res["success"]:
                    table.add_row(
                        res["apk"],
                        "[green]YES[/green]",
                        Path(res.get("output_apk", "")).name,
                        str(res.get("num_mods", 0)),
                        f"{res.get('confidence', 0):.2f}",
                    )
                else:
                    table.add_row(
                        res["apk"], "[red]NO[/red]", res.get("error", "unknown"), "-", "-"
                    )
            console.print(table)

        return results
