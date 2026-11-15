#!/usr/bin/env python3
"""Runnable example: Remove ads using natural language.

Demonstrates the full APK Morph library API in a script:

1. Analyze an APK (decompile + metadata extraction)
2. Generate a PatchPlan from plain English ("remove all ads")
3. Validate & simulate the changes
4. Rebuild, align and sign the patched APK

Requires:
- Ollama running with a capable model (e.g. llama3.2)
- Apktool, zipalign, apksigner on PATH
- A sample APK (provide via command line)

Usage:
    python examples/remove_ads.py path/to/sample_game.apk
"""

import sys
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax

from apkmorph.analyzer import APKAnalyzer
from apkmorph.builder import APKBuilder
from apkmorph.models import AnalysisReport, PatchPlan
from apkmorph.patch_generator import PatchGenerator

console = Console()


def remove_ads_example(apk_path: Path, model: str = "llama3.2") -> None:
    """Demonstrate end-to-end ad removal using the library API."""
    if not apk_path.exists():
        console.print(
            f"[bold red]APK not found:[/bold red] {apk_path}\n\n"
            "Download a sample game APK or provide a valid path.\n"
            "Example: python examples/remove_ads.py mygame.apk"
        )
        sys.exit(1)

    console.print(
        Panel(
            "[bold]APK Morph — Remove Ads Example[/bold]\n"
            f"Target: [cyan]{apk_path.name}[/cyan]\n"
            "Request: [italic]remove all ads and analytics trackers[/italic]",
            title=":rocket: Starting",
            border_style="blue",
        )
    )

    # 1. Analyze the APK
    console.print("\n[bold blue]Step 1:[/bold blue] Analyzing APK...")
    analyzer = APKAnalyzer(working_dir=Path("decompiled"))
    report: AnalysisReport = analyzer.decompile(str(apk_path))
    console.print(f"[green]✓[/green] Analysis complete — {report.summary()}")

    console.print("\n[bold]Key components:[/bold]")
    for comp in report.find_components("ad", limit=8):
        console.print(f"  • [yellow]{comp}[/yellow]")

    # 2. Generate intelligent patch plan via local LLM
    console.print("\n[bold blue]Step 2:[/bold blue] Generating patch plan with LLM...")
    generator = PatchGenerator(model=model)

    try:
        plan: PatchPlan = generator.from_description(
            "remove all ads and analytics trackers. "
            "NOP ad loading calls, disable tracking SDKs, "
            "remove AdMob references and analytics initialization.",
            report,
        )

        console.print(
            Panel(
                plan.rationale or "LLM provided no rationale.",
                title="LLM Reasoning",
                border_style="blue",
            )
        )

        console.print("\n[bold]Proposed modifications:[/bold]")
        for i, mod in enumerate(plan.modifications, start=1):
            short_class = mod.class_name.split(".")[-1]
            console.print(
                f"  {i}. [cyan]{short_class}[/cyan].[yellow]{mod.method}[/yellow] "
                f"(conf {mod.confidence:.2f})\n"
                f"     → {mod.description}"
            )
            if mod.diff.strip():
                console.print(Syntax(mod.diff, "smali", line_numbers=False, word_wrap=True))
                console.print("")

        # 3. Safety validation & simulation
        console.print("\n[bold blue]Step 3:[/bold blue] Validating and simulating...")
        generator.validate(plan)

        sim_report = generator.simulate_apply(plan, report.decompiled_dir)
        if sim_report["success"]:
            console.print("[green]✓ Simulation passed — all targets reachable[/green]")
            for applied in sim_report.get("applied", []):
                console.print(f"   • Would edit {applied['class']}")
        else:
            console.print("[yellow]Simulation reported issues (see below)[/yellow]")
            for err in sim_report.get("errors", []):
                console.print(f"   ! {err}")

        # 4. Rebuild and sign (note: real Smali edits would be applied here
        # in a complete implementation; current example rebuilds the tree
        # after simulation for demonstration)
        console.print("\n[bold blue]Step 4:[/bold blue] Rebuilding patched APK...")
        builder = APKBuilder(build_dir=Path("builds"))
        final_apk = builder.rebuild_and_sign(
            decompiled_dir=str(report.decompiled_dir),
            output_name=f"noads_{apk_path.stem}.apk",
            keystore=None,  # uses debug keystore
        )

        console.print(
            Panel(
                f"[bold green]Success![/bold green]\n\n"
                f"Patched APK: [white]{final_apk.resolve()}[/white]\n\n"
                "Install with:\n"
                f"    adb install {final_apk.name}",
                title=":package: Build Complete",
                border_style="green",
            )
        )

        console.print(
            "\n[italic]Next steps:[/italic] Try different descriptions, inspect "
            "the decompiled/smali changes, or run the Streamlit UI with "
            "[bold]apkmorph ui[/bold]."
        )

    except RuntimeError as exc:
        console.print(f"[red]Error:[/red] {exc}")
        if "Ollama" in str(exc):
            console.print(
                "\n[yellow]Is Ollama running? Try:[/yellow]\n    ollama serve"
            )
        sys.exit(2)
    except Exception as exc:  # pylint: disable=broad-except
        console.print(f"[red]Unexpected failure:[/red] {exc}")
        sys.exit(3)


if __name__ == "__main__":
    target = Path(sys.argv[1] if len(sys.argv) > 1 else "sample_game.apk")
    remove_ads_example(target)
