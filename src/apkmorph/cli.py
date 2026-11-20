"""Command line interface for APK Morph.

Provides CLI commands for APK analysis, natural-language patch generation,
application of patches, explanation, and launching the Streamlit UI.
"""

import json
import subprocess
import sys
from datetime import datetime
from pathlib import Path
from typing import List, Optional

import typer
from pydantic import ValidationError
from rich.console import Console
from rich.panel import Panel
from rich.syntax import Syntax
from rich.table import Table

from apkmorph.models import AnalysisReport, PatchPlan

# The following imports will be satisfied by the companion modules.
# They follow the exact signatures declared in the project plan.
from apkmorph.analyzer import APKAnalyzer
from apkmorph.builder import APKBuilder
from apkmorph.patch_generator import PatchGenerator
from apkmorph.utils import generate_report_md

app = typer.Typer(
    name="apkmorph",
    help="APK Morph — Natural-language AI tool for intelligent APK patching",
    add_completion=True,
    pretty_exceptions_show_locals=False,
    rich_markup_mode="rich",
)

console = Console()

# Simple persistent state for the current patch plan (used by apply/explain)
STATE_DIR = Path.home() / ".apkmorph"
STATE_FILE = STATE_DIR / "current_plan.json"


def _ensure_state_dir() -> None:
    """Create the state directory if it does not exist."""
    STATE_DIR.mkdir(parents=True, exist_ok=True)


def _save_plan(plan: PatchPlan) -> None:
    """Persist the patch plan to disk for later apply/explain commands."""
    _ensure_state_dir()
    STATE_FILE.write_text(plan.model_dump_json(indent=2))


def _load_latest_plan() -> Optional[PatchPlan]:
    """Load the most recent patch plan from disk."""
    if not STATE_FILE.exists():
        return None
    try:
        data = json.loads(STATE_FILE.read_text())
        return PatchPlan.model_validate(data)
    except Exception:
        console.print("[yellow]Could not load previous plan.[/yellow]")
        return None


@app.command()
def analyze(
    apk_path: Path = typer.Argument(
        ...,
        exists=True,
        dir_okay=False,
        file_okay=True,
        help="Path to the APK file to analyze",
    ),
    output: Optional[Path] = typer.Option(
        None,
        "--output",
        "-o",
        help="Path to write analysis report (JSON or .md)",
    ),
) -> None:
    """Decompile APK with Apktool and extract metadata/components via Androguard.

    Produces an AnalysisReport that subsequent patch commands can use.
    """
    if apk_path.suffix.lower() != ".apk":
        console.print("[bold red]Error: Input file must have .apk extension.[/bold red]")
        raise typer.Exit(1)

    console.print(f"[bold blue]Analyzing[/bold blue] [cyan]{apk_path.name}[/cyan] ...")

    try:
        analyzer = APKAnalyzer()
        report: AnalysisReport = analyzer.decompile(str(apk_path.resolve()))

        console.print("[green]✓[/green] Decompilation and analysis completed")

        summary_panel = Panel(
            report.summary(),
            title=":package: Analysis Summary",
            border_style="blue",
        )
        console.print(summary_panel)

        table = Table(title="Extracted Components", show_header=True)
        table.add_column("Category", style="dim")
        table.add_column("Count", justify="right")
        table.add_column("Sample", style="italic")

        table.add_row(
            "Activities",
            str(len(report.activities)),
            ", ".join(report.activities[:2]) + (" …" if len(report.activities) > 2 else ""),
        )
        table.add_row("Services", str(len(report.services)), "")
        table.add_row("Permissions", str(len(report.permissions)), "")
        table.add_row("Total components", str(len(report.components)), "")
        console.print(table)

        if output:
            output.parent.mkdir(parents=True, exist_ok=True)
            if str(output).endswith(".md"):
                md_text = generate_report_md(report)
                output.write_text(md_text)
            else:
                output.write_text(report.model_dump_json(indent=2))
            console.print(f"[green]Report saved → {output}[/green]")

        console.print(
            "\nNext: [bold]apkmorph patch \"disable analytics and remove ads\"[/bold]"
        )

    except FileNotFoundError as exc:
        console.print(f"[red]Required tool not found: {exc}[/red]")
        console.print("Make sure Apktool and Java are installed and on PATH.")
        raise typer.Exit(2) from exc
    except Exception as exc:
        console.print(f"[red]Analysis failed: {exc}[/red]")
        raise typer.Exit(3) from exc


@app.command()
def patch(
    description: str = typer.Argument(
        ...,
        help='Natural language request, e.g. "disable all analytics and remove splash screen"',
    ),
    apk_path: Path = typer.Argument(
        ...,
        exists=True,
        dir_okay=False,
        help="APK to be patched",
    ),
    model: str = typer.Option(
        "llama3.2",
        "--model",
        "-m",
        help="Ollama model to use (llama3.2, gemma2, phi3, codellama supported with auto-download)",
    ),
    apply_now: bool = typer.Option(
        False,
        "--apply",
        help="Immediately apply the generated plan",
    ),
) -> None:
    """Translate a plain-English request into a precise PatchPlan using a local LLM.

    The plan contains minimal Smali/XML edits with confidence scores and rationale.
    Gemma 2, Phi 3 and Code Llama are supported with automatic download.
    """
    console.print(
        f'Generating intelligent patch for request: "[italic]{description}[/italic]"'
    )

    try:
        analyzer = APKAnalyzer()
        report: AnalysisReport = analyzer.decompile(str(apk_path.resolve()))

        generator = PatchGenerator(model=model)
        plan: PatchPlan = generator.from_description(description, report)

        if not plan.modifications:
            console.print("[yellow]LLM returned no modifications.[/yellow]")
            return

        rationale_panel = Panel(
            plan.rationale or "No additional rationale provided.",
            title="LLM Reasoning",
            border_style="blue",
        )
        console.print(rationale_panel)

        mod_table = Table(title="Proposed Modifications")
        mod_table.add_column("#", justify="right")
        mod_table.add_column("Class", style="cyan")
        mod_table.add_column("Method", style="yellow")
        mod_table.add_column("Confidence", justify="right")
        mod_table.add_column("Description")

        for i, mod in enumerate(plan.modifications, start=1):
            short_class = mod.class_name.split(".")[-1]
            mod_table.add_row(
                str(i),
                short_class,
                mod.method[:35] + "…" if len(mod.method) > 35 else mod.method,
                f"{mod.confidence:.2f}",
                mod.description[:60] + "…" if len(mod.description) > 60 else mod.description,
            )
        console.print(mod_table)

        _save_plan(plan)
        console.print(f"\n[bold green]Patch plan {plan.id} saved.[/bold green]")

        if apply_now:
            _apply_plan(plan, apk_path, report=report)

    except ValidationError as exc:
        console.print("[red]LLM produced an invalid PatchPlan.[/red]")
        console.print(str(exc))
        raise typer.Exit(1) from exc
    except Exception as exc:
        console.print(f"[red]Patch generation failed: {exc}[/red]")
        raise typer.Exit(2) from exc


def _apply_plan(
    plan: PatchPlan, original_apk: Optional[Path] = None, report: Optional[AnalysisReport] = None
) -> None:
    """Apply all modifications from a PatchPlan and rebuild the APK.

    Uses PatchGenerator.apply_plan (which performs edits via _apply_modifications).
    """
    console.print("[bold]Applying patches...[/bold]")

    try:
        generator = PatchGenerator()
        if report is None and original_apk is not None:
            analyzer = APKAnalyzer()
            report = analyzer.decompile(str(original_apk))
        if report is None:
            console.print("[yellow]No decompiled report available, skipping edit phase.[/yellow]")
            return

        output_apk = generator.apply_plan(plan, report)

        console.print(
            Panel(
                f"[green]Successfully built and signed:[/green]\n[bold]{output_apk}[/bold]",
                title="Build Complete",
                border_style="green",
            )
        )
    except Exception as exc:
        console.print(f"[red]Could not apply patches: {exc}[/red]")
        raise typer.Exit(1) from exc


@app.command()
def apply(
    plan_id: Optional[str] = typer.Option(
        None,
        "--plan-id",
        "-p",
        help="Patch plan ID (uses latest if omitted)",
    ),
) -> None:
    """Apply the latest (or a specific) patch plan and produce a signed APK."""
    plan = _load_latest_plan()
    if plan is None:
        console.print("[yellow]No patch plan found. Generate one with the patch command first.[/yellow]")
        raise typer.Exit(0)

    if plan_id and not plan.id.startswith(plan_id):
        console.print(f"[red]No plan matching prefix '{plan_id}' found.[/red]")
        raise typer.Exit(1)

    console.print(f"Applying plan [bold cyan]{plan.id}[/bold cyan]")
    _apply_plan(plan)


@app.command()
def explain(
    patch_id: str = typer.Argument(..., help="ID (or prefix) of the patch plan to explain"),
) -> None:
    """Show a human-readable explanation and Smali diff for a previous patch."""
    plan = _load_latest_plan()
    if plan is None or not plan.id.startswith(patch_id):
        console.print("[red]No matching patch plan found.[/red]")
        raise typer.Exit(1)

    console.print(Panel(plan.rationale, title=f"Explanation — {plan.id}"))

    for mod in plan.modifications:
        console.print(f"\n[bold cyan]{mod.class_name}[/bold cyan] • [yellow]{mod.method}[/yellow]")
        console.print(f"{mod.description}")
        if mod.diff.strip():
            console.print(Syntax(mod.diff, "smali", line_numbers=True, word_wrap=True))
        console.print("─" * 60)


@app.command()
def batch(
    description: str = typer.Argument(
        ...,
        help='Natural language request to apply to all APKs, e.g. "disable all analytics"',
    ),
    apk_paths: List[Path] = typer.Argument(
        ...,
        exists=True,
        dir_okay=False,
        help="One or more .apk files (use *.apk for glob in shell)",
    ),
    output_dir: Path = typer.Option(
        Path("batch_patched"),
        "--output-dir",
        "-o",
        help="Output directory for all patched APKs",
        dir_okay=True,
        file_okay=False,
    ),
    model: str = typer.Option(
        "llama3.2",
        "--model",
        "-m",
        help="Ollama model",
    ),
    no_observe: bool = typer.Option(
        False,
        "--no-observe",
        help="Skip Frida runtime observation",
    ),
) -> None:
    """Apply the same natural-language patch description to multiple APKs in one command.

    Each APK gets its own analysis, LLM-generated plan (tailored to its code and runtime data),
    modifications applied, and signed APK produced in the output directory.
    """
    console.print(
        f"[bold]Batch patching {len(apk_paths)} APKs with request:[/bold] [italic]{description}[/italic]"
    )
    console.print(f"Output directory: {output_dir.resolve()}")

    try:
        generator = PatchGenerator(model=model)
        results = generator.batch(
            description=description,
            apk_paths=[str(p) for p in apk_paths],
            output_dir=output_dir,
            model=model,
            observe_runtime=not no_observe,
        )

        success_count = sum(1 for r in results if r.get("success", False))
        console.print(
            f"\n[bold green]Batch complete: {success_count}/{len(apk_paths)} APKs successfully patched.[/bold green]"
        )
    except Exception as exc:
        console.print(f"[red]Batch failed: {exc}[/red]")
        raise typer.Exit(1) from exc


@app.command()
def export(
    plan_id: str = typer.Argument(..., help="ID (or prefix) of the saved plan to export"),
    fmt: str = typer.Option(
        "python",
        "--format",
        "-f",
        help="Export format: python (standalone script) or json (template)",
    ),
    output: Optional[Path] = typer.Option(
        None, "--output", "-o", help="Output file path (default: <plan_id>.py or .json)"
    ),
) -> None:
    """Export a generated PatchPlan as a reusable Python script or JSON template.

    The Python script is self-contained, embeds the exact modifications, and can be
    executed on other APKs without re-running the LLM. JSON is useful for templates
    or version control.
    """
    plan = _load_latest_plan()
    if plan is None or not plan.id.startswith(plan_id):
        console.print("[red]No matching patch plan found.[/red]")
        console.print("Run 'apkmorph patch ...' first.")
        raise typer.Exit(1)

    console.print(f"Exporting plan [bold cyan]{plan.id}[/bold cyan] as {fmt}...")

    try:
        generator = PatchGenerator()
        out_path = generator.export(plan, output, fmt=fmt)
        console.print(f"[green]✓ Successfully exported to[/green] [bold]{out_path}[/bold]")

        if fmt.lower() == "python":
            console.print(
                Panel(
                    "Run with: [bold]python "
                    f"{out_path.name} your_app.apk[/bold]\n\n"
                    "The script works offline and can be committed to git.",
                    title="Next steps",
                    border_style="green",
                )
            )
    except Exception as exc:
        console.print(f"[red]Export failed: {exc}[/red]")
        raise typer.Exit(1) from exc


@app.command()
def ui(
    port: int = typer.Option(8501, "--port", help="Port on which to run the Streamlit server"),
    debug: bool = typer.Option(False, "--debug", help="Run Streamlit in debug mode"),
) -> None:
    """Launch the clean, modern Streamlit web dashboard."""
    ui_file = Path(__file__).parent / "ui" / "app.py"

    if not ui_file.exists():
        console.print("[red]UI file src/apkmorph/ui/app.py not found.[/red]")
        console.print("Please ensure the full project has been installed.")
        raise typer.Exit(1)

    cmd = [
        sys.executable,
        "-m",
        "streamlit",
        "run",
        str(ui_file),
        "--server.port",
        str(port),
        "--theme.base",
        "light",
        "--theme.primaryColor",
        "#2563eb",
        "--theme.backgroundColor",
        "#f1f5f9",
    ]
    if debug:
        cmd.append("--logger.level=debug")

    console.print("[bold]Starting APK Morph UI...[/bold]")
    console.print(f"URL will be http://localhost:{port}")
    try:
        subprocess.call(cmd)
    except KeyboardInterrupt:
        console.print("\n[blue]UI stopped by user.[/blue]")


if __name__ == "__main__":
    app()
