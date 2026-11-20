"""Local LLM client using Ollama.

Provides structured prompting for turning natural-language patch requests
into concrete PatchPlan JSON that can be validated into Pydantic models.
Now supports XML and resource edits with AI-suggested string changes and
uses Frida runtime observations to target live-executed methods.
"""

import json
from typing import Any, Optional

import ollama
from pydantic import ValidationError
from rich.console import Console

from apkmorph.models import AnalysisReport, PatchPlan
from apkmorph.plugins import list_custom_patch_types


class LLMClient:
    """Client for Ollama that supplies specialized system prompts and
    structured output scaffolding for APK modification tasks.

    All communication stays on the local machine. Temperature is kept low
    for more deterministic engineering-focused responses. Now capable of
    suggesting XML edits, resource string changes (resources.arsc is
    rebuilt on next Apktool invocation) and using Frida runtime observations
    to make patches target only methods that actually execute.

    Supports friendly aliases for Gemma 2, Phi 3 and Code Llama with
    automatic download on first use.
    """

    DEFAULT_MODEL = "llama3.2"
    DEFAULT_TEMPERATURE = 0.15
    DEFAULT_CONTEXT = 12288

    MODEL_ALIASES = {
        "gemma2": "gemma2",
        "phi3": "phi3",
        "codellama": "codellama",
        "llama3.2": "llama3.2",
    }

    def __init__(self, model: str = DEFAULT_MODEL, temperature: Optional[float] = None) -> None:
        self.model = self._resolve_alias(model)
        self.temperature = temperature or self.DEFAULT_TEMPERATURE
        self.console = Console()
        self._ensure_model()

    def _resolve_alias(self, model: str) -> str:
        key = model.lower().strip().replace(".", "").replace(":", "")
        return self.MODEL_ALIASES.get(key, model)

    def _ensure_model(self) -> None:
        """Auto-download supported models if missing (non-blocking best effort)."""
        try:
            available = [m["name"] for m in ollama.list().get("models", [])]
            if not any(self.model in name for name in available):
                self.console.print(f"[blue]Pulling model {self.model} (first use)[/blue]")
                ollama.pull(self.model)
                self.console.print("[green]Model ready[/green]")
        except Exception as exc:
            self.console.print(f"[yellow]Model auto-download skipped: {exc}[/yellow]")

    def query(self, description: str, report: AnalysisReport) -> PatchPlan:
        """Send enriched context to Ollama and parse the returned PatchPlan."""
        prompt = self._build_patch_prompt(description, report)
        try:
            response = ollama.chat(
                model=self.model,
                messages=[
                    {"role": "system", "content": self._system_prompt()},
                    {"role": "user", "content": prompt},
                ],
                options={"temperature": self.temperature, "num_ctx": self.DEFAULT_CONTEXT},
                format="json",
            )
            content = response["message"]["content"]
            data = json.loads(content.strip())
            plan = PatchPlan.model_validate(data)
            return plan
        except ValidationError as exc:
            self.console.print("[red]Validation error from LLM, using fallback plan[/red]")
            return PatchPlan(
                description=description,
                rationale="LLM response did not match schema. No modifications generated.",
                confidence=0.3,
            )
        except Exception as exc:
            self.console.print(f"[red]LLM query failed: {exc}[/red]")
            return PatchPlan(
                description=description,
                rationale=f"Error communicating with Ollama: {exc}",
                confidence=0.0,
            )

    def _system_prompt(self) -> str:
        custom_types = list_custom_patch_types()
        types_str = ", ".join(custom_types) if custom_types else "none"
        return (
            "You are an expert Android reverse-engineering assistant. "
            "Translate the user request into a minimal, safe PatchPlan. "
            f"Supported edit_type values: smali, xml, resource, {types_str}. "
            "Use runtime observations to target only live methods. "
            "Return ONLY valid JSON matching the PatchPlan schema. "
            "Keep changes minimal and explain your reasoning."
        )

    def _build_patch_prompt(self, description: str, report: AnalysisReport) -> str:
        custom_types = list_custom_patch_types()
        observations = "\n".join(report.runtime_observations[:15]) or "No runtime observations."
        sample_strings = "\n".join(report.strings[:15])
        sample_resources = "\n".join(
            f"{k}={v}" for k, v in list(report.string_resources.items())[:15]
        )

        return f"""User request: {description}

Package: {report.package_name}
Main activity: {report.main_activity or 'unknown'}
Components ({len(report.components)} total): {', '.join(report.components[:12])}
Runtime observations (Frida):
{observations}
Sample strings:
{sample_strings}
String resources:
{sample_resources}
Custom patch types registered: {custom_types or 'none'}

Produce a PatchPlan JSON. Target only code that matches the request and observations.
Prefer resource edits for strings, XML for manifest tweaks, and Smali only for precise method changes.
Include a clear rationale and realistic confidence score.
"""
