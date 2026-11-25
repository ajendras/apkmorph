"""LLM interaction layer.

LLMClient builds rich, context-aware prompts that now automatically
include domain-specific prompt fragments from any custom patch types
registered via the plugin API. Queries are sent to local Ollama;
responses are parsed into PatchPlan objects.
"""

import json
from typing import Any

import ollama

from apkmorph.models import AnalysisReport, Modification, PatchPlan
from apkmorph.plugins import get_custom_prompt_fragments


class LLMClient:
    """Client for querying local Ollama models.

    The system prompt now dynamically incorporates custom patch-type
    fragments supplied by plugins, improving suggestion quality for
    domain-specific tasks (theming, permission managers, network
    security config injection, etc.).
    """

    def __init__(self, model: str = "llama3.2", temperature: float = 0.15) -> None:
        """Initialize with a specific Ollama model and sampling temperature.

        Args:
            model: Ollama model name (llama3.2, gemma2, phi3, codellama, …).
            temperature: Controls randomness (lower = more deterministic).
        """
        self.model = model
        self.temperature = temperature

    def query(self, prompt: str, system: str | None = None) -> str:
        """Send a prompt to Ollama and return the generated text.

        Raises RuntimeError on any Ollama or network issue.
        """
        try:
            response = ollama.chat(
                model=self.model,
                messages=[
                    {"role": "system", "content": system or self._default_system_prompt()},
                    {"role": "user", "content": prompt},
                ],
                options={"temperature": self.temperature, "num_ctx": 8192},
            )
            return response["message"]["content"].strip()
        except Exception as exc:
            raise RuntimeError(f"LLM query failed for model {self.model}: {exc}") from exc

    def _default_system_prompt(self) -> str:
        return (
            "You are an expert Android reverse-engineering assistant. "
            "Produce minimal, precise patches. Always respond with valid JSON only."
        )

    def generate_patch_plan(
        self, description: str, report: AnalysisReport
    ) -> PatchPlan:
        """Build a detailed prompt (including custom plugin fragments) and parse the LLM reply into a PatchPlan.

        The custom fragments supplied by register_custom_patch_type() are
        inserted verbatim so the model receives domain-specific guidance.
        """
        custom_section = get_custom_prompt_fragments()

        system = f"""You are an expert Android patch generator.
Translate the natural-language request into a list of minimal modifications.

Available edit_type values:
- smali: targeted changes to method bodies or class structure (preferred)
- xml: edits to layout files, styles.xml or other resource XML
- resource: update string or array resources (updates resources.arsc on rebuild)
- manifest: add/remove permissions, register receivers, edit components
{custom_section}

For every modification return a JSON object with:
  edit_type, target (class/method/file path), description, params (object),
  rationale, confidence (float 0.0-1.0).

Answer with a single JSON array of modification objects. No extra text."""

        context = (
            f"Package: {report.package_name}\n"
            f"Main activity: {report.main_activity}\n"
            f"Components ({len(report.components)}): {', '.join(report.components[:12])}\n"
            f"Observed strings: {report.strings[:20]}\n"
            f"Runtime observations: {report.runtime_observations or ['(none)']}\n"
            f"Permissions: {report.permissions}\n"
        )

        user_prompt = f"{context}\nUser request: {description}\n\nReturn only the JSON array of modifications."

        raw_response = self.query(user_prompt, system)

        # Extract JSON (LLM sometimes adds markdown; strip it)
        if "```json" in raw_response:
            raw_response = raw_response.split("```json")[1].split("```")[0]
        elif "```" in raw_response:
            raw_response = raw_response.split("```")[1].split("```")[0]

        try:
            data = json.loads(raw_response.strip())
            if isinstance(data, dict) and "modifications" in data:
                mod_list = data["modifications"]
            elif isinstance(data, list):
                mod_list = data
            else:
                mod_list = [data]

            modifications = []
            for item in mod_list:
                if isinstance(item, dict):
                    modifications.append(Modification(**item))

            return PatchPlan(
                description=description,
                modifications=modifications,
                rationale="LLM plan generated with custom plugin fragments",
                confidence=0.82,
                model_used=self.model,
            )
        except (json.JSONDecodeError, TypeError, ValueError) as exc:
            # Graceful fallback when JSON parsing fails
            return PatchPlan(
                description=description,
                modifications=[],
                rationale=f"Failed to parse LLM response: {exc}",
                confidence=0.25,
                model_used=self.model,
            )
