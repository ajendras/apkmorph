"""Local LLM client using Ollama.

Provides structured prompting for turning natural-language patch requests
into concrete PatchPlan JSON that can be validated into Pydantic models.
Now supports XML and resource edits with AI-suggested string changes and
uses Frida runtime observations to target live-executed methods.
The feedback loop incorporates user comments into the system prompt for
iterative refinement of confidence scores and patch quality.
"""

import json
import re
from typing import Any, Dict, List, Optional

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
    automatic download on first use. User feedback is injected into the
    system prompt to enable the refinement loop.
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

    def __init__(self, model: str = DEFAULT_MODEL) -> None:
        self.model = self.MODEL_ALIASES.get(model.lower(), model)
        self.console = Console()
        self._ensure_model_available()

    def _ensure_model_available(self) -> None:
        """Pull model from Ollama if it is not present (auto-download)."""
        try:
            models = ollama.list()
            if not any(self.model in m["name"] for m in models.get("models", [])):
                self.console.print(f"[yellow]Pulling model {self.model} (first use)...[/yellow]")
                ollama.pull(self.model)
        except Exception:
            self.console.print("[yellow]Could not auto-pull model; ensure Ollama is running.[/yellow]")

    def _build_system_prompt(self, report: AnalysisReport, feedback: Optional[str] = None) -> str:
        custom_types = list_custom_patch_types()
        feedback_part = ""
        if feedback:
            feedback_part = (
                f"\n\nPREVIOUS USER FEEDBACK: {feedback}\n"
                "Address every point raised. Target the exact methods or resources mentioned. "
                "Increase precision, reduce side-effects, and raise confidence where the feedback "
                "indicates the prior plan was incomplete or overly broad. Produce a new PatchPlan."
            )
        return f"""You are an expert Android reverse-engineering and Smali patching specialist.
You produce minimal, safe, targeted patches from plain-English requests.

Available edit types: smali, xml, resource{', ' + ', '.join(custom_types) if custom_types else ''}.

Rules:
- Only edit code that matches runtime observations when available.
- For resource edits use exact keys from the supplied string_resources map.
- Provide realistic confidence (0.0-1.0) based on match quality.
- Include a short plain-English rationale for every modification.
- Output ONLY valid JSON that matches the PatchPlan schema below. No extra text.

{feedback_part}

JSON schema:
{{
  "id": "string",
  "description": "string",
  "modifications": [
    {{
      "edit_type": "smali|xml|resource|...",
      "class_name": "string",
      "method": "string",
      "description": "string",
      "confidence": 0.0-1.0,
      "diff": "string",
      "params": {{}}
    }}
  ],
  "rationale": "string",
  "confidence": 0.0-1.0
}}
"""

    def _build_user_prompt(self, description: str, report: AnalysisReport) -> str:
        components = ", ".join(report.components[:12]) if report.components else "none"
        strings = ", ".join(report.strings[:6]) if report.strings else "none"
        observations = ", ".join(report.runtime_observations[:6]) if report.runtime_observations else "none"
        resources = str(dict(list(report.string_resources.items())[:8]))
        return f"""Request: {description}

Analysis summary: {report.summary()}

Components: {components}
Sample strings: {strings}
Runtime observations: {observations}
String resources: {resources}

Generate a precise PatchPlan that satisfies the request while respecting all rules above."""

    def _call_ollama(self, system: str, prompt: str) -> str:
        try:
            response = ollama.chat(
                model=self.model,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": prompt},
                ],
                options={
                    "temperature": self.DEFAULT_TEMPERATURE,
                    "num_ctx": self.DEFAULT_CONTEXT,
                },
            )
            return response["message"]["content"]
        except Exception as exc:
            raise RuntimeError(f"Ollama request failed: {exc}") from exc

    def _extract_json(self, text: str) -> Dict[str, Any]:
        match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", text, re.DOTALL)
        if match:
            text = match.group(1)
        else:
            match = re.search(r"(\{.*\})", text, re.DOTALL)
            if match:
                text = match.group(1)
        try:
            return json.loads(text.strip())
        except json.JSONDecodeError as exc:
            raise ValueError("Could not parse JSON from LLM response") from exc

    def generate_patch_plan(
        self, description: str, report: AnalysisReport, feedback: Optional[str] = None
    ) -> PatchPlan:
        """Generate (or refine) a PatchPlan. Feedback is injected into the system prompt."""
        system = self._build_system_prompt(report, feedback)
        user_prompt = self._build_user_prompt(description, report)
        raw = self._call_ollama(system, user_prompt)
        try:
            data = self._extract_json(raw)
            if "modifications" in data:
                for m in data["modifications"]:
                    if "confidence" not in m:
                        m["confidence"] = 0.75
            plan = PatchPlan.model_validate(data)
            if feedback and feedback not in plan.feedback_history:
                plan.feedback_history.append(feedback)
            return plan
        except (ValidationError, ValueError, KeyError) as exc:
            self.console.print("[red]LLM response could not be parsed into PatchPlan.[/red]")
            self.console.print(raw[:300] + "...")
            raise RuntimeError(f"Invalid LLM output: {exc}") from exc
