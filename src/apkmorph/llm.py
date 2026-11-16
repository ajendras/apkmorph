"""Local LLM client using Ollama.

Provides structured prompting for turning natural-language patch requests
into concrete PatchPlan JSON that can be validated into Pydantic models.
Now supports XML and resource edits with AI-suggested string changes.
"""

import json
from typing import Any

import ollama
from pydantic import ValidationError

from apkmorph.models import AnalysisReport, PatchPlan


class LLMClient:
    """Client for Ollama that supplies specialized system prompts and
    structured output scaffolding for APK modification tasks.

    All communication stays on the local machine. Temperature is kept low
    for more deterministic engineering-focused responses. Now capable of
    suggesting XML edits and resource string changes (resources.arsc is
    rebuilt on next Apktool invocation).
    """

    DEFAULT_MODEL = "llama3.2"
    DEFAULT_TEMPERATURE = 0.15
    DEFAULT_CONTEXT = 12288

    def __init__(self, model: str | None = None) -> None:
        """Initialize with an Ollama model name.

        Args:
            model: Ollama model tag (defaults to llama3.2). Must be pulled locally.
        """
        self.model = model or self.DEFAULT_MODEL

    def query(
        self,
        prompt: str,
        system_prompt: str | None = None,
        model: str | None = None,
    ) -> str:
        """Send a conversation to Ollama and return the assistant's text response.

        Args:
            prompt: User message (usually contains APK report + request)
            system_prompt: Optional system instruction (uses patch expert prompt if omitted)
            model: Override the model for this single query

        Returns:
            Raw text response from the model

        Raises:
            RuntimeError: On connection errors, Ollama not running, or malformed responses
        """
        if not prompt or not prompt.strip():
            raise ValueError("Prompt cannot be empty")

        use_model = model or self.model
        messages = []

        if system_prompt:
            messages.append({"role": "system", "content": system_prompt})
        else:
            messages.append({"role": "system", "content": self._patch_system_prompt()})

        messages.append({"role": "user", "content": prompt})

        try:
            response = ollama.chat(
                model=use_model,
                messages=messages,
                options={
                    "temperature": self.DEFAULT_TEMPERATURE,
                    "num_ctx": self.DEFAULT_CONTEXT,
                    "top_p": 0.9,
                },
            )
            content = response.get("message", {}).get("content", "")
            return content.strip()
        except ollama.ResponseError as exc:
            raise RuntimeError(f"Ollama API error: {exc}") from exc
        except ConnectionRefusedError as exc:
            raise RuntimeError(
                "Could not connect to Ollama server. "
                "Start it with: ollama serve"
            ) from exc
        except Exception as exc:
            raise RuntimeError(f"Unexpected LLM query failure: {exc}") from exc

    def _patch_system_prompt(self) -> str:
        """Expert system prompt that guides the model to produce safe, minimal,
        auditable APK patches expressed as structured JSON. Now includes
        support for XML and resource string edits.
        """
        return (
            "You are an expert Android reverse-engineering assistant specialized in "
            "producing minimal, safe, and auditable patches for APKs.\n\n"
            "Rules:\n"
            "1. ONLY output valid JSON that matches the PatchPlan Pydantic model exactly.\n"
            "2. Prefer small changes: return false from analytics methods, NOP calls, "
            "remove resource references, set boolean flags, or update string resources.\n"
            "3. Never suggest broad changes that could destabilize the app or remove "
            "core functionality unless explicitly asked.\n"
            "4. Provide a clear English rationale and per-modification confidence (0.0-1.0).\n"
            "5. Use real class names and method signatures discovered in the provided report.\n"
            "6. Include a short 'diff' field showing the exact Smali lines or XML/string change.\n"
            "7. file_path must be a relative path inside the decompiled directory.\n"
            "8. For resource and string changes use edit_type='resource', supply resource_key "
            "and new_value. This will intelligently update strings.xml (resources.arsc is "
            "regenerated on rebuild). Use edit_type='xml' for manifest or layout tweaks.\n\n"
            "Output only the JSON object. No markdown, no explanation outside the JSON."
        )

    def _build_patch_prompt(self, description: str, report: AnalysisReport) -> str:
        """Assemble a rich context prompt that includes the full analysis report,
        key components, extracted strings and string_resources.
        """
        summary_md = report.to_markdown()
        sample_components = report.find_components("", limit=12)
        sample_strings = report.strings[:25]
        sample_resource_keys = list(report.string_resources.keys())[:15]

        return f"""Request: {description}

{summary_md}

Relevant components (first 12):
{', '.join(sample_components)}

Extracted strings that may indicate trackers, ads, or analytics:
{chr(10).join(f'• {s}' for s in sample_strings) if sample_strings else 'None found.'}

Available resource keys (use these for intelligent string edits):
{', '.join(sample_resource_keys) if sample_resource_keys else 'None found.'}

Produce a PatchPlan that satisfies the request using the smallest number of targeted edits.
Focus on:
- Analytics / crash reporting SDK initialization (Smali)
- AdMob / ad view loading calls (Smali or resource removal)
- Unwanted permissions or receivers (XML)
- Splash screen or onboarding flows
- AI-suggested string changes (edit_type=resource) that will update resources.arsc

You may return a mix of Smali, XML and resource modifications.

Return ONLY a JSON object matching this structure (use realistic values from the report):
{{
  "description": "{description}",
  "rationale": "Brief explanation of the strategy including any string changes...",
  "confidence": 0.87,
  "modifications": [
    {{
      "class_name": "com.example.analytics.Tracker",
      "method": "trackEvent(Ljava/lang/String;)V",
      "edit_type": "smali",
      "diff": "    invoke-static {{p0, p1}}, ... -> return-void\\n    # was tracking call",
      "description": "NOP the tracking call that matches the user request",
      "confidence": 0.92,
      "file_path": "smali/com/example/analytics/Tracker.smali",
      "location_hint": "line 42"
    }},
    {{
      "class_name": "resource",
      "method": "update_string",
      "edit_type": "resource",
      "resource_key": "ad_banner_text",
      "new_value": "",
      "diff": "ad_banner_text changed from 'Advertisement' to empty string",
      "description": "Empty ad-related string resource (updates resources.arsc)",
      "confidence": 0.88,
      "file_path": "res/values/strings.xml"
    }}
  ]
}}
"""

    def generate_patch(self, description: str, report: AnalysisReport) -> PatchPlan:
        """High-level helper that builds the prompt, queries the LLM, cleans the
        response, and parses it into a PatchPlan.

        Raises a clear error if the LLM does not produce valid JSON.
        """
        if not description or len(description.strip()) < 4:
            raise ValueError("Description must be at least 4 characters")

        system = self._patch_system_prompt()
        user_prompt = self._build_patch_prompt(description, report)

        raw = self.query(user_prompt, system, self.model)

        # Strip common markdown fences that even good models sometimes emit
        if "```json" in raw:
            raw = raw.split("```json", 1)[1].split("```", 1)[0]
        elif "```" in raw:
            raw = raw.split("```", 2)[1]

        raw = raw.strip()

        try:
            plan = PatchPlan.model_validate_json(raw)
            return plan
        except (json.JSONDecodeError, ValidationError) as exc:
            preview = raw[:280] + "..." if len(raw) > 280 else raw
            raise RuntimeError(
                f"LLM did not return valid PatchPlan JSON.\n"
                f"Model output started with: {preview}\n\n"
                f"Error: {exc}"
            ) from exc
