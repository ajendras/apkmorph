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
        "code-llama": "codellama",
    }

    def __init__(self, model: str | None = None) -> None:
        """Initialize with an Ollama model name.

        Args:
            model: Ollama model tag (defaults to llama3.2). Friendly aliases
                   for gemma2, phi3 and codellama are supported and will be
                   auto-downloaded if not present locally.
        """
        self.model = model or self.DEFAULT_MODEL
        self.console = Console()
        self._model_ready = False

    def _ensure_model(self, model: Optional[str] = None) -> None:
        """Ensure the model (or alias) is available locally by pulling it from
        Ollama if necessary. Supports Gemma2, Phi3 and CodeLlama out of the box.
        """
        target = model or self.model
        if target.lower() in self.MODEL_ALIASES:
            target = self.MODEL_ALIASES[target.lower()]
            if model is None:
                self.model = target

        try:
            resp = ollama.list()
            available_models = [m["name"] for m in resp.get("models", [])]
            if any(
                target == m or target in m or m.startswith(target.split(":")[0])
                for m in available_models
            ):
                return

            self.console.print(
                f"[yellow]Model [bold]{target}[/bold] not found locally. "
                "Auto-downloading...[/yellow]"
            )
            self.console.print("[dim](first-time use may take 1-5 minutes)[/dim]")
            ollama.pull(target)
            self.console.print(f"[green]✓[/green] {target} is now available.")
        except Exception as exc:
            self.console.print(f"[red]Auto-download failed: {exc}[/red]")
            self.console.print(
                "[yellow]Ensure 'ollama serve' is running and you have internet access.[/yellow]"
            )

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

        if not self._model_ready:
            self._ensure_model(model)
            self._model_ready = True

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
        support for XML and resource string edits and Frida runtime data.
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
            "regenerated on rebuild). Use edit_type='xml' for manifest or layout tweaks.\n"
            "9. Prioritize modifications to methods and classes that appear in the "
            "runtime_observations. This ensures patches address actual executed code.\n"
            "10. Populate original_snippet, patched_snippet and hover_explanation for the "
            "interactive side-by-side viewer.\n\n"
            "Output only the JSON object. No markdown, no explanation outside the JSON."
        )

    def _build_patch_prompt(self, description: str, report: AnalysisReport) -> str:
        """Assemble a rich context prompt that includes the full analysis report,
        key components, extracted strings, string_resources and Frida runtime_observations.
        """
        summary_md = report.to_markdown()
        sample_components = report.find_components("", limit=12)
        sample_strings = report.strings[:25]
        sample_resource_keys = list(report.string_resources.keys())[:15]

        runtime_section = (
            "\n".join(f"• {o}" for o in report.runtime_observations)
            if report.runtime_observations
            else "No runtime observations available."
        )

        return f"""Request: {description}

{summary_md}

Relevant components (first 12):
{', '.join(sample_components)}

Extracted strings that may indicate trackers, ads, or analytics:
{chr(10).join(f'• {s}' for s in sample_strings) if sample_strings else 'None found.'}

Available resource keys (use these for intelligent string edits):
{', '.join(sample_resource_keys) if sample_resource_keys else 'None found.'}

Runtime observations from Frida (use these to target live code paths):
{runtime_section}

Produce a PatchPlan that satisfies the request using the smallest number of targeted edits.
Focus on:
- Analytics / crash reporting SDK initialization (Smali) - prefer methods seen in Frida data
- AdMob / ad view loading calls (Smali or resource removal) - use observed ad hooks
- Unwanted permissions or receivers (XML)
- Splash screen or onboarding flows
- AI-suggested string changes (edit_type=resource) that will update resources.arsc

You may return a mix of Smali, XML and resource modifications. When runtime observations
are present, make them the primary source of truth for method selection.

Return ONLY a JSON object matching this structure (use realistic values from the report):
{{
  "description": "{description}",
  "rationale": "Used Frida observations of AdView.loadAd and Firebase logEvent to target only live ad and analytics paths...",
  "confidence": 0.87,
  "modifications": [
    {{
      "class_name": "com.google.android.gms.ads.AdView",
      "method": "loadAd(Lcom/google/android/gms/ads/AdRequest;)V",
      "edit_type": "smali",
      "diff": "    invoke-virtual {{p0, p1}}, Lcom/google/android/gms/ads/AdView;->loadAd(...)V\\n    # replaced with early return",
      "description": "NOP the ad loading call observed at runtime via Frida",
      "confidence": 0.92,
      "file_path": "smali/com/google/android/gms/ads/AdView.smali",
      "location_hint": "line 42",
      "original_snippet": "    invoke-virtual {{p0, p1}}, Lcom/google/android/gms/ads/AdView;->loadAd(Lcom/google/android/gms/ads/AdRequest;)V\\n    return-void",
      "patched_snippet": "    # APK Morph disabled ad load\\n    return-void",
      "hover_explanation": "Early return prevents ad network request (observed via Frida)"
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
      "file_path": "res/values/strings.xml",
      "original_snippet": "<string name=\\"ad_banner_text\\">Advertisement</string>",
      "patched_snippet": "<string name=\\"ad_banner_text\\"></string>",
      "hover_explanation": "Removes visible ad text from UI resources"
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
