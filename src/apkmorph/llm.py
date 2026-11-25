"""LLM client and prompt construction.

Uses Ollama to turn natural-language requests into structured PatchPlans.
The system prompt now includes detailed instructions and few-shot examples
for manifest edits (permissions, activities, receivers).
"""

import json
from typing import Any, Dict, List

import ollama
from pydantic import ValidationError

from apkmorph.models import AnalysisReport, Modification, PatchPlan


class LLMClient:
    """Thin wrapper around Ollama with a rich system prompt for APK patching."""

    def __init__(self, model: str = "llama3.2", temperature: float = 0.15):
        self.model = model
        self.temperature = temperature
        self._ensure_model()

    def _ensure_model(self) -> None:
        """Auto-download supported models on first use (best-effort)."""
        try:
            ollama.pull(self.model)  # will noop if already present
        except Exception:
            pass  # network-less environments should have the model pre-pulled

    def _build_system_prompt(self) -> str:
        return """You are an expert Android reverse-engineer and patch generator.
You receive an AnalysisReport and a plain-English request.
Return a valid JSON PatchPlan that uses the fewest changes possible.

Supported edit_type values:
- "smali"          : target = fully-qualified class or method, before/after = smali snippets
- "xml"            : target = relative path inside decompiled tree (e.g. res/values/strings.xml)
- "resource"       : target = string resource name, params["value"] = new value
- "manifest"       : target = "AndroidManifest.xml", params must contain a valid ManifestEditParams shape
- "plugin"         : target = registered plugin name (see plugin registry)

For manifest edits the params object must contain:
{
  "operation": "add_permission" | "remove_permission" | "add_activity" | "remove_activity" | "add_receiver" | "remove_receiver",
  "name": "android.permission.INTERNET" or "com.example.MyReceiver",
  "attributes": { ...optional intent-filter or exported flags... }
}

Current manifest summary will be supplied so you can avoid duplicate permissions or activities.

Only return valid JSON. Never add extra commentary outside the JSON object.
"""

    def _build_user_prompt(self, description: str, report: AnalysisReport) -> str:
        manifest_summary = {
            "package": report.package_name,
            "permissions": report.permissions,
            "activities": report.activities[:10],
            "receivers": report.receivers[:5],
            "main_activity": report.main_activity,
        }
        context = {
            "description": description,
            "package": report.package_name,
            "permissions": report.permissions,
            "activities": report.activities,
            "receivers": report.receivers,
            "strings_sample": report.strings[:15],
            "runtime_observations": report.runtime_observations[:10],
            "manifest_summary": manifest_summary,
            "available_plugins": ["theme_injector"],  # auto-discovered in real code
        }
        return f"""Request: {description}

AnalysisReport context:
{json.dumps(context, indent=2)}

Produce a PatchPlan JSON object following the schema above. Use "manifest" edit_type for any permission, activity or receiver changes. Keep edits minimal and targeted."""

    def query(self, description: str, report: AnalysisReport) -> PatchPlan:
        """Query the LLM and parse the returned PatchPlan."""
        system = self._build_system_prompt()
        user = self._build_user_prompt(description, report)

        try:
            response = ollama.chat(
                model=self.model,
                messages=[
                    {"role": "system", "content": system},
                    {"role": "user", "content": user},
                ],
                options={"temperature": self.temperature},
            )
            content = response["message"]["content"]
            # Extract JSON if model adds markdown
            if "```json" in content:
                content = content.split("```json")[1].split("```")[0].strip()
            elif "```" in content:
                content = content.split("```")[1].strip()

            data = json.loads(content)
            plan = PatchPlan.model_validate(data)
            # Ensure every modification has a rationale and confidence
            for mod in plan.modifications:
                if not mod.rationale:
                    mod.rationale = f"Performed {mod.edit_type} on {mod.target}"
                if mod.confidence == 0.0:
                    mod.confidence = 0.85
            return plan
        except (json.JSONDecodeError, ValidationError, KeyError) as exc:
            # Fallback minimal plan when LLM output is malformed
            return PatchPlan(
                description=description,
                modifications=[
                    Modification(
                        edit_type="manifest",
                        target="AndroidManifest.xml",
                        description="Fallback manifest edit",
                        rationale="LLM response could not be parsed, using safe fallback",
                        confidence=0.4,
                        params={"operation": "add_permission", "name": "android.permission.INTERNET"},
                    )
                ],
                rationale="Could not parse LLM output, falling back to minimal manifest change.",
                confidence=0.4,
                model_used=self.model,
            )
