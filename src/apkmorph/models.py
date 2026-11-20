"""Pydantic models for APK Morph.

Defines AnalysisReport (immutable analysis output), PatchPlan and Modification.
All models are used by the analyzer, LLM, patch generator, CLI and UI.
"""

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class Modification(BaseModel):
    """A single targeted edit (Smali, XML, resource or custom plugin)."""

    class_name: str = Field(..., description="Fully-qualified class or special value like 'resource'")
    method: str = Field("", description="Method name/signature (empty for resource edits)")
    edit_type: str = Field("smali", description="smali | xml | resource | <custom_plugin_type>")
    description: str
    confidence: float = Field(0.75, ge=0.0, le=1.0)
    file_path: str = ""
    diff: str = ""
    location_hint: str = ""
    original_snippet: str = ""
    patched_snippet: str = ""
    hover_explanation: str = ""
    resource_key: Optional[str] = None
    new_value: Optional[str] = None
    params: Dict[str, Any] = Field(default_factory=dict)


class PatchPlan(BaseModel):
    """LLM-generated plan containing one or more modifications.

    Can be exported as JSON or embedded into a reusable Python script.
    """

    id: str = Field(
        default_factory=lambda: f"plan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    )
    description: str
    rationale: str = ""
    confidence: float = Field(0.8, ge=0.0, le=1.0)
    modifications: List[Modification] = Field(default_factory=list)


class AnalysisReport(BaseModel):
    """Immutable report produced by APKAnalyzer.decompile() and observe_runtime()."""

    apk_path: Path
    package_name: str
    version_name: Optional[str] = None
    version_code: Optional[str] = None
    min_sdk: Optional[int] = None
    target_sdk: Optional[int] = None
    decompiled_dir: Path
    main_activity: Optional[str] = None
    activities: List[str] = Field(default_factory=list)
    services: List[str] = Field(default_factory=list)
    receivers: List[str] = Field(default_factory=list)
    providers: List[str] = Field(default_factory=list)
    permissions: List[str] = Field(default_factory=list)
    components: List[str] = Field(default_factory=list)
    strings: List[str] = Field(default_factory=list)
    string_resources: Dict[str, str] = Field(default_factory=dict)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    size_bytes: int = 0
    runtime_observations: List[str] = Field(default_factory=list)

    def summary(self) -> str:
        """Return a concise human-readable summary."""
        return (
            f"Package: {self.package_name}\n"
            f"Version: {self.version_name or 'unknown'} (code {self.version_code or 'N/A'})\n"
            f"Components: {len(self.components)} total, {len(self.activities)} activities\n"
            f"Permissions: {len(self.permissions)}\n"
            f"Strings: {len(self.strings)}\n"
            f"Size: {self.size_bytes / 1024:.1f} KB\n"
            f"Runtime observations: {len(self.runtime_observations)}\n"
            f"Decompiled: {self.decompiled_dir}"
        )

    def to_markdown(self) -> str:
        """Markdown representation used in LLM prompts."""
        md = f"# Analysis Report: {self.package_name}\n\n"
        md += f"**Main activity:** {self.main_activity or 'None detected'}\n\n"
        md += "## Components\n"
        for category, items in [
            ("Activities", self.activities),
            ("Services", self.services),
            ("Permissions", self.permissions),
        ]:
            md += f"### {category} ({len(items)})\n"
            for item in items[:6]:
                md += f"- {item}\n"
            if len(items) > 6:
                md += f"- ... and {len(items) - 6} more\n"
            md += "\n"
        if self.strings:
            md += "## Sample Strings (trackers/ads)\n"
            for s in self.strings[:12]:
                md += f"- {s}\n"
            md += "\n"
        if self.runtime_observations:
            md += "## Frida Runtime Observations\n"
            for obs in self.runtime_observations[:10]:
                md += f"- {obs}\n"
        return md

    def find_components(self, term: str = "", limit: int = 10) -> List[str]:
        """Return components matching an optional term (used by prompt builder)."""
        if not term.strip():
            return self.components[:limit]
        term_lower = term.lower()
        return [c for c in self.components if term_lower in c.lower()][:limit]

    def model_copy(self, update: Optional[Dict[str, Any]] = None) -> "AnalysisReport":
        """Return a new copy with optional updates (Pydantic v2 compatible)."""
        data = self.model_dump()
        if update:
            data.update(update)
        return self.__class__.model_validate(data)
