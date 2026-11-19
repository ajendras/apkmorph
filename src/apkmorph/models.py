"""Pydantic models for APK Morph.

Defines the core data structures used across analysis, patch generation,
and UI components. All models are immutable by default and include
helpful validation and helper methods. Extended with runtime_observations
captured by Frida.
"""

from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional
import uuid

from pydantic import BaseModel, ConfigDict, Field


class Modification(BaseModel):
    """A single, auditable modification to be applied to decompiled Smali, XML or resources."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(
        default_factory=lambda: uuid.uuid4().hex[:12],
        description="Unique identifier for this modification step",
    )
    class_name: str = Field(..., description="Fully-qualified Java class name (empty for resources)")
    method: str = Field(..., description="Method name/signature or resource identifier")
    diff: str = Field(
        ...,
        description="Human-readable description of the inserted/removed instructions or string change",
    )
    description: str = Field(
        default="",
        description="Plain-English explanation of why this change is needed",
    )
    edit_type: Literal["smali", "xml", "resource"] = Field(
        default="smali",
        description="Type of edit: smali, xml or resource (updates resources.arsc on rebuild)",
    )
    file_path: Optional[Path] = Field(
        default=None,
        description="Relative path to the file to edit inside decompiled_dir",
    )
    confidence: float = Field(
        default=0.8,
        ge=0.0,
        le=1.0,
        description="Confidence score for this modification",
    )
    location_hint: Optional[str] = Field(default=None, description="e.g. line number or method offset")
    original_snippet: Optional[str] = Field(default=None, description="Original code snippet")
    patched_snippet: Optional[str] = Field(default=None, description="After patch snippet")
    hover_explanation: Optional[str] = Field(
        default=None, description="Explanation shown in UI on hover"
    )
    resource_key: Optional[str] = Field(default=None, description="For resource edits")
    new_value: Optional[str] = Field(default=None, description="New value for string resource")


class AnalysisReport(BaseModel):
    """Immutable report containing all data extracted from an APK.

    Includes decompilation metadata, components, strings, resource map,
    runtime observations from Frida, and helper methods for tests and LLM.
    """

    model_config = ConfigDict(extra="forbid", arbitrary_types_allowed=True)

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
    runtime_observations: List[str] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    size_bytes: int = 0

    def summary(self) -> str:
        """Return a compact human-readable summary."""
        return (
            f"APK: {self.apk_path.name} ({self.size_bytes / 1024:.1f} KB)\n"
            f"Package: {self.package_name}\n"
            f"Version: {self.version_name or 'N/A'}\n"
            f"Components: {len(self.components)}\n"
            f"Strings: {len(self.strings)}\n"
            f"Runtime observations: {len(self.runtime_observations)}\n"
            f"Confidence in analysis: high"
        )

    def to_markdown(self) -> str:
        """Return a rich Markdown report for CLI/UI and LLM context."""
        lines = [
            f"# Analysis Report: {self.apk_path.name}",
            f"**Package:** `{self.package_name}`",
            f"**Version:** {self.version_name or 'unknown'} (code {self.version_code or 'unknown'})",
            f"**SDK:** min={self.min_sdk} target={self.target_sdk}",
            f"**Size:** {self.size_bytes} bytes",
            "",
            "## Components",
            f"- Activities: {len(self.activities)}",
            f"- Services: {len(self.services)}",
            f"- Other: {len(self.components) - len(self.activities)}",
            "",
            "## Discovered Strings (sample)",
        ]
        for s in self.strings[:15]:
            lines.append(f"- `{s}`")
        if self.runtime_observations:
            lines.append("")
            lines.append("## Frida Runtime Observations")
            for obs in self.runtime_observations:
                lines.append(f"- {obs}")
        lines.append("")
        lines.append("Generated by APK Morph Analyzer.")
        return "\n".join(lines)

    def find_components(self, term: str = "", limit: int = 10) -> List[str]:
        """Return components matching optional term, limited."""
        if not term or not term.strip():
            return self.components[:limit]
        term_l = term.lower()
        matches = [c for c in self.components if term_l in c.lower()]
        return matches[:limit]


class PatchPlan(BaseModel):
    """Structured plan returned by the LLM describing the patches to apply."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(default_factory=lambda: "plan_" + uuid.uuid4().hex[:8])
    description: str
    rationale: str = ""
    confidence: float = Field(0.75, ge=0.0, le=1.0)
    modifications: List[Modification] = Field(default_factory=list)
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )
