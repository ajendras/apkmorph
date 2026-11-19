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
        description="Relative path to the file being modified inside decompiled_dir",
    )
    confidence: float = Field(
        default=0.8,
        ge=0.0,
        le=1.0,
        description="Confidence score for this modification (0.0-1.0)",
    )
    location_hint: Optional[str] = Field(
        default=None,
        description="Line number or other location hint for the change",
    )
    resource_key: Optional[str] = Field(
        default=None,
        description="For resource edits, the string key name",
    )
    new_value: Optional[str] = Field(
        default=None,
        description="New value for resource/string edits",
    )
    original_snippet: Optional[str] = Field(
        default=None,
        description="Original code snippet for the interactive diff viewer",
    )
    patched_snippet: Optional[str] = Field(
        default=None,
        description="Patched code snippet for the interactive diff viewer",
    )
    hover_explanation: Optional[str] = Field(
        default=None,
        description="Explanation shown on hover in the UI diff viewer",
    )


class PatchPlan(BaseModel):
    """LLM-generated plan containing a rationale and list of Modifications."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(
        default_factory=lambda: "plan_" + uuid.uuid4().hex[:8],
        description="Unique plan identifier",
    )
    description: str = Field(..., description="Original natural-language request")
    rationale: str = Field(..., description="LLM's plain-English reasoning")
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Overall confidence in the generated plan",
    )
    modifications: List[Modification] = Field(
        default_factory=list, description="Ordered list of modifications to apply"
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp when the plan was created",
    )


class AnalysisReport(BaseModel):
    """Immutable report produced by APKAnalyzer.decompile() and observe_runtime()."""

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        arbitrary_types_allowed=True,
    )

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
        """Return a concise one-line-per-field summary for CLI display."""
        return (
            f"Package: {self.package_name}\n"
            f"Version: {self.version_name or 'N/A'} (code {self.version_code or 'N/A'})\n"
            f"SDK: min={self.min_sdk} target={self.target_sdk}\n"
            f"Components: {len(self.components)} total\n"
            f"Strings: {len(self.strings)}\n"
            f"Resources: {len(self.string_resources)}\n"
            f"Observations: {len(self.runtime_observations)}\n"
            f"Size: {self.size_bytes / 1024:.1f} KB"
        )

    def to_markdown(self) -> str:
        """Return a rich Markdown report suitable for LLM context."""
        obs = "\n".join(f"* {o}" for o in self.runtime_observations[:8]) or "None."
        comps = "\n".join(f"* `{c}`" for c in self.components[:8])
        sample_strings = "\n".join(f"* `{s}`" for s in self.strings[:5])
        return f"""# Analysis Report: {self.apk_path.name}

**Package:** `{self.package_name}`
**Version:** {self.version_name or 'N/A'} (code: {self.version_code or 'N/A'})
**SDK:** min={self.min_sdk} / target={self.target_sdk}
**Main activity:** {self.main_activity or 'None detected'}
**Size:** {self.size_bytes / 1024:.1f} KB

## Components ({len(self.components)} total)
{comps}
(... {max(0, len(self.components) - 8)} more)

## Runtime Observations (Frida)
{obs}

## Extracted Strings (sample)
{sample_strings}
(... {max(0, len(self.strings) - 5)} more)

**String resources available for editing:** {len(self.string_resources)} keys
**Decompiled directory:** {self.decompiled_dir}
"""

    def find_components(self, term: str = "", limit: int = 12) -> List[str]:
        """Return components matching a (case-insensitive) term.

        Used by LLM prompt builder. Empty term returns first N components.
        """
        if not term or not term.strip():
            return self.components[:limit]
        k = term.lower().strip()
        return [c for c in self.components if k in c.lower()][:limit]
