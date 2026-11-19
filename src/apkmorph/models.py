"""Pydantic models for APK Morph.

Defines the core data structures used across analysis, patch generation,
and UI components. All models are immutable by default and include
helpful validation and helper methods. Extended with runtime_observations
captured by Frida and support for custom plugin patch types.
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
    edit_type: Literal["smali", "xml", "resource"] | str = Field(
        default="smali",
        description="Type of edit: smali, xml, resource or any registered custom plugin name",
    )
    file_path: Optional[Path] = Field(
        None,
        description="Relative path to the file to edit inside the decompiled directory",
    )
    location_hint: Optional[str] = Field(
        None, description="Line number, method offset or XPath for the edit"
    )
    original_snippet: Optional[str] = Field(
        None, description="Original code/XML snippet for the interactive diff viewer"
    )
    patched_snippet: Optional[str] = Field(
        None, description="Patched version for the interactive diff viewer"
    )
    hover_explanation: Optional[str] = Field(
        None, description="Tooltip text explaining the change for the UI"
    )
    resource_key: Optional[str] = Field(
        None, description="Resource key for string/resource edits"
    )
    new_value: Optional[str] = Field(
        None, description="New value for resource/string edits"
    )
    params: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional parameters for custom plugin-based patch types (e.g. colors for a theme injector)",
    )
    confidence: float = Field(
        default=0.8,
        ge=0.0,
        le=1.0,
        description="Confidence that this modification achieves the requested outcome",
    )


class PatchPlan(BaseModel):
    """Structured plan returned by the LLM describing all changes to make."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(
        default_factory=lambda: f"plan_{uuid.uuid4().hex[:8]}",
        description="Unique identifier for this patch plan",
    )
    description: str = Field(..., description="Original natural-language request")
    rationale: str = Field(..., description="Plain-English explanation of the overall strategy")
    confidence: float = Field(
        ..., ge=0.0, le=1.0, description="Overall confidence in the plan (0.0-1.0)"
    )
    modifications: List[Modification] = Field(
        default_factory=list, description="Ordered list of concrete modifications"
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="When the plan was generated",
    )


class AnalysisReport(BaseModel):
    """Immutable report containing everything the LLM and editors need."""

    model_config = ConfigDict(
        extra="forbid", frozen=True, arbitrary_types_allowed=True
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
    size_bytes: int
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    def summary(self) -> str:
        """Short human-readable summary used by the CLI."""
        return (
            f"Package: {self.package_name}\n"
            f"Version: {self.version_name or 'unknown'} (SDK {self.min_sdk}-{self.target_sdk})\n"
            f"Components: {len(self.components)} | Strings: {len(self.strings)}\n"
            f"Runtime observations: {len(self.runtime_observations)} | Size: {self.size_bytes >> 10} KiB"
        )

    def to_markdown(self) -> str:
        """Rich Markdown version used in LLM prompts."""
        comp_sample = "\n".join(f"- {c}" for c in self.components[:8])
        obs_sample = "\n".join(f"- {o}" for o in self.runtime_observations[:8])
        return f"""# Analysis of {self.apk_path.name}

**Package:** {self.package_name}
**Version:** {self.version_name or 'N/A'} (code {self.version_code or 'N/A'})
**SDK:** min {self.min_sdk} / target {self.target_sdk}
**Main activity:** {self.main_activity or 'unknown'}
**Size:** {self.size_bytes >> 10} KiB

## Components (sample)
{comp_sample}

## Runtime observations (Frida)
{obs_sample or 'None recorded.'}

## Extracted strings (sample)
{chr(10).join('- ' + s for s in self.strings[:10])}
"""

    def find_components(self, keyword: str = "", limit: int = 12) -> List[str]:
        """Helper used by LLM prompt construction."""
        if not keyword or not keyword.strip():
            return self.components[:limit]
        k = keyword.lower().strip()
        return [c for c in self.components if k in c.lower()][:limit]
