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

from pydantic import BaseModel, ConfigDict, Field, field_validator


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
        description="Relative path to the file to edit inside decompiled dir",
    )
    confidence: float = Field(0.8, ge=0.0, le=1.0)
    resource_key: Optional[str] = Field(
        default=None, description="For edit_type=resource: the string key"
    )
    new_value: Optional[str] = Field(
        default=None, description="For resource edits: the new string value"
    )
    original_snippet: Optional[str] = Field(
        default=None, description="Original code for diff viewer and patching"
    )
    patched_snippet: Optional[str] = Field(
        default=None, description="Patched code for diff viewer and patching"
    )
    hover_explanation: Optional[str] = Field(
        default=None, description="Tooltip text for UI diff viewer"
    )
    location_hint: Optional[str] = Field(
        default=None, description="Line number or method location"
    )

    @field_validator("confidence")
    @classmethod
    def validate_confidence(cls, v: float) -> float:
        if not 0.0 <= v <= 1.0:
            raise ValueError("confidence must be in range 0.0-1.0")
        return round(v, 2)


class PatchPlan(BaseModel):
    """Structured plan returned by LLM describing all changes to make to an APK."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(
        default_factory=lambda: f"plan_{uuid.uuid4().hex[:8]}",
        description="Unique plan identifier",
    )
    description: str = Field(..., description="The original natural language request")
    rationale: str = Field(..., description="LLM's plain-English reasoning for the changes")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Overall confidence 0-1")
    modifications: List[Modification] = Field(
        default_factory=list, description="List of concrete modifications"
    )
    created_at: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc)
    )

    @field_validator("confidence")
    @classmethod
    def validate_confidence(cls, v: float) -> float:
        return round(v, 2)

    def summary(self) -> str:
        return (
            f"{self.id} | {len(self.modifications)} changes | "
            f"confidence={self.confidence:.2f}"
        )


class AnalysisReport(BaseModel):
    """Immutable report containing all metadata, decompilation artifacts,
    string resources and runtime observations from Frida.
    """

    model_config = ConfigDict(
        extra="forbid",
        frozen=True,
        arbitrary_types_allowed=True,
        json_encoders={Path: str},
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
        return f"{self.package_name} ({self.version_name or 'unknown'}) - {len(self.components)} components, {len(self.strings)} strings"

    def to_markdown(self) -> str:
        md = f"""# APK Analysis Report

**Package:** {self.package_name}

**Version:** {self.version_name} (code: {self.version_code})

**SDK:** min={self.min_sdk} target={self.target_sdk}

**Size:** {self.size_bytes / 1024:.1f} KB

**Main Activity:** {self.main_activity or 'None'}

## Components ({len(self.components)})

"""
        for comp in self.components[:15]:
            md += f"- {comp}\n"
        if len(self.components) > 15:
            md += f"... and {len(self.components)-15} more\n"
        md += f"\n## Runtime Observations ({len(self.runtime_observations)})\n"
        for obs in self.runtime_observations:
            md += f"- {obs}\n"
        return md

    def find_components(self, term: str = "", limit: int = 12) -> List[str]:
        if not term.strip():
            return self.components[:limit]
        term = term.lower()
        return [c for c in self.components if term in c.lower()][:limit]

    def model_copy(self, *, update: Optional[Dict] = None, **kwargs: Any) -> "AnalysisReport":
        if update is None:
            update = {}
        return super().model_copy(update=update, **kwargs)


# For backward compat in tests etc.
__all__ = ["AnalysisReport", "PatchPlan", "Modification"]
