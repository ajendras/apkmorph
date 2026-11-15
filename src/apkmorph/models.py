"""Pydantic models for APK Morph.

Defines the core data structures used across analysis, patch generation,
and UI components. All models are immutable by default and include
helpful validation and helper methods.
"""

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional
import uuid

from pydantic import BaseModel, ConfigDict, Field


class Modification(BaseModel):
    """A single, auditable modification to be applied to decompiled Smali or XML."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(
        default_factory=lambda: uuid.uuid4().hex[:12],
        description="Unique identifier for this modification step",
    )
    class_name: str = Field(..., description="Fully-qualified Java class name")
    method: str = Field(..., description="Method name or signature being edited")
    diff: str = Field(
        ...,
        description="Human-readable description of the inserted/removed instructions",
    )
    description: str = Field(
        default="",
        description="Plain-English explanation of why this change is needed",
    )
    file_path: Optional[Path] = Field(
        default=None, description="Relative path to the Smali/XML file"
    )
    confidence: float = Field(
        default=0.85,
        ge=0.0,
        le=1.0,
        description="LLM confidence that this edit fulfills the request",
    )
    location_hint: Optional[str] = Field(
        default=None,
        description="Approximate line number or anchor comment in the original file",
    )


class PatchPlan(BaseModel):
    """Complete, LLM-generated plan of modifications for one user request."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    id: str = Field(
        default_factory=lambda: f"plan_{uuid.uuid4().hex[:8]}",
        description="Unique identifier for the entire patch plan",
    )
    description: str = Field(..., description="Original natural-language request")
    modifications: List[Modification] = Field(
        default_factory=list,
        description="Ordered list of concrete code changes",
    )
    rationale: str = Field(
        default="",
        description="Overall reasoning provided by the LLM for the plan",
    )
    confidence: float = Field(
        default=0.8,
        ge=0.0,
        le=1.0,
        description="Aggregate confidence across all modifications",
    )
    report_summary: str = Field(
        default="",
        description="Summary of the APK that was analyzed",
    )
    created_at: datetime = Field(default_factory=datetime.utcnow)


class AnalysisReport(BaseModel):
    """Metadata and structural information extracted from an APK."""

    model_config = ConfigDict(extra="forbid", frozen=True, arbitrary_types_allowed=True)

    id: str = Field(
        default_factory=lambda: f"report_{uuid.uuid4().hex[:8]}",
        description="Unique report identifier",
    )
    apk_path: Path = Field(..., description="Original APK filesystem path")
    package_name: str = Field(..., description="Android application ID")
    version_name: Optional[str] = Field(default=None)
    version_code: Optional[int] = Field(default=None)
    min_sdk: Optional[int] = Field(default=None)
    target_sdk: Optional[int] = Field(default=None)
    decompiled_dir: Path = Field(..., description="Root directory of decompiled sources")
    main_activity: Optional[str] = Field(default=None)
    activities: List[str] = Field(default_factory=list)
    services: List[str] = Field(default_factory=list)
    receivers: List[str] = Field(default_factory=list)
    providers: List[str] = Field(default_factory=list)
    permissions: List[str] = Field(default_factory=list)
    components: List[str] = Field(
        default_factory=list,
        description="All discovered classes and Android components",
    )
    strings: List[str] = Field(
        default_factory=list,
        description="Extracted string constants useful for keyword search",
    )
    metadata: Dict[str, Any] = Field(default_factory=dict)
    size_bytes: int = Field(default=0)
    created_at: datetime = Field(default_factory=datetime.utcnow)

    def summary(self) -> str:
        """Return a compact one-line summary suitable for CLI and UI headers."""
        version = self.version_name or "?.?"
        return (
            f"{self.package_name} v{version} • "
            f"{len(self.components)} components • "
            f"{len(self.permissions)} permissions"
        )

    def find_components(self, keyword: str, limit: int = 10) -> List[str]:
        """Case-insensitive search across component names.

        Used by the analyzer and LLM prompt builder.
        """
        if not keyword:
            return self.components[:limit]
        lower_keyword = keyword.lower()
        matches = [
            comp for comp in self.components if lower_keyword in comp.lower()
        ]
        return matches[:limit]

    def to_markdown(self) -> str:
        """Render a rich Markdown report (used by utils.generate_report_md)."""
        lines = [
            f"# Analysis Report — {self.package_name}",
            "",
            f"**Created:** {self.created_at.isoformat()}",
            f"**APK:** {self.apk_path}",
            f"**Version:** {self.version_name or 'unknown'} (code {self.version_code})",
            f"**SDK:** min {self.min_sdk} / target {self.target_sdk}",
            "",
            "## Permissions",
        ]
        for perm in self.permissions:
            lines.append(f"- `{perm}`")
        lines.append("")
        lines.append("## Main Components")
        for comp in self.components[:20]:
            lines.append(f"- `{comp}`")
        if len(self.components) > 20:
            lines.append(f"... and {len(self.components)-20} more")
        return "\n".join(lines)
