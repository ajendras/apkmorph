"""Pydantic models for APK Morph.

Defines immutable data structures for analysis reports, patch plans,
and modifications. Supports string resources, runtime observations
from Frida, XML/resource edits, and custom plugin edit types.
Now includes feedback_history to support the iterative prompt refinement loop.
"""

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, Field


class Modification(BaseModel):
    """A single targeted modification (Smali, XML, resource, or plugin)."""

    edit_type: str = Field(
        default="smali",
        description="smali | xml | resource | custom plugin name",
    )
    class_name: str = Field(..., description="Class, resource key, or XML target")
    method: str = Field(default="", description="Method or edit context")
    description: str = Field(..., description="Plain-English rationale for this edit")
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)
    diff: str = Field(default="", description="Before/after diff (if applicable)")
    params: Dict[str, Any] = Field(
        default_factory=dict,
        description="Extra parameters (e.g. string value, color for theme plugin)",
    )


class PatchPlan(BaseModel):
    """LLM-generated plan containing one or more modifications.
    Supports feedback_history for the UI refinement loop.
    """

    id: str = Field(
        default_factory=lambda: f"plan_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
        description="Unique identifier",
    )
    description: str = Field(..., description="Original natural-language request")
    modifications: List[Modification] = Field(default_factory=list)
    rationale: str = Field(default="", description="LLM reasoning and explanations")
    confidence: float = Field(default=0.75, ge=0.0, le=1.0)
    created_at: datetime = Field(default_factory=datetime.now)
    feedback_history: List[str] = Field(
        default_factory=list, description="User feedback used for iterative refinement"
    )

    def summary(self) -> str:
        """Short summary for CLI/UI."""
        fb = f", {len(self.feedback_history)} refinements" if self.feedback_history else ""
        return (
            f"PatchPlan {self.id} — {len(self.modifications)} mods, "
            f"confidence {self.confidence:.2f}{fb}"
        )


class AnalysisReport(BaseModel):
    """Full analysis of an APK (decompilation + Androguard + Frida observations).

    Defaults are provided on all optional fields so tests can construct
    minimal reports without triggering validation errors.
    """

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
        """One-line summary used by CLI and UI."""
        return (
            f"{self.package_name} v{self.version_name or '?.?'} "
            f"({self.size_bytes} bytes, {len(self.components)} components, "
            f"{len(self.runtime_observations)} observations)"
        )

    def model_copy(self, *, update: Optional[Dict[str, Any]] = None) -> "AnalysisReport":
        """Return a copy with optional updates (Pydantic v2 style)."""
        data = self.model_dump()
        if update:
            data.update(update)
        return AnalysisReport(**data)
