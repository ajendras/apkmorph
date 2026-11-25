"""Data models for APK Morph.

Pydantic models for AnalysisReport, PatchPlan, Modification and related types.
Supports edit_type values including the newly added manifest operations.
"""

from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

from pydantic import BaseModel, Field


class Modification(BaseModel):
    """A single targeted change to an APK."""

    edit_type: Literal[
        "smali",
        "xml",
        "resource",
        "manifest",
        "plugin",
    ]
    target: str = Field(
        ..., description="Class/method for smali, filename for xml/resource, or element for manifest"
    )
    description: str = Field(..., description="Plain-English description of the change")
    before: str = ""
    after: str = ""
    params: Dict[str, Any] = Field(default_factory=dict)
    rationale: str
    confidence: float = Field(0.75, ge=0.0, le=1.0)


class PatchPlan(BaseModel):
    """Complete plan returned by the LLM / PatchGenerator."""

    description: str
    modifications: List[Modification]
    rationale: str
    confidence: float = Field(0.8, ge=0.0, le=1.0)
    model_used: str = "llama3.2"


class AnalysisReport(BaseModel):
    """Immutable report produced by APKAnalyzer."""

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

    class Config:
        arbitrary_types_allowed = True
        json_encoders = {Path: str}


class ManifestEditParams(BaseModel):
    """Structured parameters for manifest edits."""

    operation: Literal[
        "add_permission",
        "remove_permission",
        "add_activity",
        "remove_activity",
        "add_receiver",
        "remove_receiver",
    ]
    name: str
    attributes: Dict[str, str] = Field(default_factory=dict)
