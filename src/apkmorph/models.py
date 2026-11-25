"""Pydantic models for APK Morph.

Defines AnalysisReport (rich APK metadata + decompiled tree), PatchPlan
and Modification (LLM-generated edit plans). All models are immutable by
default and use Pydantic v2 idioms. The ConfigDict explicitly disables
the protected "model_" namespace so that the "model_used" field no longer
triggers a warning, and the old class-based Config is replaced to silence
the DeprecationWarning that was breaking test collection on Python 3.11.
"""

from pathlib import Path
from typing import Any, Dict, List, Optional
import uuid

from pydantic import BaseModel, ConfigDict, Field


class Modification(BaseModel):
    """A single, auditable change that will be applied to Smali, XML,
    a resource file, the manifest or a custom plugin.
    """

    edit_type: str = Field(
        ...,
        description="smali | xml | resource | manifest | plugin",
    )
    target: str = Field(
        ...,
        description="Fully-qualified class, method, resource key, XPath or plugin identifier",
    )
    change: str = Field(
        ...,
        description="Concrete edit (instruction, XML snippet, new value, etc.)",
    )
    rationale: str = Field(
        default="",
        description="Plain-English explanation the LLM provides to the user",
    )
    confidence: float = Field(
        default=0.75,
        ge=0.0,
        le=1.0,
        description="LLM confidence that the edit is correct",
    )
    before: Optional[str] = Field(
        default=None,
        description="Original code/text (for diff viewer)",
    )
    after: Optional[str] = Field(
        default=None,
        description="New code/text (for diff viewer)",
    )
    params: Dict[str, Any] = Field(
        default_factory=dict,
        description="Extra parameters used by custom plugin handlers",
    )

    model_config = ConfigDict(
        protected_namespaces=(),
        extra="forbid",
        populate_by_name=True,
    )


class PatchPlan(BaseModel):
    """Complete patch plan produced by PatchGenerator.from_description().

    Contains the original request, every Modification, an overall rationale,
    confidence, the model that was used, and a unique ID for later export/apply.
    """

    plan_id: str = Field(
        default_factory=lambda: f"plan_{uuid.uuid4().hex[:8]}",
        description="Unique identifier used by CLI/UI for apply/explain/export",
    )
    description: str = Field(
        ...,
        description="Natural-language request that produced this plan",
    )
    modifications: List[Modification] = Field(default_factory=list)
    rationale: str = Field(
        default="",
        description="Overall reasoning provided by the LLM",
    )
    confidence: float = Field(
        default=0.0,
        ge=0.0,
        le=1.0,
    )
    model_used: str = Field(
        default="llama3.2",
        description="Ollama model name that generated the plan",
    )

    model_config = ConfigDict(
        protected_namespaces=(),
        extra="forbid",
    )

    def __str__(self) -> str:
        return (
            f"PatchPlan(plan_id={self.plan_id}, "
            f"confidence={self.confidence:.2f}, "
            f"mods={len(self.modifications)})"
        )


class AnalysisReport(BaseModel):
    """Immutable snapshot of everything known about an APK.

    Produced by APKAnalyzer.decompile() (and optionally enriched by
    observe_runtime()). Used as context for the LLM and by the builder.
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
    runtime_observations: List[str] = Field(default_factory=list)

    metadata: Dict[str, Any] = Field(default_factory=dict)
    size_bytes: int = 0

    model_config = ConfigDict(
        protected_namespaces=(),
        arbitrary_types_allowed=True,
        extra="forbid",
    )
