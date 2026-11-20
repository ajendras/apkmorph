"""Data models for APK Morph.

Uses Pydantic v2 for validation, defaults and immutability where appropriate.
Supports all features including runtime observations, resource edits and plugin params.
"""

from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field


class Modification(BaseModel):
    """Represents one atomic modification suggested by the LLM.

    Used for Smali edits, XML changes, resource string updates and custom plugin
    modifications. The fields original_snippet/patched_snippet/hover_explanation
    power the side-by-side diff viewer.
    """

    class_name: str
    method: str
    edit_type: str = "smali"
    diff: str = ""
    description: str = Field(..., description="Human readable explanation of the change")
    confidence: float = Field(0.75, ge=0.0, le=1.0)
    file_path: str = ""
    location_hint: Optional[str] = None
    original_snippet: str = ""
    patched_snippet: str = ""
    hover_explanation: str = ""
    # For resource edits
    resource_key: Optional[str] = None
    new_value: Optional[str] = None
    # For custom plugin types
    params: Dict[str, Any] = Field(default_factory=dict)


class PatchPlan(BaseModel):
    """Structured output from the LLM describing the patch to apply.

    Persisted to disk for the apply/explain CLI commands.
    """

    id: str = Field(
        default_factory=lambda: f"plan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    )
    description: str
    rationale: str = "No rationale provided by model."
    confidence: float = Field(0.8, ge=0.0, le=1.0)
    modifications: List[Modification] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.now)

    model_config = ConfigDict(frozen=True)

    def summary(self) -> str:
        n = len(self.modifications)
        return f"{self.id} - {self.description} ({n} mods, conf={self.confidence:.2f})"


class AnalysisReport(BaseModel):
    """Full analysis result from decompilation, Androguard and optional Frida observation.

    Immutable. Used as context for the LLM and for applying patches.
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

    model_config = ConfigDict(frozen=True)

    def summary(self) -> str:
        return (
            f"{self.package_name} v{self.version_name or '?'} "
            f"({len(self.components)} components, {len(self.strings)} strings)"
        )

    def to_markdown(self) -> str:
        lines = [
            f"# APK Analysis: {self.apk_path.name}",
            f"**Package:** {self.package_name}",
            f"**Version:** {self.version_name or 'N/A'} (SDK {self.min_sdk}-{self.target_sdk})",
            f"**Components:** {len(self.components)}",
            f"**Strings:** {len(self.strings)} (resources: {len(self.string_resources)})",
            "\n## Runtime Observations",
        ]
        lines.extend(self.runtime_observations or ["(no observations)"])
        lines.append("\n## Key Strings")
        for s in self.strings[:10]:
            lines.append(f"- {s}")
        return "\n".join(lines)

    def find_components(self, term: str = "", limit: int = 12) -> List[str]:
        if not term:
            return self.components[:limit]
        term_l = term.lower()
        return [c for c in self.components if term_l in c.lower()][:limit]
