"""Tests for PatchGenerator including new XML/resource support."""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from pydantic import ValidationError

from apkmorph.models import AnalysisReport, Modification, PatchPlan
from apkmorph.patch_generator import PatchGenerator


@pytest.fixture
def sample_report(tmp_path: Path) -> AnalysisReport:
    """Minimal report with string resources for testing."""
    return AnalysisReport(
        apk_path=tmp_path / "test.apk",
        package_name="com.example.test",
        decompiled_dir=tmp_path,
        components=["com.example.MainActivity"],
        strings=["analytics", "ad"],
        string_resources={"app_name": "Test", "ad_text": "Buy now"},
        metadata={},
    )


def test_from_description_calls_llm(sample_report: AnalysisReport) -> None:
    """Test that from_description invokes LLM and returns validated plan."""
    generator = PatchGenerator(model="llama3.2")
    mock_plan = PatchPlan(
        description="remove ads",
        rationale="Empty ad string resources",
        modifications=[
            Modification(
                class_name="resource",
                method="strings",
                edit_type="resource",
                resource_key="ad_text",
                new_value="",
                diff="ad_text changed to empty",
                description="Remove ad text",
                file_path=Path("res/values/strings.xml"),
                confidence=0.9,
            )
        ],
    )

    with patch.object(generator.llm, "generate_patch", return_value=mock_plan):
        plan = generator.from_description("remove ads", sample_report)
        assert plan.description == "remove ads"
        assert len(plan.modifications) == 1
        assert plan.modifications[0].edit_type == "resource"


def test_validate_accepts_resource_edit() -> None:
    """Test validation passes for a valid resource modification."""
    plan = PatchPlan(
        description="change string",
        rationale="test",
        modifications=[
            Modification(
                class_name="resource",
                method="update",
                edit_type="resource",
                resource_key="app_name",
                new_value="My App",
                diff="name changed",
                description="Update app name",
                file_path=Path("res/values/strings.xml"),
                confidence=0.85,
            )
        ],
    )
    generator = PatchGenerator()
    # Should not raise
    generator.validate(plan)


def test_validate_rejects_invalid_resource() -> None:
    """Test validation rejects resource edit missing resource_key."""
    plan = PatchPlan(
        description="bad resource",
        rationale="test",
        modifications=[
            Modification(
                class_name="resource",
                method="update",
                edit_type="resource",
                resource_key="",  # missing
                new_value="foo",
                diff="bad",
                description="bad",
                file_path=Path("res/values/strings.xml"),
                confidence=0.9,
            )
        ],
    )
    generator = PatchGenerator()
    with pytest.raises(ValueError, match="must specify resource_key"):
        generator.validate(plan)


def test_simulate_apply_resource(sample_report: AnalysisReport, tmp_path: Path) -> None:
    """Test simulate_apply handles resource edits."""
    mod = Modification(
        class_name="resource",
        method="strings",
        edit_type="resource",
        resource_key="ad_text",
        new_value="",
        diff="ad_text -> ''",
        description="Remove ad text",
        file_path=Path("res/values/strings.xml"),
        confidence=0.88,
    )
    plan = PatchPlan(
        description="test",
        modifications=[mod],
    )

    # Create the target XML
    xml_path = tmp_path / "res" / "values" / "strings.xml"
    xml_path.parent.mkdir(parents=True)
    xml_path.write_text(
        '''<?xml version="1.0" encoding="utf-8"?>
<resources>
    <string name="ad_text">Buy now</string>
</resources>''',
        encoding="utf-8",
    )

    generator = PatchGenerator()
    result = generator.simulate_apply(plan, tmp_path)

    assert result["success"] is True
    assert len(result["applied"]) == 1
    assert result["applied"][0]["edit_type"] == "resource"
