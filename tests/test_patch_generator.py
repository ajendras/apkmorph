"""Tests for PatchGenerator including prompt construction, validation and simulation
for Smali, XML and resource edits.
"""

import pytest
from pathlib import Path
from unittest.mock import patch

from apkmorph.patch_generator import PatchGenerator
from apkmorph.models import AnalysisReport, PatchPlan, Modification


@pytest.fixture
def sample_report(tmp_path: Path) -> AnalysisReport:
    return AnalysisReport(
        apk_path=tmp_path / "app.apk",
        package_name="com.example.app",
        decompiled_dir=tmp_path,
        components=["com.example.MainActivity", "com.google.ads.AdView"],
        strings=["Advertisement", "Analytics"],
        string_resources={"ad_text": "Ad", "app_name": "App"},
        runtime_observations=[
            "observed: ad - loadAd()",
            "observed: analytics - logEvent()",
        ],
    )


@pytest.fixture
def sample_plan() -> PatchPlan:
    mod1 = Modification(
        class_name="com.google.ads.AdView",
        method="loadAd",
        diff="- invoke-virtual {p0, p1} ... \n+ return-void",
        description="Prevent ad loading observed at runtime",
        edit_type="smali",
        confidence=0.92,
        file_path=Path("smali/com/google/ads/AdView.smali"),
    )
    mod2 = Modification(
        class_name="resource",
        method="string_update",
        diff="ad_text changed to empty",
        description="Empty the ad banner text",
        edit_type="resource",
        resource_key="ad_text",
        new_value="",
        confidence=0.85,
        file_path=Path("res/values/strings.xml"),
    )
    return PatchPlan(
        description="disable ads and analytics",
        rationale="Targeted live methods from Frida observations and updated resource string",
        confidence=0.88,
        modifications=[mod1, mod2],
        report_summary="com.example.app v1.0 • ...",
    )


def test_from_description(sample_report: AnalysisReport) -> None:
    generator = PatchGenerator(model="llama3.2")
    mock_plan = PatchPlan(
        description="test request",
        rationale="test rationale",
        confidence=0.75,
        modifications=[],
    )
    with patch.object(generator.llm, "generate_patch", return_value=mock_plan):
        plan = generator.from_description(
            "remove ads", sample_report, observe=False
        )
        assert plan.description == "test request"
        assert plan.report_summary == sample_report.summary()


def test_validate(sample_plan: PatchPlan) -> None:
    generator = PatchGenerator()
    # should pass
    assert generator.validate(sample_plan) is True


def test_validate_low_confidence(sample_plan: PatchPlan) -> None:
    # create a low confidence mod
    bad_mod = Modification(
        class_name="Bad",
        method="bad",
        diff="bad",
        description="bad",
        edit_type="smali",
        confidence=0.4,
    )
    bad_plan = sample_plan.model_copy(
        update={"modifications": [bad_mod]}
    )
    generator = PatchGenerator()
    with pytest.raises(ValueError, match="confidence too low"):
        generator.validate(bad_plan)


def test_simulate_apply(sample_plan: PatchPlan, tmp_path: Path) -> None:
    generator = PatchGenerator()
    result = generator.simulate_apply(sample_plan, tmp_path)
    assert result["success"] is True
    assert result["simulated"] is True
    assert len(result["applied"]) == 2
    assert result["plan_id"] == sample_plan.id
    resource_mods = [a for a in result["applied"] if a["edit_type"] == "resource"]
    assert len(resource_mods) == 1
    assert resource_mods[0]["target"] == "ad_text"
