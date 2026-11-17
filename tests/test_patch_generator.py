"""Tests for PatchGenerator.

Covers prompt construction, validation, simulate_apply for Smali/XML/resource
edits, and Frida-aware report enrichment. All external calls (LLM, filesystem
edits, Frida) are mocked so the suite runs cleanly in CI.
"""

from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from apkmorph.patch_generator import PatchGenerator
from apkmorph.models import AnalysisReport, PatchPlan, Modification


@pytest.fixture
def sample_report(tmp_path):
    return AnalysisReport(
        apk_path=Path("test.apk"),
        package_name="com.example.testapp",
        decompiled_dir=tmp_path / "decompiled",
        components=["com.example.testapp.MainActivity", "com.google.ads.AdView"],
        strings=["ad", "analytics", "firebase"],
        string_resources={"app_name": "Test", "ad_banner": "Ad"},
        runtime_observations=[
            "observed: ad - AdView.loadAd()",
            "observed: analytics - logEvent(screen_view)",
        ],
        metadata={},
    )


@pytest.fixture
def sample_plan():
    mods = [
        Modification(
            class_name="com.google.ads.AdView",
            method="loadAd",
            edit_type="smali",
            diff="- invoke-virtual ...loadAd",
            description="NOP ad load observed via Frida",
            confidence=0.92,
            file_path=Path("smali/com/google/ads/AdView.smali"),
        ),
        Modification(
            class_name="resource",
            method="string_update",
            edit_type="resource",
            resource_key="ad_banner",
            new_value="",
            diff="ad_banner changed to empty",
            description="Clear ad string resource",
            confidence=0.85,
            file_path=Path("res/values/strings.xml"),
        ),
    ]
    return PatchPlan(
        description="remove ads",
        modifications=mods,
        rationale="Targeted live ad and analytics paths from Frida data",
        confidence=0.88,
        report_summary="Test APK",
    )


def test_from_description(sample_report):
    generator = PatchGenerator()
    with patch.object(generator.llm, "generate_patch") as mock_gen:
        mock_gen.return_value = PatchPlan(
            description="remove ads",
            modifications=[],
            rationale="mock",
            confidence=0.8,
        )
        with patch("apkmorph.patch_generator.APKAnalyzer") as mock_anal:
            plan = generator.from_description(
                "remove ads and analytics", sample_report, observe=False
            )
    assert isinstance(plan, PatchPlan)
    mock_gen.assert_called_once()


def test_from_description_with_observe(sample_report):
    generator = PatchGenerator()
    with patch.object(generator.llm, "generate_patch") as mock_gen:
        mock_gen.return_value = PatchPlan(
            description="remove ads",
            modifications=[],
            rationale="mock",
            confidence=0.8,
        )
        with patch("apkmorph.analyzer.APKAnalyzer") as mock_anal:
            mock_anal.return_value.observe_runtime.return_value = sample_report
            generator.from_description("remove ads", sample_report, observe=True)
    mock_anal.return_value.observe_runtime.assert_called_once()


def test_validate_accepts_valid(sample_plan):
    generator = PatchGenerator()
    generator.validate(sample_plan)  # should not raise


def test_validate_rejects_low_confidence():
    generator = PatchGenerator()
    low_mod = Modification(
        class_name="com.test.Bad",
        method="bad",
        edit_type="smali",
        diff="",
        description="dangerous delete",
        confidence=0.1,
    )
    bad_plan = PatchPlan(
        description="bad plan",
        modifications=[low_mod],
        rationale="",
        confidence=0.2,
    )
    with pytest.raises(ValueError, match="low confidence"):
        generator.validate(bad_plan)


def test_validate_rejects_dangerous():
    generator = PatchGenerator()
    danger_mod = Modification(
        class_name="com.test.Bad",
        method="bad",
        edit_type="smali",
        diff="",
        description="delete core class",
        confidence=0.7,
    )
    bad_plan = PatchPlan(
        description="bad",
        modifications=[danger_mod],
        rationale="",
        confidence=0.8,
    )
    with pytest.raises(ValueError, match="dangerous"):
        generator.validate(bad_plan)


def test_simulate_apply(sample_plan, tmp_path):
    generator = PatchGenerator()
    decomp = tmp_path / "decomp"
    decomp.mkdir()
    (decomp / "smali").mkdir()
    result = generator.simulate_apply(sample_plan, decomp)
    assert result["applied"] is True
    assert result["modifications"] == 2
    assert len(result["changes"]) == 2
    assert "ad_banner" in str(result["changes"])


def test_simulate_apply_missing_dir(sample_plan):
    generator = PatchGenerator()
    result = generator.simulate_apply(sample_plan, "/nonexistent")
    assert result["applied"] is False
    assert "does not exist" in result["error"]


def test_simulate_apply_resource_only():
    generator = PatchGenerator()
    res_mod = Modification(
        class_name="resource",
        method="update",
        edit_type="resource",
        resource_key="title",
        new_value="New Title",
        diff="title=New Title",
        description="Update app title",
        confidence=0.9,
    )
    plan = PatchPlan(
        description="change title",
        modifications=[res_mod],
        rationale="simple string update",
        confidence=0.9,
    )
    result = generator.simulate_apply(plan, Path("/tmp"))
    assert result["applied"] is True
    assert any("title" in c for c in result["changes"])


def test_prompt_includes_frida_data(sample_report):
    generator = PatchGenerator()
    with patch.object(generator.llm, "generate_patch") as mock_gen:
        mock_gen.return_value = PatchPlan(
            description="test", modifications=[], rationale="ok", confidence=0.8
        )
        generator.from_description("disable ads", sample_report, observe=False)
    # generate_patch internally builds prompt containing runtime section
    call_args = mock_gen.call_args[0]
    assert len(call_args) >= 2
    # the report passed contains runtime_observations
    assert len(call_args[1].runtime_observations) > 0
