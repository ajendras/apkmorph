"""Tests for PatchGenerator.

Covers from_description (with mocked LLM), validate (valid + error cases),
and simulate_apply for all edit_types (smali, xml, resource). Uses mocks
so no Ollama server or real filesystem is required. Updated for Python 3.12
CI, new Frida-aware prompt path and resource edit support.
"""

import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from apkmorph.patch_generator import PatchGenerator
from apkmorph.llm import LLMClient
from apkmorph.models import AnalysisReport, PatchPlan, Modification


@pytest.fixture
def sample_report():
    return AnalysisReport(
        apk_path=Path("test.apk"),
        package_name="com.example.testapp",
        decompiled_dir=Path("/tmp/decomp"),
        components=["com.example.AdActivity"],
        strings=["ad", "analytics"],
        string_resources={"ad_text": "Buy now!", "app_name": "Test"},
        runtime_observations=["observed: ad - loadAd()"],
        metadata={},
        size_bytes=2048,
    )


@pytest.fixture
def sample_mod():
    return Modification(
        class_name="com.example.AdActivity",
        method="loadAd(Lcom/google/android/gms/ads/AdRequest;)V",
        diff="- invoke-virtual {p0, p1} ...loadAd\n+ return-void",
        description="Disable ad load observed via Frida",
        edit_type="smali",
        confidence=0.92,
        file_path=Path("smali/com/example/AdActivity.smali"),
        original_snippet="invoke-virtual ...",
        patched_snippet="return-void",
        hover_explanation="Early return prevents ad network call",
    )


@pytest.fixture
def sample_plan(sample_mod):
    return PatchPlan(
        description="remove ads and analytics",
        modifications=[sample_mod],
        rationale="Targeted live methods from Frida observations and emptied ad string resource.",
        confidence=0.89,
        report_summary="Test app v1.0 • 12 components",
    )


def test_generator_init():
    gen = PatchGenerator(model="llama3.2")
    assert gen.model == "llama3.2"
    assert isinstance(gen.llm, LLMClient)


@patch.object(LLMClient, "generate_patch")
def test_from_description(mock_generate, sample_report):
    mock_plan = PatchPlan(
        description="remove ads and analytics",
        rationale="Used Frida data to target only executed ad paths.",
        confidence=0.87,
        modifications=[],
    )
    mock_generate.return_value = mock_plan

    generator = PatchGenerator(model="llama3.2")
    plan = generator.from_description("disable ads", sample_report)

    assert plan.description == "remove ads and analytics"
    assert plan.rationale.startswith("Used Frida")
    mock_generate.assert_called_once_with("disable ads", sample_report)


def test_validate_success(sample_plan):
    generator = PatchGenerator()
    # should not raise
    generator.validate(sample_plan)


def test_validate_fails_on_low_confidence():
    generator = PatchGenerator()
    bad_mod = Modification(
        class_name="com.example.Foo",
        method="bar",
        diff="bad change",
        description="low confidence edit",
        edit_type="smali",
        confidence=0.25,
    )
    bad_plan = PatchPlan(
        description="bad",
        modifications=[bad_mod],
        rationale="test",
        confidence=0.3,
    )
    with pytest.raises(ValueError, match="low confidence"):
        generator.validate(bad_plan)


def test_validate_fails_on_missing_fields():
    generator = PatchGenerator()
    bad_mod = Modification(
        class_name="",
        method="",
        diff="",
        description="invalid",
        edit_type="smali",
        confidence=0.8,
    )
    bad_plan = PatchPlan(
        description="bad",
        modifications=[bad_mod],
        rationale="test",
        confidence=0.8,
    )
    with pytest.raises(ValueError, match="must specify class_name and method"):
        generator.validate(bad_plan)


def test_simulate_apply_smali(sample_plan):
    generator = PatchGenerator()
    result = generator.simulate_apply(sample_plan, "/tmp/decomp")

    assert result["success"] is True
    assert result["dry_run"] is True
    assert result["total_changes"] == 1
    assert result["applied"][0]["edit_type"] == "smali"
    assert "AdActivity" in result["applied"][0]["class_name"]
    assert "Frida" in result["rationale"]


def test_simulate_apply_resource_and_xml():
    generator = PatchGenerator()
    mods = [
        Modification(
            class_name="resource",
            method="update_string",
            diff="ad_text changed",
            description="Empty ad string",
            edit_type="resource",
            resource_key="ad_text",
            new_value="",
            confidence=0.88,
        ),
        Modification(
            class_name="com.example.Settings",
            method="onCreate",
            diff="<activity android:name=...>",
            description="Disable analytics receiver",
            edit_type="xml",
            file_path=Path("AndroidManifest.xml"),
            confidence=0.75,
        ),
    ]
    plan = PatchPlan(
        description="clean resources and manifest",
        modifications=mods,
        rationale="Updated string resource and XML per request.",
        confidence=0.82,
    )

    result = generator.simulate_apply(plan, Path("/tmp/decomp"))
    assert result["total_changes"] == 2
    assert result["applied"][0]["resource_key"] == "ad_text"
    assert result["applied"][0]["new_value"] == ""
    assert result["applied"][1]["edit_type"] == "xml"
    assert "AndroidManifest.xml" in str(result["applied"][1]["file_path"])
