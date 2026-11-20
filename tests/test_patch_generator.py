"""Tests for PatchGenerator.

Covers prompt building (including Frida/runtime data and resources), plan validation,
simulate_apply for Smali/XML/resource edits, and batch processing with full mocking."""
import pytest
from pathlib import Path
from unittest.mock import patch

from apkmorph.patch_generator import PatchGenerator
from apkmorph.models import AnalysisReport, PatchPlan, Modification
from apkmorph.llm import LLMClient


@pytest.fixture
def temp_dir(tmp_path):
    return tmp_path


@pytest.fixture
def sample_report(temp_dir):
    decomp = temp_dir / "decompiled"
    decomp.mkdir()
    return AnalysisReport(
        apk_path=Path("test.apk"),
        package_name="com.test.app",
        decompiled_dir=decomp,
        size_bytes=2048,
        strings=["admob", "firebase"],
        string_resources={"ad_string": "Buy now!", "app_name": "Test"},
        components=["com.test.app.MainActivity", "com.google.ads.AdView"],
        runtime_observations=["observed: ad - loadAd"],
        metadata={},
    )


@pytest.fixture
def sample_plan():
    mod1 = Modification(
        class_name="com.google.ads.AdView",
        method="loadAd",
        edit_type="smali",
        description="Disable ad loading",
        confidence=0.9,
        file_path="smali/com/google/ads/AdView.smali",
        original_snippet="invoke-virtual {p0, p1}, ...loadAd",
        patched_snippet="return-void",
        hover_explanation="Prevents ad display",
    )
    mod2 = Modification(
        class_name="resource",
        method="update_string",
        edit_type="resource",
        resource_key="ad_string",
        new_value="",
        description="Empty ad string",
        confidence=0.85,
        file_path="res/values/strings.xml",
        original_snippet='<string name="ad_string">Buy now!</string>',
        patched_snippet='<string name="ad_string"></string>',
        hover_explanation="Removes ad text from resources",
    )
    return PatchPlan(
        description="remove ads",
        rationale="Targeted live ad load path observed by Frida and ad string.",
        confidence=0.88,
        modifications=[mod1, mod2],
    )


@patch("apkmorph.patch_generator.LLMClient")
def test_from_description(mock_llm_class, sample_report):
    mock_llm = mock_llm_class.return_value
    mock_llm.generate_patch.return_value = sample_plan()
    generator = PatchGenerator(model="llama3.2")
    plan = generator.from_description("remove all ads", sample_report)
    assert isinstance(plan, PatchPlan)
    assert plan.description == "remove ads"
    assert len(plan.modifications) == 2
    mock_llm.generate_patch.assert_called_once()


def test_llm_builds_prompt_with_frida_and_resources(sample_report):
    llm = LLMClient(model="llama3.2")
    prompt = llm._build_patch_prompt("disable analytics and remove ads", sample_report)
    assert "Runtime observations from Frida" in prompt
    assert "firebase" in prompt
    assert "ad_string" in prompt
    assert "observed: ad - loadAd" in prompt
    assert "resource keys" in prompt


def test_validate_plan(sample_plan):
    generator = PatchGenerator()
    validated = generator.validate(sample_plan)
    assert isinstance(validated, PatchPlan)


def test_simulate_apply(sample_plan, sample_report, temp_dir):
    generator = PatchGenerator()
    with patch("apkmorph.patch_generator.SmaliEditor") as mock_editor, \
         patch("apkmorph.builder.APKBuilder") as mock_builder:
        mock_editor.return_value.apply_modification.return_value = True
        mock_builder.return_value.rebuild_and_sign.return_value = Path("patched.apk")
        result = generator.simulate_apply(sample_plan, sample_report.decompiled_dir)
        assert result["applied"] is True
        assert "patched" in str(result.get("output", ""))


def test_batch(sample_report, temp_dir):
    generator = PatchGenerator()
    apk_list = ["app1.apk", "app2.apk"]
    with patch.object(generator, "from_description") as mock_from, \
         patch.object(generator, "apply_plan") as mock_apply, \
         patch("apkmorph.analyzer.APKAnalyzer") as mock_analyzer_class:
        mock_from.return_value = sample_plan()
        mock_apply.return_value = Path(temp_dir / "patched_test.apk")
        mock_analyzer = mock_analyzer_class.return_value
        mock_analyzer.decompile.return_value = sample_report
        results = generator.batch(
            description="disable analytics",
            apk_paths=apk_list,
            output_dir=temp_dir,
            model="phi3",
            observe_runtime=False,
        )
        assert len(results) == 2
        assert all(r.get("success", False) for r in results)
        assert mock_from.call_count == 2


def test_resource_edit_in_plan(sample_plan):
    resource_mods = [m for m in sample_plan.modifications if m.edit_type == "resource"]
    assert len(resource_mods) == 1
    mod = resource_mods[0]
    assert mod.resource_key == "ad_string"
    assert mod.new_value == ""
