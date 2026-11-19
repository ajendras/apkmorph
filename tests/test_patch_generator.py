"""Tests for PatchGenerator.

Covers prompt construction (via LLMClient), PatchPlan/Modification validation,
simulate_apply for Smali/XML/resource edits, batch mode, and the new
Frida-aware and resource-editing paths. Uses mocks so tests run in CI
without Ollama server, Frida device or real APKs.
"""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from apkmorph.llm import LLMClient
from apkmorph.models import AnalysisReport, Modification, PatchPlan
from apkmorph.patch_generator import PatchGenerator


@pytest.fixture
def sample_report(tmp_path):
    return AnalysisReport(
        apk_path=tmp_path / "test.apk",
        package_name="com.example.app",
        decompiled_dir=tmp_path / "decomp",
        size_bytes=102400,
        strings=["firebase", "admob", "crashlytics"],
        string_resources={"app_name": "Test", "ad_text": "Advertisement"},
        components=["com.example.MainActivity", "com.google.ads.AdView"],
        activities=["com.example.MainActivity"],
        services=[],
        receivers=[],
        providers=[],
        permissions=["android.permission.INTERNET"],
        metadata={},
        main_activity="com.example.MainActivity",
        version_name="1.0",
        version_code="1",
        min_sdk=24,
        target_sdk=34,
        runtime_observations=[
            "observed: ad - com.google.android.gms.ads.AdView.loadAd() called",
            "observed: analytics - FirebaseAnalytics.logEvent()",
        ],
    )


def test_modification_and_plan_models():
    mod = Modification(
        class_name="com.google.ads.AdView",
        method="loadAd",
        diff="- invoke-virtual ...AdView;->loadAd",
        description="NOP ad load observed via Frida",
        edit_type="smali",
        confidence=0.92,
        file_path=Path("smali/com/google/ads/AdView.smali"),
        original_snippet="invoke-virtual {p0, p1}",
        patched_snippet="# APK Morph disabled ad load\nreturn-void",
        hover_explanation="Early return prevents ad network request (observed via Frida)",
        resource_key=None,
        new_value=None,
    )
    plan = PatchPlan(
        description="remove ads",
        rationale="Frida showed ad loads; replaced with early return and emptied ad string resource.",
        confidence=0.88,
        modifications=[mod],
    )
    assert plan.id.startswith("plan_")
    assert len(plan.modifications) == 1
    assert plan.modifications[0].confidence == 0.92
    assert plan.modifications[0].edit_type == "smali"


def test_llm_generate_patch(sample_report):
    valid_json = """
{
  "description": "disable all analytics and remove ads",
  "rationale": "Frida observations showed Firebase and AdView calls; targeted those methods and emptied ad string resource.",
  "confidence": 0.87,
  "modifications": [
    {
      "class_name": "com.google.android.gms.ads.AdView",
      "method": "loadAd(Lcom/google/android/gms/ads/AdRequest;)V",
      "edit_type": "smali",
      "diff": "    invoke-virtual {p0, p1} ...\\n    # replaced with early return",
      "description": "NOP the ad loading call observed at runtime via Frida",
      "confidence": 0.92,
      "file_path": "smali/com/google/android/gms/ads/AdView.smali",
      "location_hint": "line 42",
      "original_snippet": "    invoke-virtual {p0, p1} ...\\n    return-void",
      "patched_snippet": "    # APK Morph disabled ad load\\n    return-void",
      "hover_explanation": "Early return prevents ad network request (observed via Frida)"
    },
    {
      "class_name": "resource",
      "method": "update_string",
      "edit_type": "resource",
      "resource_key": "ad_banner_text",
      "new_value": "",
      "diff": "ad_banner_text changed from 'Advertisement' to empty string",
      "description": "Empty ad-related string resource (updates resources.arsc)",
      "confidence": 0.88,
      "file_path": "res/values/strings.xml",
      "original_snippet": "<string name=\\"ad_banner_text\\">Advertisement</string>",
      "patched_snippet": "<string name=\\"ad_banner_text\\"></string>",
      "hover_explanation": "Removes visible ad text from UI resources"
    }
  ]
}
"""
    with patch("apkmorph.llm.ollama") as mock_ollama:
        mock_ollama.chat.return_value = valid_json
        client = LLMClient(model="llama3.2")
        plan = client.generate_patch("disable all analytics and remove ads", sample_report)
        assert isinstance(plan, PatchPlan)
        assert len(plan.modifications) == 2
        assert any(m.edit_type == "resource" for m in plan.modifications)
        assert any("Frida" in plan.rationale for m in [plan])  # pylint: disable=use-a-generator
        mock_ollama.chat.assert_called_once()


def test_patch_generator_from_description(sample_report):
    with patch("apkmorph.patch_generator.LLMClient") as MockLLM:
        mock_client = MagicMock()
        mock_client.generate_patch.return_value = PatchPlan(
            description="test",
            rationale="test rationale",
            confidence=0.9,
            modifications=[],
        )
        MockLLM.return_value = mock_client

        generator = PatchGenerator(model="phi3")
        plan = generator.from_description("remove ads", sample_report)
        assert isinstance(plan, PatchPlan)
        MockLLM.assert_called_once_with(model="phi3")
        mock_client.generate_patch.assert_called_once_with("remove ads", sample_report)


def test_simulate_apply(sample_report, tmp_path):
    plan = PatchPlan(
        description="test",
        rationale="test",
        confidence=0.8,
        modifications=[
            Modification(
                class_name="com.example.Main",
                method="onCreate",
                diff="return-void",
                description="nop",
                edit_type="smali",
                file_path=Path("smali/com/example/Main.smali"),
            )
        ],
    )
    generator = PatchGenerator()
    with patch("apkmorph.patch_generator.SmaliEditor") as _, patch(
        "apkmorph.patch_generator.XMLResourceEditor"
    ) as _:
        result = generator.simulate_apply(plan, str(tmp_path))
        assert isinstance(result, dict)
        assert result["applied"] == 1
        assert "plan_id" in result


def test_batch(sample_report, tmp_path):
    with patch("apkmorph.patch_generator.PatchGenerator.from_description") as mock_from, patch(
        "apkmorph.patch_generator.PatchGenerator.apply_plan"
    ) as mock_apply, patch("apkmorph.analyzer.APKAnalyzer") as MockAnalyzer:
        mock_from.return_value = PatchPlan(
            description="batch test",
            rationale="ok",
            confidence=0.8,
            modifications=[],
        )
        mock_apply.return_value = Path("patched.apk")
        mock_analyzer_instance = MagicMock()
        mock_analyzer_instance.decompile.return_value = sample_report
        MockAnalyzer.return_value = mock_analyzer_instance

        generator = PatchGenerator(model="llama3.2")
        results = generator.batch(
            description="disable analytics",
            apk_paths=[str(tmp_path / "a.apk"), str(tmp_path / "b.apk")],
            output_dir=tmp_path / "out",
            model="llama3.2",
            observe_runtime=False,
        )
        assert len(results) == 2
        assert all(r.get("success", False) for r in results)
        assert mock_from.call_count == 2
