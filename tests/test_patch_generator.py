"""Tests for patch generation and application logic.

Tests prompt construction, plan validation, simulation of edits (Smali, XML, resource),
batch processing, and integration with runtime observations.
"""

import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from apkmorph.patch_generator import PatchGenerator
from apkmorph.models import AnalysisReport, PatchPlan, Modification
from apkmorph.analyzer import APKAnalyzer


@pytest.fixture
def sample_report(tmp_path: Path):
    return AnalysisReport(
        apk_path=tmp_path / "sample.apk",
        package_name="com.example.sample",
        version_name="2.0",
        version_code="20",
        min_sdk=21,
        target_sdk=33,
        decompiled_dir=tmp_path / "decompiled_sample",
        main_activity="com.example.sample.MainActivity",
        activities=["com.example.sample.MainActivity"],
        services=[],
        receivers=[],
        providers=[],
        permissions=[],
        components=["com.example.sample.MainActivity"],
        strings=["logEvent", "loadAd", "Firebase"],
        string_resources={"welcome_message": "Welcome to the app!", "ad_text": "Sponsored"},
        metadata={},
        size_bytes=5000000,
        runtime_observations=[
            "observed: analytics - FirebaseAnalytics.logEvent() called",
            "observed: ad - com.google.android.gms.ads.AdView.loadAd() called 3 times",
        ],
    )


@pytest.fixture
def sample_plan():
    mod1 = Modification(
        class_name="com.google.firebase.analytics.FirebaseAnalytics",
        method="logEvent(Ljava/lang/String;Landroid/os/Bundle;)V",
        edit_type="smali",
        diff="    return-void\n    # analytics disabled by APK Morph",
        description="Replace analytics logEvent with early return based on Frida observation",
        confidence=0.88,
        file_path="smali/com/google/firebase/analytics/FirebaseAnalytics.smali",
        location_hint="line 45",
        original_snippet="    invoke-virtual {p0, p1, p2}, ...->logEvent",
        patched_snippet="    return-void",
        hover_explanation="Prevents analytics event from being sent to server (observed at runtime)",
    )
    mod2 = Modification(
        class_name="resource",
        method="update_string",
        edit_type="resource",
        resource_key="ad_text",
        new_value="",
        diff='ad_text=""',
        description="Empty the ad_text string resource",
        confidence=0.75,
        file_path="res/values/strings.xml",
        original_snippet='<string name="ad_text">Sponsored</string>',
        patched_snippet='<string name="ad_text"></string>',
        hover_explanation="Removes ad text from the compiled resources.arsc",
    )
    return PatchPlan(
        description="disable analytics and remove ads",
        rationale="Used Frida runtime observations to target live analytics and ad paths. Also cleared ad string resource.",
        confidence=0.82,
        modifications=[mod1, mod2],
        id="plan_test123",
    )


def test_from_description(sample_report: AnalysisReport):
    with patch("apkmorph.patch_generator.LLMClient.generate_patch") as mock_generate:
        mock_generate.return_value = sample_plan()
        generator = PatchGenerator(model="phi3")
        plan = generator.from_description("disable analytics and remove ads", sample_report)
        assert plan.confidence > 0.7
        assert len(plan.modifications) == 2
        assert any(m.edit_type == "resource" for m in plan.modifications)
        assert any("Frida" in m.description for m in plan.modifications)
        mock_generate.assert_called_once()


def test_validate(sample_plan: PatchPlan):
    generator = PatchGenerator()
    validated_plan = generator.validate(sample_plan)
    assert validated_plan.id == "plan_test123"
    assert validated_plan.confidence == 0.82


def test_simulate_apply(sample_plan: PatchPlan, tmp_path: Path, sample_report: AnalysisReport):
    generator = PatchGenerator()
    simulation = generator.simulate_apply(sample_plan, sample_report.decompiled_dir)
    assert simulation is not None
    assert simulation["applied"] is True
    assert len(simulation.get("modifications", [])) == 2
    assert "rationale" in simulation


def test_batch(sample_plan: PatchPlan, tmp_path: Path):
    apk1 = tmp_path / "app1.apk"
    apk2 = tmp_path / "app2.apk"
    apk1.touch()
    apk2.touch()
    output_dir = tmp_path / "output"
    with patch("apkmorph.patch_generator.PatchGenerator.from_description") as mock_from, \
         patch("apkmorph.patch_generator.PatchGenerator.apply_plan") as mock_apply, \
         patch("apkmorph.analyzer.APKAnalyzer") as mock_analyzer_class, \
         patch("apkmorph.builder.APKBuilder") as mock_builder_class:

        mock_analyzer = MagicMock()
        mock_analyzer_class.return_value = mock_analyzer
        mock_report = MagicMock(spec=AnalysisReport)
        mock_report.decompiled_dir = tmp_path / "decomp1"
        mock_analyzer.decompile.return_value = mock_report
        mock_analyzer.observe_runtime.return_value = mock_report

        mock_from.return_value = sample_plan
        mock_apply.return_value = tmp_path / "patched_app1.apk"

        generator = PatchGenerator(model="llama3.2")
        results = generator.batch(
            description="disable analytics and remove ads",
            apk_paths=[str(apk1), str(apk2)],
            output_dir=output_dir,
            model="llama3.2",
            observe_runtime=True,
        )

        assert len(results) == 2
        assert mock_analyzer.decompile.call_count == 2
        assert mock_from.call_count == 2
        assert mock_apply.call_count == 2
        for r in results:
            assert r.get("success", False) is True
