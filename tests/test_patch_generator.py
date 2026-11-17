import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from apkmorph.patch_generator import PatchGenerator
from apkmorph.models import AnalysisReport, PatchPlan, Modification


def test_from_description_with_mocked_llm():
    with patch("apkmorph.llm.LLMClient.generate_patch") as mock_generate:
        mock_mod = Modification(
            class_name="com.google.firebase.analytics.FirebaseAnalytics",
            method="logEvent(Ljava/lang/String;Landroid/os/Bundle;)V",
            diff="    return-void",
            description="Replace analytics call with early return",
            edit_type="smali",
            confidence=0.92,
            file_path=Path("smali/com/google/firebase/analytics/FirebaseAnalytics.smali"),
            original_snippet="    invoke-virtual ...",
            patched_snippet="    # patched by APK Morph\n    return-void",
            hover_explanation="Prevents Firebase event logging observed via Frida",
        )
        mock_plan = PatchPlan(
            description="disable all analytics",
            rationale="Targeted live Firebase calls seen in runtime observations",
            confidence=0.89,
            modifications=[mock_mod],
            report_summary="com.example.testapp v1.0 • 5 components",
        )
        mock_generate.return_value = mock_plan

        generator = PatchGenerator(model="llama3.2")
        report = AnalysisReport(
            apk_path=Path("test.apk"),
            package_name="com.example.testapp",
            decompiled_dir=Path("/tmp/decompiled_test"),
            strings=["analytics", "firebase"],
            activities=["com.example.testapp.MainActivity"],
            services=[],
            receivers=[],
            providers=[],
            permissions=[],
            components=["com.example.testapp.MainActivity"],
            string_resources={"analytics_enabled": "true"},
            runtime_observations=[
                "observed: analytics - FirebaseAnalytics.logEvent() called"
            ],
        )

        plan = generator.from_description("disable all analytics", report)

        assert plan.description == "disable all analytics"
        assert len(plan.modifications) == 1
        assert plan.modifications[0].edit_type == "smali"
        assert plan.confidence == 0.89
        mock_generate.assert_called_once()


def test_validate_accepts_valid_plan():
    generator = PatchGenerator()
    mod = Modification(
        class_name="com.example.AdManager",
        method="loadAd",
        diff="- invoke-virtual ...",
        description="Disable ad loading observed at runtime",
        edit_type="smali",
        confidence=0.85,
        file_path=Path("smali/com/example/AdManager.smali"),
    )
    plan = PatchPlan(
        description="remove ads",
        rationale="Used Frida data to target only executed ad paths",
        confidence=0.88,
        modifications=[mod],
    )

    generator.validate(plan)  # should not raise


def test_validate_rejects_invalid_plan():
    generator = PatchGenerator()
    mod = Modification(
        class_name="com.example.Class",
        method="method",
        diff="change",
        description="",
        edit_type="smali",
        confidence=0.1,
    )
    plan = PatchPlan(
        description="bad plan",
        rationale="bad",
        confidence=0.3,
        modifications=[mod],
    )

    with pytest.raises(ValueError, match="too low"):
        generator.validate(plan)

    with pytest.raises(ValueError, match="missing a description"):
        bad_mod = mod.model_copy(update={"description": ""})
        bad_plan = plan.model_copy(update={"confidence": 0.8, "modifications": [bad_mod]})
        generator.validate(bad_plan)


def test_simulate_apply_for_smali_xml_resource():
    generator = PatchGenerator()
    mods = [
        Modification(
            class_name="com.example.AdView",
            method="loadAd",
            diff="    # APK Morph disabled ad load\n    return-void",
            description="NOP ad load observed via Frida",
            edit_type="smali",
            confidence=0.95,
            file_path=Path("smali/com/example/AdView.smali"),
            original_snippet="    invoke-virtual {p0,p1}",
            patched_snippet="    # disabled",
            hover_explanation="Prevents network request to ad server",
        ),
        Modification(
            class_name="resource",
            method="update_string",
            diff="ad_text changed to empty",
            description="Remove ad banner text",
            edit_type="resource",
            resource_key="ad_banner_text",
            new_value="",
            confidence=0.82,
            file_path=Path("res/values/strings.xml"),
        ),
        Modification(
            class_name="com.example.Tracker",
            method="trackEvent",
            diff="<uses-permission android:name=.../> removed",
            description="Remove tracking permission",
            edit_type="xml",
            confidence=0.78,
            file_path=Path("AndroidManifest.xml"),
        ),
    ]
    plan = PatchPlan(
        description="remove ads, tracking and analytics",
        rationale="Targeted only methods seen in runtime observations",
        confidence=0.87,
        modifications=mods,
    )

    decompiled_dir = Path("/tmp/fake_decomp")
    with patch.object(Path, "exists", return_value=True):
        result = generator.simulate_apply(plan, decompiled_dir)

    assert result["success"] is True
    assert result["total"] == 3
    assert len(result["applied"]) == 3
    assert len(result["modified_files"]) >= 2
    edit_types = {m["edit_type"] for m in result["applied"]}
    assert edit_types == {"smali", "resource", "xml"}
    assert result["confidence"] == 0.87
