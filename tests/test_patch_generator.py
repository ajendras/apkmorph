"""Tests for PatchGenerator.

Verifies prompt construction, plan validation, simulation of apply for
Smali/XML/resource edits, batch processing, and runtime-aware patching.
Uses heavy mocking so tests run in CI without Ollama, Frida or real APKs.
"""

import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from apkmorph.patch_generator import PatchGenerator
from apkmorph.models import AnalysisReport, PatchPlan, Modification


def test_from_description() -> None:
    report = AnalysisReport(
        apk_path=Path("test.apk"),
        package_name="com.test.app",
        decompiled_dir=Path("/tmp/decomp"),
        size_bytes=5000,
        strings=["ad", "analytics", "crash"],
        runtime_observations=["observed: ad - loadAd", "observed: analytics - logEvent"],
        metadata={},
    )

    with patch("apkmorph.patch_generator.LLMClient") as MockLLMClient:
        mock_client = MagicMock()
        mock_mod_smali = Modification(
            class_name="com.google.android.gms.ads.AdView",
            method="loadAd",
            diff="- invoke-virtual {p0, p1} ...loadAd\n+ return-void",
            description="NOP ad load observed via Frida",
            edit_type="smali",
            file_path=Path("smali/com/google/android/gms/ads/AdView.smali"),
            confidence=0.92,
            original_snippet="invoke-virtual ...",
            patched_snippet="return-void",
            hover_explanation="Prevents ad network request",
        )
        mock_mod_resource = Modification(
            class_name="resource",
            method="update_string",
            diff="ad_banner_text changed from 'Advertisement' to ''",
            description="Empty ad-related string resource",
            edit_type="resource",
            resource_key="ad_banner_text",
            new_value="",
            file_path=Path("res/values/strings.xml"),
            confidence=0.88,
            original_snippet='<string name="ad_banner_text">Advertisement</string>',
            patched_snippet='<string name="ad_banner_text"></string>',
            hover_explanation="Removes visible ad text from UI resources",
        )
        mock_plan = PatchPlan(
            id="plan_test123",
            description="disable all analytics and remove ads",
            rationale="Used Frida observations of AdView.loadAd and Firebase logEvent to target only live paths",
            confidence=0.87,
            modifications=[mock_mod_smali, mock_mod_resource],
        )
        mock_client.generate_patch.return_value = mock_plan
        MockLLMClient.return_value = mock_client

        generator = PatchGenerator(model="phi3")
        plan = generator.from_description("disable all analytics and remove ads", report)

        assert plan.id.startswith("plan_")
        assert plan.confidence > 0.8
        assert len(plan.modifications) == 2
        assert plan.modifications[0].edit_type == "smali"
        assert plan.modifications[1].edit_type == "resource"
        assert plan.modifications[1].resource_key == "ad_banner_text"
        mock_client.generate_patch.assert_called_once()


def test_validate() -> None:
    generator = PatchGenerator()
    mod = Modification(
        class_name="com.example.Tracker",
        method="trackEvent",
        diff="removed tracking call",
        description="remove tracker",
        edit_type="smali",
        file_path=Path("smali/com/example/Tracker.smali"),
        confidence=0.8,
    )
    plan = PatchPlan(
        description="remove tracking",
        rationale="static analysis + runtime data",
        modifications=[mod],
        confidence=0.8,
    )
    validated = generator.validate(plan)
    assert validated is plan
    assert validated.confidence == 0.8


def test_simulate_apply() -> None:
    generator = PatchGenerator()
    plan = PatchPlan(
        description="test edits",
        rationale="test",
        modifications=[
            Modification(
                class_name="com.test.Ad",
                method="show",
                diff="...",
                description="remove ad",
                edit_type="smali",
                file_path=Path("smali/..."),
                confidence=0.9,
            ),
            Modification(
                class_name="resource",
                method="update",
                diff="app_name changed",
                description="rename app",
                edit_type="resource",
                resource_key="app_name",
                new_value="PatchedApp",
                file_path=Path("res/values/strings.xml"),
                confidence=0.85,
            ),
        ],
    )
    simulation = generator.simulate_apply(plan, "/tmp/fake_decomp")
    assert simulation["applied"] == 2
    assert "smali" in simulation["changes"]
    assert "resource" in simulation["changes"]
    assert simulation["dry_run"] is True


def test_batch() -> None:
    with patch.object(PatchGenerator, "from_description") as mock_from, patch.object(
        PatchGenerator, "apply_plan"
    ) as mock_apply:
        mock_from.return_value = PatchPlan(
            description="batch test",
            rationale="...",
            modifications=[],
            confidence=0.8,
        )
        mock_apply.return_value = Path("patched_app.apk")

        generator = PatchGenerator(model="llama3.2")
        results = generator.batch(
            description="disable analytics",
            apk_paths=["app1.apk", "app2.apk"],
            output_dir=Path("/tmp/batch_out"),
            model="llama3.2",
            observe_runtime=False,
        )

        assert len(results) == 2
        for r in results:
            assert r.get("success") is True
            assert "patched" in r.get("output", "")
        assert mock_from.call_count == 2
        assert mock_apply.call_count == 2
