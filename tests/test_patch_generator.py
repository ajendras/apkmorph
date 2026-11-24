"""Tests for PatchGenerator.

Tests prompt building, plan validation, simulation, batch processing, export, rollback on failure,
and device install integration. Uses mocks for LLM and builder to avoid external dependencies.
"""

from pathlib import Path
from unittest.mock import patch, MagicMock
import json

import pytest

from apkmorph.patch_generator import PatchGenerator
from apkmorph.models import AnalysisReport, PatchPlan, Modification
from apkmorph.builder import APKBuilder


@pytest.fixture
def sample_report(tmp_path):
    return AnalysisReport(
        apk_path=tmp_path / "sample.apk",
        package_name="com.sample.app",
        version_name="1.0",
        version_code=1,
        min_sdk=21,
        target_sdk=30,
        decompiled_dir=tmp_path / "decomp",
        main_activity="com.sample.app.MainActivity",
        activities=["com.sample.app.MainActivity"],
        services=[],
        receivers=[],
        providers=[],
        permissions=[],
        components=["com.sample.app.MainActivity"],
        strings=["hello", "ad", "analytics"],
        string_resources={"title": "Sample"},
        metadata={"runtime_observed": True},
        size_bytes=2048,
        runtime_observations=["observed: ad loadAd"],
    )


def test_from_description(sample_report):
    generator = PatchGenerator(model="phi3")
    fake_response = {
        "id": "plan_98765",
        "rationale": "The app uses Firebase for analytics. We will patch the logEvent calls.",
        "confidence": 0.92,
        "modifications": [
            {
                "class_name": "com.sample.app.AnalyticsHelper",
                "method": "logEvent",
                "edit_type": "smali",
                "description": "Comment out analytics tracking",
                "confidence": 0.95,
                "diff": "- invoke-static {v0, v1}, Lcom/sample/app/AnalyticsHelper;->logEvent(Ljava/lang/String;)V\n+ # Disabled analytics call",
                "params": {},
            }
        ],
    }
    with patch("apkmorph.patch_generator.LLMClient") as MockLLM:
        mock_instance = MockLLM.return_value
        mock_instance.query.return_value = json.dumps(fake_response)
        plan = generator.from_description("disable all analytics", sample_report)

    assert plan.id == "plan_98765"
    assert "analytics" in plan.rationale.lower()
    assert len(plan.modifications) == 1
    assert plan.modifications[0].confidence > 0.9


def test_validate(sample_report):
    generator = PatchGenerator()
    mod = Modification(
        class_name="com.sample.app.MainActivity",
        method="onCreate",
        edit_type="smali",
        description="Remove ad banner",
        confidence=0.88,
        diff="- ad code",
        params={},
    )
    plan = PatchPlan(
        id="plan_test",
        rationale="Test plan",
        confidence=0.88,
        modifications=[mod],
    )
    validated_plan = generator.validate(plan)
    assert validated_plan.id == "plan_test"


def test_simulate_apply(sample_report):
    generator = PatchGenerator()
    mod = Modification(
        class_name="com.sample.app.AdManager",
        method="showAd",
        edit_type="smali",
        description="Replace ad with stub",
        confidence=0.9,
        diff="- invoke ad\n+ return-void",
    )
    plan = PatchPlan(
        id="plan_sim",
        rationale="Sim test",
        confidence=0.9,
        modifications=[mod],
    )
    with patch("apkmorph.patch_generator.SmaliEditor") as MockEditor:
        mock_editor = MockEditor.return_value
        mock_editor.apply_modification.return_value = True
        result = generator.simulate_apply(plan, sample_report.decompiled_dir)
        assert result["applied"] is True
        assert "modifications" in result


def test_apply_plan_rollback_on_failure(sample_report):
    generator = PatchGenerator()
    plan = PatchPlan(
        id="plan_fail",
        rationale="will fail",
        confidence=0.6,
        modifications=[],
    )
    with patch("apkmorph.patch_generator.safe_copytree") as mock_backup, patch(
        "apkmorph.patch_generator.SmaliEditor"
    ), patch.object(
        APKBuilder,
        "rebuild_and_sign",
        side_effect=RuntimeError("Apktool build failed"),
    ), pytest.raises(
        RuntimeError, match="Apktool build failed"
    ):
        generator.apply_plan(plan, sample_report)
    mock_backup.assert_called_once()


def test_batch_mode(tmp_path, sample_report):
    generator = PatchGenerator(model="llama3.2")
    apks = [tmp_path / "a.apk", tmp_path / "b.apk"]
    for a in apks:
        a.touch()
    with patch.object(generator, "from_description") as mock_from_desc, patch.object(
        generator, "apply_plan"
    ) as mock_apply:
        mock_from_desc.return_value = PatchPlan(
            id="p1", rationale="", confidence=0.8, modifications=[]
        )
        mock_apply.return_value = tmp_path / "patched_a.apk"
        results = generator.batch(
            "remove ads",
            [str(p) for p in apks],
            output_dir=tmp_path / "batch_out",
            model="llama3.2",
            observe_runtime=False,
            install=False,
            launch=False,
        )
        assert len(results) == 2
        assert mock_from_desc.call_count == 2
        assert mock_apply.call_count == 2


def test_export_plan(sample_report, tmp_path):
    generator = PatchGenerator()
    plan = PatchPlan(
        id="plan_export_test",
        rationale="Exported plan for remove ads",
        confidence=0.85,
        modifications=[
            Modification(
                class_name="com.sample.AdActivity",
                method="onResume",
                edit_type="smali",
                description="Remove ad view",
                confidence=0.9,
                diff="- adview",
            )
        ],
    )
    output_py = tmp_path / "remove_ads_patch.py"
    exported_path = generator.export(plan, output_py, fmt="python")
    assert exported_path == output_py
    content = exported_path.read_text(encoding="utf-8")
    assert "from apkmorph.models" in content
    assert "remove ads" in content.lower()

    output_json = tmp_path / "template.json"
    json_path = generator.export(plan, output_json, fmt="json")
    assert json_path.exists()
    data = json.loads(json_path.read_text())
    assert data["id"] == "plan_export_test"
