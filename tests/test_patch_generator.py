"""Tests for PatchGenerator.

Covers prompt building, plan validation, simulation, batch processing,
export, and the new automatic rollback behavior on rebuild failure.
"""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from pydantic import ValidationError

from apkmorph.models import AnalysisReport, Modification, PatchPlan
from apkmorph.patch_generator import PatchGenerator


def test_from_description_returns_valid_plan(mocker):
    mock_llm = mocker.patch("apkmorph.patch_generator.LLMClient")
    mock_llm.return_value.query.return_value = PatchPlan(
        id="plan_abc123",
        description="disable analytics",
        rationale="Removed Firebase calls",
        confidence=0.85,
        modifications=[
            Modification(
                edit_type="smali",
                class_name="com.example.Analytics",
                method="logEvent",
                description="Comment out tracking",
                confidence=0.85,
                diff="- invoke\n+ # invoke",
            )
        ],
    )

    generator = PatchGenerator(model="llama3.2")
    report = AnalysisReport(
        apk_path=Path("test.apk"),
        package_name="com.test.app",
        decompiled_dir=Path("/tmp/decomp"),
        main_activity=".MainActivity",
        activities=[],
        services=[],
        receivers=[],
        providers=[],
        permissions=[],
        components=[],
        strings=["analytics"],
        string_resources={"analytics_key": "enabled"},
        version_name="1.0",
        version_code="1",
        min_sdk=21,
        target_sdk=33,
        size_bytes=1024,
        metadata={},
        runtime_observations=[],
    )

    plan = generator.from_description("disable analytics", report)
    assert plan.id == "plan_abc123"
    assert len(plan.modifications) == 1
    assert plan.confidence == 0.85


def test_validate_rejects_invalid_plan():
    generator = PatchGenerator()
    bad_plan = PatchPlan(
        id="bad",
        description="bad",
        rationale="bad",
        confidence=1.2,  # out of range
        modifications=[],
    )
    assert not generator.validate(bad_plan)


def test_simulate_apply(tmp_path):
    generator = PatchGenerator()
    decomp = tmp_path / "decomp"
    decomp.mkdir()
    (decomp / "smali/com/test/Main.smali").parent.mkdir(parents=True)
    (decomp / "smali/com/test/Main.smali").write_text("")

    mod = Modification(
        edit_type="smali",
        class_name="com.test.Main",
        method="onCreate",
        description="remove ad",
        confidence=0.9,
        diff="",
    )
    plan = PatchPlan(
        id="p1",
        description="test",
        rationale="test",
        confidence=0.9,
        modifications=[mod],
    )

    result = generator.simulate_apply(plan, decomp)
    assert result["would_modify"] == 1
    assert len(result["applied"]) == 1
    assert result["success_rate"] == 1.0


def test_batch_success(mocker, tmp_path):
    mocker.patch("apkmorph.patch_generator.APKAnalyzer")
    mocker.patch("apkmorph.patch_generator.PatchGenerator.from_description")
    mocker.patch("apkmorph.patch_generator.PatchGenerator.apply_plan", return_value=Path("out.apk"))

    generator = PatchGenerator()
    results = generator.batch(
        description="remove ads",
        apk_paths=["app1.apk", "app2.apk"],
        output_dir=tmp_path / "out",
        observe_runtime=False,
    )

    assert len(results) == 2
    assert results[0]["success"] is True


def test_export_python_script(tmp_path):
    generator = PatchGenerator()
    mod = Modification(
        edit_type="resource",
        class_name="",
        method="",
        description="change title",
        confidence=0.7,
        diff="",
    )
    plan = PatchPlan(
        id="plan_export",
        description="change title",
        rationale="updated string",
        confidence=0.7,
        modifications=[mod],
    )

    out = generator.export(plan, tmp_path / "exported.py", fmt="python")
    assert out.exists()
    content = out.read_text()
    assert "PatchGenerator" in content
    assert "change title" in content


def test_apply_plan_rollback_on_failure(mocker, tmp_path):
    """Test the core new behavior: automatic rollback when rebuild fails."""
    decomp = tmp_path / "decompiled_app"
    decomp.mkdir(parents=True)
    manifest = decomp / "AndroidManifest.xml"
    manifest.write_text('<manifest package="com.test.app"/>')

    report = AnalysisReport(
        apk_path=tmp_path / "test.apk",
        package_name="com.test.app",
        decompiled_dir=decomp,
        main_activity=".MainActivity",
        activities=[".MainActivity"],
        services=[],
        receivers=[],
        providers=[],
        permissions=[],
        components=[".MainActivity"],
        strings=["test"],
        string_resources={"app_name": "Test"},
        version_name="1.0",
        version_code="1",
        min_sdk=21,
        target_sdk=33,
        size_bytes=2048,
        metadata={},
        runtime_observations=["observed: onCreate"],
    )

    mod = Modification(
        edit_type="smali",
        class_name="com.test.app.MainActivity",
        method="onCreate",
        description="disable analytics",
        confidence=0.8,
        diff="- invoke-static",
    )
    plan = PatchPlan(
        id="plan_rollback_test",
        description="disable analytics",
        rationale="Remove tracking calls",
        confidence=0.8,
        modifications=[mod],
    )

    generator = PatchGenerator(model="llama3.2")

    # Mock editor so _apply_modification succeeds
    mocker.patch.object(generator, "_apply_modification", return_value=True)
    # Force rebuild_and_sign to fail
    mocker.patch(
        "apkmorph.builder.APKBuilder.rebuild_and_sign",
        side_effect=RuntimeError("Simulated apktool failure"),
    )
    # Spy on the rollback method
    mocker.patch.object(generator, "_rollback")

    with pytest.raises(RuntimeError) as exc_info:
        generator.apply_plan(plan, report, install=False)

    assert "rolled back" in str(exc_info.value).lower()
    assert "rebuild" in str(exc_info.value).lower()
    generator._rollback.assert_called_once()

    # Manifest should still exist (rollback restored original tree)
    assert manifest.exists()


def test_apply_plan_success_path(mocker, tmp_path):
    """Ensure happy path does not call rollback and returns an APK path."""
    decomp = tmp_path / "happy_decomp"
    decomp.mkdir()
    (decomp / "AndroidManifest.xml").write_text("<manifest/>")

    report = AnalysisReport(
        apk_path=Path("test.apk"),
        package_name="com.example",
        decompiled_dir=decomp,
        main_activity=".Main",
        activities=[],
        services=[],
        receivers=[],
        providers=[],
        permissions=[],
        components=[],
        strings=[],
        string_resources={},
        version_name=None,
        version_code=None,
        min_sdk=None,
        target_sdk=None,
        size_bytes=1000,
        metadata={},
        runtime_observations=[],
    )

    plan = PatchPlan(
        id="plan_ok",
        description="ok",
        rationale="ok",
        confidence=0.9,
        modifications=[],
    )

    generator = PatchGenerator()
    mocker.patch.object(generator, "_apply_modification", return_value=True)
    mocker.patch(
        "apkmorph.builder.APKBuilder.rebuild_and_sign",
        return_value=Path("patched_ok.apk"),
    )
    mocker.patch.object(generator, "_rollback")  # should not be called

    result = generator.apply_plan(plan, report)
    assert result.name == "patched_ok.apk"
    generator._rollback.assert_not_called()
