"""Tests for PatchGenerator including the new confidence UI support and feedback refinement loop."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from pydantic import ValidationError

from apkmorph.models import AnalysisReport, Modification, PatchPlan
from apkmorph.patch_generator import PatchGenerator


@pytest.fixture
def sample_report(tmp_path: Path) -> AnalysisReport:
    decomp = tmp_path / "decomp"
    decomp.mkdir()
    return AnalysisReport(
        apk_path=tmp_path / "test.apk",
        package_name="com.example.app",
        decompiled_dir=decomp,
        components=["com.example.MainActivity"],
        strings=["hello", "ad"],
        string_resources={"app_name": "Test App"},
        runtime_observations=["observed: ad load"],
    )


@pytest.fixture
def sample_plan() -> PatchPlan:
    return PatchPlan(
        description="remove ads",
        modifications=[
            Modification(
                class_name="com.example.AdView",
                method="loadAd",
                description="Remove ad loading call",
                confidence=0.65,
                diff="- invoke-virtual\n+ # removed",
            )
        ],
        rationale="Targeted the observed ad method.",
        confidence=0.65,
    )


def test_from_description(sample_report: AnalysisReport) -> None:
    generator = PatchGenerator(model="llama3.2")
    with patch.object(generator.llm, "generate_patch_plan") as mock_gen:
        mock_gen.return_value = PatchPlan(
            description="test",
            modifications=[Modification(class_name="Test", description="ok", confidence=0.8)],
            confidence=0.8,
        )
        plan = generator.from_description("disable analytics", sample_report)
        assert plan.confidence == 0.8
        mock_gen.assert_called_once()


def test_refine_plan_with_feedback(sample_report: AnalysisReport, sample_plan: PatchPlan) -> None:
    generator = PatchGenerator(model="llama3.2")
    feedback = "Target the interstitial show() method instead of the banner. Increase confidence."
    with patch.object(generator, "from_description") as mock_from:
        refined_mock = sample_plan.model_copy()
        refined_mock.confidence = 0.88
        refined_mock.feedback_history = [feedback]
        refined_mock.rationale += "\n\n---\nUser feedback incorporated: ..."
        mock_from.return_value = refined_mock

        refined = generator.refine_plan(sample_plan, feedback, sample_report)

        assert refined.confidence > 0.8
        assert len(refined.feedback_history) == 1
        assert "interstitial" in refined.rationale.lower()
        mock_from.assert_called_once_with(
            sample_plan.description, sample_report, feedback=feedback
        )


def test_validate_plan(sample_plan: PatchPlan) -> None:
    generator = PatchGenerator()
    assert generator.validate(sample_plan) is True

    bad_plan = PatchPlan(description="bad", modifications=[], confidence=1.2)
    assert generator.validate(bad_plan) is False


def test_simulate_apply(sample_plan: PatchPlan, tmp_path: Path) -> None:
    generator = PatchGenerator()
    result = generator.simulate_apply(sample_plan, tmp_path)
    assert result["would_change"] == 1
    assert len(result["applied"]) == 1
    assert result["applied"][0]["confidence"] == 0.65


def test_batch(sample_report: AnalysisReport, tmp_path: Path) -> None:
    apk1 = tmp_path / "app1.apk"
    apk1.touch()
    apk2 = tmp_path / "app2.apk"
    apk2.touch()

    generator = PatchGenerator()
    with patch.object(APKAnalyzer, "decompile", return_value=sample_report), patch.object(
        generator, "from_description"
    ), patch.object(generator, "apply_plan", return_value=tmp_path / "out.apk"):
        results = generator.batch(
            "remove ads",
            [str(apk1), str(apk2)],
            tmp_path / "batch_out",
            observe_runtime=False,
        )
        assert len(results) == 2
        assert results[0]["success"] is True


def test_export_python(sample_plan: PatchPlan, tmp_path: Path) -> None:
    generator = PatchGenerator()
    out_path = tmp_path / "export_test.py"
    exported = generator.export(sample_plan, out_path, fmt="python")
    assert exported.exists()
    content = exported.read_text()
    assert "def main" in content
    assert sample_plan.description in content
    assert "PatchPlan" in content


def test_export_json(sample_plan: PatchPlan, tmp_path: Path) -> None:
    generator = PatchGenerator()
    out_path = tmp_path / "plan.json"
    exported = generator.export(sample_plan, out_path, fmt="json")
    assert exported.exists()
    data = json.loads(exported.read_text())
    assert data["confidence"] == sample_plan.confidence
    assert len(data["modifications"]) == len(sample_plan.modifications)


def test_apply_plan_rollback_on_failure(sample_report: AnalysisReport, sample_plan: PatchPlan, tmp_path: Path) -> None:
    generator = PatchGenerator()
    sample_report.decompiled_dir = tmp_path / "decomp"
    sample_report.decompiled_dir.mkdir()

    with patch.object(generator.editor, "apply_modification", side_effect=RuntimeError("inject failure")):
        with pytest.raises(RuntimeError, match="rolled back"):
            generator.apply_plan(sample_plan, sample_report)
    # backup should have been used; original dir still exists
    assert sample_report.decompiled_dir.exists()
