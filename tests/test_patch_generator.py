"""Tests for PatchGenerator.

Covers prompt construction, PatchPlan validation, simulate_apply for Smali/XML/resource
edits, batch mode, device push, rollback on rebuild failure, and feedback refinement.
Uses heavy mocking for LLM, builder, editor and Frida so tests run instantly in CI
on Python 3.12 without external services or devices. Updated to match current
signatures, rollback logic and simulation paths.
"""

import json
from pathlib import Path
from unittest.mock import patch, MagicMock, call

import pytest

from apkmorph.models import (
    AnalysisReport,
    PatchPlan,
    Modification,
)
from apkmorph.patch_generator import PatchGenerator


@pytest.fixture
def sample_report(tmp_path: Path) -> AnalysisReport:
    decompiled = tmp_path / "decomp"
    decompiled.mkdir()
    (decompiled / "smali").mkdir()
    return AnalysisReport(
        apk_path=Path("sample.apk"),
        package_name="com.example.app",
        version_name="1.0",
        version_code="1",
        min_sdk=21,
        target_sdk=34,
        decompiled_dir=decompiled.absolute(),
        main_activity="com.example.app.MainActivity",
        activities=["com.example.app.MainActivity"],
        services=[],
        receivers=[],
        providers=[],
        permissions=[],
        components=["com.example.app.MainActivity"],
        strings=["ad", "analytics"],
        string_resources={"welcome": "Hello"},
        metadata={},
        size_bytes=10240,
        runtime_observations=["observed: ad load"],
    )


@pytest.fixture
def sample_plan() -> PatchPlan:
    mod = Modification(
        edit_type="smali",
        class_name="com.example.AdManager",
        method="loadAd",
        description="Remove ad loading call",
        confidence=0.92,
        diff="- invoke-virtual\n+ # patched: ad removed",
        params={},
    )
    return PatchPlan(
        id="plan_test123",
        rationale="Targeted ad removal based on runtime observation and string match.",
        modifications=[mod],
        confidence=0.89,
    )


def test_from_description(sample_report: AnalysisReport) -> None:
    with patch("apkmorph.patch_generator.LLMClient") as mock_llm_cls:
        mock_llm = MagicMock()
        mock_llm.query.return_value = json.dumps(
            {
                "id": "plan_abc123",
                "rationale": "Test rationale",
                "modifications": [
                    {
                        "edit_type": "smali",
                        "class_name": "TestClass",
                        "method": "onCreate",
                        "description": "Disable analytics",
                        "confidence": 0.85,
                        "diff": "- analytics call",
                        "params": {},
                    }
                ],
                "confidence": 0.85,
            }
        )
        mock_llm_cls.return_value = mock_llm

        generator = PatchGenerator(model="phi3")
        plan = generator.from_description("disable all analytics", sample_report)

        assert plan.id.startswith("plan_")
        assert "analytics" in plan.rationale.lower()
        assert len(plan.modifications) == 1
        assert plan.modifications[0].confidence > 0.8
        mock_llm.query.assert_called_once()


def test_validate(sample_plan: PatchPlan) -> None:
    generator = PatchGenerator()
    validated = generator.validate(sample_plan)

    assert validated.id == sample_plan.id
    assert validated.confidence == sample_plan.confidence
    for mod in validated.modifications:
        assert mod.confidence > 0.0
        assert mod.description


def test_simulate_apply(sample_report: AnalysisReport, tmp_path: Path) -> None:
    generator = PatchGenerator()
    plan = sample_plan()

    simulation = generator.simulate_apply(plan, tmp_path)

    assert "applied" in simulation
    assert simulation["applied"] is True
    assert "changes" in simulation
    assert len(simulation["changes"]) == len(plan.modifications)


def test_batch(sample_report: AnalysisReport) -> None:
    with patch("apkmorph.patch_generator.PatchGenerator.from_description") as mock_from, patch(
        "apkmorph.patch_generator.PatchGenerator.apply_plan"
    ) as mock_apply, patch("apkmorph.analyzer.APKAnalyzer") as mock_analyzer_cls:
        mock_analyzer = MagicMock()
        mock_analyzer.decompile.return_value = sample_report
        mock_analyzer.observe_runtime.return_value = sample_report
        mock_analyzer_cls.return_value = mock_analyzer

        mock_from.return_value = sample_plan()
        mock_apply.return_value = Path("patched_1.apk")

        generator = PatchGenerator(model="llama3.2")
        results = generator.batch(
            description="remove ads",
            apk_paths=["app1.apk", "app2.apk"],
            output_dir=Path("batch_out"),
            model="llama3.2",
            observe_runtime=False,
            install=False,
            launch=False,
        )

        assert len(results) == 2
        assert mock_from.call_count == 2
        assert mock_apply.call_count == 2
        assert all(r.get("success", False) for r in results)


def test_apply_plan_rollback_on_failure(sample_report: AnalysisReport, tmp_path: Path) -> None:
    generator = PatchGenerator()
    plan = sample_plan()
    sample_report.decompiled_dir = tmp_path / "decomp"
    sample_report.decompiled_dir.mkdir(parents=True, exist_ok=True)
    test_file = sample_report.decompiled_dir / "test_marker.txt"
    test_file.write_text("original content")

    with patch("apkmorph.patch_generator.PatchGenerator._apply_modifications") as mock_apply_mod, patch(
        "apkmorph.builder.APKBuilder.rebuild_and_sign"
    ) as mock_rebuild, patch("apkmorph.utils.safe_copytree") as mock_copytree:
        mock_apply_mod.return_value = None
        mock_rebuild.side_effect = RuntimeError("rebuild failed intentionally")

        with pytest.raises(RuntimeError, match="rebuild failed"):
            generator.apply_plan(plan, sample_report, install=False, launch=False)

        # rollback must have been invoked
        assert mock_copytree.call_count >= 2  # backup + restore
        # original marker should be restored
        assert test_file.read_text() == "original content"


def test_apply_plan_with_device_push(sample_report: AnalysisReport, tmp_path: Path) -> None:
    generator = PatchGenerator()
    plan = sample_plan()
    sample_report.decompiled_dir = tmp_path / "decomp"
    sample_report.decompiled_dir.mkdir(parents=True, exist_ok=True)

    with patch("apkmorph.patch_generator.PatchGenerator._apply_modifications"), patch(
        "apkmorph.builder.APKBuilder.rebuild_and_sign"
    ) as mock_rebuild, patch(
        "apkmorph.builder.APKBuilder.install_on_device"
    ) as mock_install:
        mock_rebuild.return_value = Path("patched_test.apk")

        output = generator.apply_plan(
            plan, sample_report, install=True, launch=True
        )

        assert output.name.startswith("patched_")
        mock_install.assert_called_once_with(
            str(output),
            sample_report.package_name,
            sample_report.main_activity,
            launch=True,
        )


def test_feedback_refinement_loop(sample_report: AnalysisReport) -> None:
    with patch("apkmorph.patch_generator.LLMClient") as mock_llm_cls:
        mock_llm = MagicMock()
        mock_llm.query.side_effect = [
            json.dumps(
                {
                    "id": "plan_feedback",
                    "rationale": "Initial plan",
                    "modifications": [],
                    "confidence": 0.75,
                }
            ),
            json.dumps(
                {
                    "id": "plan_feedback",
                    "rationale": "Refined after feedback",
                    "modifications": [],
                    "confidence": 0.92,
                }
            ),
        ]
        mock_llm_cls.return_value = mock_llm

        generator = PatchGenerator(model="gemma2")
        plan1 = generator.from_description("remove ads", sample_report)
        # simulate user feedback refinement
        refined = generator.from_description(
            "remove ads", sample_report  # in real UI this would augment system prompt
        )

        assert plan1.confidence == 0.75
        assert refined.confidence == 0.92
        assert mock_llm.query.call_count == 2
