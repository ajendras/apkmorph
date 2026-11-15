"""Tests for PatchGenerator.

Focuses on prompt construction, PatchPlan validation (including dangerous
patterns and confidence thresholds), and the simulate_apply dry-run.
LLMClient is fully mocked to keep tests deterministic and fast.
"""

import re
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from pydantic import ValidationError

from apkmorph.models import AnalysisReport, Modification, PatchPlan
from apkmorph.patch_generator import PatchGenerator


@pytest.fixture
def sample_report(tmp_path: Path) -> AnalysisReport:
    return AnalysisReport(
        apk_path=tmp_path / "test.apk",
        package_name="com.example.game",
        decompiled_dir=tmp_path / "decomp",
        components=[
            "com.example.game.MainActivity",
            "com.example.analytics.Tracker",
            "com.example.ads.AdLoader",
        ],
        strings=["analytics", "admob", "splash"],
        metadata={"smali_classes": 42},
        size_bytes=2048576,
    )


@pytest.fixture
def good_modification() -> Modification:
    return Modification(
        class_name="com.example.analytics.Tracker",
        method="trackEvent(Ljava/lang/String;)V",
        diff="    invoke-static {p0, p1}, Lcom/example/analytics/Tracker;->trackEvent(Ljava/lang/String;)V\n"
        "    # replaced with early return",
        description="Replace tracking call with early return",
        confidence=0.88,
        file_path=Path("smali/com/example/analytics/Tracker.smali"),
    )


@pytest.fixture
def good_plan(good_modification: Modification) -> PatchPlan:
    return PatchPlan(
        description="disable all analytics",
        modifications=[good_modification],
        rationale="Targeted the Tracker class which appears in strings.xml",
        confidence=0.85,
        report_summary="com.example.game v1.0 • 3 components",
    )


def test_from_description_calls_llm_and_validates(sample_report: AnalysisReport):
    with patch.object(PatchGenerator, "llm") as mock_llm:
        mock_llm.generate_patch.return_value = PatchPlan(
            description="disable all analytics",
            modifications=[
                Modification(
                    class_name="com.example.analytics.Tracker",
                    method="track(Ljava/lang/String;)V",
                    diff="return-void",
                    description="NOP analytics",
                    confidence=0.9,
                    file_path=Path("smali/com/example/analytics/Tracker.smali"),
                )
            ],
            rationale="Found tracker in report",
            confidence=0.87,
        )

        generator = PatchGenerator(model="llama3.2")
        plan = generator.from_description("disable analytics", sample_report)

        assert isinstance(plan, PatchPlan)
        assert plan.description == "disable analytics"
        assert len(plan.modifications) == 1
        mock_llm.generate_patch.assert_called_once_with(
            "disable analytics", sample_report
        )


def test_from_description_rejects_empty_description(sample_report: AnalysisReport):
    generator = PatchGenerator()
    with pytest.raises(ValueError, match="cannot be empty"):
        generator.from_description("", sample_report)

    with pytest.raises(ValueError, match="at least 5 characters"):
        generator.from_description("hi", sample_report)


def test_from_description_requires_report_with_components():
    generator = PatchGenerator()
    empty_report = AnalysisReport(
        apk_path=Path("x.apk"),
        package_name="test",
        decompiled_dir=Path("/tmp"),
    )
    with pytest.raises(ValueError, match="must contain components"):
        generator.from_description("remove ads", empty_report)


def test_validate_accepts_good_plan(good_plan: PatchPlan):
    generator = PatchGenerator()
    # Should not raise
    generator.validate(good_plan)


def test_validate_rejects_empty_modifications():
    generator = PatchGenerator()
    bad_plan = PatchPlan(
        description="do nothing",
        modifications=[],
        rationale="nothing to do",
    )
    with pytest.raises(ValueError, match="contains no modifications"):
        generator.validate(bad_plan)


def test_validate_rejects_low_confidence():
    generator = PatchGenerator()
    low_plan = PatchPlan(
        description="test",
        modifications=[
            Modification(
                class_name="com.test.Foo",
                method="bar()V",
                diff="nop",
                description="low confidence",
                confidence=0.2,
            )
        ],
        confidence=0.9,
    )
    with pytest.raises(ValueError, match="low confidence"):
        generator.validate(low_plan)


def test_validate_rejects_dangerous_patterns(good_modification: Modification):
    generator = PatchGenerator()

    dangerous = good_modification.model_copy(
        update={
            "diff": "    invoke-static {}, Ljava/lang/Runtime;->exec(Ljava/lang/String;)V  # rm -rf",
            "description": "dangerous command",
        }
    )
    bad_plan = PatchPlan(
        description="bad",
        modifications=[dangerous],
        rationale="test",
        confidence=0.8,
    )

    with pytest.raises(ValueError, match="dangerous pattern"):
        generator.validate(bad_plan)


def test_validate_rejects_path_traversal():
    generator = PatchGenerator()
    bad_mod = Modification(
        class_name="com.test.Evil",
        method="evil()V",
        diff="const-string v0, \"../../etc/passwd\"",
        description="traversal",
        file_path=Path("../../etc/passwd"),
        confidence=0.8,
    )
    bad_plan = PatchPlan(
        description="bad",
        modifications=[bad_mod],
        rationale="test",
        confidence=0.8,
    )

    with pytest.raises(ValueError, match="unsafe file_path"):
        generator.validate(bad_plan)


def test_validate_rejects_core_framework_with_low_confidence():
    generator = PatchGenerator()
    core_mod = Modification(
        class_name="android.os.Build",
        method="getFingerprint()Ljava/lang/String;",
        diff="    invoke-static {}, Landroid/os/Build;->getFingerprint()Ljava/lang/String;",
        description="modify build fingerprint",
        confidence=0.6,
        file_path=Path("smali/android/os/Build.smali"),
    )
    bad_plan = PatchPlan(
        description="bad",
        modifications=[core_mod],
        rationale="test",
        confidence=0.6,
    )

    with pytest.raises(ValueError, match="touches core Android classes"):
        generator.validate(bad_plan)


def test_simulate_apply_reports_success(sample_report: AnalysisReport, tmp_path: Path):
    decomp_dir = tmp_path / "decomp"
    decomp_dir.mkdir()

    # Create a fake target file
    target_smali = decomp_dir / "smali" / "com" / "example" / "analytics"
    target_smali.mkdir(parents=True)
    tracker_file = target_smali / "Tracker.smali"
    tracker_file.write_text(
        ".class public Lcom/example/analytics/Tracker;\n"
        ".method public static trackEvent(Ljava/lang/String;)V\n"
        "    return-void\n"
        ".end method"
    )

    mod = Modification(
        class_name="com.example.analytics.Tracker",
        method="trackEvent(Ljava/lang/String;)V",
        diff="return-void",
        description="disable",
        confidence=0.9,
        file_path=Path("smali/com/example/analytics/Tracker.smali"),
    )
    plan = PatchPlan(
        description="test",
        modifications=[mod],
        rationale="test",
    )

    generator = PatchGenerator()
    with patch.object(generator.smali, "read_method") as mock_read:
        mock_read.return_value = {"start": 1, "end": 3}

        result = generator.simulate_apply(plan, decomp_dir)

    assert result["success"] is True
    assert len(result["applied"]) == 1
    assert len(result["errors"]) == 0
    mock_read.assert_called_once()


def test_simulate_apply_handles_missing_file(sample_report: AnalysisReport, tmp_path: Path):
    generator = PatchGenerator()
    mod = Modification(
        class_name="com.missing.Class",
        method="foo()V",
        diff="nop",
        description="missing",
        confidence=0.8,
        file_path=Path("smali/com/missing/Class.smali"),
    )
    plan = PatchPlan(description="test", modifications=[mod])

    result = generator.simulate_apply(plan, tmp_path / "nonexistent")

    assert result["success"] is False
    assert any("Target file not found" in e for e in result["errors"])


def test_llm_prompt_includes_key_context(sample_report: AnalysisReport):
    """Indirect test that the prompt builder receives expected data."""
    generator = PatchGenerator()
    with patch.object(generator.llm, "generate_patch") as mock_gen:
        mock_gen.return_value = PatchPlan(
            description="test",
            modifications=[],
            rationale="ok",
            confidence=0.8,
        )
        try:
            generator.from_description("remove ads", sample_report)
        except Exception:
            pass  # we only care about the call

        # The prompt is built internally; we can only assert the call happened
        # with the report we supplied
        mock_gen.assert_called_once()
        assert mock_gen.call_args[0][1] is sample_report


def test_patch_plan_validation_error_propagates():
    # Test that malformed Modification raises during model construction
    with pytest.raises(ValidationError):
        Modification(
            class_name="",  # required field missing effectively
            method="",
            diff="",
            confidence=1.5,  # out of range
        )
