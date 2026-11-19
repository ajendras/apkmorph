"""Tests for patch generation, validation and the new batch mode."""

import pytest
from unittest.mock import patch, MagicMock, ANY
from pathlib import Path

from apkmorph.models import AnalysisReport, PatchPlan, Modification
from apkmorph.patch_generator import PatchGenerator


@pytest.fixture
def sample_report():
    return AnalysisReport(
        apk_path=Path("test.apk"),
        package_name="com.example.test",
        decompiled_dir=Path("/tmp/decomp_test"),
        components=["com.example.MainActivity"],
        strings=["test string", "ad banner"],
        string_resources={"app_name": "Test App"},
        runtime_observations=["observed: ad - loadAd"],
        size_bytes=1024 * 1024,
    )


@pytest.fixture
def sample_plan():
    mod = Modification(
        class_name="com.example.AdManager",
        method="loadAd()V",
        diff="- invoke-virtual ... \n+ return-void",
        description="Disable ad loading",
        edit_type="smali",
        file_path=Path("smali/com/example/AdManager.smali"),
        confidence=0.9,
        original_snippet="invoke-virtual {p0}, Lcom/example/AdManager;->loadAd()V",
        patched_snippet="return-void",
        hover_explanation="Prevents ad network calls",
    )
    return PatchPlan(
        description="remove ads",
        rationale="Targeted the ad load method observed at runtime",
        confidence=0.88,
        modifications=[mod],
    )


def test_from_description(sample_report):
    with patch("apkmorph.patch_generator.LLMClient") as mock_llm_cls:
        mock_llm = MagicMock()
        mock_llm.generate_patch.return_value = PatchPlan(
            description="test", rationale="test", confidence=0.75, modifications=[]
        )
        mock_llm_cls.return_value = mock_llm
        generator = PatchGenerator(model="llama3.2")
        plan = generator.from_description("remove ads", sample_report)
        assert plan.description == "test"
        mock_llm.generate_patch.assert_called_once()


def test_validate(sample_plan):
    generator = PatchGenerator()
    assert generator.validate(sample_plan) is True


def test_simulate_apply(sample_plan, sample_report):
    generator = PatchGenerator()
    sim = generator.simulate_apply(sample_plan, sample_report.decompiled_dir)
    assert "applied" in sim
    assert len(sim["applied"]) >= 0


@patch("apkmorph.patch_generator.console.print")
def test_batch_mode(mock_print, sample_report, sample_plan):
    generator = PatchGenerator()
    with patch.object(generator, "from_description", return_value=sample_plan):
        with patch("apkmorph.patch_generator.APKAnalyzer") as MockAnalyzer:
            mock_analyzer = MagicMock()
            mock_analyzer.decompile.return_value = sample_report
            mock_analyzer.observe_runtime.return_value = sample_report
            MockAnalyzer.return_value = mock_analyzer
            with patch("apkmorph.patch_generator.APKBuilder") as MockBuilder:
                mock_builder = MagicMock()
                mock_builder.rebuild_and_sign.return_value = Path("/tmp/patched_test.apk")
                MockBuilder.return_value = mock_builder
                with patch.object(generator, "_apply_modifications", return_value=["file1.smali"]):
                    results = generator.batch(
                        description="remove ads",
                        apk_paths=["test.apk"],
                        output_dir=Path("/tmp/batch_test"),
                        observe_runtime=False,
                    )
    assert len(results) == 1
    assert results[0]["success"] is True
    assert results[0]["apk"] == "test.apk"
    assert "patched_test.apk" in results[0]["output_apk"]
    mock_print.assert_called()
