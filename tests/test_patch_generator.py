"""Tests for patch generation, validation, simulation, batch and the new export feature."""

import json
from pathlib import Path
from unittest.mock import patch

import pytest

from apkmorph.analyzer import APKAnalyzer
from apkmorph.llm import LLMClient
from apkmorph.models import AnalysisReport, Modification, PatchPlan
from apkmorph.patch_generator import PatchGenerator


@pytest.fixture
def sample_report(tmp_path: Path) -> AnalysisReport:
    decomp = tmp_path / "decompiled_test"
    decomp.mkdir()
    return AnalysisReport(
        apk_path=Path("test.apk"),
        package_name="com.example.testapp",
        decompiled_dir=decomp.absolute(),
        components=["com.example.testapp.MainActivity"],
        strings=["ad", "analytics"],
        string_resources={"app_name": "Test", "ad_text": "Advertisement"},
        metadata={},
        size_bytes=2048,
    )


@pytest.fixture
def sample_modification() -> Modification:
    return Modification(
        class_name="com.example.testapp.MainActivity",
        method="onCreate(Landroid/os/Bundle;)V",
        edit_type="smali",
        description="Return early to disable analytics",
        confidence=0.88,
        diff="- invoke-static ...analytics\n+ return-void",
        original_snippet="invoke-static",
        patched_snippet="return-void",
        hover_explanation="Early return prevents analytics upload",
    )


@pytest.fixture
def sample_plan(sample_modification: Modification) -> PatchPlan:
    return PatchPlan(
        description="disable analytics and remove ads",
        rationale="Targeted methods observed at runtime via Frida",
        confidence=0.85,
        modifications=[sample_modification],
    )


def test_from_description(sample_report: AnalysisReport, monkeypatch):
    """Test that from_description returns a valid PatchPlan (LLM is mocked)."""

    def mock_generate_patch(desc: str, report: AnalysisReport) -> PatchPlan:
        return PatchPlan(
            description=desc,
            rationale="Mocked rationale for testing",
            modifications=[
                Modification(
                    class_name="com.example.AdManager",
                    method="loadAd",
                    edit_type="smali",
                    description="Disable ad loading",
                    confidence=0.9,
                )
            ],
        )

    monkeypatch.setattr(LLMClient, "generate_patch", mock_generate_patch)

    generator = PatchGenerator(model="phi3")
    plan = generator.from_description(
        "disable analytics", sample_report, observe_runtime=False
    )

    assert isinstance(plan, PatchPlan)
    assert plan.description == "disable analytics"
    assert len(plan.modifications) == 1
    assert plan.modifications[0].confidence == 0.9


def test_validate(sample_plan: PatchPlan):
    generator = PatchGenerator()
    assert generator.validate(sample_plan) is True

    # invalid plan
    bad_plan = PatchPlan(description="bad", modifications=[])
    assert generator.validate(bad_plan) is False


def test_simulate_apply(sample_plan: PatchPlan, tmp_path: Path):
    generator = PatchGenerator()
    result = generator.simulate_apply(sample_plan, tmp_path)
    assert result["total"] == 1
    assert result["simulated"] is True
    assert len(result["applied"]) == 1
    assert result["applied"][0]["edit_type"] == "smali"


def test_batch(sample_report: AnalysisReport, tmp_path: Path, monkeypatch):
    """Test batch with heavy mocking to avoid real LLM/apktool calls."""

    def mock_decompile(_path: str) -> AnalysisReport:
        return sample_report

    def mock_observe(report: AnalysisReport, **kwargs) -> AnalysisReport:
        return report

    def mock_from_description(*args, **kwargs) -> PatchPlan:
        return PatchPlan(
            description="batch test",
            modifications=[
                Modification(
                    class_name="Test",
                    method="test",
                    edit_type="smali",
                    description="test mod",
                    confidence=0.8,
                )
            ],
        )

    def mock_apply_plan(self, plan: PatchPlan, report: AnalysisReport) -> Path:
        return tmp_path / "patched_test.apk"

    monkeypatch.setattr(APKAnalyzer, "decompile", mock_decompile)
    monkeypatch.setattr(APKAnalyzer, "observe_runtime", mock_observe)
    monkeypatch.setattr(PatchGenerator, "from_description", mock_from_description)
    monkeypatch.setattr(PatchGenerator, "apply_plan", mock_apply_plan)

    generator = PatchGenerator()
    results = generator.batch(
        description="test batch",
        apk_paths=["app1.apk", "app2.apk"],
        output_dir=tmp_path / "batch_out",
        observe_runtime=False,
    )

    assert len(results) == 2
    assert results[0]["success"] is True
    assert "patched_test.apk" in results[0]["output"]


def test_export_json(sample_plan: PatchPlan, tmp_path: Path):
    generator = PatchGenerator()
    out_path = generator.export(sample_plan, tmp_path / "export_test", fmt="json")

    assert out_path.suffix == ".json"
    assert out_path.exists()

    data = json.loads(out_path.read_text(encoding="utf-8"))
    assert data["description"] == sample_plan.description
    assert data["id"] == sample_plan.id
    assert len(data["modifications"]) == 1
    assert data["modifications"][0]["confidence"] == 0.88


def test_export_python(sample_plan: PatchPlan, tmp_path: Path):
    generator = PatchGenerator()
    out_path = generator.export(sample_plan, tmp_path / "testpatch", fmt="python")

    assert out_path.suffix == ".py"
    assert out_path.exists()
    assert out_path.stat().st_mode & 0o111 != 0  # executable on Unix

    content = out_path.read_text(encoding="utf-8")
    assert "Reusable APK Morph patch" in content
    assert sample_plan.description in content
    assert "PLAN_JSON" in content
    assert "PatchPlan.model_validate" in content
    assert "def main" in content
    assert "generator.apply_plan" in content
    assert "apkmorph.builder" in content
