"""Tests for patch generation, application, simulation and the new device push feature."""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from pydantic import ValidationError

from apkmorph.models import AnalysisReport, PatchPlan, Modification
from apkmorph.patch_generator import PatchGenerator


@pytest.fixture
def sample_report(tmp_path: Path) -> AnalysisReport:
    decomp_dir = tmp_path / "decompiled_test"
    decomp_dir.mkdir()
    return AnalysisReport(
        apk_path=Path("test.apk"),
        package_name="com.example.test",
        decompiled_dir=decomp_dir,
        main_activity="com.example.test.MainActivity",
        components=["com.example.test.MainActivity"],
        strings=["test string", "ad banner"],
        string_resources={"app_name": "Test App"},
        runtime_observations=["observed: ad load"],
        metadata={},
    )


@pytest.fixture
def sample_plan() -> PatchPlan:
    return PatchPlan(
        description="remove ads",
        modifications=[
            Modification(
                edit_type="smali",
                class_name="com.example.test.MainActivity",
                method="onCreate",
                description="Comment out ad initialization",
                confidence=0.85,
                diff="- invoke ad\n+ # invoke ad",
            )
        ],
        rationale="Targeted the observed ad load call.",
        confidence=0.82,
    )


def test_from_description(sample_report: AnalysisReport):
    generator = PatchGenerator(model="llama3.2")
    with patch.object(generator.llm, "query") as mock_query:
        mock_query.return_value = PatchPlan(
            description="test", rationale="ok", confidence=0.8
        )
        plan = generator.from_description("test request", sample_report, observe_runtime=False)
        assert plan is not None
        mock_query.assert_called_once()


def test_simulate_apply(sample_plan: PatchPlan, tmp_path: Path):
    generator = PatchGenerator()
    result = generator.simulate_apply(sample_plan, tmp_path)
    assert result["success"] is True
    assert result["total"] == 1
    assert len(result["applied"]) == 1


def test_apply_plan(sample_report: AnalysisReport, sample_plan: PatchPlan, tmp_path: Path):
    generator = PatchGenerator()
    with patch.object(generator.editor, "apply_modification", return_value=True), patch.object(
        generator.builder, "rebuild_and_sign", return_value=tmp_path / "patched.apk"
    ):
        output = generator.apply_plan(sample_plan, sample_report, install=False)
        assert output.name == "patched.apk"


def test_apply_plan_with_device_push(sample_report, sample_plan, tmp_path):
    generator = PatchGenerator()
    mock_apk = tmp_path / "patched_test.apk"
    mock_apk.touch()
    with patch.object(
        generator.builder, "rebuild_and_sign", return_value=mock_apk
    ), patch.object(generator.builder, "install_on_device") as mock_install, patch(
        "apkmorph.patch_generator.console"
    ):
        output = generator.apply_plan(
            sample_plan, sample_report, install=True, launch=True
        )
        mock_install.assert_called_with(
            str(mock_apk),
            sample_report.package_name,
            sample_report.main_activity,
            launch=True,
        )
        assert output == mock_apk


def test_batch(sample_report, tmp_path):
    generator = PatchGenerator()
    apk1 = tmp_path / "app1.apk"
    apk1.touch()
    apk2 = tmp_path / "app2.apk"
    apk2.touch()
    with patch.object(generator, "from_description") as mock_from, patch.object(
        generator, "apply_plan", return_value=tmp_path / "out.apk"
    ), patch("apkmorph.patch_generator.APKAnalyzer") as mock_analyzer:
        mock_analyzer.return_value.decompile.return_value = sample_report
        mock_from.return_value = PatchPlan(description="batch", rationale="ok")
        results = generator.batch(
            "disable ads",
            [str(apk1), str(apk2)],
            tmp_path / "output",
            observe_runtime=False,
            install=False,
        )
        assert len(results) == 2
        assert results[0]["success"] is True


def test_export_python(sample_plan, tmp_path):
    generator = PatchGenerator()
    out_path = tmp_path / "exported.py"
    result_path = generator.export(sample_plan, out_path, fmt="python")
    assert result_path.exists()
    content = result_path.read_text()
    assert "PatchGenerator" in content
    assert "def main()" in content
    assert sample_plan.id in content


def test_export_json(sample_plan, tmp_path):
    generator = PatchGenerator()
    out_path = tmp_path / "plan.json"
    result = generator.export(sample_plan, out_path, fmt="json")
    assert result.exists()
    data = json.loads(result.read_text())
    assert data["description"] == sample_plan.description
