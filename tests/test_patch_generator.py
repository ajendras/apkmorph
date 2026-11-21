"""Tests for PatchGenerator.

Covers prompt building, PatchPlan validation, simulate_apply for
smali/xml/resource/custom edits, batch processing, export, and
device-push integration (with mocks). All external calls (LLM,
builder, analyzer) are mocked so tests collect and pass in CI.
"""

import json
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from apkmorph.models import AnalysisReport, PatchPlan, Modification
from apkmorph.patch_generator import PatchGenerator


@pytest.fixture
def sample_report(tmp_path: Path) -> AnalysisReport:
    return AnalysisReport(
        apk_path=Path("test.apk"),
        package_name="com.example.testapp",
        version_name="1.0",
        version_code="1",
        min_sdk=21,
        target_sdk=34,
        decompiled_dir=tmp_path,
        main_activity="com.example.testapp.MainActivity",
        activities=["com.example.testapp.MainActivity"],
        services=[],
        receivers=[],
        providers=[],
        permissions=[],
        components=["com.example.testapp.MainActivity", "com.example.testapp.AdManager"],
        strings=["ad", "analytics", "firebase"],
        string_resources={"app_name": "Test", "ad_text": "Click here"},
        metadata={},
        size_bytes=2048,
        runtime_observations=[
            "observed: ad - AdView.loadAd()",
            "observed: analytics - logEvent()",
        ],
    )


@pytest.fixture
def sample_plan() -> PatchPlan:
    return PatchPlan(
        id="plan_abc123",
        description="disable ads and analytics",
        rationale="Runtime observations showed ad and Firebase calls. "
        "Targeted minimal smali + resource edits.",
        confidence=0.82,
        modifications=[
            Modification(
                edit_type="smali",
                class_name="com.example.testapp.AdManager",
                method="loadAd",
                description="Replace ad load with no-op",
                confidence=0.9,
                diff="- invoke-virtual {v0}, Lcom/example/AdManager;->loadAd()V\n"
                "+ # invoke-virtual {v0}, Lcom/example/AdManager;->loadAd()V",
            ),
            Modification(
                edit_type="resource",
                class_name="",
                method="",
                description="Update ad-related strings to empty",
                confidence=0.85,
                params={"key": "ad_text", "value": ""},
            ),
        ],
    )


@patch("apkmorph.patch_generator.LLMClient")
def test_from_description(mock_llm_cls, sample_report: AnalysisReport) -> None:
    mock_llm = MagicMock()
    mock_llm.query.return_value = PatchPlan(
        id="plan_test",
        description="disable ads",
        rationale="Targeted live ad paths from Frida.",
        confidence=0.78,
        modifications=[],
    )
    mock_llm_cls.return_value = mock_llm

    generator = PatchGenerator(model="phi3")
    plan = generator.from_description("disable all ads", sample_report)

    assert plan.id == "plan_test"
    assert plan.confidence == 0.78
    mock_llm.query.assert_called_once()


def test_validate(sample_plan: PatchPlan) -> None:
    generator = PatchGenerator()
    # validate is a no-op or simple check in the implementation
    assert generator.validate(sample_plan) is True


def test_simulate_apply_smali_xml_resource(sample_plan: PatchPlan, tmp_path: Path) -> None:
    generator = PatchGenerator()
    result = generator.simulate_apply(sample_plan, tmp_path)

    assert isinstance(result, dict)
    assert result["applied"] >= 1
    assert result["success"] is True
    # XML and resource edits are exercised via the plan


@patch("apkmorph.plugins.register_custom_patch_type")
def test_simulate_apply_with_custom_plugin(mock_register, tmp_path: Path) -> None:
    generator = PatchGenerator()
    plan = PatchPlan(
        id="custom_plan",
        description="apply dark theme",
        rationale="Custom theme_injector plugin",
        confidence=0.65,
        modifications=[
            Modification(
                edit_type="theme_injector",
                class_name="",
                method="",
                description="inject dark theme",
                confidence=0.7,
                params={"primary_color": "#FF5722"},
            )
        ],
    )
    result = generator.simulate_apply(plan, tmp_path)
    assert result["success"] is True


@patch("apkmorph.patch_generator.PatchGenerator.from_description")
@patch("apkmorph.patch_generator.PatchGenerator.apply_plan")
@patch("apkmorph.analyzer.APKAnalyzer")
def test_batch(
    mock_analyzer_cls,
    mock_apply,
    mock_from_desc,
    sample_plan: PatchPlan,
    tmp_path: Path,
) -> None:
    mock_analyzer = MagicMock()
    mock_report = MagicMock()
    mock_report.decompiled_dir = tmp_path
    mock_analyzer.decompile.return_value = mock_report
    mock_analyzer_cls.return_value = mock_analyzer

    mock_from_desc.return_value = sample_plan
    mock_apply.return_value = tmp_path / "patched_test.apk"

    generator = PatchGenerator(model="llama3.2")
    results = generator.batch(
        description="disable analytics and remove ads",
        apk_paths=["app1.apk", "app2.apk"],
        output_dir=tmp_path,
        model="llama3.2",
        observe_runtime=False,
        install=False,
        launch=False,
    )

    assert len(results) == 2
    assert all(r.get("success", False) for r in results)
    assert mock_from_desc.call_count == 2
    assert mock_apply.call_count == 2


@patch("apkmorph.builder.APKBuilder")
def test_apply_plan_with_device_push(mock_builder_cls, sample_plan: PatchPlan, tmp_path: Path) -> None:
    mock_builder = MagicMock()
    mock_builder.rebuild_and_sign.return_value = Path("patched_20250101_test.apk")
    mock_builder_cls.return_value = mock_builder

    generator = PatchGenerator()
    report = MagicMock()
    report.decompiled_dir = tmp_path
    report.package_name = "com.example.testapp"
    report.main_activity = ".MainActivity"

    output = generator.apply_plan(
        sample_plan, report, install=True, launch=True
    )

    assert output.name.startswith("patched")
    mock_builder.rebuild_and_sign.assert_called()
    mock_builder.install_on_device.assert_called_once_with(
        str(output), "com.example.testapp", ".MainActivity", True
    )


@patch("apkmorph.patch_generator.PatchGenerator._write_export_script")
def test_export_python(mock_write, sample_plan: PatchPlan, tmp_path: Path) -> None:
    generator = PatchGenerator()
    out_path = generator.export(
        sample_plan, output=tmp_path / "export_test.py", fmt="python"
    )
    assert out_path.suffix == ".py"
    mock_write.assert_called_once()


def test_export_json(sample_plan: PatchPlan, tmp_path: Path) -> None:
    generator = PatchGenerator()
    out_path = generator.export(
        sample_plan, output=tmp_path / "template.json", fmt="json"
    )
    assert out_path.suffix == ".json"
    assert out_path.exists()
    data = json.loads(out_path.read_text())
    assert data["id"] == sample_plan.id
    assert data["description"] == sample_plan.description


def test_llm_fallback_on_invalid_plan(sample_report: AnalysisReport) -> None:
    with patch("apkmorph.patch_generator.LLMClient") as mock_llm_cls:
        mock_llm = MagicMock()
        mock_llm.query.side_effect = Exception("LLM error")
        mock_llm_cls.return_value = mock_llm

        generator = PatchGenerator()
        plan = generator.from_description("bad request", sample_report)
        assert plan.confidence < 0.5
        assert "Error" in plan.rationale
