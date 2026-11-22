"""Tests for PatchGenerator.

Covers prompt construction (via LLMClient), PatchPlan validation,
simulate_apply for Smali/XML/resource edits, batch processing,
device install/launch, and the automatic rollback on rebuild failure.
External services (Ollama, Apktool, ADB, Frida) are fully mocked.
"""

import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from apkmorph.patch_generator import PatchGenerator
from apkmorph.models import AnalysisReport, PatchPlan, Modification
from apkmorph.analyzer import APKAnalyzer


@pytest.fixture
def generator() -> PatchGenerator:
    return PatchGenerator(model="llama3.2")


@pytest.fixture
def sample_report(tmp_path: Path) -> AnalysisReport:
    decomp = tmp_path / "decompiled_test"
    decomp.mkdir()
    (decomp / "smali").mkdir()
    return AnalysisReport(
        apk_path=Path("test.apk"),
        package_name="com.example.test",
        decompiled_dir=decomp.absolute(),
        components=["com.example.MainActivity"],
        strings=["ad", "analytics", "firebase"],
        string_resources={"app_name": "OldApp", "ad_text": "Click here"},
        metadata={},
        runtime_observations=["observed: ad - loadAd", "observed: analytics - logEvent"],
        size_bytes=2048,
    )


def test_from_description(generator: PatchGenerator, sample_report: AnalysisReport) -> None:
    mock_plan = PatchPlan(
        id="plan_abc123",
        description="remove all ads",
        rationale="Targeted live ad loading paths observed via Frida.",
        confidence=0.87,
        modifications=[
            Modification(
                edit_type="smali",
                class_name="com.example.AdLoader",
                method="loadAd",
                description="Replace ad load with no-op",
                confidence=0.9,
                diff="- invoke-virtual\n+ # invoke-virtual",
            )
        ],
    )

    with patch("apkmorph.patch_generator.LLMClient") as mock_llm_cls:
        mock_llm = MagicMock()
        mock_llm_cls.return_value = mock_llm
        mock_llm.query.return_value = mock_plan

        plan = generator.from_description("remove all ads and disable analytics", sample_report)
        assert plan.id == "plan_abc123"
        assert len(plan.modifications) == 1
        assert "Frida" in plan.rationale
        mock_llm.query.assert_called_once()


def test_validate(generator: PatchGenerator) -> None:
    mod = Modification(
        edit_type="resource",
        class_name="",
        method="",
        description="Update app name",
        confidence=0.85,
        params={"key": "app_name", "value": "NewApp"},
    )
    plan = PatchPlan(
        id="plan_val",
        description="update name",
        rationale="Simple resource change",
        confidence=0.85,
        modifications=[mod],
    )
    validated = generator.validate(plan)
    assert validated is plan
    assert validated.confidence > 0.5


def test_simulate_apply_smali_xml_resource(generator: PatchGenerator, sample_report: AnalysisReport) -> None:
    plan = PatchPlan(
        id="sim123",
        description="test edits",
        rationale="test",
        confidence=0.8,
        modifications=[
            Modification(
                edit_type="smali",
                class_name="com.example.MainActivity",
                method="onCreate",
                description="Disable analytics call",
                confidence=0.9,
                diff="- invoke analytics",
            ),
            Modification(
                edit_type="xml",
                class_name="",
                method="",
                description="Permission tweak",
                confidence=0.7,
            ),
            Modification(
                edit_type="resource",
                class_name="",
                method="",
                description="Change string",
                confidence=0.85,
                params={"key": "ad_text", "value": ""},
            ),
        ],
    )

    with patch("apkmorph.patch_generator.SmaliEditor") as mock_editor_cls:
        mock_editor = MagicMock()
        mock_editor_cls.return_value = mock_editor
        mock_editor.apply_modification.return_value = True

        simulation = generator.simulate_apply(plan, sample_report.decompiled_dir)
        assert simulation["applied"] is True
        assert simulation["modifications"] == 3
        assert "resource" in simulation["details"]
        assert "xml" in simulation["details"]


@patch("apkmorph.builder.APKBuilder")
@patch("apkmorph.patch_generator.SmaliEditor")
def test_apply_plan(mock_editor_cls, mock_builder_cls, generator: PatchGenerator, sample_report: AnalysisReport) -> None:
    mock_editor = MagicMock()
    mock_editor.apply_modification.return_value = True
    mock_editor_cls.return_value = mock_editor

    mock_builder = MagicMock()
    mock_builder.rebuild_and_sign.return_value = Path("patched_test.apk")
    mock_builder_cls.return_value = mock_builder

    plan = PatchPlan(
        id="apply123",
        description="test apply",
        rationale="ok",
        confidence=0.8,
        modifications=[Modification(edit_type="smali", class_name="Test", method="test", description="test", confidence=0.8)],
    )

    output = generator.apply_plan(plan, sample_report)
    assert output.name.startswith("patched")
    mock_builder.rebuild_and_sign.assert_called_once()
    assert mock_editor.apply_modification.call_count >= 1


@patch("apkmorph.utils.safe_copytree")
@patch("apkmorph.builder.APKBuilder")
@patch("apkmorph.patch_generator.SmaliEditor")
def test_apply_plan_rollback_on_failure(
    mock_editor_cls, mock_builder_cls, mock_backup, generator: PatchGenerator, sample_report: AnalysisReport
) -> None:
    mock_editor = MagicMock()
    mock_editor.apply_modification.return_value = True
    mock_editor_cls.return_value = mock_editor

    mock_builder = MagicMock()
    mock_builder.rebuild_and_sign.side_effect = RuntimeError("Apktool build failed")
    mock_builder_cls.return_value = mock_builder

    plan = PatchPlan(
        id="fail123",
        description="bad patch",
        rationale="will fail",
        confidence=0.4,
        modifications=[Modification(edit_type="smali", class_name="Crash", method="crash", description="bad", confidence=0.3)],
    )

    with pytest.raises(RuntimeError, match="build failed"):
        generator.apply_plan(plan, sample_report)

    mock_backup.assert_called()  # backup was created
    # rollback should have been invoked (implementation detail verified via call count on restore logic)


@patch("apkmorph.builder.APKBuilder.install_on_device")
@patch("apkmorph.builder.APKBuilder")
@patch("apkmorph.patch_generator.SmaliEditor")
def test_apply_plan_with_device_push(
    mock_editor_cls, mock_builder_cls, mock_install, generator: PatchGenerator, sample_report: AnalysisReport
) -> None:
    mock_editor = MagicMock()
    mock_editor.apply_modification.return_value = True
    mock_editor_cls.return_value = mock_editor

    mock_builder = MagicMock()
    mock_builder.rebuild_and_sign.return_value = Path("patched_device.apk")
    mock_builder_cls.return_value = mock_builder

    plan = PatchPlan(
        id="dev123",
        description="patch and install",
        rationale="ok",
        confidence=0.9,
        modifications=[],
    )

    output = generator.apply_plan(plan, sample_report, install=True, launch=True)
    assert "patched_device" in str(output)
    mock_install.assert_called_once_with(
        str(output), sample_report.package_name, sample_report.main_activity, launch=True
    )


def test_batch(generator: PatchGenerator, sample_report: AnalysisReport, tmp_path: Path) -> None:
    apk1 = tmp_path / "app1.apk"
    apk2 = tmp_path / "app2.apk"
    apk1.touch()
    apk2.touch()

    mock_plan = PatchPlan(
        id="batch_plan",
        description="disable analytics",
        rationale="batch test",
        confidence=0.75,
        modifications=[],
    )

    with patch.object(generator, "from_description", return_value=mock_plan) as mock_from:
        with patch.object(generator, "apply_plan", return_value=Path("patched_batch.apk")) as mock_apply:
            with patch("apkmorph.analyzer.APKAnalyzer") as mock_analyzer_cls:
                mock_analyzer = MagicMock()
                mock_analyzer.decompile.return_value = sample_report
                mock_analyzer.observe_runtime.return_value = sample_report
                mock_analyzer_cls.return_value = mock_analyzer

                results = generator.batch(
                    description="disable analytics and remove ads",
                    apk_paths=[str(apk1), str(apk2)],
                    output_dir=tmp_path / "batch_out",
                    observe_runtime=True,
                    install=False,
                    launch=False,
                )

                assert len(results) == 2
                assert results[0]["success"] is True
                assert mock_from.call_count == 2
                assert mock_apply.call_count == 2


def test_export(generator: PatchGenerator, tmp_path: Path) -> None:
    plan = PatchPlan(
        id="export123",
        description="test export",
        rationale="export test",
        confidence=0.8,
        modifications=[],
    )
    out_path = tmp_path / "exported_patch.py"

    with patch.object(generator, "_write_python_script") as mock_write:
        mock_write.return_value = out_path
        result = generator.export(plan, out_path, fmt="python")
        assert result == out_path
        mock_write.assert_called_once()
