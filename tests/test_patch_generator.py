"""Tests for PatchGenerator.

Covers prompt construction, PatchPlan validation, simulate_apply for
Smali/XML/resource edits, batch mode, rollback on rebuild failure,
device install, and confidence/rationale fields. Uses mocks so no
real Ollama, Frida, APK or ADB is required.
"""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch, mock_open

import pytest

from apkmorph.models import AnalysisReport, Modification, PatchPlan
from apkmorph.patch_generator import PatchGenerator


@pytest.fixture
def generator():
    return PatchGenerator(model="llama3.2")


@pytest.fixture
def sample_report(tmp_path: Path):
    decomp = tmp_path / "decomp"
    decomp.mkdir()
    (decomp / "smali" / "com" / "example").mkdir(parents=True)
    (decomp / "smali" / "com" / "example" / "MainActivity.smali").write_text(
        ".class Lcom/example/MainActivity;\n.method onCreate()V\n.end method"
    )
    (decomp / "res" / "values").mkdir(parents=True)
    (decomp / "res" / "values" / "strings.xml").write_text(
        '<resources><string name="app_name">Old</string></resources>'
    )

    return AnalysisReport(
        apk_path=Path("test.apk"),
        package_name="com.example.app",
        version_name="1.0",
        version_code="1",
        min_sdk=24,
        target_sdk=34,
        decompiled_dir=decomp.absolute(),
        main_activity=".MainActivity",
        activities=[".MainActivity"],
        services=[],
        receivers=[],
        providers=[],
        permissions=[],
        components=["com.example.MainActivity"],
        strings=["analytics", "ad"],
        string_resources={"app_name": "Old"},
        metadata={"runtime_observed": True},
        size_bytes=1024,
        runtime_observations=["observed: analytics"],
    )


def test_from_description(generator: PatchGenerator, sample_report: AnalysisReport):
    sample_json = {
        "id": "plan-123",
        "description": "disable analytics",
        "rationale": "Found Firebase calls in onCreate",
        "confidence": 0.85,
        "modifications": [
            {
                "edit_type": "smali",
                "class_name": "com.example.MainActivity",
                "method": "onCreate",
                "description": "Comment out analytics",
                "confidence": 0.9,
                "diff": "- invoke-static\n+ # invoke-static",
                "params": {},
            }
        ],
    }

    with patch("apkmorph.patch_generator.LLMClient") as mock_llm_class:
        mock_llm = MagicMock()
        mock_llm.query.return_value = json.dumps(sample_json)
        mock_llm_class.return_value = mock_llm

        plan = generator.from_description("disable analytics", sample_report)

    assert isinstance(plan, PatchPlan)
    assert plan.id == "plan-123"
    assert plan.confidence == 0.85
    assert len(plan.modifications) == 1
    assert plan.modifications[0].class_name == "com.example.MainActivity"
    assert "analytics" in plan.rationale.lower()


def test_validate_plan(generator: PatchGenerator):
    mod = Modification(
        edit_type="smali",
        class_name="com.example.Main",
        method="onCreate",
        description="test",
        confidence=0.8,
        diff="- old\n+ new",
    )
    plan = PatchPlan(
        id="p1",
        description="test",
        rationale="ok",
        confidence=0.8,
        modifications=[mod],
    )
    # should not raise
    generator.validate(plan)


def test_simulate_apply_smali_xml_resource(generator: PatchGenerator, sample_report: AnalysisReport, tmp_path: Path):
    mod_smali = Modification(
        edit_type="smali",
        class_name="com.example.MainActivity",
        method="onCreate",
        description="nop analytics",
        confidence=0.85,
        diff="- invoke\n+ nop",
        params={},
    )
    mod_resource = Modification(
        edit_type="resource",
        class_name="",
        method="",
        description="change string",
        confidence=0.75,
        diff="",
        params={"key": "app_name", "value": "Patched"},
    )
    plan = PatchPlan(
        id="p2",
        description="test",
        rationale="test",
        confidence=0.8,
        modifications=[mod_smali, mod_resource],
    )

    with patch("apkmorph.smali.SmaliEditor.apply_modification", return_value=True):
        simulation = generator.simulate_apply(plan, sample_report.decompiled_dir)

    assert simulation["applied"] == 2
    assert any("smali" in m for m in simulation["details"])
    assert any("resource" in m for m in simulation["details"])


@patch("apkmorph.patch_generator.APKBuilder")
def test_apply_plan_rollback_on_failure(mock_builder, generator: PatchGenerator, sample_report: AnalysisReport, tmp_path: Path):
    plan = PatchPlan(
        id="p3",
        description="fail test",
        rationale="will fail",
        confidence=0.6,
        modifications=[],
    )

    mock_builder.return_value.rebuild_and_sign.side_effect = RuntimeError("rebuild failed")

    with patch("apkmorph.utils.safe_copytree") as mock_backup:
        with pytest.raises(RuntimeError, match="rebuild failed"):
            generator.apply_plan(plan, sample_report)

    mock_backup.assert_called()  # rollback should have been attempted


@patch("apkmorph.builder.APKBuilder.install_on_device")
def test_apply_plan_with_device_push(mock_install, generator: PatchGenerator, sample_report: AnalysisReport):
    plan = PatchPlan(
        id="p4",
        description="install test",
        rationale="ok",
        confidence=0.9,
        modifications=[],
    )

    with patch("apkmorph.patch_generator.PatchGenerator._apply_modifications", return_value=True):
        with patch("apkmorph.patch_generator.APKBuilder") as mock_b:
            mock_b.return_value.rebuild_and_sign.return_value = Path("patched.apk")
            output = generator.apply_plan(plan, sample_report, install=True, launch=True)

    mock_install.assert_called_once()
    assert "patched" in str(output)


def test_batch(generator: PatchGenerator, tmp_path: Path):
    apk1 = tmp_path / "a.apk"
    apk2 = tmp_path / "b.apk"
    apk1.touch()
    apk2.touch()

    with patch.object(generator, "from_description") as mock_from:
        mock_from.return_value = PatchPlan(
            id="batch1",
            description="batch test",
            rationale="ok",
            confidence=0.8,
            modifications=[],
        )
        with patch.object(generator, "apply_plan", return_value=Path("out.apk")):
            results = generator.batch(
                description="disable ads",
                apk_paths=[str(apk1), str(apk2)],
                output_dir=tmp_path / "out",
                model="llama3.2",
                observe_runtime=False,
                install=False,
                launch=False,
            )

    assert len(results) == 2
    assert results[0]["success"] is True


def test_export_python(generator: PatchGenerator, sample_report: AnalysisReport, tmp_path: Path):
    plan = PatchPlan(
        id="export1",
        description="export test",
        rationale="ok",
        confidence=0.9,
        modifications=[],
    )

    out = tmp_path / "exported.py"
    path = generator.export(plan, out, fmt="python")
    assert path.exists()
    content = path.read_text()
    assert "PatchPlan" in content
    assert "from apkmorph" in content
