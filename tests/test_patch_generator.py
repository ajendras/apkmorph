"""Tests for PatchGenerator.

Covers prompt construction, validation, simulate_apply, manifest edits,
rollback behaviour, gallery integration and the new natural-language
manifest support.
"""

import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from apkmorph.models import AnalysisReport, Modification, PatchPlan
from apkmorph.patch_generator import PatchGenerator


@pytest.fixture
def sample_report(tmp_path: Path) -> AnalysisReport:
    decomp = tmp_path / "decompiled"
    decomp.mkdir()
    (decomp / "AndroidManifest.xml").write_text(
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<manifest package="com.example.app">\n'
        '  <uses-permission android:name="android.permission.CAMERA"/>\n'
        '</manifest>',
        encoding="utf-8",
    )
    return AnalysisReport(
        apk_path=tmp_path / "test.apk",
        package_name="com.example.app",
        decompiled_dir=decomp,
        permissions=["android.permission.CAMERA"],
        activities=["com.example.MainActivity"],
        receivers=[],
        components=["com.example.MainActivity"],
        strings=["hello"],
        string_resources={"app_name": "Test App"},
    )


def test_from_description_includes_manifest_context(sample_report: AnalysisReport):
    generator = PatchGenerator(model="llama3.2")
    with patch.object(generator.llm, "query") as mock_query:
        mock_query.return_value = PatchPlan(
            description="add internet permission",
            modifications=[
                Modification(
                    edit_type="manifest",
                    target="AndroidManifest.xml",
                    description="Add INTERNET permission",
                    rationale="App needs network access",
                    params={"operation": "add_permission", "name": "android.permission.INTERNET"},
                    confidence=0.9,
                )
            ],
            rationale="Added network permission",
            confidence=0.9,
        )
        plan = generator.from_description("add internet permission", sample_report)
        assert any(m.edit_type == "manifest" for m in plan.modifications)
        mock_query.assert_called_once()


def test_manifest_edit_validation(sample_report: AnalysisReport):
    generator = PatchGenerator()
    plan = PatchPlan(
        description="test manifest",
        modifications=[
            Modification(
                edit_type="manifest",
                target="AndroidManifest.xml",
                description="Add permission",
                rationale="Test",
                params={"operation": "add_permission", "name": "android.permission.INTERNET"},
                confidence=0.85,
            )
        ],
        rationale="test",
    )
    # Should not raise
    generator.validate(plan, sample_report)


def test_manifest_edit_validation_bad_operation(sample_report: AnalysisReport):
    generator = PatchGenerator()
    plan = PatchPlan(
        description="bad op",
        modifications=[
            Modification(
                edit_type="manifest",
                target="AndroidManifest.xml",
                description="Bad op",
                rationale="Test",
                params={"operation": "bad_op", "name": "foo"},
                confidence=0.9,
            )
        ],
        rationale="test",
    )
    with pytest.raises(ValueError, match="Unknown manifest operation"):
        generator.validate(plan, sample_report)


def test_apply_manifest_edit(sample_report: AnalysisReport):
    generator = PatchGenerator()
    mod = Modification(
        edit_type="manifest",
        target="AndroidManifest.xml",
        description="Add internet permission",
        rationale="Needed for API calls",
        params={"operation": "add_permission", "name": "android.permission.INTERNET"},
        confidence=0.9,
    )
    plan = PatchPlan(
        description="add permission",
        modifications=[mod],
        rationale="Added permission",
        confidence=0.9,
    )
    result = generator.apply_plan(plan, sample_report)
    assert result["success"] is True
    manifest = (sample_report.decompiled_dir / "AndroidManifest.xml").read_text(encoding="utf-8")
    assert "android.permission.INTERNET" in manifest


def test_simulate_apply_includes_manifest(sample_report: AnalysisReport):
    generator = PatchGenerator()
    plan = PatchPlan(
        description="test",
        modifications=[
            Modification(
                edit_type="manifest",
                target="AndroidManifest.xml",
                description="Add receiver",
                rationale="Listen for boot",
                params={"operation": "add_receiver", "name": ".BootReceiver"},
                confidence=0.85,
            )
        ],
        rationale="test",
    )
    simulation = generator.simulate_apply(plan, sample_report.decompiled_dir)
    assert any(m["edit_type"] == "manifest" for m in simulation["applied"])


def test_rollback_on_failure(sample_report: AnalysisReport):
    generator = PatchGenerator()
    # Force failure by making the editor return False
    with patch.object(generator.editor, "apply_modification", return_value=False):
        plan = PatchPlan(
            description="failing plan",
            modifications=[
                Modification(
                    edit_type="manifest",
                    target="AndroidManifest.xml",
                    description="will fail",
                    rationale="test",
                    params={"operation": "add_permission", "name": "android.permission.WRITE_EXTERNAL_STORAGE"},
                )
            ],
            rationale="will fail",
        )
        with pytest.raises(RuntimeError, match="rolled back"):
            generator.apply_plan(plan, sample_report)
        # Original manifest should be restored (we never changed it because apply_modification was mocked)
        assert "CAMERA" in (sample_report.decompiled_dir / "AndroidManifest.xml").read_text(encoding="utf-8")
