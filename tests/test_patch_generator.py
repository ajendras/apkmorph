"""Tests for PatchGenerator.

Covers prompt construction, PatchPlan validation, simulate_apply for
Smali/XML/resource edits, batch processing, rollback on rebuild failure,
device install integration, feedback refinement loop, and custom plugins.
All LLM, builder, editor and filesystem calls are mocked so collection
and execution succeed in CI without Ollama, real APKs or Frida.
"""

import pytest
import json
from unittest.mock import patch, MagicMock
from pathlib import Path

from apkmorph.patch_generator import PatchGenerator
from apkmorph.models import AnalysisReport, PatchPlan, Modification
from apkmorph.builder import APKBuilder
from apkmorph.plugins import register_custom_patch_type, list_custom_patch_types


@pytest.fixture
def sample_report():
    """Minimal report for testing patch generation."""
    return AnalysisReport(
        apk_path=Path("test.apk"),
        package_name="com.example.testapp",
        decompiled_dir=Path("/tmp/decomp_test"),
        main_activity="com.example.MainActivity",
        components=["com.example.MainActivity"],
        strings=["ads", "analytics", "firebase"],
        string_resources={"ad_text": "Click to install", "app_name": "Test App"},
        metadata={"runtime_observed": True},
        size_bytes=2048,
        runtime_observations=["observed: ad - loadAd"],
    )


@pytest.fixture
def sample_plan():
    """Sample PatchPlan with mixed edit types."""
    mod1 = Modification(
        edit_type="smali",
        class_name="com.example.MainActivity",
        method="onCreate",
        description="Remove ad initialization",
        confidence=0.92,
        diff="- invoke-virtual {v0}, Lcom/google/ads/AdView;->loadAd()V\n+ # patched: ad removed",
        params={},
    )
    mod2 = Modification(
        edit_type="resource",
        class_name="",
        method="",
        description="Update ad string to empty",
        confidence=0.85,
        diff="",
        params={"key": "ad_text", "value": ""},
    )
    return PatchPlan(
        id="plan_test123",
        rationale="Targeted ad removal and string cleanup based on runtime observations and resource scan. High confidence because hooks confirmed live ad paths.",
        confidence=0.88,
        modifications=[mod1, mod2],
    )


def test_from_description(sample_report):
    """Test natural language to PatchPlan using mocked LLM."""
    generator = PatchGenerator(model="phi3")
    expected_json = {
        "id": "plan_test123",
        "rationale": "Targeted ad removal based on observed ad loads.",
        "confidence": 0.88,
        "modifications": [
            {
                "edit_type": "smali",
                "class_name": "com.example.MainActivity",
                "method": "onCreate",
                "description": "Remove ad initialization",
                "confidence": 0.92,
                "diff": "- invoke-virtual {v0}, Lcom/google/ads/AdView;->loadAd()V\n+ # patched: ad removed",
                "params": {},
            }
        ],
    }

    with patch.object(generator.llm, "query") as mock_query:
        mock_query.return_value = json.dumps(expected_json)
        with patch("apkmorph.patch_generator.PatchGenerator.validate") as mock_validate:
            mock_validate.side_effect = lambda p: p
            plan = generator.from_description("disable all ads and analytics", sample_report)

            assert plan.id == "plan_test123"
            assert len(plan.modifications) == 1
            assert plan.modifications[0].edit_type == "smali"
            assert "ad" in plan.rationale.lower()
            mock_query.assert_called_once()


def test_validate(sample_plan):
    """Test PatchPlan validation and normalization."""
    generator = PatchGenerator()
    validated = generator.validate(sample_plan)
    assert validated.id == sample_plan.id
    assert validated.confidence == pytest.approx(0.88)
    for mod in validated.modifications:
        assert mod.confidence > 0.5
        assert mod.description


def test_simulate_apply(sample_plan, sample_report):
    """Test dry-run simulation for Smali, XML, resource and plugin edits."""
    generator = PatchGenerator()

    with patch("apkmorph.patch_generator.SmaliEditor") as mock_editor_class:
        mock_editor = MagicMock()
        mock_editor.apply_modification.return_value = True
        mock_editor_class.return_value = mock_editor

        simulation = generator.simulate_apply(sample_plan, sample_report.decompiled_dir)

        assert simulation["applied"] == len(sample_plan.modifications)
        assert simulation["success"] is True
        assert "smali" in simulation["details"]
        assert "resource" in simulation["details"]
        mock_editor.apply_modification.assert_called()


def test_batch(sample_report):
    """Test batch processing of multiple APKs with shared description."""
    generator = PatchGenerator(model="llama3.2")

    with patch.object(generator, "from_description") as mock_from, \
         patch.object(generator, "apply_plan") as mock_apply, \
         patch("apkmorph.patch_generator.APKAnalyzer") as mock_analyzer:

        mock_from.return_value = PatchPlan(
            id="batch_plan",
            rationale="Batch test",
            confidence=0.85,
            modifications=[]
        )
        mock_apply.return_value = Path("patched_batch_1.apk")
        mock_analyzer.return_value.decompile.return_value = sample_report

        results = generator.batch(
            description="remove ads",
            apk_paths=["app1.apk", "app2.apk"],
            output_dir=Path("batch_out"),
            model="phi3",
            observe_runtime=False,
            install=False,
            launch=False,
        )

        assert len(results) == 2
        assert all(r.get("success", False) for r in results)
        assert mock_from.call_count == 2
        assert mock_apply.call_count == 2


def test_apply_plan_rollback_on_failure(sample_plan, sample_report, tmp_path):
    """Test automatic backup + rollback when rebuild_and_sign fails."""
    decomp_dir = tmp_path / "decomp_fail"
    decomp_dir.mkdir()
    sample_report.decompiled_dir = decomp_dir

    generator = PatchGenerator()

    with patch("apkmorph.patch_generator.safe_copytree") as mock_backup, \
         patch.object(generator, "_apply_modifications") as mock_apply_mod, \
         patch("apkmorph.patch_generator.APKBuilder") as mock_builder_class, \
         patch("apkmorph.utils.safe_copytree") as mock_restore:

        mock_builder = MagicMock()
        mock_builder.rebuild_and_sign.side_effect = RuntimeError("Apktool build failed")
        mock_builder_class.return_value = mock_builder
        mock_apply_mod.return_value = True

        with pytest.raises(RuntimeError, match="Apktool build failed"):
            generator.apply_plan(sample_plan, sample_report)

        mock_backup.assert_called()
        mock_restore.assert_called()
        assert mock_restore.call_count >= 1


def test_apply_plan_with_device_push(sample_plan, sample_report):
    """Test apply_plan with --install/--launch calling install_on_device."""
    generator = PatchGenerator()

    with patch.object(generator, "_apply_modifications") as mock_mods, \
         patch("apkmorph.patch_generator.APKBuilder") as mock_builder_class:

        mock_builder = MagicMock()
        mock_builder.rebuild_and_sign.return_value = Path("patched_test.apk")
        mock_builder.install_on_device.return_value = None
        mock_builder_class.return_value = mock_builder

        output = generator.apply_plan(
            sample_plan,
            sample_report,
            install=True,
            launch=True
        )

        assert output.name.startswith("patched_")
        mock_builder.rebuild_and_sign.assert_called_once()
        mock_builder.install_on_device.assert_called_once_with(
            str(output),
            sample_report.package_name,
            sample_report.main_activity,
            launch=True,
        )


def test_refine_with_feedback(sample_plan):
    """Test feedback loop that augments LLM prompt and improves confidence."""
    generator = PatchGenerator()

    improved_json = {
        "id": "plan_test123",
        "rationale": "Improved rationale after user feedback: made patch more aggressive by also clearing ad strings in resources.arsc.",
        "confidence": 0.94,
        "modifications": sample_plan.modifications,
    }

    with patch.object(generator.llm, "query") as mock_query:
        mock_query.return_value = json.dumps(improved_json)
        refined = generator.refine_with_feedback(
            sample_plan,
            "Make the patch more aggressive and also clear ad strings"
        )
        assert refined.confidence > 0.9
        assert "aggressive" in refined.rationale.lower()
        assert "resources.arsc" in refined.rationale.lower()
        mock_query.assert_called_once()


def test_custom_patch_plugin():
    """Test registration and dispatch of custom patch types via plugin API."""
    @register_custom_patch_type("theme_injector")
    def inject_theme(mod: Modification, decompiled_dir: Path) -> bool:
        """Dummy plugin that always succeeds for test."""
        (decompiled_dir / "res" / "values" / "styles.xml").touch()
        return True

    assert "theme_injector" in list_custom_patch_types()

    generator = PatchGenerator()
    report = AnalysisReport(
        apk_path=Path("test.apk"),
        package_name="com.test",
        decompiled_dir=Path("/tmp/decomp"),
        components=[],
        strings=[],
        string_resources={},
        metadata={},
        size_bytes=0,
    )
    mod = Modification(
        edit_type="theme_injector",
        class_name="",
        method="",
        description="Apply dark theme",
        confidence=0.8,
        diff="",
        params={"primary_color": "#FF5722"},
    )
    plan = PatchPlan(
        id="plugin_test",
        rationale="Custom theme plugin",
        confidence=0.8,
        modifications=[mod],
    )

    with patch("apkmorph.patch_generator.SmaliEditor") as mock_editor:
        mock_editor.return_value.apply_modification.return_value = True
        result = generator.apply_plan(plan, report)
        assert result is not None


def test_export_python_script(sample_plan, tmp_path):
    """Test exporting PatchPlan as self-contained Python script."""
    generator = PatchGenerator()
    out_path = tmp_path / "exported_patch.py"

    exported = generator.export(sample_plan, out_path, fmt="python")
    assert exported.exists()
    content = exported.read_text()
    assert "from apkmorph" in content
    assert "PatchPlan" in content
    assert sample_plan.id in content
    assert "disable all analytics" in content or "remove ads" in content.lower()


def test_prompt_includes_runtime_and_resources(sample_report):
    """Test that LLM prompt includes Frida observations and string_resources."""
    generator = PatchGenerator()
    with patch.object(generator.llm, "query") as mock_query:
        mock_query.return_value = '{"id":"p1","rationale":"ok","confidence":0.8,"modifications":[]}'
        generator.from_description("remove ads", sample_report)
        call_args = mock_query.call_args[0][0]  # prompt
        assert "observed:" in call_args
        assert "string_resources" in call_args
        assert "ad_text" in call_args
