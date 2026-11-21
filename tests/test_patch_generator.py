"""Tests for PatchGenerator including prompt construction, validation,
simulation, batch, export and resource/XML support.
"""

import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from apkmorph.patch_generator import PatchGenerator
from apkmorph.models import AnalysisReport, PatchPlan, Modification
from apkmorph.plugins import register_custom_patch_type


@pytest.fixture
def sample_report(tmp_path):
    return AnalysisReport(
        apk_path=tmp_path / "sample.apk",
        package_name="com.example.sample",
        decompiled_dir=tmp_path / "decomp",
        strings=["ad", "analytics", "hello world"],
        string_resources={"app_name": "Sample App", "ad_string": "Click to win!"},
        runtime_observations=["observed: ad - loadAd() called"],
        metadata={},
    )


@pytest.fixture
def sample_plan():
    return PatchPlan(
        id="plan_123_test",
        description="remove ads and disable analytics",
        rationale="Targeted live ad and analytics methods observed at runtime. Also updated strings.",
        confidence=0.88,
        modifications=[
            Modification(
                edit_type="smali",
                class_name="com.example.AdLoader",
                method="loadBanner",
                description="NOP the ad load call",
                confidence=0.9,
                diff="- invoke-virtual {v0}, Lcom/example/AdLoader;->loadBanner()V\n+ # patched",
            ),
            Modification(
                edit_type="resource",
                class_name="ad_string",
                method="",
                description="Empty the ad prompt string",
                confidence=0.85,
                params={"value": ""},
            ),
        ],
    )


def test_from_description(sample_report):
    with patch("apkmorph.llm.LLMClient.query") as mock_query:
        mock_query.return_value = PatchPlan(
            description="remove ads and disable analytics",
            modifications=[],
            rationale="Test rationale",
            confidence=0.75,
        )
        generator = PatchGenerator(model="phi3")
        plan = generator.from_description("remove ads and disable analytics", sample_report)
        assert plan is not None
        assert mock_query.called


def test_validate(sample_plan):
    generator = PatchGenerator()
    # make one mod invalid
    sample_plan.modifications.append(
        Modification(
            edit_type="bad_type",
            class_name="",
            description="bad mod",
            confidence=1.5,
        )
    )
    validated = generator.validate(sample_plan)
    assert validated.modifications[-1].edit_type == "smali"
    assert validated.modifications[-1].class_name != ""
    assert validated.modifications[-1].confidence <= 1.0
    assert len(validated.rationale) > 10


def test_simulate_apply(sample_plan, tmp_path):
    generator = PatchGenerator()
    sim = generator.simulate_apply(sample_plan, tmp_path)
    assert sim["simulated"] is True
    assert sim["success"] is True
    assert len(sim["applied"]) == len(sample_plan.modifications)
    assert sim["overall_confidence"] == sample_plan.confidence
    for a in sim["applied"]:
        assert "target" in a
        assert "description" in a


def test_apply_plan(sample_plan, sample_report):
    generator = PatchGenerator()
    with patch.object(generator.editor, "apply_modification", return_value=True) as mock_apply, patch.object(
        generator.builder, "rebuild_and_sign", return_value=Path("patched_sample.apk")
    ) as mock_build:
        result = generator.apply_plan(sample_plan, sample_report)
        assert result.name == "patched_sample.apk"
        assert mock_apply.call_count == len(sample_plan.modifications)
        mock_build.assert_called_once()


def test_batch(sample_report):
    generator = PatchGenerator()
    apk_list = ["app1.apk", "app2.apk"]
    out_dir = Path("/tmp/batch_out")
    with patch.object(generator, "from_description") as mock_from, patch.object(
        generator, "apply_plan"
    ) as mock_apply, patch("apkmorph.patch_generator.APKAnalyzer") as mock_ana_class:
        mock_ana = MagicMock()
        mock_ana.decompile.return_value = sample_report
        mock_ana.observe_runtime.return_value = sample_report
        mock_ana_class.return_value = mock_ana
        mock_plan = PatchPlan(
            description="test batch",
            modifications=[Modification(class_name="Test", description="test", edit_type="smali")],
            rationale="batch test",
        )
        mock_from.return_value = mock_plan
        mock_apply.return_value = Path("patched_app1.apk")
        results = generator.batch(
            "disable analytics",
            apk_list,
            out_dir,
            model="llama3.2",
            observe_runtime=True,
        )
        assert len(results) == 2
        assert results[0]["success"] is True
        assert mock_from.call_count == 2
        assert "mod_count" in results[0]


def test_export(sample_plan, tmp_path):
    generator = PatchGenerator()
    py_path = tmp_path / "mypatch.py"
    exported = generator.export(sample_plan, py_path, fmt="python")
    assert exported.exists()
    content = exported.read_text(encoding="utf-8")
    assert "Standalone patch exported by APK Morph" in content
    assert "remove ads and disable analytics" in content
    assert "PatchPlan.model_validate_json" in content
    assert "def main()" in content

    json_path = tmp_path / "template.json"
    exported_json = generator.export(sample_plan, json_path, fmt="json")
    assert exported_json.exists()
    assert '"id": "plan_123_test"' in exported_json.read_text(encoding="utf-8")


def test_custom_patch_type_support():
    # test that custom types are accepted in validate
    @register_custom_patch_type("theme_injector")
    def dummy_theme(mod, dir_path):  # pylint: disable=unused-variable
        return True

    generator = PatchGenerator()
    plan = PatchPlan(
        description="apply dark theme",
        modifications=[
            Modification(
                edit_type="theme_injector",
                class_name="styles.xml",
                description="inject dark theme colors",
                confidence=0.8,
            )
        ],
        rationale="custom plugin used",
    )
    validated = generator.validate(plan)
    assert validated.modifications[0].edit_type == "theme_injector"
