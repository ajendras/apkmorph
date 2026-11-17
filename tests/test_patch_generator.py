"""Tests for patch generation, validation and simulation.

Covers prompt construction, LLM output parsing, safety validation,
simulate_apply and the new snippet population used by the interactive
side-by-side diff viewer.
"""

import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from apkmorph.patch_generator import PatchGenerator
from apkmorph.models import AnalysisReport, PatchPlan, Modification


@pytest.fixture
def sample_report(tmp_path):
    decomp = tmp_path / "decompiled_test"
    decomp.mkdir()
    (decomp / "smali").mkdir()
    sample_smali = decomp / "smali" / "TestClass.smali"
    sample_smali.write_text(
        ".class public LTestClass;\n"
        ".method public onCreate()V\n"
        "    invoke-super {p0}, Landroid/app/Activity;->onCreate()V\n"
        "    return-void\n"
        ".end method\n"
    )
    return AnalysisReport(
        apk_path=Path("test.apk"),
        package_name="com.test.app",
        decompiled_dir=decomp,
        components=["com.test.app.TestClass"],
        strings=["analytics", "ad"],
        string_resources={"app_name": "Test App"},
        runtime_observations=["observed: ad - loadAd"],
        metadata={},
    )


@pytest.fixture
def sample_plan():
    mod = Modification(
        class_name="com.test.app.TestClass",
        method="onCreate()V",
        diff="    invoke-super {p0}, ...",
        description="Disable analytics call observed at runtime",
        edit_type="smali",
        file_path=Path("smali/TestClass.smali"),
        confidence=0.92,
    )
    return PatchPlan(
        description="disable analytics",
        modifications=[mod],
        rationale="Targeted the method seen in Frida observations",
        confidence=0.89,
    )


def test_from_description_enriches_with_snippets(sample_report):
    generator = PatchGenerator(model="llama3.2")

    # Mock the LLM so we get a deterministic plan
    with patch.object(generator.llm, "generate_patch") as mock_generate:
        mock_generate.return_value = sample_plan()
        plan = generator.from_description("disable analytics", sample_report, observe=False)

        assert len(plan.modifications) == 1
        mod = plan.modifications[0]
        assert mod.original_snippet is not None
        assert "onCreate" in mod.original_snippet
        assert mod.patched_snippet is not None
        assert mod.hover_explanation is not None
        assert "Confidence:" in mod.hover_explanation


def test_validate_rejects_low_confidence():
    generator = PatchGenerator()
    bad_mod = Modification(
        class_name="com.example.Foo",
        method="bar()V",
        diff="return-void",
        description="bad change",
        confidence=0.3,
    )
    bad_plan = PatchPlan(
        description="bad plan",
        modifications=[bad_mod],
        rationale="low confidence",
    )

    with pytest.raises(ValueError, match="confidence too low"):
        generator.validate(bad_plan)


def test_simulate_apply_returns_expected_structure(sample_plan, tmp_path):
    generator = PatchGenerator()
    result = generator.simulate_apply(sample_plan, tmp_path)

    assert "applied" in result
    assert len(result["applied"]) == 1
    applied = result["applied"][0]
    assert applied["mod_id"] == sample_plan.modifications[0].id
    assert "original" in applied
    assert "patched" in applied
    assert "explanation" in applied


def test_from_description_uses_observed_methods(sample_report):
    generator = PatchGenerator()
    # The LLM prompt already includes runtime observations; we just
    # verify that the enrichment path runs without error.
    with patch.object(generator.llm, "generate_patch") as mock_llm:
        mock_llm.return_value = sample_plan()
        plan = generator.from_description("remove ads", sample_report, observe=True)
        assert any("ad" in m.hover_explanation.lower() for m in plan.modifications)
