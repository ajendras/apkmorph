"""Unit tests for PatchGenerator.

Mocks LLMClient, SmaliEditor, APKBuilder, and Analyzer so that prompt
construction, validation, simulation, batch, and export can be tested
in CI without Ollama, apktool, or real files.
"""

from pathlib import Path
from unittest.mock import MagicMock, patch

from apkmorph.models import AnalysisReport, Modification, PatchPlan
from apkmorph.patch_generator import PatchGenerator


def _make_report() -> AnalysisReport:
    return AnalysisReport(
        apk_path=Path("test.apk"),
        package_name="com.example.testapp",
        decompiled_dir=Path("/tmp/decomp"),
        components=["com.example.testapp.MainActivity", "com.example.testapp.AdView"],
        strings=["advertisement", "trackEvent"],
        string_resources={"ad_text": "Click to win!"},
        metadata={"runtime_observed": True},
        size_bytes=2048000,
        runtime_observations=[
            "observed: ad - com.google.android.gms.ads.AdView.loadAd() called",
            "observed: tracking - trackEvent()",
        ],
    )


def _make_plan() -> PatchPlan:
    return PatchPlan(
        id="plan_abc123",
        description="remove ads and disable tracking",
        modifications=[
            Modification(
                edit_type="smali",
                class_name="com.example.testapp.AdView",
                method="loadAd",
                description="Comment out ad loading",
                confidence=0.92,
                diff="- invoke-virtual ...",
            ),
            Modification(
                edit_type="resource",
                class_name="strings",
                description="Clear ad string",
                confidence=0.88,
                params={"ad_text": ""},
            ),
        ],
        rationale="Targeted observed ad and tracking calls plus the ad string resource.",
        confidence=0.90,
    )


def test_from_description():
    report = _make_report()
    expected_plan = _make_plan()

    with patch("apkmorph.patch_generator.LLMClient") as MockLLM, patch(
        "apkmorph.patch_generator.APKAnalyzer"
    ), patch.object(PatchGenerator, "validate", return_value=expected_plan):
        mock_llm = MockLLM.return_value
        mock_llm.query.return_value = expected_plan

        generator = PatchGenerator(model="phi3")
        plan = generator.from_description("remove ads and disable tracking", report)

        assert plan.id == "plan_abc123"
        assert len(plan.modifications) == 2
        assert plan.confidence > 0.8
        mock_llm.query.assert_called_once()


def test_validate_lowers_confidence_for_missing_targets():
    report = _make_report()
    plan = _make_plan()
    # add a modification for a class that does not exist
    plan.modifications.append(
        Modification(
            edit_type="smali",
            class_name="com.example.UnknownClass",
            method="unknown",
            description="should be downgraded",
            confidence=0.95,
        )
    )

    generator = PatchGenerator()
    validated = generator.validate(plan, report)

    for mod in validated.modifications:
        if "UnknownClass" in mod.class_name:
            assert mod.confidence < 0.6
    assert validated.confidence > 0.0


def test_simulate_apply_for_resource_and_xml():
    plan = _make_plan()
    generator = PatchGenerator()
    sim = generator.simulate_apply(plan, Path("/tmp"))

    assert sim["success"] is True
    assert sim["would_modify"] == 2
    assert any("resource" in step for step in sim["applied"])
    assert "rationale" in sim


def test_batch():
    report = _make_report()
    plan = _make_plan()
    output_dir = Path("/tmp/batch_out")

    with patch("apkmorph.patch_generator.PatchGenerator.from_description", return_value=plan), patch(
        "apkmorph.patch_generator.PatchGenerator.apply_plan", return_value=Path("patched.apk")
    ), patch("apkmorph.patch_generator.APKAnalyzer") as MockAnalyzer, patch(
        "pathlib.Path.mkdir"
    ):
        mock_analyzer = MockAnalyzer.return_value
        mock_analyzer.decompile.return_value = report
        mock_analyzer.observe_runtime.return_value = report

        generator = PatchGenerator()
        results = generator.batch(
            description="remove ads",
            apk_paths=["app1.apk", "app2.apk"],
            output_dir=output_dir,
            observe_runtime=True,
        )

        assert len(results) == 2
        assert results[0]["success"] is True
        assert "output" in results[0]


def test_export_python_script():
    plan = _make_plan()
    generator = PatchGenerator()

    with patch.object(Path, "write_text") as mock_write, patch.object(
        Path, "parent"
    ) as mock_parent:
        mock_parent.mkdir = MagicMock()
        path = generator.export(plan, Path("exported_patch.py"), fmt="python")

        assert path.suffix == ".py"
        mock_write.assert_called_once()
        content = mock_write.call_args[0][0]
        assert "Self-contained patch script" in content
        assert "PLAN_DATA" in content
        assert "def main" in content


def test_export_json():
    plan = _make_plan()
    generator = PatchGenerator()

    with patch.object(Path, "write_text") as mock_write, patch.object(
        Path, "parent"
    ) as mock_parent:
        mock_parent.mkdir = MagicMock()
        path = generator.export(plan, fmt="json")

        assert path.suffix == ".json"
        mock_write.assert_called_once()
        # JSON export uses model_dump_json
        assert "model_dump_json" in str(mock_write.call_args)
