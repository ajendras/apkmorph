"""Streamlit UI for APK Morph.

Provides a clean dashboard with APK upload, natural-language prompt input,
analysis summary, PatchPlan display and the new interactive side-by-side
Smali diff viewer (hover any highlighted line for an explanation). One-click
rebuild and download of the signed APK.
"""

import streamlit as st
from pathlib import Path
import tempfile
import shutil

from apkmorph.analyzer import APKAnalyzer
from apkmorph.patch_generator import PatchGenerator
from apkmorph.builder import APKBuilder
from apkmorph.models import AnalysisReport, PatchPlan
from apkmorph.smali import SmaliEditor


st.set_page_config(
    page_title="APK Morph",
    page_icon="📦",
    layout="wide",
    initial_sidebar_state="expanded",
)


def main() -> None:
    st.title("📦 APK Morph")
    st.markdown(
        "Describe the change you want. Local AI finds the code, shows an "
        "**interactive side-by-side diff** with hover explanations, then rebuilds a signed APK."
    )

    # Sidebar controls
    with st.sidebar:
        st.header("APK")
        uploaded = st.file_uploader(
            "Upload an APK", type=["apk"], label_visibility="collapsed"
        )
        analyze_btn = st.button("Analyze APK", type="primary", use_container_width=True)

        st.divider()
        st.caption("Configuration")
        model = st.selectbox("Ollama model", ["llama3.2", "llama3", "phi3"], index=0)
        observe_runtime = st.checkbox("Observe runtime with Frida", value=True)

    # Session state
    if "report" not in st.session_state:
        st.session_state.report = None
    if "plan" not in st.session_state:
        st.session_state.plan = None
    if "decompiled_temp" not in st.session_state:
        st.session_state.decompiled_temp = None

    analyzer = APKAnalyzer(working_dir=Path("decompiled_ui"))
    generator = PatchGenerator(model=model)
    builder = APKBuilder()
    editor = SmaliEditor()

    # Analysis flow
    if uploaded and analyze_btn:
        with st.spinner("Decompiling APK and extracting metadata..."):
            # Save uploaded file to a temporary location
            with tempfile.NamedTemporaryFile(delete=False, suffix=".apk") as tmp:
                tmp.write(uploaded.getvalue())
                tmp_path = Path(tmp.name)

            try:
                report = analyzer.decompile(str(tmp_path))
                if observe_runtime:
                    report = analyzer.observe_runtime(report)
                st.session_state.report = report
                st.session_state.decompiled_temp = report.decompiled_dir
                st.success(f"Analyzed {report.package_name}")
            except Exception as e:
                st.error(f"Analysis failed: {e}")
            finally:
                tmp_path.unlink(missing_ok=True)

    report: AnalysisReport | None = st.session_state.report

    if report:
        st.subheader("Analysis Summary")
        st.info(report.summary())

        with st.expander("Full report (Markdown)", expanded=False):
            st.markdown(report.to_markdown())

        # Natural language request
        st.subheader("What should we change?")
        description = st.text_area(
            "Describe the change in plain English",
            placeholder='Disable analytics, remove all ads, change the app name to "MyCustomApp"',
            height=80,
            key="prompt",
        )

        if st.button("Generate Patch Plan", type="primary"):
            with st.spinner("Querying local LLM and building plan..."):
                try:
                    plan = generator.from_description(
                        description, report, observe=observe_runtime
                    )
                    st.session_state.plan = plan
                    st.success("Patch plan generated")
                except Exception as e:
                    st.error(f"Failed to generate plan: {e}")

    plan: PatchPlan | None = st.session_state.plan

    if plan:
        st.divider()
        st.subheader("🧠 Patch Plan")
        st.caption(plan.description)

        col_rat, col_conf = st.columns([3, 1])
        with col_rat:
            st.markdown(f"**Rationale**  \n{plan.rationale}")
        with col_conf:
            st.metric("Overall confidence", f"{plan.confidence:.2f}")

        st.subheader("Interactive Diff Viewer")
        st.caption("Hover highlighted lines in the **Patched** column for explanations")

        for i, mod in enumerate(plan.modifications):
            with st.expander(
                f"{i+1}. {mod.class_name} • {mod.method}  "
                f"(confidence {mod.confidence:.2f})",
                expanded=i == 0,
            ):
                # Render the interactive HTML viewer
                html = editor.get_diff_html(mod)
                st.components.v1.html(html, height=520, scrolling=True)

        # Apply & rebuild section
        if st.button("Apply Patches & Rebuild Signed APK", type="primary", use_container_width=True):
            with st.spinner("Applying patches and rebuilding..."):
                try:
                    # Apply each modification to the decompiled tree
                    for mod in plan.modifications:
                        editor.apply_modification(report.decompiled_dir, mod)

                    signed_apk = builder.rebuild_and_sign(str(report.decompiled_dir))
                    st.success(f"Built: {signed_apk.name}")

                    with open(signed_apk, "rb") as f:
                        st.download_button(
                            label="Download patched APK",
                            data=f,
                            file_name=signed_apk.name,
                            mime="application/vnd.android.package-archive",
                        )
                except Exception as e:
                    st.error(f"Build failed: {e}")

        if st.button("Clear plan"):
            st.session_state.plan = None
            st.rerun()


if __name__ == "__main__":
    main()
