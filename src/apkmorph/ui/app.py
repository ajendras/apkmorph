"""Streamlit UI for APK Morph.

Provides upload, natural-language prompt input, confidence scoring UI element
with color-coded metrics and progress bar, side-by-side diff viewer, and a
user feedback form that triggers LLM prompt refinement via PatchGenerator.refine_plan().
"""

import shutil
import tempfile
from pathlib import Path

import streamlit as st

from apkmorph.analyzer import APKAnalyzer
from apkmorph.builder import APKBuilder
from apkmorph.models import AnalysisReport
from apkmorph.patch_generator import PatchGenerator


st.set_page_config(
    page_title="APK Morph",
    page_icon="🧬",
    layout="wide",
    initial_sidebar_state="expanded",
)


def main() -> None:
    st.title("🧬 APK Morph")
    st.caption(
        "Natural-language AI patching • Local Ollama • Confidence scoring & feedback-driven refinement"
    )

    with st.sidebar:
        st.header("Configuration")
        model = st.selectbox(
            "Ollama model",
            options=["llama3.2", "gemma2", "phi3"],
            index=0,
        )
        observe = st.checkbox("Observe runtime (Frida)", value=True)
        st.caption("Feedback submitted in the main view is automatically injected into the next LLM prompt.")

    tab1, tab2 = st.tabs(["Patch Generator", "Batch & Export"])

    with tab1:
        uploaded = st.file_uploader(
            "Upload APK", type=["apk"], help="Any Android package (.apk)"
        )

        if uploaded:
            tmp_dir = Path(tempfile.mkdtemp())
            apk_path = tmp_dir / uploaded.name
            with open(apk_path, "wb") as f:
                f.write(uploaded.getbuffer())

            st.success(f"Loaded {uploaded.name}")

            analyzer = APKAnalyzer(working_dir=tmp_dir / "decompiled")
            with st.spinner("Decompiling and extracting metadata..."):
                report: AnalysisReport = analyzer.decompile(str(apk_path))
                if observe:
                    with st.spinner("Observing runtime (or simulating)..."):
                        report = analyzer.observe_runtime(report)

            st.session_state.report = report
            st.subheader("Analysis")
            st.info(report.summary())

            description = st.text_area(
                "What change do you want?",
                placeholder='disable all analytics, remove ads, change primary color to #FF5722',
                height=80,
                key="prompt_input",
            )

            if st.button("Generate Plan", type="primary"):
                if not description.strip():
                    st.error("Please enter a description")
                else:
                    with st.spinner("Querying local LLM..."):
                        generator = PatchGenerator(model=model)
                        plan = generator.from_description(description, report)
                        st.session_state.current_plan = plan
                        st.session_state.feedback_history = []
                        st.rerun()

            if "current_plan" in st.session_state:
                plan = st.session_state.current_plan
                report = st.session_state.report

                st.divider()
                st.subheader("📊 Confidence Scoring")
                conf = plan.confidence
                if conf >= 0.8:
                    color = "#22c55e"
                    label = "HIGH"
                elif conf >= 0.6:
                    color = "#eab308"
                    label = "MEDIUM"
                else:
                    color = "#ef4444"
                    label = "LOW – refine below"
                st.markdown(
                    f"""
                    <div style="background:{color}15;border:2px solid {color};border-radius:8px;padding:16px;margin-bottom:16px">
                        <span style="font-size:2.2rem;font-weight:bold;color:{color}">{label}</span><br>
                        <span style="font-size:3rem;font-weight:bold;color:{color}">{conf:.2f}</span>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
                st.progress(conf)
                st.caption("LLM-generated confidence. Higher is better. Use the feedback form to improve it.")

                st.subheader("Rationale")
                st.write(plan.rationale)

                st.subheader("Proposed Modifications")
                for i, mod in enumerate(plan.modifications):
                    with st.expander(
                        f"#{i+1} {mod.class_name.split('.')[-1]} • {mod.method or 'global'} "
                        f"(confidence {mod.confidence:.2f})",
                        expanded=i == 0,
                    ):
                        st.write(mod.description)
                        if mod.diff:
                            col_orig, col_new = st.columns(2)
                            with col_orig:
                                st.markdown("**Before**")
                                st.code(
                                    "\n".join(
                                        line for line in mod.diff.split("\n") if line.startswith("-") or not line.startswith(("+", "-"))
                                    ),
                                    language="smali",
                                )
                            with col_new:
                                st.markdown("**After**")
                                st.code(
                                    "\n".join(
                                        line for line in mod.diff.split("\n") if line.startswith("+") or not line.startswith(("+", "-"))
                                    ),
                                    language="smali",
                                )
                        st.metric("Mod Confidence", f"{mod.confidence:.2f}")

                st.divider()
                st.subheader("🔄 User Feedback Loop")
                st.info(
                    "Tell the AI what to improve. Your text is appended to the system prompt on the next generation."
                )
                rating = st.slider(
                    "Your own confidence rating for this plan",
                    0.0,
                    1.0,
                    float(plan.confidence),
                    0.05,
                )
                feedback_text = st.text_area(
                    "Feedback / corrections",
                    value="",
                    placeholder="Target the loadAd() method in the banner class instead. Avoid removing the whole permission block.",
                    height=110,
                )

                if st.button("Refine Prompt with Feedback", type="secondary"):
                    if feedback_text.strip():
                        with st.spinner("Generating refined plan..."):
                            generator = PatchGenerator(model=model)
                            refined = generator.refine_plan(plan, feedback_text, report)
                            refined.confidence = (refined.confidence + rating) / 2
                            st.session_state.current_plan = refined
                            st.session_state.feedback_history.append(feedback_text)
                            st.success("Plan refined – review the new confidence score above.")
                            st.rerun()
                    else:
                        st.warning("Enter feedback before refining.")

                if st.button("Build & Sign APK", type="primary"):
                    with st.spinner("Applying patches, rebuilding, signing..."):
                        try:
                            generator = PatchGenerator(model=model)
                            out_apk = generator.apply_plan(plan, report, install=False, launch=False)
                            st.balloons()
                            st.success(f"Finished: {out_apk.name}")
                            with open(out_apk, "rb") as f:
                                st.download_button(
                                    label="Download patched APK",
                                    data=f,
                                    file_name=out_apk.name,
                                    mime="application/vnd.android.package-archive",
                                )
                        except Exception as e:
                            st.error(f"Build error: {e}")

    with tab2:
        st.subheader("Batch Processing")
        st.caption("Run the same request on many APKs (uses the feedback-aware generator).")
        st.info("Batch functionality is available from the CLI (`apkmorph batch ...`). The UI focuses on single-APK interactive refinement.")

        st.subheader("Export")
        if "current_plan" in st.session_state:
            plan = st.session_state.current_plan
            if st.button("Export as Python script"):
                generator = PatchGenerator()
                path = generator.export(plan, fmt="python")
                with open(path, "rb") as f:
                    st.download_button("Download .py", f, file_name=path.name)
            if st.button("Export as JSON template"):
                generator = PatchGenerator()
                path = generator.export(plan, fmt="json")
                with open(path, "rb") as f:
                    st.download_button("Download .json", f, file_name=path.name)
        else:
            st.caption("Generate a plan first to enable export.")

    # Cleanup helper
    if st.button("Clear temporary files"):
        for p in Path("decompiled_ui").glob("**/*"):
            if p.is_dir():
                shutil.rmtree(p, ignore_errors=True)
        st.success("Temporary files cleared.")


if __name__ == "__main__":
    main()
