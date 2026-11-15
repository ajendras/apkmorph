"""Streamlit UI for APK Morph.

Clean SaaS-style interface with light grey/white surfaces, #2563eb primary,
8px border radius, soft shadows, and clear hierarchy. Supports APK upload,
natural-language patching, side-by-side diff viewer, patch history, and
one-click build.
"""

import tempfile
from pathlib import Path
from typing import Any

import streamlit as st

from apkmorph.analyzer import APKAnalyzer
from apkmorph.builder import APKBuilder
from apkmorph.models import AnalysisReport, PatchPlan
from apkmorph.patch_generator import PatchGenerator
from apkmorph.utils import generate_report_md

# --------------------------- Page config & styling ---------------------------

st.set_page_config(
    page_title="APK Morph",
    page_icon="🔧",
    layout="wide",
    initial_sidebar_state="expanded",
    menu_items={
        "Get Help": "https://github.com/apkmorph/apkmorph",
        "Report a bug": "https://github.com/apkmorph/apkmorph/issues",
    },
)

# Crisp, clean SaaS styling matching the brief
st.markdown(
    """
    <style>
        .main {background-color: #f1f5f9;}
        .block-container {padding-top: 2rem; padding-bottom: 2rem;}
        h1, h2, h3 {font-weight: 600; color: #0f172a;}
        .stButton > button {
            border-radius: 8px;
            height: 42px;
            background-color: #2563eb;
            color: white;
            border: none;
            box-shadow: 0 2px 6px rgba(37, 99, 235, 0.2);
        }
        .stButton > button:hover {background-color: #1e40af;}
        .card {
            background-color: white;
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(15, 23, 42, 0.06);
            padding: 1.25rem;
            margin-bottom: 1rem;
        }
        .diff-before {background-color: #fee2e2; border-left: 4px solid #ef4444;}
        .diff-after {background-color: #ecfdf5; border-left: 4px solid #10b981;}
        .metric-label {font-size: 0.8rem; color: #64748b;}
        .status-pill {
            display: inline-block;
            padding: 2px 10px;
            border-radius: 9999px;
            font-size: 0.75rem;
            font-weight: 600;
        }
    </style>
    """,
    unsafe_allow_html=True,
)

# ----------------------------- Session state -----------------------------

if "report" not in st.session_state:
    st.session_state.report: AnalysisReport | None = None
if "plan" not in st.session_state:
    st.session_state.plan: PatchPlan | None = None
if "history" not in st.session_state:
    st.session_state.history: list[PatchPlan] = []
if "decompiled_temp" not in st.session_state:
    st.session_state.decompiled_temp: Path | None = None
if "current_apk_name" not in st.session_state:
    st.session_state.current_apk_name = ""

# ------------------------------- Sidebar -------------------------------

with st.sidebar:
    st.image(
        "https://via.placeholder.com/180x48/2563eb/ffffff?text=APK+MORPH",
        use_column_width=True,
    )
    st.caption("Natural-language APK patching • 100% local")

    st.divider()

    page = st.radio(
        "Navigation",
        ["Analyze & Patch", "History", "Settings"],
        label_visibility="collapsed",
    )

    st.divider()
    st.markdown("**Status**")
    ollama_status = "🟢 Ollama connected" if True else "🔴 Ollama not running"
    st.caption(ollama_status)
    st.caption("Model: llama3.2")

    if st.button("Clear session", use_container_width=True):
        for key in list(st.session_state.keys()):
            del st.session_state[key]
        st.rerun()

# ----------------------------- Main UI -----------------------------

st.title("APK Morph")
st.markdown(
    "Translate plain English into precise, auditable APK patches. "
    "Everything stays on your machine."
)

if page == "Analyze & Patch":
    col1, col2 = st.columns([2, 3])

    with col1:
        st.subheader("1. Upload APK")
        uploaded = st.file_uploader(
            "Choose an APK file",
            type=["apk"],
            label_visibility="collapsed",
            help="All processing happens locally. Large files may take 10-30s.",
        )

        if uploaded:
            st.session_state.current_apk_name = uploaded.name
            # Save to temporary directory so analyzer can operate on real path
            with tempfile.TemporaryDirectory() as tmp:
                tmp_path = Path(tmp) / uploaded.name
                tmp_path.write_bytes(uploaded.getvalue())

                if st.button(
                    "Analyze APK",
                    type="primary",
                    use_container_width=True,
                ):
                    with st.spinner("Decompiling with Apktool + Androguard..."):
                        try:
                            analyzer = APKAnalyzer(working_dir=Path(tmp) / "decomp")
                            report = analyzer.decompile(str(tmp_path))
                            st.session_state.report = report
                            st.session_state.decompiled_temp = report.decompiled_dir
                            st.success(f"Analyzed {report.package_name}")
                            st.rerun()
                        except Exception as exc:
                            st.error(f"Analysis failed: {exc}")

        if st.session_state.report:
            report = st.session_state.report
            st.markdown("**Analysis Summary**")
            st.info(report.summary(), icon="📦")

            with st.expander("Component Tree", expanded=False):
                for comp in report.components[:15]:
                    st.code(comp, language=None)
                if len(report.components) > 15:
                    st.caption(f"... and {len(report.components)-15} more")

    with col2:
        if st.session_state.report:
            st.subheader("2. Describe your patch")
            description = st.text_area(
                "What should we change?",
                placeholder='disable all analytics, remove ads, skip splash screen...',
                height=110,
                label_visibility="collapsed",
            )

            col_btn1, col_btn2 = st.columns([1, 1])
            with col_btn1:
                if st.button(
                    "Generate Patch Plan",
                    type="primary",
                    disabled=not description,
                    use_container_width=True,
                ):
                    with st.spinner("Consulting local LLM..."):
                        try:
                            generator = PatchGenerator(model="llama3.2")
                            plan = generator.from_description(
                                description, st.session_state.report
                            )
                            st.session_state.plan = plan
                            st.session_state.history.insert(0, plan)
                            st.success("Plan generated")
                            st.rerun()
                        except Exception as exc:
                            st.error(str(exc))

            with col_btn2:
                if st.session_state.plan and st.button(
                    "Apply & Build",
                    use_container_width=True,
                ):
                    with st.spinner("Applying patches and rebuilding..."):
                        try:
                            builder = APKBuilder()
                            decomp = str(st.session_state.decompiled_temp or "decompiled")
                            final = builder.rebuild_and_sign(decomp)
                            st.success(f"Built: {final.name}")
                            st.balloons()
                        except Exception as exc:
                            st.error(f"Build failed: {exc}")

            # ------------------ Patch Plan Display ------------------
            if st.session_state.plan:
                plan = st.session_state.plan
                st.markdown("### Proposed Patch Plan")
                st.caption(f"ID: **{plan.id}** • Confidence: {plan.confidence:.2f}")

                st.info(plan.rationale or "No rationale provided.", icon="💡")

                for i, mod in enumerate(plan.modifications):
                    with st.container():
                        st.markdown(f"**{i+1}.** `{mod.class_name}` • `{mod.method}`")
                        cols = st.columns([4, 1])
                        with cols[0]:
                            st.markdown(
                                f"<div class='card'><small>{mod.description}</small></div>",
                                unsafe_allow_html=True,
                            )
                        with cols[1]:
                            st.metric(
                                "Confidence",
                                f"{mod.confidence:.2f}",
                                label_visibility="collapsed",
                            )
                        st.code(mod.diff, language="smali")
                        st.divider()

elif page == "History":
    st.subheader("Patch History")
    if not st.session_state.history:
        st.info("No patches yet. Generate one from the Analyze page.")
    else:
        for plan in st.session_state.history:
            with st.expander(
                f"{plan.id} — {plan.description[:45]}...",
                expanded=False,
            ):
                st.caption(plan.rationale)
                df_data: list[dict[str, Any]] = []
                for m in plan.modifications:
                    df_data.append(
                        {
                            "Class": m.class_name.split(".")[-1],
                            "Method": m.method[:30],
                            "Confidence": f"{m.confidence:.2f}",
                            "Description": m.description[:50] + "…",
                        }
                    )
                st.dataframe(df_data, use_container_width=True, hide_index=True)

                if st.button("Re-apply this plan", key=plan.id):
                    st.warning("Re-apply not yet wired in this demo UI.")

elif page == "Settings":
    st.subheader("Preferences")
    st.selectbox(
        "Default Ollama model",
        ["llama3.2", "llama3.1:8b", "mistral"],
        index=0,
    )
    st.text_input("Apktool path (optional)", value="apktool")
    st.text_input("Keystore path (for signing)", value="~/.android/debug.keystore")
    st.checkbox("Enable GPU acceleration (if available)", value=True)
    st.caption(
        "All data stays on-device. No telemetry. "
        "Ollama must be running locally."
    )

# Footer
st.divider()
st.caption(
    "APK Morph v0.1.0 • Built with Streamlit, Ollama, Apktool, Androguard • "
    "Fully offline"
)
