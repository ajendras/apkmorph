# Changelog

All notable changes to this project are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-11-15

### Added

- Instant Ingestion — Upload any APK for automatic decompilation via Apktool and Androguard metadata extraction
- Natural Language — Type requests like 'disable all analytics' and the LLM builds a targeted modification plan
- Code Reasoning — Local Ollama model maps English intent to specific methods, classes and resource IDs
- Precise Patches — Generates minimal Smali edits, XML tweaks and resource swaps while preserving signatures
- Before/After View — Side-by-side diff with plain-English rationale for every inserted or removed instruction
- One-click Build — Rebuilds, zipaligns and signs the new APK using test or user-provided keys
- Visual Dashboard — Streamlit UI shows component tree, patch history, confidence scores and export options
- Fully Local — No data leaves your machine; works with any Ollama model and optional GPU acceleration
