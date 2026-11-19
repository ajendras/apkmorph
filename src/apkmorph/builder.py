"""APK rebuild and signing module.

APKBuilder orchestrates Apktool rebuild, zipalign, and apksigner steps.
Uses test keystore when none is provided. All operations are local.
"""

import subprocess
from datetime import datetime
from pathlib import Path
from typing import Optional

from apkmorph.utils import run_apktool


class APKBuilder:
    """Rebuilds decompiled APKs and signs them.

    Uses Apktool for assembly, zipalign for alignment, and apksigner
    (falling back to a standard Android debug keystore when no keystore
    is supplied). Raises clear, actionable errors when tools are missing.
    """

    def __init__(self, build_dir: Path | None = None) -> None:
        """Initialize builder with optional custom build directory.

        Args:
            build_dir: Directory for intermediate build artifacts
        """
        self.build_dir = build_dir or Path("builds")
        self.build_dir.mkdir(parents=True, exist_ok=True)
        self._test_keystore = Path.home() / ".android" / "debug.keystore"

    def rebuild(self, decompiled_dir: str, output_apk: str) -> Path:
        """Rebuild decompiled directory into an unsigned APK using Apktool.

        Args:
            decompiled_dir: Path to directory containing smali/, res/, AndroidManifest.xml etc.
            output_apk: Desired path for the rebuilt APK

        Returns:
            Path to the rebuilt (unsigned) APK

        Raises:
            FileNotFoundError: If decompiled_dir does not exist
            RuntimeError: If Apktool fails or output is missing
        """
        decomp_path = Path(decompiled_dir).resolve()
        if not decomp_path.exists():
            raise FileNotFoundError(f"Decompiled directory not found: {decomp_path}")

        output_path = Path(output_apk).resolve()
        output_path.parent.mkdir(parents=True, exist_ok=True)

        if not str(output_path).lower().endswith(".apk"):
            output_path = output_path.with_suffix(".apk")

        console_msg = f"[blue]Rebuilding with Apktool → {output_path.name}[/blue]"
        try:
            # -f forces overwrite; no --force-stop (invalid flag). Apktool
            # will regenerate resources.arsc after any XML/string edits.
            run_apktool(
                ["b", str(decomp_path), "-o", str(output_path), "-f"]
            )
        except subprocess.CalledProcessError as exc:
            stderr = getattr(exc, "stderr", b"").decode(errors="replace")
            raise RuntimeError(f"Apktool build failed:\n{stderr}") from exc
        except FileNotFoundError as exc:
            raise RuntimeError(
                "Apktool not found. Install via: https://ibotpeaches.github.io/Apktool/"
            ) from exc

        if not output_path.exists():
            raise RuntimeError(f"Apktool did not create expected output: {output_path}")

        return output_path

    def align_and_sign(
        self, apk_path: str, keystore: str | None = None
    ) -> Path:
        """Align APK with zipalign and sign it.

        If keystore is None, uses the standard Android debug keystore
        (~/.android/debug.keystore) with password 'android'.

        Args:
            apk_path: Path to the unsigned APK
            keystore: Optional path to a JKS/PKCS12 keystore

        Returns:
            Path to the final signed and aligned APK

        Raises:
            FileNotFoundError: If input APK or required tools are missing
            RuntimeError: On alignment or signing failure with actionable message
        """
        apk = Path(apk_path).resolve()
        if not apk.exists():
            raise FileNotFoundError(f"APK to sign not found: {apk}")

        aligned = self.build_dir / f"aligned_{apk.name}"
        final_apk = apk.with_name(
            f"patched_{datetime.now():%Y%m%d_%H%M}_{apk.stem}.apk"
        )

        # 1. Zipalign
        try:
            subprocess.run(
                ["zipalign", "-p", "-f", "4", str(apk), str(aligned)],
                check=True,
                capture_output=True,
                text=True,
            )
        except FileNotFoundError:
            raise RuntimeError(
                "zipalign command not found. "
                "Please install Android SDK build-tools and add to PATH."
            ) from None
        except subprocess.CalledProcessError as exc:
            raise RuntimeError(f"zipalign failed: {exc.stderr}") from exc

        # 2. Sign
        if keystore is None:
            ks_path = self._test_keystore
            ks_pass = "android"
            alias = "androiddebugkey"
            if not ks_path.exists():
                raise RuntimeError(
                    f"Default debug keystore not found at {ks_path}.\n"
                    "Either run: keytool -genkey -v -keystore ~/.android/debug.keystore "
                    '-storepass android -alias androiddebugkey -keyalg RSA -keysize 2048\n'
                    "or provide --keystore on the command line."
                )
        else:
            ks_path = Path(keystore)
            if not ks_path.exists():
                raise FileNotFoundError(f"Keystore not found: {ks_path}")
            ks_pass = "changeit"  # common default; production users should supply via env
            alias = "upload"

        try:
            sign_cmd = [
                "apksigner",
                "sign",
                "--ks",
                str(ks_path),
                "--ks-pass",
                f"pass:{ks_pass}",
                "--alias",
                alias,
                "--out",
                str(final_apk),
                str(aligned),
            ]
            subprocess.run(sign_cmd, check=True, capture_output=True, text=True)

            # Verify signature
            verify_cmd = ["apksigner", "verify", "--verbose", str(final_apk)]
            subprocess.run(verify_cmd, check=True, capture_output=True, text=True)

            # Cleanup intermediate
            if aligned.exists():
                aligned.unlink()

            return final_apk

        except FileNotFoundError:
            raise RuntimeError(
                "apksigner not found. Install Android SDK platform-tools."
            ) from None
        except subprocess.CalledProcessError as exc:
            stderr = exc.stderr if hasattr(exc, "stderr") else str(exc)
            raise RuntimeError(f"Signing failed:\n{stderr}") from exc

    def rebuild_and_sign(
        self,
        decompiled_dir: str,
        output_name: str = "patched.apk",
        keystore: str | None = None,
    ) -> Path:
        """Convenience one-shot: rebuild then align+sign.

        Used by the UI and example scripts.
        """
        unsigned = self.rebuild(decompiled_dir, str(self.build_dir / output_name))
        signed = self.align_and_sign(str(unsigned), keystore)
        # Move final artifact out of build dir for user convenience
        final = Path.cwd() / signed.name
        if final != signed:
            signed.rename(final)
        return final
