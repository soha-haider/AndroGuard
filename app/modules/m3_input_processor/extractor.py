import os
import shutil
import subprocess
import zipfile
from functools import cached_property
from pathlib import Path


def _tool(name: str) -> list[str]:
    """Resolves a CLI tool to an absolute path so we never need shell=True (works for .bat wrappers on Windows too)."""
    if name == "bundletool" and not shutil.which(name) and os.environ.get("BUNDLETOOL_JAR"):
        return ["java", "-jar", os.environ["BUNDLETOOL_JAR"]]
    path = shutil.which(name)
    if not path:
        raise RuntimeError(f"{name} not found in PATH")
    return [path]


def _run(cmd: list[str], step: str, ok=(0,)):
    # errors="replace": tool logs may contain bytes the console codepage can't decode (e.g. obfuscated class names)
    # stdin=DEVNULL: apktool.bat calls `pause` when run via cmd /c, which would otherwise hang waiting for a key
    result = subprocess.run(cmd, capture_output=True, text=True, errors="replace", stdin=subprocess.DEVNULL)
    if result.returncode not in ok:
        raise RuntimeError(f"{step} failed: {result.stderr}")


class APKExtractor:
    def __init__(self, file_path: Path, workspace_dir: Path):
        self.file_path = Path(file_path)
        self.workspace_dir = Path(workspace_dir)
        self.decompiled_dir = self.workspace_dir / "decompiled"
        self.java_dir = self.workspace_dir / "jadx_src"
        self.is_aab = self.file_path.suffix.lower() == ".aab"

    @cached_property
    def apk_path(self) -> Path:
        """APK used for analysis: the input itself, or a universal APK generated from the AAB via bundletool."""
        if not self.is_aab:
            return self.file_path
        apks = self.workspace_dir / "bundle.apks"
        _run(_tool("bundletool") + ["build-apks", f"--bundle={self.file_path}", f"--output={apks}",
                                    "--mode=universal", "--overwrite"], "bundletool build-apks")
        universal = self.workspace_dir / "universal.apk"
        with zipfile.ZipFile(apks) as zf, open(universal, "wb") as out:
            out.write(zf.read("universal.apk"))
        return universal

    def decode_resources(self) -> Path:
        """Decodes AndroidManifest.xml and resources with apktool."""
        _run(_tool("apktool") + ["d", str(self.apk_path), "-o", str(self.decompiled_dir), "-f"], "Resource decoding")
        return self.decompiled_dir

    def decompile_source(self) -> Path:
        """Decompiles bytecode into Java source code with jadx."""
        # jadx exits 3 when output is saved but some methods failed to decompile, which is normal for real apps
        _run(_tool("jadx") + ["-d", str(self.java_dir), str(self.apk_path)], "jadx decompilation", ok=(0, 3))
        return self.java_dir
