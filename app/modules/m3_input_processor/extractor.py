import os
import shutil
import subprocess
import zipfile
from functools import cached_property
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parents[3] / "tools"  # optional local installs: tools/apktool, tools/jadx/bin


def _tool(name: str) -> list[str]:
    """Resolves a CLI tool to an absolute path so we never need shell=True (works for .bat wrappers on Windows too)."""
    if name == "bundletool" and not shutil.which(name) and os.environ.get("BUNDLETOOL_JAR"):
        return ["java", "-jar", os.environ["BUNDLETOOL_JAR"]]
    path = shutil.which(name) or shutil.which(name, path=f"{TOOLS_DIR / name}{os.pathsep}{TOOLS_DIR / name / 'bin'}")
    if not path:
        raise RuntimeError(f"{name} not found in PATH or {TOOLS_DIR / name}")
    return [path]


def _run(cmd: list[str], step: str, ok=(0,), ok_marker=None, env=None):
    # errors="replace": tool logs may contain bytes the console codepage can't decode (e.g. obfuscated class names)
    # stdin=DEVNULL: apktool.bat calls `pause` when run via cmd /c, which would otherwise hang waiting for a key
    result = subprocess.run(cmd, capture_output=True, text=True, errors="replace", stdin=subprocess.DEVNULL, env=env)
    output = result.stdout + result.stderr  # jadx logs to stdout, apktool to stderr
    if result.returncode not in ok and not (ok_marker and ok_marker in output):
        tail = "\n".join(output.strip().splitlines()[-20:])
        raise RuntimeError(f"{step} failed (exit code {result.returncode}):\n{tail}")


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
        # -s: skip smali disassembly (the slowest part); code analysis uses jadx output, apktool only feeds res/manifest
        _run(_tool("apktool") + ["d", str(self.apk_path), "-o", str(self.decompiled_dir), "-f", "-s"], "Resource decoding")
        return self.decompiled_dir

    def decompile_source(self) -> Path:
        """Decompiles bytecode into Java source code with jadx (-r: resources already come from apktool)."""
        # jadx's launcher lets the JVM grow to 70% of RAM, which busy machines refuse ("paging file is too small").
        # 4 GB is enough for apps with ~10k classes; set JADX_OPTS yourself to raise it for bigger ones.
        env = {**os.environ, "JADX_OPTS": os.environ.get("JADX_OPTS", "-Xmx4g")}
        # jadx exits 3 when output is saved but some methods failed to decompile, which is normal for real apps.
        # jadx.bat on Windows turns every non-zero code into 1, so its "finished with errors" log line counts too.
        _run(_tool("jadx") + ["-r", "-d", str(self.java_dir), str(self.apk_path)], "jadx decompilation", ok=(0, 3),
             ok_marker="finished with errors", env=env)
        return self.java_dir
