import contextlib
import os
import shutil
import signal
import subprocess
import zipfile
from functools import cached_property
from pathlib import Path

TOOLS_DIR = Path(__file__).resolve().parents[3] / "tools"  # optional local installs: tools/apktool, tools/jadx/bin


def _tool(name: str) -> list[str]:
    """Resolves a CLI tool to an absolute path so we never need shell=True (works for .bat wrappers on Windows too)."""
    if name == "bundletool" and not shutil.which(name):
        jar = os.environ.get("BUNDLETOOL_JAR") or next(iter(sorted((TOOLS_DIR / "bundletool").glob("bundletool*.jar"))), None)
        if jar:
            return ["java", "-jar", str(jar)]
    path = shutil.which(name) or shutil.which(name, path=f"{TOOLS_DIR / name}{os.pathsep}{TOOLS_DIR / name / 'bin'}")
    if not path:
        raise RuntimeError(f"{name} not found in PATH or {TOOLS_DIR / name}")
    return [path]


TOOL_TIMEOUT = int(os.environ.get("ANDROGUARD_TOOL_TIMEOUT", 900))  # seconds per tool run; raise it for huge apps
RUNNING: set[subprocess.Popen] = set()


def _kill(proc: subprocess.Popen):
    # the .bat wrappers start java as a child, so the whole process tree has to go
    if os.name == "nt":
        subprocess.run(["taskkill", "/T", "/F", "/PID", str(proc.pid)], capture_output=True)
    else:
        with contextlib.suppress(ProcessLookupError):  # it may have exited on its own a moment ago
            os.killpg(proc.pid, signal.SIGKILL)


def stop_tools():
    """Kills the tool runs in progress (used to cancel a scan)."""
    for proc in list(RUNNING):
        _kill(proc)


def _run(cmd: list[str], step: str, ok=(0,), ok_marker=None, env=None, timeout=None):
    # errors="replace": tool logs may contain bytes the console codepage can't decode (e.g. obfuscated class names)
    # stdin=DEVNULL: apktool.bat calls `pause` when run via cmd /c, which would otherwise hang waiting for a key
    timeout = timeout or TOOL_TIMEOUT
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL, text=True,
                            errors="replace", env=env, start_new_session=os.name != "nt")
    RUNNING.add(proc)
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        _kill(proc)
        proc.communicate()
        limit = f"{timeout // 60} minutes" if timeout >= 120 else f"{timeout} seconds"
        raise RuntimeError(f"{step} took longer than {limit} and was stopped")
    finally:
        RUNNING.discard(proc)
    output = stdout + stderr  # jadx logs to stdout, apktool to stderr
    if proc.returncode not in ok and not (ok_marker and ok_marker in output):
        tail = "\n".join(output.strip().splitlines()[-20:])
        raise RuntimeError(f"{step} failed (exit code {proc.returncode}):\n{tail}")


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
