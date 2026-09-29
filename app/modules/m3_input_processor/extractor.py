import subprocess
from pathlib import Path

class APKExtractor:
    def __init__(self, file_path: Path, workspace_dir: Path):
        self.file_path = Path(file_path)
        self.workspace_dir = Path(workspace_dir)
        self.decompiled_dir = self.workspace_dir / "decompiled"
        self.java_dir = self.workspace_dir / "jadx_src"
        self.is_aab = self.file_path.suffix.lower() == ".aab"

    def decode_resources(self) -> Path:
        """Decodes AndroidManifest.xml and resources (apktool for APK, jadx for AAB)."""
        if self.is_aab:
            # JADX decodes proto-format resources and manifests directly from AAB files
            cmd = ["jadx", "-d", str(self.decompiled_dir), "--e-res", str(self.file_path)]
        else:
            # Standard apktool decoding for APK files
            cmd = ["apktool", "d", str(self.file_path), "-o", str(self.decompiled_dir), "-f"]
            
        result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
        if result.returncode != 0:
            raise RuntimeError(f"Resource decoding failed: {result.stderr}")
        return self.decompiled_dir

    def decompile_source(self) -> Path:
        """Decompiles bytecode into Java source code (compatible with both APK and AAB)."""
        cmd = ["jadx", "-d", str(self.java_dir), str(self.file_path)]
        result = subprocess.run(cmd, capture_output=True, text=True, shell=True)
        if result.returncode != 0:
            raise RuntimeError(f"jadx decompilation failed: {result.stderr}")
        return self.java_dir