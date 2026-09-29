import os
import shutil
import tempfile
from pathlib import Path

class WorkspaceManager:
    def __init__(self, base_dir: str = None):
        if base_dir:
            self.workspace_dir = Path(base_dir)
            self.workspace_dir.mkdir(parents=True, exist_ok=True)
            self._cleanup = False
        else:
            self._temp_dir = tempfile.TemporaryDirectory(prefix="androguard_m3_")
            self.workspace_dir = Path(self._temp_dir.name)
            self._cleanup = True

    def get_path(self, relative_path: str) -> Path:
        path = self.workspace_dir / relative_path
        path.parent.mkdir(parents=True, exist_ok=True)
        return path

    def cleanup(self):
        if self._cleanup and hasattr(self, '_temp_dir'):
            self._temp_dir.cleanup()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.cleanup()