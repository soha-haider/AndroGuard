import hashlib
import zipfile
from pathlib import Path

# Marker entry that must exist inside each package type
MANIFEST_ENTRY = {
    ".apk": "AndroidManifest.xml",
    ".aab": "base/manifest/AndroidManifest.xml",
}


def validate_package(file_path: Path) -> tuple[str, str]:
    """Validates an uploaded APK/AAB and returns (package_type, sha256). Raises ValueError if invalid."""
    file_path = Path(file_path)
    ext = file_path.suffix.lower()
    if ext not in MANIFEST_ENTRY:
        raise ValueError(f"Unsupported file type: {ext or 'none'} (expected .apk or .aab)")
    if not zipfile.is_zipfile(file_path):
        raise ValueError("File is not a valid ZIP-based Android package")
    with zipfile.ZipFile(file_path) as zf:
        if MANIFEST_ENTRY[ext] not in zf.namelist():
            raise ValueError(f"Missing {MANIFEST_ENTRY[ext]}; not a valid {ext.upper()[1:]}")
    with open(file_path, "rb") as f:
        sha256 = hashlib.file_digest(f, "sha256").hexdigest()
    return ext[1:], sha256
