import sys
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

from app.modules.m3_input_processor.workspace import WorkspaceManager
from app.modules.m3_input_processor.extractor import APKExtractor

def test_extraction(file_path: str):
    target_path = Path(file_path)
    if not target_path.exists():
        print(f'[!] Target file not found at: {target_path}')
        return

    ext = target_path.suffix.lower()
    if ext not in ['.apk', '.aab']:
        print(f'[!] Unsupported file extension: {ext}. Please provide an .apk or .aab file.')
        return

    print(f'[+] Starting full extraction test on [{ext.upper()}]: {target_path.name}')
    with WorkspaceManager() as ws:
        extractor = APKExtractor(target_path, ws.workspace_dir)
        
        print(f'[+] Decoding resources and manifest from {ext.upper()}...')
        decompiled_path = extractor.decode_resources()
        print(f'[✓] Resources decoded to: {decompiled_path}')
        
        print(f'[+] Decompiling source code from {ext.upper()} using jadx...')
        java_path = extractor.decompile_source()
        print(f'[✓] Source code decompiled to: {java_path}')
        
        # Verify AndroidManifest.xml (checks root or base module folder for AABs)
        manifest = decompiled_path / "AndroidManifest.xml"
        if not manifest.exists():
            manifest = decompiled_path / "resources" / "AndroidManifest.xml"
            
        if manifest.exists():
            print(f'[✓] AndroidManifest.xml verified ({manifest.stat().st_size} bytes)')
        else:
            print('[!] Warning: AndroidManifest.xml not located in expected paths!')

if __name__ == '__main__':
    if len(sys.argv) > 1:
        test_extraction(sys.argv[1])
    else:
        print('Usage: python -m tests.test_full_extraction <path_to_sample.apk_or_.aab>')