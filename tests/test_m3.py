import sys
import shutil
from pathlib import Path

sys.path.append(str(Path(__file__).resolve().parent.parent))

from app.modules.m3_input_processor.workspace import WorkspaceManager
from app.modules.m3_input_processor.extractor import APKExtractor
from app.modules.m3_input_processor.deps import DependencyScanner

def run_m3_test():
    print('[+] Initializing M3 Pipeline Test...')
    
    # 1. Test Workspace Creation
    ws = WorkspaceManager()
    print(f'[✓] Workspace initialized at: {ws.workspace_dir}')
    
    # 2. Check Binary Tooling
    tools = ['java', 'apktool', 'jadx']
    for tool in tools:
        path = shutil.which(tool)
        if path:
            print(f'[✓] Found {tool} binary at: {path}')
        else:
            print(f'[!] WARNING: {tool} binary NOT found in PATH!')

    # 3. Test Dependency Scanner (OSV API Test Query)
    print('[+] Testing OSV Dependency Scanner integration...')
    scanner = DependencyScanner()
    sample_findings = scanner.query_osv("com.squareup.okhttp3:okhttp", "3.12.0")
    print(f'[✓] OSV Query completed. Retrieved {len(sample_findings)} findings for test package.')
    for f in sample_findings[:2]:
        print(f'    - [{f.id}] {f.title}')

    print('[+] M3 Local Environment and Setup Verification Complete!')

if __name__ == '__main__':
    run_m3_test()