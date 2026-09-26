import os
import subprocess
import xml.etree.ElementTree as ET
from typing import Dict, Any, List

class APKExtractor:
    def __init__(self, apk_path: str, output_dir: str):
        self.apk_path = apk_path
        self.output_dir = output_dir

    def decompile_apktool(self) -> str:
        """Decompiles APK using Apktool to extract resources and AndroidManifest.xml."""
        decompiled_path = os.path.join(self.output_dir, "apktool_out")
        cmd = ["apktool", "d", self.apk_path, "-o", decompiled_path, "-f"]
        subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return decompiled_path

    def decompile_jadx(self) -> str:
        """Decompiles APK to Java source code using JADX."""
        jadx_out_path = os.path.join(self.output_dir, "jadx_out")
        cmd = ["jadx", "-d", jadx_out_path, self.apk_path]
        subprocess.run(cmd, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return jadx_out_path

    def parse_manifest(self, apktool_dir: str) -> Dict[str, Any]:
        """Parses AndroidManifest.xml to extract package info, permissions, and components."""
        manifest_path = os.path.join(apktool_dir, "AndroidManifest.xml")
        if not os.path.exists(manifest_path):
            raise FileNotFoundError(f"Manifest not found at {manifest_path}")

        tree = ET.parse(manifest_path)
        root = tree.getroot()

        package_name = root.attrib.get("package", "Unknown")
        permissions = [
            elem.attrib.get("{http://schemas.android.com/apk/res/android}name")
            for elem in root.findall("uses-permission")
        ]

        # Extract components
        application = root.find("application")
        exported_components = []
        if application is not None:
            for tag in ["activity", "service", "receiver", "provider"]:
                for comp in application.findall(tag):
                    is_exported = comp.attrib.get("{http://schemas.android.com/apk/res/android}exported")
                    if is_exported == "true":
                        name = comp.attrib.get("{http://schemas.android.com/apk/res/android}name")
                        exported_components.append({"type": tag, "name": name})

        return {
            "package_name": package_name,
            "permissions": permissions,
            "exported_components": exported_components
        }