import sys
from pathlib import Path
from opencore_legacy_patcher.support import macos_installer_handler

h = macos_installer_handler.InstallerCreation()
res = h._install_via_manual_extraction("/tmp/InstallAssistant_fake.pkg")
print(f"Result: {res}")
