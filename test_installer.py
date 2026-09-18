import sys
import logging
from opencore_legacy_patcher.support.macos_installer_handler import InstallerCreation

logging.basicConfig(level=logging.INFO)
ic = InstallerCreation()
print("Calling install_macOS_installer...")
ic.install_macOS_installer("/Users/matteoiaccarino/Desktop")
print("Done")
