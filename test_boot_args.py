import sys
import logging
sys.path.append("/Volumes/Test Files OCLP 14.3/OCLP-T1-MBP143/Source")
from opencore_legacy_patcher.efi_builder.build import BuildOpenCore
from opencore_legacy_patcher.constants import Constants
class DummyComputer:
    def __init__(self):
        self.real_model = "MacBookAir8,1"
        self.dgpu = None
        self.wifi = None
class DummyConstants(Constants):
    def __init__(self):
        super().__init__()
        self.computer = DummyComputer()
        self.custom_model = "MacBookAir8,1"
        self.build_path = "/tmp/oclp_build"
        self.opencore_release_folder = "/tmp/oclp_release"
        self.oc_build_path = "/tmp/oc_build"
c = DummyConstants()
# Mock logging
logging.basicConfig(level=logging.ERROR)
try:
    b = BuildOpenCore("MacBookAir8,1", c)
    b.build_opencore()
    print("BOOT ARGS:")
    print(b.config["NVRAM"]["Add"]["7C436110-AB2A-4BBB-A880-FE41995C9F82"]["boot-args"])
except Exception as e:
    print(e)
