import sys
from pathlib import Path
from opencore_legacy_patcher.constants import Constants
from opencore_legacy_patcher.efi_builder.build import BuildOpenCore
import logging

logging.basicConfig(level=logging.INFO)

def build_profile(profile_name, output_dir):
    c = Constants()
    c.custom_model = "MacBookPro14,3"
    c.build_profile = profile_name
    
    # We must also mock the computer object so the builder thinks it's building for 14,3
    class DummyComputer:
        real_model = "MacBookPro14,3"
        build_model = "MacBookPro14,3"
        wifi = None
        pcie_webcam = True
        internal_keyboard_type = "Modern"
        trackpad_type = "Modern"
        # minimal mock for required properties
        
    c.computer = DummyComputer()
    c.allow_oc_everywhere = False # so SMBIOS builds native spoof
    
    try:
        BuildOpenCore("MacBookPro14,3", c)
        print(f"✅ Successfully built {profile_name}")
    except Exception as e:
        print(f"❌ Failed to build {profile_name}: {e}")

if __name__ == "__main__":
    print("Building STANDARD...")
    build_profile("standard", "Standard-Build")
    
    print("\nBuilding TEST-B...")
    build_profile("test_b", "TEST-B-Build")
    
    print("\nBuilding TEST-C...")
    build_profile("test_c", "TEST-C-TAHOE-ALBERT")

    print("\nBuilding TEST-D...")
    build_profile("test_d", "TEST-D-ALL-IN-ONE")
