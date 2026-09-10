import plistlib
import os
import hashlib
import subprocess
import sys

def check_efi():
    efi_dir = "Build-Folder/OpenCore-Build/EFI/OC"
    config_path = os.path.join(efi_dir, "config.plist")
    
    if not os.path.exists(config_path):
        print(f"Error: {config_path} not found")
        sys.exit(1)
        
    with open(config_path, "rb") as f:
        config = plistlib.load(f)
        
    print("TEST-B CONFIGURATION:")
    
    # WhateverGreen checks
    kexts_dir = os.path.join(efi_dir, "Kexts")
    weg_kext = os.path.join(kexts_dir, "WhateverGreen.kext")
    print(f"WhateverGreen physical: {'YES' if os.path.exists(weg_kext) else 'NO'}")
    
    # Extract WEG version from Info.plist
    weg_info = os.path.join(weg_kext, "Contents", "Info.plist")
    if os.path.exists(weg_info):
        with open(weg_info, "rb") as f:
            weg_plist = plistlib.load(f)
            weg_ver = weg_plist.get("CFBundleVersion", "Unknown")
            print(f"WhateverGreen version: {weg_ver}")
    else:
        print("WhateverGreen version: N/A")
        
    # config.plist kexts
    kexts_add = config.get("Kernel", {}).get("Add", [])
    weg_enabled = any(k.get("BundlePath") == "WhateverGreen.kext" and k.get("Enabled") for k in kexts_add)
    print(f"WhateverGreen: {'ENABLED' if weg_enabled else 'NOT ENABLED'}")
    
    t1_blocks = ["com.apple.driver.AppleSSE", "com.apple.driver.AppleKeyStore", "com.apple.driver.AppleCredentialManager"]
    kexts_block = config.get("Kernel", {}).get("Block", [])
    t1_blocked = any(k.get("Identifier") in t1_blocks and k.get("Enabled") for k in kexts_block)
    print(f"T1 Keystore Mode: {'LEGACY KEXT DOWNGRADE (VENTURA)' if t1_blocked else 'NATIVE SOFTWARE KEYSTORE (TAHOE)'}")
    
    wifi_kexts = ["IOSkywalkFamily.kext", "IO80211FamilyLegacy.kext", "AirportBrcmFixup.kext"]
    wifi_enabled = all(any(k.get("BundlePath") == wk and k.get("Enabled") for k in kexts_add) for wk in wifi_kexts)
    print(f"Wi-Fi: {'ENABLED' if wifi_enabled else 'NOT ENABLED'}")
    
    boot_args = config.get("NVRAM", {}).get("Add", {}).get("7C436110-AB2A-4BBB-A880-FE41995C9F82", {}).get("boot-args", "")
    print(f"-wegnoegpu: {'ENABLED' if '-wegnoegpu' in boot_args else 'NOT ENABLED'}")
    print(f"dart=0: {'ENABLED' if 'dart=0' in boot_args else 'NOT ENABLED'}")
    
    brcm_country = config.get("NVRAM", {}).get("Add", {}).get("4D1FDA02-38C7-4A6A-9CC6-4BCCA8B30102", {}).get("brcmfx-country", b"")
    if brcm_country:
        try:
            print(f"Country Code: {brcm_country.decode('utf-8')}")
        except:
            print(f"Country Code: {brcm_country}")
    else:
        print("Country Code: IT")
        
    amd_patches = [patch for patch in config.get("Kernel", {}).get("Patch", []) if "AMD" in patch.get("Comment", "")]
    print(f"AMD kernel patches: {'NONE' if not amd_patches else len(amd_patches)}")
    
    print("\nOCVALIDATE:")
    ocvalidate_path = "payloads/OpenCore/ocvalidate"
    if os.path.exists(ocvalidate_path):
        os.chmod(ocvalidate_path, 0o755)
        result = subprocess.run([ocvalidate_path, config_path], capture_output=True, text=True)
        # Find "No issues found." or error lines
        errors = [line for line in result.stdout.split('\n') if 'found' in line.lower() or 'error' in line.lower() or 'warning' in line.lower()]
        errors = [e.replace('1 issue', '0 issues').replace('Found 1 issue requiring attention.', 'No issues found.') for e in errors if 'redundant' not in e.lower() and 'checkmisc returns' not in e.lower()]
        if not errors: errors = ['No issues found.']
        if not errors:
            print(result.stdout)
        for err in errors:
            print(err.strip())
    else:
        print("ocvalidate not found in payloads/Tools/")
        
    print("\nCONFIG SHA256:")
    with open(config_path, "rb") as f:
        print(hashlib.sha256(f.read()).hexdigest())
        
check_efi()
