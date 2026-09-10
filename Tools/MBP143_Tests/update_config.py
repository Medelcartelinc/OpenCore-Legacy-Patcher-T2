import plistlib
import sys

plist_path = sys.argv[1]

with open(plist_path, 'rb') as f:
    pl = plistlib.load(f)

pl['Kernel']['Add'].append({
    'Arch': 'x86_64',
    'BundlePath': 'WhateverGreen.kext',
    'Comment': 'WhateverGreen',
    'Enabled': True,
    'ExecutablePath': 'Contents/MacOS/WhateverGreen',
    'MaxKernel': '',
    'MinKernel': '12.0.0',
    'PlistPath': 'Contents/Info.plist'
})

boot_args = pl['NVRAM']['Add']['7C436110-AB2A-4BBB-A880-FE41995C9F82']['boot-args']
if '-wegnoegpu' not in boot_args:
    pl['NVRAM']['Add']['7C436110-AB2A-4BBB-A880-FE41995C9F82']['boot-args'] = boot_args + ' -wegnoegpu'

with open(plist_path, 'wb') as f:
    plistlib.dump(pl, f, sort_keys=True)
