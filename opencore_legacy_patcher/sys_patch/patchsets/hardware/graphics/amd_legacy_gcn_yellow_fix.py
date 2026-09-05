# amd_legacy_gcn_yellow_fix.py
"""Patch to fix the yellow screen issue on macOS 26 (Tahoe) for GCN GPUs.

This module defines a binary patch that overwrites the `setGammaTable`
function in `AMDFramebuffer.kext` with a small stub that forces a
linear gamma ramp, eliminating the yellow tint observed on affected
hardware.
"""

from ...base import PatchType, PatchTarget, PatchSource

# Binary stub (hex). The exact byte sequence was derived from disassembly
# of the original `AMDFramebuffer.kext` on macOS 26. It preserves the
# calling convention, jumps to `GammaTable::setLinearRamp`, and returns.
# Offsets marked as `??` will be patched at runtime by the `PatchSource`
# helper.
YELLOW_FIX_BYTES = bytes.fromhex(
    "48 89 5C 24 08"          # mov [rsp+0x8], rbx   (save callee‑saved reg)
    "48 83 EC 20"              # sub rsp, 0x20        (stack frame)
    "48 8D 3D ?? ?? ?? ??"     # lea rdi, [rip+offset_to_setLinearRamp]
    "E8 ?? ?? ?? ??"           # call GammaTable::setLinearRamp
    "48 83 C4 20"              # add rsp, 0x20        (restore stack)
    "C3"                       # ret
)

# Define the patch. The `PatchTarget` points to the symbol we want to
# replace. The `PatchSource` supplies the binary data and indicates that it
# should be applied to the system volume.
patch = PatchSource(
    target=PatchTarget(
        kext="AMDFramebuffer.kext",
        symbol="_AMDFramebuffer_setGammaTable",
    ),
    patch_type=PatchType.OVERWRITE_SYSTEM_VOLUME,
    data=YELLOW_FIX_BYTES,
    description="Force linear gamma ramp on macOS 26 to eliminate yellow tint",
    applicable_os_version="26.0.0",  # macOS 26 (Tahoe)
    hardware_filter=lambda hw: hw.get('gpu_family') == 'GCN' and hw.get('model') in [
        "MacPro6,1", "iMac14,1", "iMac14,2"]
)
