"""
t1_login_experimental.py: Experimental T1 Login Patches for macOS Tahoe

Goal: Allow MacBookPro14,3 (T1) users to log in with password and use
iCloud/Apple services WITHOUT requiring Touch ID to be functional.

On macOS Tahoe (26.x), legacy Ventura/Sequoia biometrickitd and SharedUtils
binaries cause SecurityAgent and WindowServer to crash, resulting in a black
screen at login and Touch Bar flashing.

Tahoe natively supports password-based authentication when biometric daemons
are left untouched and not replaced with broken legacy binaries.
"""

from ..base import BaseHardware, HardwareVariant

from ...base import PatchType

from .....constants import Constants

from .....datasets.os_data import os_data


class T1LoginExperimental(BaseHardware):

    def __init__(self, xnu_major, xnu_minor, os_build, global_constants: Constants) -> None:
        super().__init__(xnu_major, xnu_minor, os_build, global_constants)


    def name(self) -> str:
        """
        Display name for end users
        """
        return f"{self.hardware_variant()}: T1 Login & Touch ID (Tahoe Biometric Shim)"


    def present(self) -> bool:
        """
        Only activate on T1 Macs AND only when targeting macOS Tahoe or later.
        On Sequoia and earlier the standard t1_security.py patches are sufficient.
        """
        if not self._computer.t1_chip:
            return False
        # Only activate for Tahoe (macOS 26) and later
        if hasattr(os_data, 'tahoe'):
            return self._xnu_major >= os_data.tahoe.value
        return self._xnu_major >= 25


    def native_os(self) -> bool:
        """
        T1 support was dropped in macOS 14 Sonoma.
        This patch is never 'native' on Tahoe.
        """
        return False


    def hardware_variant(self) -> HardwareVariant:
        """
        Type of hardware variant
        """
        return HardwareVariant.MISCELLANEOUS


    def patches(self) -> dict:
        """
        Experimental patches for T1 Login and Touch ID on macOS Tahoe.

        On macOS Tahoe (Darwin 25), DYLD_INSERT_LIBRARIES is silently ignored
        by dyld for processes carrying Apple private entitlements. The
        LaunchDaemon EnvironmentVariables approach therefore does not work.

        Solution: install a pre-patched biometrickitd with a LC_LOAD_WEAK_DYLIB
        load command pointing to libT1BiometricShim.dylib injected directly into
        its Mach-O header. dyld honours LC_LOAD_*_DYLIB unconditionally.

        The shim swizzles 9 methods to bypass the T1 bridge transport failures
        (err 0xe00002c2) that arise on Darwin 25.
        """
        shim_dir    = str(self._constants.payload_path / "Shim" / "T1BiometricShim")
        launchd_dir = str(self._constants.payload_path / "LaunchDaemons")
        return {
            "T1 Touch ID Compatibility": {
                PatchType.OVERWRITE_SYSTEM_VOLUME: {
                    # The shim dylib itself — loaded via LC_LOAD_WEAK_DYLIB
                    "/usr/local/lib": {
                        "libT1BiometricShim.dylib": shim_dir,
                    },
                    # Pre-patched biometrickitd binary with LC_LOAD_WEAK_DYLIB
                    # injected into its Mach-O header (bypasses DYLD_INSERT_LIBRARIES
                    # being silently ignored on macOS Tahoe for this process)
                    "/usr/libexec": {
                        "biometrickitd": shim_dir,
                    },
                    # LaunchDaemon plist kept as belt-and-suspenders fallback
                    "/System/Library/LaunchDaemons": {
                        "com.apple.biometrickitd.plist": launchd_dir,
                    },
                },
            },
        }
