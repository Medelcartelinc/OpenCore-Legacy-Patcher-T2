#!/usr/bin/env python3
"""
check_root_patching.py: catch root-patching bugs that leave a Mac unbootable.

Root patching edits a mounted copy of the sealed system volume and then blesses
a new APFS snapshot of it. Whatever ends up in that snapshot is what the Mac
boots next time - so a patch that deletes the wrong file, a failed copy that
goes unnoticed, or a snapshot created after something already went wrong all
turn into a Mac that no longer starts. The SecureBootModel check
(check_secure_boot_model.py) covers the EFI side; this one covers the
root-patching side.

Like the SecureBootModel check, this runs the real code - the real patchset
definitions, the real detection gates, the real sys_patch flow - with every
host value simulated, instead of grepping for patterns:

  patchsets:paths       every patchset, for every supported macOS version:
                        nothing deletes or replaces files the Mac needs to boot
                        (kernel, Kernel Collections, boot.efi, launchd, dyld,
                        core kexts ...), no empty/".."/"/" file names (rm -R of a
                        whole folder), only absolute target folders, only known
                        PatchTypes, and every installed file has a source
  sys_patch:destination _get_destination_path() sends every *_SYSTEM_VOLUME
                        patch to the mounted copy, never to the live, sealed
                        root (the REMOVE_SYSTEM_VOLUME bug fixed in 059cc9a)
  sys_patch:seal-guard  PatchSysVolume with simulated failures: if installing,
                        removing, the AppleHDA patch or the Kernel Collection
                        rebuild fails, no new snapshot may be created and the
                        run may not report success; when a KC rebuild is
                        required it has to happen before the snapshot
  files:failures        install_new_file()/remove_file() with a failing
                        cp/rm/rsync: the failure has to reach the caller,
                        otherwise sys_patch seals a half-patched volume
  detect:gates          HardwarePatchsetDetection must block root patching when
                        FileVault is on, SIP is not lowered, AMFI is active,
                        Secure Boot is on, the OS is unsupported or the root
                        volume is already modified - and the FileVault and SIP
                        probes themselves must report a stock setup as blocked
  detect:gpu-mix        Metal and non-Metal (and, on Sequoia+, Metal 3802 and
                        31001) patchsets are never installed together - mixing
                        them leaves WindowServer unable to start

Usage:
  check_root_patching.py --root DIR [--baseline DIR] --json OUT [--summary OUT.md]

--root      the tree to check (a PR checkout, or the repo itself)
--baseline  optional tree to compare against (main). Problems that also exist
            there are reported as "already broken on main" and don't fail.

Exit code: 0 = OK, 1 = problems (new ones, if --baseline is given),
           2 = the check itself could not run against --root.

Nothing here touches a real volume: every subprocess, mount, kmutil and bless
call is replaced, and off macOS pyobjc/wx are replaced by inert stubs.
"""

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

CASES = [
    "patchsets:paths",
    "sys_patch:destination",
    "sys_patch:seal-guard",
    "files:failures",
    "detect:gates",
    "detect:gpu-mix",
]

WORKER_TIMEOUT = 15 * 60

MOUNT = "/System/Volumes/Update/mnt1"

# (xnu_major, xnu_minor, build) - one per supported release plus the minor
# versions patchsets branch on (base.py: macOS_12_4 ... macOS_26_0)
OS_MATRIX = [
    (20, 6, "20G1427"),                                             # Big Sur
    (21, 1, "21A559"), (21, 5, "21F79"), (21, 6, "21H1320"),        # Monterey
    (22, 4, "22E252"), (22, 6, "22H730"),                           # Ventura
    (23, 1, "23B74"), (23, 2, "23C64"), (23, 4, "23E214"), (23, 6, "23H626"),  # Sonoma
    (24, 2, "24C101"), (24, 3, "24D60"), (24, 6, "24G90"),          # Sequoia
    (25, 0, "25A354"), (25, 6, "25G76"),                            # Tahoe
]

# Files and folders the Mac needs to get to the login window. A patchset may
# never delete or replace these (or anything inside them). Folder entries end
# with "/".
BOOT_CRITICAL = [
    "/System/Library/Kernels/",
    "/System/Library/KernelCollections/",
    "/System/Library/PrelinkedKernels/",
    "/System/Library/Caches/com.apple.kext.caches/",
    "/System/Library/CoreServices/boot.efi",
    "/System/Library/CoreServices/bootbase.efi",
    "/System/Library/CoreServices/PlatformSupport.plist",
    "/System/Library/CoreServices/SystemVersion.plist",
    "/System/Library/CoreServices/BridgeVersion.plist",
    "/usr/standalone/i386/",
    "/sbin/launchd",
    "/usr/lib/dyld",
    "/usr/lib/libSystem.B.dylib",
    "/System/Library/dyld/",
    "/System/Cryptexes/",
    "/System/Library/Frameworks/Kernel.framework/",
    "/System/Library/Frameworks/IOKit.framework/",
    "/System/Library/PrivateFrameworks/CoreTrust.framework/",
    "/System/Library/Extensions/apfs.kext",
    "/System/Library/Extensions/AppleAPFS.kext",
    "/System/Library/Extensions/IOStorageFamily.kext",
    "/System/Library/Extensions/IOPCIFamily.kext",
    "/System/Library/Extensions/IOACPIFamily.kext",
    "/System/Library/Extensions/AppleACPIPlatform.kext",
    "/System/Library/Extensions/AppleSMC.kext",
    "/System/Library/Extensions/AppleEFIRuntime.kext",
    "/System/Library/Extensions/AppleRTC.kext",
    "/System/Library/Extensions/AppleKeyStore.kext",
    "/System/Library/Extensions/AppleSEPManager.kext",
    "/System/Library/Extensions/AppleCredentialManager.kext",
    "/System/Library/Extensions/AppleImage4.kext",
    "/System/Library/Extensions/AppleMobileFileIntegrity.kext",
    "/System/Library/Extensions/CoreTrust.kext",
    "/System/Library/Extensions/corecrypto.kext",
    "/System/Library/Extensions/Sandbox.kext",
    "/System/Library/Extensions/IONVMeFamily.kext",
    "/System/Library/Extensions/IOAHCIFamily.kext",
    "/System/Library/Extensions/AppleAHCIPort.kext",
    "/System/Library/Extensions/IOPlatformPluginFamily.kext",
    "/System/Library/Extensions/System.kext",
]

# Folders whose own entries may never be removed or replaced as a whole.
NEVER_AS_TARGET = {"/", "/System", "/System/Library", "/System/Library/Extensions",
                   "/System/Library/Frameworks", "/System/Library/PrivateFrameworks",
                   "/System/Library/CoreServices", "/usr", "/usr/lib", "/Library",
                   "/Library/Extensions", "/private", "/private/var", "/Applications"}


def _macos(xnu, minor=None) -> str:
    """Darwin 20-24 = macOS 11-15, Darwin 25 = macOS 26 (Tahoe)"""
    major = int(xnu) + 1 if int(xnu) >= 25 else int(xnu) - 9
    return f"{major}.{minor}" if minor is not None else str(major)


# ----------------------------------------------------------------------------
# Worker side - runs inside a subprocess, with cwd/sys.path set to the tree
# ----------------------------------------------------------------------------

def _install_stubs() -> None:
    import importlib.abc
    import importlib.machinery
    from unittest import mock

    stub_roots = {
        "objc", "Foundation", "CoreFoundation", "AppKit", "IOKit", "wx",
        "applescript", "PyObjCTools", "Quartz", "Cocoa", "WebKit",
        "SystemConfiguration", "LocalAuthentication", "ServiceManagement",
        "Security", "webview",
    }

    class _StubFinder(importlib.abc.MetaPathFinder, importlib.abc.Loader):
        def find_spec(self, name, path, target=None):
            if name.split(".")[0] in stub_roots:
                return importlib.machinery.ModuleSpec(name, self, is_package=True)
            return None

        def create_module(self, spec):
            module = mock.MagicMock()
            module.__path__ = []
            module.__spec__ = spec
            return module

        def exec_module(self, module):
            pass

    sys.meta_path.insert(0, _StubFinder())


def _problem(case, subject, message, **extra):
    entry = {"case": case, "subject": subject, "message": message}
    entry.update(extra)
    return entry


def _worker(root: str, case: str, out_path: str) -> None:
    import copy
    import logging
    import subprocess as real_subprocess
    from types import SimpleNamespace

    os.chdir(root)
    sys.path.insert(0, root)
    if sys.platform != "darwin":
        _install_stubs()
    logging.disable(logging.CRITICAL)

    from opencore_legacy_patcher import constants
    from opencore_legacy_patcher.datasets import example_data, os_data, sip_data
    from opencore_legacy_patcher.support import utilities, subprocess_wrapper
    from opencore_legacy_patcher.sys_patch.patchsets import detect
    from opencore_legacy_patcher.sys_patch.patchsets.base import PatchType

    try:
        utilities.disable_cls()
    except Exception:
        pass

    # Simulated host: no NVRAM, no ROM, nothing loaded, nothing on disk to find
    utilities.get_nvram = lambda *a, **k: None
    utilities.get_rom = lambda *a, **k: None
    utilities.check_kext_loaded = lambda *a, **k: False
    utilities.find_any_oclp_manifest = lambda *a, **k: None

    problems, checked, errors = [], 0, []
    host_dump = example_data.iMac.iMac201_Stock
    install_types = [PatchType.OVERWRITE_SYSTEM_VOLUME, PatchType.OVERWRITE_DATA_VOLUME,
                     PatchType.MERGE_SYSTEM_VOLUME, PatchType.MERGE_DATA_VOLUME]
    remove_types = [PatchType.REMOVE_SYSTEM_VOLUME, PatchType.REMOVE_DATA_VOLUME]
    system_types = [PatchType.OVERWRITE_SYSTEM_VOLUME, PatchType.MERGE_SYSTEM_VOLUME, PatchType.REMOVE_SYSTEM_VOLUME]

    def new_constants(xnu=os_data.os_data.tahoe, minor=6, build="25G76", computer=None):
        c = constants.Constants()
        c.computer = copy.deepcopy(computer or host_dump)
        c.detected_os = xnu
        c.detected_os_minor = minor
        c.detected_os_build = build
        c.detected_os_version = _macos(xnu, minor)
        c.wxpython_variant = False
        return c

    # Every probe that would touch the host. Gates are switched on one by one
    # in detect:gates; everywhere else they are "all clear".
    GATE_METHODS = [
        "_validation_check_unsupported_host_os",
        "_validation_check_missing_network_connection",
        "_validation_check_filevault_is_enabled",
        "_validation_check_system_integrity_protection_enabled",
        "_validation_check_secure_boot_model_enabled",
        "_validation_check_amfi_enabled",
        "_validation_check_whatevergreen_missing",
        "_validation_check_force_opengl_missing",
        "_validation_check_force_compat_missing",
        "_validation_check_nvda_drv_missing",
        "_validation_check_root_is_dirty",
    ]
    Detection = detect.HardwarePatchsetDetection
    originals = {name: getattr(Detection, name) for name in GATE_METHODS if hasattr(Detection, name)}

    def clear_gates(blocked=()):
        for name in originals:
            value = name in blocked
            setattr(Detection, name, lambda self, *a, _v=value, **k: _v)
        Detection._is_cached_kernel_debug_kit_present = lambda self: True
        Detection._is_cached_metallib_support_pkg_present = lambda self: True
        Detection._already_has_networking_patches = lambda self: False

    class FakeSip:
        def __init__(self, value):
            self._value = value

        def get_sip_status(self):
            return SimpleNamespace(value=self._value)

    detect.py_sip_xnu = SimpleNamespace(SipXnu=lambda: FakeSip(0x803))

    # ------------------------------------------------------------------------
    if case == "patchsets:paths":
        clear_gates()
        critical_dirs = [p.rstrip("/") for p in BOOT_CRITICAL if p.endswith("/")]
        critical_files = [p for p in BOOT_CRITICAL if not p.endswith("/")]

        def critical_hit(full_path):
            for d in critical_dirs:
                if full_path == d or full_path.startswith(d + "/"):
                    return d + "/"
            for f in critical_files:
                if full_path == f or full_path.startswith(f + "/"):
                    return f
            return None

        seen = set()
        for xnu, minor, build in OS_MATRIX:
            version = _macos(xnu, minor)
            c = new_constants(xnu, minor, build)
            try:
                patches = Detection(c, xnu_major=xnu, xnu_minor=minor, os_build=build,
                                    os_version=version, validation=True).patches
            except Exception as e:
                errors.append({"case": case, "subject": f"macOS {version}",
                               "message": f"patchset detection raised {e!r}"[:300]})
                continue
            if not isinstance(patches, dict):
                errors.append({"case": case, "subject": f"macOS {version}", "message": "patches is not a dict"})
                continue

            for name, patchset in patches.items():
                checked += 1

                def report(where, message):
                    key = (name, where, message)
                    if key in seen:
                        return
                    seen.add(key)
                    problems.append(_problem(case, f"{name}: {where}", f"{message} (first seen on macOS {version})"))

                if not isinstance(patchset, dict):
                    report("-", "patchset is not a dict")
                    continue
                for ptype, content in patchset.items():
                    if ptype not in list(PatchType):
                        report(str(ptype), "unknown PatchType - sys_patch silently ignores it")
                        continue
                    if ptype == PatchType.EXECUTE:
                        for command in content or {}:
                            if not str(command).startswith("/"):
                                report(str(command)[:80], "EXECUTE command without an absolute path - the privileged helper can't run it")
                        continue
                    if not isinstance(content, dict):
                        report(str(ptype), "expected {folder: {file: source}}")
                        continue
                    for folder, entries in content.items():
                        folder = str(folder)
                        where = f"{ptype.value} {folder}"
                        if not folder.startswith("/"):
                            report(where, "target folder isn't absolute - it would be resolved relative to the mount point")
                        if ".." in folder.split("/") or "//" in folder.rstrip("/"):
                            report(where, "target folder contains '..' or '//'")
                        if folder.startswith(MOUNT) or folder.startswith("/System/Volumes/"):
                            report(where, "target folder already contains a mount point - sys_patch adds it itself")
                        # Installs are {file: source}, removals {file: ...} or [file, ...]
                        if isinstance(entries, dict):
                            items = list(entries.items())
                        elif isinstance(entries, (list, tuple)) and ptype in remove_types:
                            items = [(entry, None) for entry in entries]
                        else:
                            report(where, "expected {file: source}" if ptype in install_types else "expected a list of files")
                            continue
                        for file_name, source in items:
                            file_name = str(file_name)
                            if file_name in ("", ".", "..") or "/" in file_name or file_name.strip() != file_name:
                                report(f"{where}/{file_name!r}",
                                       "file name is empty, '.', '..', contains '/' or surrounding spaces - "
                                       "rm -R would hit the folder itself or something outside it")
                                continue
                            full = f"{folder.rstrip('/')}/{file_name}"
                            if folder.rstrip("/") in NEVER_AS_TARGET and ptype in remove_types and file_name in ("Extensions", "Frameworks"):
                                report(full, "removes a whole system folder")
                            hit = critical_hit(full)
                            if hit:
                                verb = "deletes" if ptype in remove_types else "replaces"
                                report(full, f"{verb} {hit}, which the Mac needs to boot - the next boot fails")
                            if ptype in install_types and (not isinstance(source, str) or not source.strip()):
                                report(full, f"no source version given ({source!r}) - install would copy from the payload root")

        if not checked:
            errors.append({"case": case, "subject": "-", "message": "no patchsets were produced for any macOS version"})

    # ------------------------------------------------------------------------
    elif case == "sys_patch:destination":
        from opencore_legacy_patcher.sys_patch import sys_patch

        obj = sys_patch.PatchSysVolume.__new__(sys_patch.PatchSysVolume)
        obj.mount_location = MOUNT
        obj.mount_location_data = ""
        for ptype in list(install_types) + list(remove_types):
            for folder in ("/System/Library/Extensions", "/System/Library/Frameworks", "/Library/Extensions"):
                checked += 1
                try:
                    dest = obj._get_destination_path(ptype, folder)
                except Exception as e:
                    errors.append({"case": case, "subject": f"{ptype.value} {folder}", "message": repr(e)[:300]})
                    continue
                if ptype in system_types:
                    if dest != MOUNT + folder:
                        problems.append(_problem(case, f"{ptype.value} {folder}",
                            f"resolves to '{dest}' instead of '{MOUNT}{folder}' - the patch would hit the live, "
                            f"sealed root volume instead of the mounted copy (see 059cc9a)"))
                else:
                    if dest != folder:
                        problems.append(_problem(case, f"{ptype.value} {folder}",
                            f"data-volume patch resolves to '{dest}' instead of '{folder}'"))

    # ------------------------------------------------------------------------
    elif case == "sys_patch:seal-guard":
        from opencore_legacy_patcher.sys_patch import sys_patch

        events = []

        class Boom(Exception):
            pass

        def scenario(label, *, fail=None, kdk_required=True, extra_patch=None, kc_result=True):
            """Run _patch_root_vol() with simulated subsystems; return (events, succeeded)."""
            events.clear()

            def fake_install(src, dest, name, method):
                events.append(("install", name))
                if fail == "install":
                    raise Boom("cp failed")

            def fake_remove(dest, name):
                events.append(("remove", name))
                if fail == "remove":
                    raise Boom("rm failed")

            class FakeRebuild:
                def __init__(self, **kwargs):
                    self.kwargs = kwargs

                def rebuild(self):
                    events.append(("kc_rebuild", bool(self.kwargs.get("auxiliary_cache_only"))))
                    if fail == "kc_raise":
                        raise Boom("kmutil crashed")
                    return kc_result

            class FakeKCSupport:
                def __init__(self, *a, **k):
                    pass

                def add_auxkc_support(self, install_file, source, folder, dest):
                    return dest

                def check_kexts_needs_authentication(self, name):
                    return False

            class FakeSnapshot:
                def __init__(self, *a, **k):
                    pass

                def create_snapshot(self):
                    events.append(("snapshot",))
                    return True

                def revert_snapshot(self):
                    return True

            class FakeHelpers:
                def __init__(self, *a, **k):
                    pass

                def tahoe_applehda_patch(self, *a, **k):
                    events.append(("applehda",))
                    if fail == "applehda":
                        raise Boom("codesign failed")

                def __getattr__(self, name):
                    return lambda *a, **k: True

            class FakeAutoPatcher:
                def __init__(self, *a, **k):
                    pass

                def install_auto_patcher_launch_agent(self, *a, **k):
                    pass

            sys_patch.install_new_file = fake_install
            sys_patch.remove_file = fake_remove
            sys_patch.kernelcache = SimpleNamespace(RebuildKernelCache=FakeRebuild, KernelCacheSupport=FakeKCSupport)
            sys_patch.APFSSnapshot = FakeSnapshot
            sys_patch.sys_patch_helpers = SimpleNamespace(SysPatchHelpers=FakeHelpers)
            sys_patch.InstallAutomaticPatchingServices = FakeAutoPatcher
            sys_patch.subprocess_wrapper = SimpleNamespace(
                run_as_root=lambda *a, **k: real_subprocess.CompletedProcess(a, 0, b"", b""),
                run_as_root_and_verify=lambda *a, **k: None,
                run_and_verify=lambda *a, **k: None,
                run=lambda *a, **k: real_subprocess.CompletedProcess(a, 0, b"", b""),
            )

            c = new_constants()
            obj = sys_patch.PatchSysVolume.__new__(sys_patch.PatchSysVolume)
            obj.model = "iMac20,1"
            obj.constants = c
            obj.computer = c.computer
            obj.root_supports_snapshot = True
            obj.mount_location = MOUNT
            obj.mount_location_data = ""
            obj.needs_kmutil_exemptions = False
            obj.kdk_path = None
            obj.metallib_path = None
            obj._metallib_preflight_refresh_attempted = False
            obj.hardware_details = {
                detect.HardwarePatchsetSettings.KERNEL_DEBUG_KIT_REQUIRED: kdk_required,
                detect.HardwarePatchsetSettings.METALLIB_SUPPORT_PKG_REQUIRED: False,
            }
            obj.skip_root_kmutil_requirement = not kdk_required
            obj.requires_kdk_caching = kdk_required
            obj.requires_metallib_caching = False
            obj.mount_obj = SimpleNamespace(mount=lambda: True, unmount=lambda *a, **k: True)
            obj._preflight_checks = lambda patches, src: patches
            obj._unmount_root_vol = lambda: events.append(("unmount",))
            obj._write_patchset = lambda patches: events.append(("manifest",))

            patchset = {
                "Test Graphics": {
                    PatchType.REMOVE_SYSTEM_VOLUME: {"/System/Library/Extensions": {"OldDriver.kext": "26.0"}},
                    PatchType.OVERWRITE_SYSTEM_VOLUME: {"/System/Library/Extensions": {"TestDriver.kext": "12.5"}},
                },
            }
            if extra_patch:
                patchset.update(extra_patch)
            obj.patch_set_dictionary = patchset

            c.root_patcher_succeeded = False
            obj._patch_root_vol()
            return list(events), bool(c.root_patcher_succeeded)

        def snapshot_index(ev):
            return next((i for i, e in enumerate(ev) if e[0] == "snapshot"), None)

        # Sanity: a clean run has to seal, otherwise the harness is broken
        try:
            ev, ok = scenario("ok")
        except Exception as e:
            ev, ok = None, None
            errors.append({"case": case, "subject": "clean run", "message": f"_patch_root_vol() raised {e!r}"[:300]})
        if ev is not None:
            if snapshot_index(ev) is None or not ok:
                errors.append({"case": case, "subject": "clean run",
                               "message": f"a run without failures did not seal/succeed (events: {ev}) - scenario not reproduced"})
            else:
                checked += 1
                kc = next((i for i, e in enumerate(ev) if e[0] == "kc_rebuild"), None)
                if kc is None:
                    problems.append(_problem(case, "kext patch + Kernel Debug Kit required",
                        "the Kernel Collection is never rebuilt although a kext was installed into "
                        "/System/Library/Extensions - the sealed snapshot boots a KC that doesn't match"))
                elif kc > snapshot_index(ev):
                    problems.append(_problem(case, "kext patch + Kernel Debug Kit required",
                        "the Kernel Collection is rebuilt after the snapshot was created - the new KC isn't in the snapshot that boots"))

        failures = [
            ("install", {}, "installing a file fails"),
            ("remove", {}, "removing a file fails"),
            ("kc_raise", {}, "the Kernel Collection rebuild raises"),
            (None, {"kc_result": False}, "the Kernel Collection rebuild reports failure"),
            ("applehda", {"extra_patch": {"Modern Audio": {
                PatchType.OVERWRITE_SYSTEM_VOLUME: {"/System/Library/Extensions": {"AppleHDA.kext": "26.0"}}}}},
             "the AppleHDA patch/re-sign fails"),
        ]
        for fail, kwargs, label in failures:
            try:
                ev, ok = scenario(label, fail=fail, **kwargs)
            except Exception as e:
                # An exception escaping _patch_root_vol() is fine for safety as long as nothing was sealed
                ev, ok = list(events), False
                escaped = repr(e)
            else:
                escaped = None
            checked += 1
            if snapshot_index(ev) is not None:
                problems.append(_problem(case, label,
                    f"a new APFS snapshot is still created when {label} - the half-patched volume becomes "
                    f"the boot target and the Mac may not start again"))
            if ok:
                problems.append(_problem(case, label,
                    f"root patching reports success when {label}"))
            if escaped:
                errors.append({"case": case, "subject": label,
                               "message": f"_patch_root_vol() let {escaped[:150]} escape (nothing sealed, but the GUI gets an exception)"})

    # ------------------------------------------------------------------------
    elif case == "files:failures":
        from opencore_legacy_patcher.sys_patch.utilities import files

        calls = []
        failing = {"name": None}

        def fake_run_as_root(cmd, *a, **k):
            cmd = [str(x) for x in cmd]
            calls.append(cmd)
            rc = 1 if Path(cmd[0]).name == failing["name"] else 0
            return real_subprocess.CompletedProcess(cmd, rc, b"", b"simulated failure" if rc else b"")

        subprocess_wrapper.run_as_root = fake_run_as_root
        files.subprocess_wrapper = subprocess_wrapper
        # The real one probes clonefile() support through macOS-only APIs
        files.generate_copy_arguments = lambda s, d: ["/bin/cp", "-R", s, d] if Path(s).is_dir() else ["/bin/cp", s, d]

        def make_tree():
            base = Path(tempfile.mkdtemp())
            src, dst = base / "src", base / "dst"
            (src / "Thing.framework" / "Versions").mkdir(parents=True)
            (src / "Driver.kext" / "Contents").mkdir(parents=True)
            (src / "libthing.dylib").write_bytes(b"x")
            dst.mkdir()
            (dst / "Old.kext").mkdir()
            (dst / "libold.dylib").write_bytes(b"x")
            (dst / "Driver.kext").mkdir()
            (dst / "libthing.dylib").write_bytes(b"old")
            return str(src), str(dst)

        scenarios = [
            ("rsync", "install", PatchType.MERGE_SYSTEM_VOLUME, "Thing.framework",
             "merging a framework (MERGE_SYSTEM_VOLUME) and rsync fails"),
            ("cp", "install", PatchType.OVERWRITE_SYSTEM_VOLUME, "libthing.dylib",
             "replacing a file and cp fails"),
            ("cp", "install", PatchType.OVERWRITE_SYSTEM_VOLUME, "Driver.kext",
             "replacing a kext and cp fails"),
            ("rm", "install", PatchType.OVERWRITE_SYSTEM_VOLUME, "Driver.kext",
             "replacing a kext and removing the old one fails"),
            ("rm", "remove", None, "Old.kext", "removing a kext and rm fails"),
            ("rm", "remove", None, "libold.dylib", "removing a file and rm fails"),
        ]
        for binary, action, ptype, name, label in scenarios:
            src, dst = make_tree()
            failing["name"] = binary
            calls.clear()
            raised = None
            try:
                if action == "install":
                    files.install_new_file(src, dst, name, ptype)
                else:
                    files.remove_file(dst, name)
            except Exception as e:
                raised = e
            ran = any(Path(c[0]).name == binary for c in calls)
            if not ran:
                errors.append({"case": case, "subject": label,
                               "message": f"{binary} was never called - scenario not reproduced (calls: {[c[0] for c in calls]})"})
                continue
            checked += 1
            if raised is None:
                problems.append(_problem(case, label,
                    f"{binary} exits non-zero but {('install_new_file' if action == 'install' else 'remove_file')}() "
                    f"returns normally - sys_patch rebuilds the KC and seals a half-patched volume as if it had worked"))

    # ------------------------------------------------------------------------
    elif case == "detect:gates":
        host = example_data.iMac.iMac122_Upgraded  # needs non-Metal + Metal patches on Tahoe
        gate_names = {
            "_validation_check_unsupported_host_os": "the macOS version is unsupported",
            "_validation_check_filevault_is_enabled": "FileVault is on",
            "_validation_check_system_integrity_protection_enabled": "SIP isn't lowered",
            "_validation_check_secure_boot_model_enabled": "Apple Secure Boot is on",
            "_validation_check_amfi_enabled": "AMFI is active",
            "_validation_check_root_is_dirty": "the root volume is already modified",
        }

        def run_detection(blocked=()):
            clear_gates(blocked)
            c = new_constants(computer=host)
            return Detection(c, validation=False, disabled_patchsets=[])

        try:
            base = run_detection()
        except Exception as e:
            base = None
            errors.append({"case": case, "subject": "all clear", "message": f"detection raised {e!r}"[:300]})
        if base is not None:
            if not base.can_patch:
                blockers = [k for k, v in (base.device_properties or {}).items() if str(k).startswith("Validation:") and v is True]
                errors.append({"case": case, "subject": "all clear",
                               "message": f"root patching blocked with every gate clear ({blockers}) - scenario not reproduced"})
            else:
                for method, label in gate_names.items():
                    if method not in originals:
                        checked += 1
                        problems.append(_problem(case, method,
                            f"HardwarePatchsetDetection.{method}() is gone - nothing blocks root patching when {label}"))
                        continue
                    try:
                        det = run_detection(blocked=(method,))
                    except Exception as e:
                        errors.append({"case": case, "subject": method, "message": f"detection raised {e!r}"[:300]})
                        continue
                    checked += 1
                    if det.can_patch:
                        problems.append(_problem(case, method,
                            f"root patching is still allowed when {label} - the gate isn't wired into the requirements"))
                    if method == "_validation_check_system_integrity_protection_enabled" and det.can_unpatch:
                        problems.append(_problem(case, method,
                            "reverting root patches is still allowed when SIP isn't lowered - the revert can't mount the system volume"))

        # The probes themselves, against a simulated stock Mac
        for name, func in originals.items():
            setattr(Detection, name, func)
        Detection._is_cached_kernel_debug_kit_present = lambda self: True
        Detection._is_cached_metallib_support_pkg_present = lambda self: True

        probe = Detection.__new__(Detection)
        probe._constants = new_constants()
        probe._xnu_major = os_data.os_data.tahoe
        probe._xnu_minor = 6

        real_run = real_subprocess.run
        try:
            detect.subprocess.run = lambda *a, **k: real_subprocess.CompletedProcess(a, 0, b"FileVault is On.\n", b"")
            fv = Detection._validation_check_filevault_is_enabled
            fv = getattr(fv, "__wrapped__", fv)
            checked += 1
            if fv(probe) is not True:
                problems.append(_problem(case, "_validation_check_filevault_is_enabled",
                    "reports FileVault as off while fdesetup says 'FileVault is On.' - root patching would go ahead "
                    "with FileVault on"))
        except Exception as e:
            errors.append({"case": case, "subject": "FileVault probe", "message": repr(e)[:300]})
        finally:
            detect.subprocess.run = real_run

        try:
            saved = copy.deepcopy(sip_data.system_integrity_protection.csr_values)
            utilities.py_sip_xnu = SimpleNamespace(SipXnu=lambda: FakeSip(0))
            configs = sip_data.system_integrity_protection.root_patch_sip_ventura
            checked += 1
            if Detection._validation_check_system_integrity_protection_enabled(probe, configs) is not True:
                problems.append(_problem(case, "_validation_check_system_integrity_protection_enabled",
                    "reports SIP as lowered on a Mac with SIP fully enabled (csr-active-config 0) - root patching "
                    "would try to write to the sealed system volume"))
            sip_data.system_integrity_protection.csr_values.clear()
            sip_data.system_integrity_protection.csr_values.update(saved)
        except Exception as e:
            errors.append({"case": case, "subject": "SIP probe", "message": repr(e)[:300]})

    # ------------------------------------------------------------------------
    elif case == "detect:gpu-mix":
        from opencore_legacy_patcher.sys_patch.patchsets.hardware.base import HardwareVariantGraphicsSubclass as Sub

        class FakeGPU:
            def __init__(self, name, sub):
                self._name, self._sub = name, sub

            def name(self):
                return self._name

            def hardware_variant_graphics_subclass(self):
                return self._sub

        combos = [
            (os_data.os_data.tahoe, [("Graphics: Intel Sandy Bridge", Sub.NON_METAL_GRAPHICS), ("Graphics: AMD Polaris", Sub.METAL_31001_GRAPHICS)]),
            (os_data.os_data.tahoe, [("Graphics: Nvidia Tesla", Sub.NON_METAL_GRAPHICS), ("Graphics: Intel Ivy Bridge", Sub.METAL_3802_GRAPHICS)]),
            (os_data.os_data.ventura, [("Graphics: AMD TeraScale 2", Sub.NON_METAL_GRAPHICS), ("Graphics: Nvidia Kepler", Sub.METAL_3802_GRAPHICS)]),
            (os_data.os_data.sequoia, [("Graphics: Intel Ivy Bridge", Sub.METAL_3802_GRAPHICS), ("Graphics: AMD Polaris", Sub.METAL_31001_GRAPHICS)]),
            (os_data.os_data.tahoe, [("Graphics: Nvidia Kepler", Sub.METAL_3802_GRAPHICS), ("Graphics: AMD Vega", Sub.METAL_31001_GRAPHICS)]),
        ]
        for xnu, gpus in combos:
            det = Detection.__new__(Detection)
            det._xnu_major = xnu
            det._constants = new_constants(xnu)
            subject = f"macOS {_macos(xnu)}: " + " + ".join(n for n, _ in gpus)
            try:
                result = det._strip_incompatible_hardware([FakeGPU(n, s) for n, s in gpus])
            except Exception as e:
                errors.append({"case": case, "subject": subject, "message": f"_strip_incompatible_hardware() raised {e!r}"[:300]})
                continue
            checked += 1
            subs = {g.hardware_variant_graphics_subclass() for g in result}
            metal = subs & {Sub.METAL_3802_GRAPHICS, Sub.METAL_31001_GRAPHICS}
            if Sub.NON_METAL_GRAPHICS in subs and metal:
                problems.append(_problem(case, subject,
                    "Metal and non-Metal graphics patches would be installed together - WindowServer can't start"))
            elif xnu >= os_data.os_data.sequoia and metal == {Sub.METAL_3802_GRAPHICS, Sub.METAL_31001_GRAPHICS}:
                problems.append(_problem(case, subject,
                    "Metal 3802 and Metal 31001 patches would be installed together on Sequoia or newer"))
            if not result:
                problems.append(_problem(case, subject, "every graphics patchset was stripped - no acceleration at all"))

    else:
        raise SystemExit(f"unknown case {case}")

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump({"case": case, "checked": checked, "problems": problems, "errors": errors}, f)


# ----------------------------------------------------------------------------
# Driver side
# ----------------------------------------------------------------------------

def run_tree(root: Path) -> dict:
    results = {"cases": {}, "problems": [], "errors": [], "fatal": None}
    for case in CASES:
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False) as tmp:
            out = tmp.name
        start = time.time()
        try:
            proc = subprocess.run(
                [sys.executable, os.path.abspath(__file__), "--worker", "--root", str(root), "--case", case, "--out", out],
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=WORKER_TIMEOUT, check=False,
            )
            data = json.loads(Path(out).read_text(encoding="utf-8")) if proc.returncode == 0 else None
        except subprocess.TimeoutExpired:
            proc, data = None, None
        except (OSError, ValueError):
            data = None
        finally:
            Path(out).unlink(missing_ok=True)

        if data is None:
            tail = (proc.stderr.decode("utf-8", "replace")[-1500:] if proc else "timed out")
            results["fatal"] = results["fatal"] or f"{case}: the check could not run ({tail.strip().splitlines()[-1] if tail.strip() else 'no output'})"
            results["cases"][case] = {"checked": 0, "problems": 0, "errors": 1, "seconds": round(time.time() - start)}
            print(f"[{case}] could not run:\n{tail}", file=sys.stderr)
            continue

        results["cases"][case] = {"checked": data["checked"], "problems": len(data["problems"]),
                                  "errors": len(data["errors"]), "seconds": round(time.time() - start)}
        results["problems"].extend(data["problems"])
        results["errors"].extend(data["errors"])
        print(f"[{case}] checked {data['checked']}, problems {len(data['problems'])}, "
              f"could not check {len(data['errors'])} ({round(time.time() - start)}s)")

    if not results["fatal"] and not any(c["checked"] for c in results["cases"].values()):
        results["fatal"] = "nothing could be checked"
    return results


def _key(p):
    return (p["case"], p["subject"], p["message"].split(" (first seen")[0])


def write_summary(path: str, result: dict) -> None:
    lines = ["## Root patching check", ""]
    if result["fatal"]:
        lines.append(f"❌ The check could not run: `{result['fatal']}`")
    elif result["new"]:
        lines.append(f"❌ {len(result['new'])} problem(s)")
    else:
        lines.append("✅ No root-patching problem that could leave a Mac unbootable was found.")
    lines += ["", "| Case | Checked | Problems | Couldn't check |", "|---|---|---|---|"]
    for case, c in result["cases"].items():
        lines.append(f"| `{case}` | {c['checked']} | {c['problems']} | {c['errors']} |")
    for title, items in (("Problems", result["new"]), ("Already broken on main", result["known"])):
        if items:
            lines += ["", f"### {title}", "", "| Case | Where | Problem |", "|---|---|---|"]
            lines += [f"| `{p['case']}` | `{p['subject']}` | {p['message']} |" for p in items[:200]]
    if result["errors"]:
        lines += ["", "### Couldn't check", "", "| Case | Where | Error |", "|---|---|---|"]
        lines += [f"| `{e['case']}` | `{e['subject']}` | {e['message']} |" for e in result["errors"][:100]]
    Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    parser.add_argument("--baseline")
    parser.add_argument("--json")
    parser.add_argument("--summary")
    parser.add_argument("--worker", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--case", help=argparse.SUPPRESS)
    parser.add_argument("--out", help=argparse.SUPPRESS)
    args = parser.parse_args()

    if args.worker:
        _worker(os.path.abspath(args.root), args.case, args.out)
        return 0

    print(f"== Checking {args.root}")
    current = run_tree(Path(args.root).resolve())

    known_keys = set()
    if args.baseline:
        print(f"== Checking baseline {args.baseline}")
        base = run_tree(Path(args.baseline).resolve())
        if base["fatal"]:
            print(f"baseline could not be checked ({base['fatal']}) - treating every problem as new")
        else:
            known_keys = {_key(p) for p in base["problems"]}

    new = [p for p in current["problems"] if _key(p) not in known_keys]
    known = [p for p in current["problems"] if _key(p) in known_keys]

    result = {
        "fatal": current["fatal"],
        "cases": current["cases"],
        "new": new,
        "known": known,
        "errors": current["errors"],
    }

    for p in new:
        print(f"PROBLEM [{p['case']}] {p['subject']}: {p['message']}")
    for p in known:
        print(f"already on main [{p['case']}] {p['subject']}: {p['message']}")
    for e in current["errors"][:50]:
        print(f"could not check [{e['case']}] {e['subject']}: {e['message']}")

    if args.json:
        Path(args.json).write_text(json.dumps(result, indent=1), encoding="utf-8")
    if args.summary:
        write_summary(args.summary, result)

    if current["fatal"]:
        return 2
    return 1 if new else 0


if __name__ == "__main__":
    sys.exit(main())
