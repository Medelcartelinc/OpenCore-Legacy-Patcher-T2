"""
sys_patch_helpers.py: Additional support functions for sys_patch.py
"""

import os
import logging
import plistlib
import subprocess
import sys
import shutil
import glob

from typing import Union
from pathlib import Path
from datetime import datetime

from .. import constants

from ..datasets import os_data
from ..volume   import generate_copy_arguments

from ..support import (
    generate_smbios,
    subprocess_wrapper
)


class SysPatchHelpers:
    """
    Library of helper functions for sys_patch.py and related libraries
    """

    def __init__(self, global_constants: constants.Constants):
        self.constants: constants.Constants = global_constants


    def snb_board_id_patch(self, source_files_path: str):
        """
        Patch AppleIntelSNBGraphicsFB.kext to support unsupported Board IDs

        AppleIntelSNBGraphicsFB hard codes the supported Board IDs for Sandy Bridge iGPUs
        Because of this, the kext errors out on unsupported systems
        This function simply patches in a supported Board ID, using 'determine_best_board_id_for_sandy()'
        to supplement the ideal Board ID

        Parameters:
            source_files_path (str): Path to the source files

        """

        # Safely resolve and validate the source path to prevent path traversal attacks
        try:
            source_path = Path(source_files_path).resolve()
        except (OSError, ValueError) as e:
            logging.error(f"Invalid source path: {source_files_path}")
            logging.exception("Stack Trace:")
            raise Exception(f"Invalid source path: {e}")

        if self.constants.computer.reported_board_id in self.constants.sandy_board_id_stock:
            return

        logging.info(f"Found unsupported Board ID {self.constants.computer.reported_board_id}, performing AppleIntelSNBGraphicsFB bin patching")

        board_to_patch = generate_smbios.determine_best_board_id_for_sandy(self.constants.computer.reported_board_id, self.constants.computer.gpus)
        logging.info(f"Replacing {board_to_patch} with {self.constants.computer.reported_board_id}")

        board_to_patch_hex = bytes.fromhex(board_to_patch.encode('utf-8').hex())
        reported_board_hex = bytes.fromhex(self.constants.computer.reported_board_id.encode('utf-8').hex())

        if len(board_to_patch_hex) > len(reported_board_hex):
            # Pad the reported Board ID with zeros to match the length of the board to patch
            reported_board_hex = reported_board_hex + bytes(len(board_to_patch_hex) - len(reported_board_hex))
        elif len(board_to_patch_hex) < len(reported_board_hex):
            logging.error(f"Error: Board ID {self.constants.computer.reported_board_id} is longer than {board_to_patch}")
            raise Exception("Host's Board ID is longer than the kext's Board ID, cannot patch!!!")

        # Construct the target path safely
        relative_path = Path("10.13.6/System/Library/Extensions/AppleIntelSNBGraphicsFB.kext/Contents/MacOS/AppleIntelSNBGraphicsFB")
        path = source_path / relative_path
        
        # Verify the resolved path is still within the expected source directory (prevent directory escape)
        try:
            path.relative_to(source_path)
        except ValueError:
            logging.error(f"Path traversal detected: {path} is outside {source_path}")
            logging.exception("Stack Trace:")
            raise Exception("Path traversal attack detected!")
        
        if not path.exists():
            logging.error(f"Error: Could not find {path}")
            logging.exception("Stack Trace:")
            raise Exception("Failed to find AppleIntelSNBGraphicsFB.kext, cannot patch!!!")

        try:
            with open(path, 'rb') as f:
                data = f.read()
                data = data.replace(board_to_patch_hex, reported_board_hex)
            with open(path, 'wb') as f:
                f.write(data)
        except (OSError, IOError) as e:
            logging.error(f"Failed to patch binary: {e}")
            logging.exception("Stack Trace:")
            raise Exception(f"Failed to patch AppleIntelSNBGraphicsFB.kext: {e}")


    def generate_patchset_plist(self, patchset: dict, file_name: str, kdk_used: Path, metallib_used: Path):
        """
        Generate patchset file for user reference

        Parameters:
            patchset (dict): Dictionary of patchset, sys_patch/patchsets
            file_name (str): Name of the file to write to
            kdk_used (Path): Path to the KDK used, if any
            metallib_used (Path): Path to the Metal Library used, if any

        Returns:
            bool: True if successful, False if not

        """

        source_path = Path(self.constants.payload_path)
        source_path_file = source_path / file_name

        kdk_string = "Not applicable"
        if kdk_used:
            kdk_string = str(kdk_used)

        metallib_used_string = "Not applicable"
        if metallib_used:
            metallib_used_string = str(metallib_used)

        data = {
            "OpenCore Legacy Patcher": f"v{self.constants.patcher_version}",
            "PatcherSupportPkg": f"v{self.constants.patcher_support_pkg_version}",
            "Time Patched": f"{datetime.now().strftime('%B %d, %Y @ %H:%M:%S')}",
            "Commit URL": f"{self.constants.commit_info[2]}",
            "Kernel Debug Kit Used": f"{kdk_string}",
            "Metal Library Used": f"{metallib_used_string}",
            "OS Version": f"{self.constants.detected_os}.{self.constants.detected_os_minor} ({self.constants.detected_os_build})",
            "Custom Signature": bool(Path(self.constants.payload_local_binaries_root_path / ".signed").exists()),
        }

        data.update(patchset)

        # Create backup before writing (TOCTTOU prevention and data loss protection)
        if source_path_file.exists():
            backup_path = source_path_file.with_stem(f"{source_path_file.stem}.backup")
            try:
                shutil.copy2(source_path_file, backup_path)
                logging.info(f"Created backup of patchset at {backup_path}")
                os.remove(source_path_file)
            except (OSError, IOError) as e:
                logging.warning(f"Failed to create backup of patchset: {e}")
                logging.exception("Stack Trace:")
                # Continue anyway, but log the issue
                try:
                    os.remove(source_path_file)
                except OSError:
                    pass

        # Write to a temporary file first, then rename (atomic write)
        temp_path = source_path_file.with_suffix(source_path_file.suffix + '.tmp')
        try:
            with temp_path.open("wb") as f:
                plistlib.dump(data, f, sort_keys=False)
            # Atomic rename to target location
            temp_path.replace(source_path_file)
        except (OSError, IOError) as e:
            logging.error(f"Failed to write patchset plist: {e}")
            logging.exception("Stack Trace:")
            # Clean up temp file if it exists
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                pass
            return False

        # Verify the file was written successfully
        if source_path_file.exists():
            return True

        logging.error(f"Patchset file was not created at {source_path_file}")
        logging.exception("Stack Trace:")
        return False


    def disable_window_server_caching(self):
        """
        Disable WindowServer's asset caching

        On legacy GCN GPUs, the WindowServer cache generated creates
        corrupted Opaque shaders.

        To work-around this, we disable WindowServer caching
        And force macOS into properly generating the Opaque shaders
        """

        if self.constants.detected_os < os_data.os_data.ventura:
            return

        logging.info("Disabling WindowServer Caching")
        
        # Use glob to find matching paths and remove them without shell expansion
        window_server_paths = glob.glob("/private/var/folders/*/*/*/WindowServer/com.apple.WindowServer")
        if window_server_paths:
            for path in window_server_paths:
                try:
                    subprocess_wrapper.run_as_root(["/bin/rm", "-rf", path], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                except Exception as e:
                    logging.error(f"Failed to remove WindowServer cache at {path}: {e}")
                    logging.exception("Stack Trace:")
        
        # Disable writing to WindowServer folder
        window_server_dirs = glob.glob("/private/var/folders/*/*/*/WindowServer")
        if window_server_dirs:
            for path in window_server_dirs:
                try:
                    subprocess_wrapper.run_as_root(["/usr/bin/chflags", "uchg", path], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                except Exception as e:
                    logging.warning(f"Failed to set immutable flag on {path}: {e}")
                    logging.exception("Stack Trace:")
        
        # Reference:
        #   To reverse write lock:
        #   'chflags nouchg /private/var/folders/*/*/*/WindowServer'


    def install_rsr_repair_binary(self):
        """
        Installs RSRRepair

        RSRRepair is a utility that will sync the SysKC and BootKC in the event of a panic

        With macOS 13.2, Apple implemented the Rapid Security Response System
        However Apple added a half baked snapshot reversion system if seal was broken,
        which forgets to handle Preboot BootKC syncing.

        Thus this application will try to re-sync the BootKC with SysKC in the event of a panic
            Reference: https://github.com/dortania/OpenCore-Legacy-Patcher/issues/1019

        This is a (hopefully) temporary work-around, however likely to stay.
        RSRRepair has the added bonus of fixing desynced KCs from 'bless', so useful in Big Sur+
            Source: https://github.com/flagersgit/RSRRepair

        """

        if self.constants.detected_os < os_data.os_data.big_sur:
            return

        logging.info("Installing Kernel Collection syncing utility")
        try:
            result = subprocess_wrapper.run_as_root([self.constants.rsrrepair_userspace_path, "--install"], stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            if result.returncode != 0:
                logging.error("- Failed to install RSRRepair")
                logging.exception("Stack Trace:")
                subprocess_wrapper.log(result)
        except Exception as e:
            logging.error(f"Error installing RSRRepair: {e}")
            logging.exception("Stack Trace:")


    def patch_gpu_compiler_libraries(self, mount_point: Union[str, Path]):
        """
        Fix GPUCompiler.framework's libraries to resolve linking issues

        On 13.3 with 3802 GPUs, OCLP will downgrade GPUCompiler to resolve
        graphics support. However the binary hardcodes the library names,
        and thus we need to adjust the libraries to match (31001.669)

        Important portions of the library will be downgraded to 31001.669,
        and the remaining bins will be copied over (via CoW to reduce waste)

        Primary folders to merge:
        - 31001.XXX: (current OS version)
            - include:
                - module.modulemap
                - opencl-c.h
            - lib (entire directory)

        Note: With macOS Sonoma, 32023 compiler is used instead and so this patch is not needed
              until macOS 14.2 Beta 2 with version '32023.26'.

        Parameters:
            mount_point: The mount point of the target volume
        """
        if os_data.os_data.sonoma < self.constants.detected_os < os_data.os_data.ventura:
            return

        if self.constants.detected_os == os_data.os_data.ventura:
            if self.constants.detected_os_minor < 4: # 13.3
                return
            BASE_VERSION = "31001"
            GPU_VERSION = f"{BASE_VERSION}.669"
        elif self.constants.detected_os == os_data.os_data.sonoma:
            if self.constants.detected_os_minor < 2: # 14.2 Beta 2
                return
            BASE_VERSION = "32023"
            GPU_VERSION = f"{BASE_VERSION}.26"
        else:
            # Fall back for newer versions
            BASE_VERSION = "32023"
            GPU_VERSION = f"{BASE_VERSION}.26"

        mount_point = Path(mount_point)
        LIBRARY_DIR = mount_point / f"System/Library/PrivateFrameworks/GPUCompiler.framework/Versions/{BASE_VERSION}/Libraries/lib/clang"
        DEST_DIR = LIBRARY_DIR / GPU_VERSION

        if not DEST_DIR.exists():
            logging.error(f"Failed to find GPUCompiler libraries at {DEST_DIR}")
            logging.exception("Stack Trace:")
            raise Exception(f"Failed to find GPUCompiler libraries at {DEST_DIR}")

        for file in LIBRARY_DIR.iterdir():
            if file.is_file():
                continue
            if file.name == GPU_VERSION:
                continue

            # Partial match as each OS can increment the version
            if not file.name.startswith(f"{BASE_VERSION}."):
                continue

            logging.info(f"Merging GPUCompiler.framework libraries to match binary")

            src_dir = LIBRARY_DIR / file.name
            dest_lib_dir = DEST_DIR / "lib"
            
            if not dest_lib_dir.exists():
                # Validate that generate_copy_arguments returns a valid result
                copy_args = generate_copy_arguments(str(src_dir / "lib"), str(DEST_DIR / ""))
                if not copy_args:
                    logging.error(f"Failed to generate copy arguments for {src_dir}/lib")
                    logging.exception("Stack Trace:")
                    raise Exception(f"Failed to generate copy arguments for {src_dir}/lib")
                
                try:
                    result = subprocess_wrapper.run_as_root_and_verify(copy_args, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
                    if result and result.returncode != 0:
                        logging.error(f"Failed to copy GPUCompiler libraries")
                        logging.exception("Stack Trace:")
                        raise Exception(f"Failed to copy GPUCompiler libraries")
                except Exception as e:
                    logging.error(f"Error copying GPUCompiler libraries: {e}")
                    logging.exception("Stack Trace:")
                    raise

            break
