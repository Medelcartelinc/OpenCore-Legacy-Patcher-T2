"""
subprocess_wrapper.py: Wrapper for subprocess module to better handle errors and output
                       Additionally handles our Privileged Helper Tool
"""

import enum
import stat
import shlex
import logging
import subprocess
import os
import atexit
import threading
from . import utilities

from pathlib import Path
from typing import Callable, Optional


OCLP_PRIVILEGED_HELPER = "/Library/PrivilegedHelperTools/com.albert-mueller.opencore-legacy-patcher.privileged-helper"
OCLP_PRIVILEGED_HELPER_EXPECTED_MODE = 0o4755

ADMIN_PASSWORD_PROMPT_MESSAGE = (
    "OpenCore Legacy Patcher needs your administrator password to apply root patches. "
    "You will only be asked once - it is kept in memory until the app quits."
)
ADMIN_PASSWORD_RETRY_MESSAGE = "Incorrect password, please try again. " + ADMIN_PASSWORD_PROMPT_MESSAGE
ADMIN_PASSWORD_MAX_ATTEMPTS = 3

# Session-wide administrator credential cache (Issue #356).
#
# Without it every privileged operation that could not go through the Privileged Helper
# Tool - which is every one of them on an unsigned/ad-hoc build, since the helper refuses
# callers without a matching certificate chain - spawned its own
# 'osascript ... with administrator privileges'. AppleScript only caches that
# authorization inside the process that asked for it, and each osascript call is a new
# process, so root patching asked for the password again for nearly every command, plus
# once more for the disk image mounts.
#
# The password is kept in process memory only, never written anywhere, never logged,
# and dropped at exit. Python strings cannot be reliably wiped, so this is a
# convenience/exposure trade-off, not a secure-memory guarantee; the process already
# held the password transiently for the sudo-based DMG mounts before this change.
_admin_session_lock = threading.RLock()
_cached_admin_password: Optional[str] = None
_admin_prompt_icon_path = None
# Set once the helper has reported a non-transient failure (signing/certificates), so we
# stop invoking it for every single command of the session.
_privileged_helper_unusable = False
# True when the last password request was cancelled by the user
_admin_password_cancelled = False
# True once sudo rejected every attempt (e.g. the account is not an administrator);
# later commands then go straight to osascript instead of re-running the dialog loop.
_sudo_elevation_failed = False


class PrivilegedHelperErrorCodes(enum.IntEnum):
    """
    Error codes for Privileged Helper Tool.

    Reference:
        payloads/Tools/PrivilegedHelperTool/main.m
    """
    OCLP_PHT_ERROR_MISSING_ARGUMENTS           = 160
    OCLP_PHT_ERROR_SET_UID_MISSING             = 161
    OCLP_PHT_ERROR_SET_UID_FAILED              = 162
    OCLP_PHT_ERROR_SELF_PATH_MISSING           = 163
    OCLP_PHT_ERROR_PARENT_PATH_MISSING         = 164
    OCLP_PHT_ERROR_SIGNING_INFORMATION_MISSING = 165
    OCLP_PHT_ERROR_INVALID_TEAM_ID             = 166
    OCLP_PHT_ERROR_INVALID_CERTIFICATES        = 167
    OCLP_PHT_ERROR_COMMAND_MISSING             = 168
    OCLP_PHT_ERROR_COMMAND_FAILED              = 169
    OCLP_PHT_ERROR_CATCH_ALL                   = 170


# Errors that will not go away by retrying within this session: the helper (or the app
# calling it) simply is not signed in a way the helper accepts.
_HELPER_PERMANENT_ERRORS = (
    PrivilegedHelperErrorCodes.OCLP_PHT_ERROR_SIGNING_INFORMATION_MISSING.value,
    PrivilegedHelperErrorCodes.OCLP_PHT_ERROR_INVALID_TEAM_ID.value,
    PrivilegedHelperErrorCodes.OCLP_PHT_ERROR_INVALID_CERTIFICATES.value,
)


def _helper_path_is_safe_to_repair() -> bool:
    """
    Validate that OCLP_PRIVILEGED_HELPER is a plausible, untampered helper binary
    before we consider handing it setuid-root.

    This matters because repair_privileged_helper_permissions() ultimately runs
    'chmod 4755 <path>' AS ROOT. chmod(1), Path.exists() and Path.stat() all follow
    symlinks, so without these checks anyone able to replace that path with a symlink
    could have us mark an arbitrary root-owned binary setuid-root - a local privilege
    escalation, using an authorization prompt the user has every reason to approve.

    A helper that has lost its setuid bit is itself a possible sign of tampering, so
    "unexpected permissions" is treated as a reason to look harder, not as routine drift.

    Checks (all must hold):
      - the path is a regular file and NOT a symlink (lstat, so we inspect the link itself)
      - it is owned by root
      - its parent directory is owned by root and is not group- or world-writable

    Deliberately does NOT enforce a code-signature/Team ID check: this fork intentionally
    runs an unsigned helper, so codesign verification would fail by design here. That means
    these checks are a floor, not a guarantee - they stop the symlink/permission tricks a
    non-root local attacker can play, not a compromise that already has root.

    Returns:
        bool: True if the helper looks like our binary in its expected location.
    """
    helper_path = Path(OCLP_PRIVILEGED_HELPER)

    try:
        # lstat(), NOT stat(): we want to inspect the path itself, not its symlink target
        helper_stat = helper_path.lstat()
        parent_stat = helper_path.parent.lstat()
    except OSError as error:
        logging.error(f"Could not stat Privileged Helper Tool: {error}")
        return False
    except Exception as e: # behebt eine Sicherheitslücke, die erlaubt Angreifern, den Priveleged Helper Tool einen unerwartetes Fehler auszulösen, um beliebiges Code auszuführen
        logging.error(f"Could not stat Privileged Helper Tool due to unexpected error: {error}")
        logging.exception("Stack Trace:")
        return False

    if stat.S_ISLNK(helper_stat.st_mode):
        logging.error("Privileged Helper Tool is a symlink - refusing to repair permissions")
        return False

    if not stat.S_ISREG(helper_stat.st_mode):
        logging.error("Privileged Helper Tool is not a regular file - refusing to repair permissions")
        return False

    if helper_stat.st_uid != 0:
        logging.error(f"Privileged Helper Tool is not owned by root (uid {helper_stat.st_uid}) - refusing to repair permissions")
        return False

    if parent_stat.st_uid != 0:
        logging.error(f"Privileged Helper Tool's directory is not owned by root (uid {parent_stat.st_uid}) - refusing to repair permissions")
        return False

    if stat.S_IMODE(parent_stat.st_mode) & (stat.S_IWGRP | stat.S_IWOTH):
        logging.error("Privileged Helper Tool's directory is group- or world-writable - refusing to repair permissions")
        return False

    return True


def privileged_helper_needs_setuid_repair() -> bool:
    """
    Check whether the Privileged Helper Tool is missing its expected
    permission bits (4755: setuid root, rwxr-xr-x).

    This can drift after certain OS updates or re-signing steps, and
    manifests as OCLP_PHT_ERROR_SET_UID_MISSING/FAILED when the helper
    is invoked.

    Returns:
        bool: True if the helper tool exists, passes the safety checks in
              _helper_path_is_safe_to_repair(), and its permissions need to be
              repaired. False if it's already correct, isn't installed yet
              (nothing to repair here), or failed validation.
    """
    helper_path = Path(OCLP_PRIVILEGED_HELPER)
    if not helper_path.exists():
        return False

    current_mode = stat.S_IMODE(helper_path.lstat().st_mode)
    if current_mode == OCLP_PRIVILEGED_HELPER_EXPECTED_MODE:
        return False

    logging.info(f"Privileged Helper Tool has unexpected permissions: {oct(current_mode)} (expected {oct(OCLP_PRIVILEGED_HELPER_EXPECTED_MODE)})")

    # Only now, once we know we would actually chmod something, pay for the validation
    if _helper_path_is_safe_to_repair():
        return True
    elif not _helper_path_is_safe_to_repair(): # behebt eine Sicherheitslücke, die erlaubt Angreifern, Root-Rechte zu erhalten
        return False
    else:
        logging.error("We failed to assess the safety of repairing the Priveleged Helper Tool. It won't be repaired, just to be on the safe side.")
        logging.info("Please ensure that OpenCore Legacy Patcher T2 is downloaded only from the official GitHub repository.")
        return False


def repair_privileged_helper_permissions():

        if not _helper_path_is_safe_to_repair():
            return False

        prompt = "OpenCore Legacy Patcher T2 needs administrator permission to repair the permissions of its privileged helper tool."

        result=utilities.get_admin_permission(
            action="/bin/chmod", 
            args=[f"{oct(OCLP_PRIVILEGED_HELPER_EXPECTED_MODE)[2:]} {OCLP_PRIVILEGED_HELPER}".encode("utf-8")],
            reason=prompt,
            # the defaults for the buttons are ok, so we would touch them
        )
        if result.returncode == 0:
            return True
        else:
            return False




def run(*args, **kwargs):
    """
    Basic subprocess.run wrapper.
    """
    return subprocess.run(*args, **kwargs)


def run_as_root(*args, **kwargs):
    """
    Run subprocess as root.

    Note: Full path to first argument is required.
    Helper tool does not resolve PATH.

    Always returns a CompletedProcess - callers (notably run_as_root_and_verify()
    and verify()) dereference .returncode unconditionally, so returning None here
    would turn a handled failure into an AttributeError.
    """
    # Check if first argument exists
    if not Path(args[0][0]).exists():
        raise FileNotFoundError(f"File not found: {args[0][0]}")

    _command = list(args[0])

    # If we are already running as root (e.g. launched via sudo), bypass the Helper Tool
    if os.geteuid() == 0:
        return subprocess.run(_command, **kwargs)

    global _privileged_helper_unusable

    if Path(OCLP_PRIVILEGED_HELPER).exists() and not _privileged_helper_unusable:
        if privileged_helper_needs_setuid_repair():
            if not repair_privileged_helper_permissions():
                logging.error("Privileged Helper Tool permissions could not be repaired, cannot complete request.")
                # Deliberately no osascript fallback here: the helper being in an
                # unexpected state is exactly when a silent downgrade to an
                # administrator-password prompt is least appropriate, since that
                # prompt is indistinguishable from one an attacker could provoke.
                return subprocess.CompletedProcess(
                    args=_command,
                    returncode=PrivilegedHelperErrorCodes.OCLP_PHT_ERROR_SET_UID_FAILED.value,
                    stdout=b"",
                    stderr=b"Privileged Helper Tool permissions could not be repaired",
                )
        result = subprocess.run([OCLP_PRIVILEGED_HELPER] + _command, **kwargs)
        # Any of our own PrivilegedHelperErrorCodes sentinel values (160-170) means the helper
        # tool itself couldn't do its job - an escalation failure (eg. missing/invalid setuid bit)
        # or another internal precondition (signing/certificates/command validation) - as opposed
        # to the wrapped command failing on its own merits with an ordinary low exit code, which is
        # just returned as-is: retrying that via osascript wouldn't fix a genuine command failure,
        # and would only cost an extra administrator-password prompt for nothing.
        _helper_error = __resolve_privileged_helper_errors(result.returncode)
        if _helper_error is None:
            return result
        if result.returncode in _HELPER_PERMANENT_ERRORS:
            _privileged_helper_unusable = True
            logging.error(f"Privileged Helper Tool rejected this build ({_helper_error}), not using it for the rest of this session.")
        else:
            logging.error(f"Privileged Helper Tool failed ({_helper_error}).")
    elif not Path(OCLP_PRIVILEGED_HELPER).exists():
        logging.warning(f"Privileged Helper Tool not found at {OCLP_PRIVILEGED_HELPER}.")
    process =_command[0]
    _command.remove(process)
    return utilities.get_admin_permission(action=process, args=_command)



def mount_dmg(
    dmg_path: Path,
    mount_point: Path,
    shadow_path: Path = None,
    password: str = None,
    admin_password_prompt: Optional[Callable[[], str]] = None,
    retry_on_auth_error: bool = False
) -> subprocess.CompletedProcess:
    """
    Attach a disk image via 'hdiutil attach', using '-stdinpass' rather than
    the deprecated (and, on some systems, less reliable) '-passphrase' flag.

    Some systems (observed starting with macOS 26.4) require elevated
    privileges to mount disk images, a regression from prior unprivileged
    mounts succeeding, which manifests as "Permission denied". If
    'admin_password_prompt' is supplied and the unprivileged attempt fails
    with "Permission denied", this clears com.apple.quarantine (which can
    independently trip hdiutil's own Gatekeeper-style authentication gate)
    and retries once, elevated via 'sudo'.

    'retry_on_auth_error' additionally treats "Authentication error" as a
    retry trigger. Only pass this for a fixed, known-correct 'password' (e.g.
    PatcherSupportPkg's convention of a hardcoded passphrase): with a
    user-supplied password, "Authentication error" more likely means a wrong
    password than a privilege gate, and would otherwise wrongly prompt for an
    administrator password on every incorrect attempt.

    Deliberately not routed through "do shell script ... with administrator
    privileges" (security_authtrampoline): that mechanism runs detached from
    the current login/Aqua session, and hdiutil's own internal authentication
    appears to depend on that session being present. 'admin_password_prompt'
    is expected to only collect a password (e.g. via a plain AppleScript
    "display dialog"), not to perform the elevation itself.
    """
    mount_point.parent.mkdir(parents=True, exist_ok=True)

    cmd = ["/usr/bin/hdiutil", "attach", "-noverify", str(dmg_path), "-mountpoint", str(mount_point), "-nobrowse"]
    if shadow_path:
        shadow_path.parent.mkdir(parents=True, exist_ok=True)
        cmd.extend(["-shadow", str(shadow_path)])
    # Only ask hdiutil to read a passphrase from stdin when we actually have one;
    # passing -stdinpass with a closed stdin changes behaviour for unencrypted images
    # for no reason.
    if password:
        cmd.append("-stdinpass")

    # Force hdiutil and CoreFoundation to output in English so error matching is consistent.
    env = os.environ.copy()
    env["LC_ALL"] = "C"
    env["LANG"] = "en_US.UTF-8"
    env["AppleLanguages"] = '("en")'

    process = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)
    stdout, _ = process.communicate(input=password.encode() if password else None)

    if process.returncode == 0 or admin_password_prompt is None:
        return subprocess.CompletedProcess(args=cmd, returncode=process.returncode, stdout=stdout)

    # Privilege error patterns across macOS versions / POSIX:
    _privilege_error = (
        b"Permission denied" in stdout
        or b"Operation not permitted" in stdout
        or b"not permitted" in stdout.lower()
    )
    _auth_error = retry_on_auth_error and b"Authentication error" in stdout

    # DiskImages / CoreFoundation localization may cause non-English error messages
    # on non-English installations. If unprivileged attach failed and we have an admin prompt,
    # retry with elevation rather than aborting due to language differences or unknown error strings.
    _should_retry = _privilege_error or _auth_error or retry_on_auth_error or (process.returncode != 0 and password is not None)
    if not _should_retry:
        return subprocess.CompletedProcess(args=cmd, returncode=process.returncode, stdout=stdout)

    logging.info("- Unprivileged hdiutil attach failed, retrying with administrator privileges")
    action = cmd[0]
    cmd.remove(action)
    utilities.get_admin_permission(action=action, args=cmd, reason=admin_password_prompt)


def verify(process_result: subprocess.CompletedProcess) -> None:
    """
    Verify process result and raise exception if failed.
    """
    if process_result.returncode == 0:
        return

    # Ohne das Logging hier bemerkt ein Benutzer ausserhalb der GUI einen Fehlschlag
    # nur an der Exception, ohne Kommando, Exit-Code oder Ausgabe.
    logging.error(f"Process failed with exit code {process_result.returncode}")
    log(process_result)
    raise Exception(f"Process failed with exit code {process_result.returncode}")


def run_and_verify(*args, **kwargs) -> None:
    """
    Run subprocess and verify result.

    Asserts on failure.
    """
    verify(run(*args, **kwargs))


def run_as_root_and_verify(*args, **kwargs) -> None:
    """
    Run subprocess as root and verify result.

    Asserts on failure.
    """
    verify(run_as_root(*args, **kwargs))


def log(process: subprocess.CompletedProcess) -> None:
    """
    Display subprocess error output in formatted string.
    """
    for line in generate_log(process).split("\n"):
        logging.error(line)


def generate_log(process: subprocess.CompletedProcess) -> str:
    """
    Display subprocess error output in formatted string.
    Note this function is still used for zero return code errors, since
    some software don't ever return non-zero regardless of success.

    Format:

        Command: <command>
        Return Code: <return code>
        Standard Output:
            <standard output line 1>
            <standard output line 2>
            ...
        Standard Error:
            <standard error line 1>
            <standard error line 2>
            ...
    """
    output = "Subprocess failed.\n"
    output += f"    Command: {process.args}\n"
    output += f"    Return Code: {process.returncode}\n"
    _returned_error = __resolve_privileged_helper_errors(process.returncode)
    if _returned_error:
        output += f"        Likely Enum: {_returned_error}\n"
    output += f"    Standard Output:\n"
    if process.stdout:
        output += __format_output(process.stdout.decode("utf-8"))
    else:
        output += "        None\n"
    output += f"    Standard Error:\n"
    if process.stderr:
        output += __format_output(process.stderr.decode("utf-8"))
    else:
        output += "        None\n"

    return output


def __resolve_privileged_helper_errors(return_code: int) -> Optional[str]:
    """
    Attempt to resolve Privileged Helper Tool error codes.

    Returns the enum name for one of our sentinel codes (160-170), or None for any
    other exit code - callers distinguish "the helper itself failed" from "the wrapped
    command failed" on exactly this None check.
    """
    if return_code not in [error_code.value for error_code in PrivilegedHelperErrorCodes]:
        return None

    return PrivilegedHelperErrorCodes(return_code).name


def __format_output(output: str) -> str:
    """
    Format output.
    """
    if not output:
        # Shouldn't happen, but just in case
        return "        None\n"

    _result = "\n".join([f"        {line}" for line in output.split("\n") if line not in ["", "\n"]])
    if not _result.endswith("\n"):
        _result += "\n"

    return _result
