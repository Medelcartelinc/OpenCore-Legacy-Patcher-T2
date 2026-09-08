"""
subprocess_wrapper.py: Wrapper for subprocess module to better handle errors and output
                       Additionally handles our Privileged Helper Tool
"""

import enum
import stat
import shlex
import logging
import subprocess
import Security
import os

from pathlib import Path
from typing import Callable, Optional


OCLP_PRIVILEGED_HELPER = "/Library/PrivilegedHelperTools/com.dortania.opencore-legacy-patcher.privileged-helper"
OCLP_PRIVILEGED_HELPER_EXPECTED_MODE = 0o4755


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
    if not _helper_path_is_safe_to_repair():
        return False

    return True


def repair_privileged_helper_permissions() -> bool:
    """
    Reset the Privileged Helper Tool back to 4755 using the Security framework,
    which is supported on macOS 10.0+, that easily fits with 10.10!

    Note: Deliberately does NOT go through run_as_root() (i.e. the helper
    tool itself), since a helper tool missing its setuid bit can't elevate
    itself - that's precisely the problem being repaired here.

    Callers may assume a single contract: this returns True on success and False
    on ANY failure (user cancelled, Authorization Services error, unexpected
    exception). It never raises and never terminates the process - it is called
    from the GUI, where killing the interpreter mid-run could leave a half-written
    EFI behind.

    AuthorizationExecuteWithPrivileges has been deprecated since macOS 10.7 and is
    unavailable from sandboxed contexts; SMJobBless/SMAppService is the sanctioned
    replacement. Kept for now because it works on the wide OS range this fork targets.
    """
    if not _helper_path_is_safe_to_repair():
        # Should already have been caught by privileged_helper_needs_setuid_repair(),
        # re-checked here so this stays safe if called directly.
        return False

    # Authorize the privileged operation using macOS Authorization Services.
    # This causes macOS to present its native authorization UI rather than
    # requiring OCLP to collect an administrator password.
    # MARK: IMPORTANT

    # If this doesn't work make sure that you have pyObjC 12.1, as that was version that has been tested.
    status, auth_ref = Security.AuthorizationCreate(
        None,
        None,
        Security.kAuthorizationFlagDefaults,
        None
    )

    if status != Security.errAuthorizationSuccess:
        logging.error(f"AuthorizationCreate failed with status {status}")
        return False

    try:
        # Request the right to execute a privileged tool.
        rights = (
            Security.AuthorizationItem(
                Security.kAuthorizationRightExecute,
                0,
                None,
                0
            ),
        )
        prompt = b"OpenCore Legacy Patcher T2 needs administrator permission to repair the permissions of its privileged helper tool."

        environment = (
            Security.AuthorizationItem(
                Security.kAuthorizationEnvironmentPrompt,
                len(prompt),
                prompt,
                0
            ),
        )

        status, authorized_rights = Security.AuthorizationCopyRights(
            auth_ref,
            rights,
            environment,
            (
                Security.kAuthorizationFlagInteractionAllowed
                | Security.kAuthorizationFlagExtendRights
            ),
            None,
        )

        if status == Security.errAuthorizationCanceled:
            logging.info("User canceled the request")
            return False

        if status != Security.errAuthorizationSuccess:
            logging.error(f"AuthorizationCopyRights failed with status {status}")
            return False

        # Re-validate immediately before the chmod to narrow the TOCTOU window between
        # the check above and the privileged operation itself. This does not close the
        # window (chmod still resolves the path itself), it only shrinks it.
        if not _helper_path_is_safe_to_repair():
            return False

        chmod_arguments = (
            oct(OCLP_PRIVILEGED_HELPER_EXPECTED_MODE)[2:].encode("utf-8"),
            OCLP_PRIVILEGED_HELPER.encode("utf-8"),
        )

        status, _ = Security.AuthorizationExecuteWithPrivileges(
            auth_ref,
            b"/bin/chmod",
            Security.kAuthorizationFlagDefaults,
            chmod_arguments,
            None,
        )

        if status == Security.errAuthorizationCanceled:
            logging.info("User canceled the request")
            return False

        if status != Security.errAuthorizationSuccess:
            logging.error(f"AuthorizationExecuteWithPrivileges failed with status {status}")
            return False

        logging.info("Privileged Helper Tool permissions repaired (4755)")
        return True

    # Ohne diesen Block wurde eine unerwartete Exception (z.B. ein PyObjC-Fehler bei
    # abweichender pyObjC-Version) ungefangen bis in den GUI-Aufrufer durchgereicht.
    # Jetzt: protokollieren und False zurueckgeben, damit der Aufrufer einen einzigen,
    # vorhersehbaren Fehlerfall behandeln muss.
    except Exception:
        logging.error("Running the Privileged Helper Tool operation failed.")
        logging.exception("Stack Trace:")
        return False

    finally:
        Security.AuthorizationFree(
           auth_ref,
           Security.kAuthorizationFlagDefaults
        )


def run(*args, **kwargs) -> subprocess.CompletedProcess:
    """
    Basic subprocess.run wrapper.
    """
    return subprocess.run(*args, **kwargs)


def run_as_root(*args, **kwargs) -> subprocess.CompletedProcess:
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

    if Path(OCLP_PRIVILEGED_HELPER).exists():
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
        if _helper_error is not None:
            logging.error(f"Privileged Helper Tool failed ({_helper_error}). Falling back to osascript.")
            return osascript(_command, **kwargs)
        return result
    else:
        logging.warning(f"Privileged Helper Tool not found at {OCLP_PRIVILEGED_HELPER}. Falling back to osascript.")
        return osascript(_command, **kwargs)


def osascript(cmd_args, **kwargs) -> subprocess.CompletedProcess:
    """
    Elevate via AppleScript's "do shell script ... with administrator privileges".

    Nur als Fallback gedacht: dieser Pfad fragt den Benutzer nach einem Admin-Passwort,
    statt den Helper zu benutzen. Ein Angreifer, der den Helper unbrauchbar macht
    (loeschen, Rechte zerstoeren), kann OCLP damit in diesen Pfad zwingen und dem
    Benutzer einen erwarteten Passwort-Prompt praesentieren - das ist eine
    Phishing-Oberflaeche, keine Codeausfuehrung. Deshalb wird oben beim
    fehlgeschlagenen Repair bewusst NICHT hierher zurueckgefallen.

    Der Parametername ist 'cmd_args' und nicht 'args': die urspruengliche Fassung
    referenzierte ein nicht existierendes 'args' und loeste NameError aus.
    """
    cmd_string = shlex.join(str(arg) for arg in cmd_args)
    # Escape for the AppleScript string literal: backslashes first, then quotes.
    # Newlines cannot appear inside an AppleScript string literal at all, so they are
    # rejected outright rather than producing a syntactically broken script.
    if "\n" in cmd_string or "\r" in cmd_string:
        raise ValueError("Refusing to build AppleScript from a command containing newlines")
    as_safe_string = cmd_string.replace('\\', '\\\\').replace('"', '\\"')
    apple_script = f'do shell script "{as_safe_string}" with administrator privileges'
    return subprocess.run(["/usr/bin/osascript", "-e", apple_script], **kwargs)


def applescript_icon_clause(icon_path) -> str:
    """
    Build the 'with icon POSIX file "..."' fragment for a 'display dialog' call.

    Two things this deliberately does NOT do, both of which used to break dialogs:

      1. It does not hand AppleScript an HFS path. The previous form,
         str(icon_path).replace("/", ":")[1:], produced "Users:me:...icns" - an HFS
         path whose first component is read as the VOLUME name, so it resolved
         against a non-existent volume "Users". 'with icon POSIX file "/Users/..."'
         takes the POSIX path as-is.
      2. It does not reference a file that isn't there. A missing icon makes
         'display dialog' raise, and every caller here wraps that in a try/except -
         so a cosmetic problem silently swallows the whole dialog. Where that dialog
         is how we collect an administrator password, the result is a mount that
         fails with no prompt ever shown. Returning an empty clause loses the icon
         and keeps the dialog.

    Returns:
        str: the clause including its leading space, or "" if no usable icon exists.
    """
    try:
        path = Path(icon_path)
        if not path.is_file():
            logging.warning(f"Dialog icon missing, continuing without it: {path}")
            return ""
    except Exception:
        return ""

    # A quote or backslash would break out of the AppleScript string literal.
    # Nothing in our own bundle contains either; drop the icon rather than
    # building a script we cannot escape correctly.
    if '"' in str(path) or "\\" in str(path):
        logging.warning("Dialog icon path contains characters that cannot be quoted, continuing without it")
        return ""

    return f' with icon POSIX file "{path}"'


def request_admin_password(icon_path=None, message: str = "OpenCore Legacy Patcher requires administrator access to mount patch resources.") -> str:
    """
    Prompt for the local administrator password via a plain dialog.

    Deliberately NOT routed through "do shell script ... with administrator
    privileges": that mechanism runs the elevated command via
    /usr/libexec/security_authtrampoline, a process detached from the current
    login/Aqua session. hdiutil's own internal authentication (DIHelperAgentMaster)
    appears to depend on that session being present, so a hdiutil invocation
    elevated via the trampoline can fail with "hdiutil: attach failed -
    Authentication error" even though the same command run under sudo from a
    session-bound process succeeds. A plain "display dialog" only needs a
    WindowServer session to render, so we use it purely to collect the password
    and feed it to sudo ourselves.

    A failure to even show the dialog is logged rather than swallowed: silently
    returning "" here reads downstream as "user cancelled" and aborts elevation,
    which previously turned any dialog problem into an unexplained mount failure.

    Returns:
        str: the password, or "" if cancelled or the dialog could not be shown.
    """
    import applescript

    script = (
        f'set theResult to display dialog "{message}" default answer "" with hidden answer '
        f'with title "OpenCore Legacy Patcher"{applescript_icon_clause(icon_path)}\n'
        'return the text returned of theResult'
    )

    try:
        return applescript.AppleScript(script).run() or ""
    except Exception as error:
        # -128 is AppleScript's "User canceled" - expected, not a fault.
        if "-128" in str(error):
            logging.info("Administrator password prompt cancelled by user")
        else:
            logging.error(f"Failed to display administrator password prompt: {error}")
        return ""


def _sudo_will_prompt() -> bool:
    """
    Whether 'sudo -k' would actually ask for a password on this machine.

    Matters because mount_dmg() feeds sudo and hdiutil from the same stdin: the
    first line is consumed by sudo's prompt, the rest is handed to hdiutil's
    -stdinpass. If sudo does not prompt (a NOPASSWD sudoers rule - which '-k' does
    NOT override, it only clears the credential timestamp), that first line falls
    through to hdiutil and is tried as the image passphrase, producing an
    authentication failure that looks nothing like its actual cause.

    Returns:
        bool: True if a password line should be sent, False if sudo runs unprompted.
    """
    try:
        result = subprocess.run(
            ["/usr/bin/sudo", "-k", "-n", "-v"],
            stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=15
        )
    except Exception:
        # Assume a prompt: sending a password line sudo did not want is recoverable
        # via the caller's retry, withholding one it did want hangs on EOF.
        return True
    return result.returncode != 0


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

    # Force hdiutil to output in English so we can reliably match "Permission denied".
    # NOTE: brittle by nature - hdiutil's wording is not a stable interface. If a future
    # macOS reworks these messages, the elevation retry silently stops triggering.
    env = os.environ.copy()
    env["LC_ALL"] = "C"

    process = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)
    stdout, _ = process.communicate(input=password.encode() if password else None)

    if process.returncode == 0 or admin_password_prompt is None:
        return subprocess.CompletedProcess(args=cmd, returncode=process.returncode, stdout=stdout)

    # EACCES is not the only shape this takes: the same gate has also surfaced as
    # EPERM ("Operation not permitted"). Match both.
    _privilege_error = b"Permission denied" in stdout or b"Operation not permitted" in stdout
    _auth_error = retry_on_auth_error and b"Authentication error" in stdout

    # These strings are not a stable interface, and LC_ALL only reaches hdiutil's
    # POSIX-level messages - the DiskImages framework localises via AppleLanguages,
    # so a non-English system can produce a failure none of the matches above catch.
    # When the caller passed a fixed, known-correct passphrase (retry_on_auth_error),
    # a wrong password is not a plausible explanation for the failure, so fall back
    # to retrying elevated on ANY error rather than giving up on a string mismatch.
    # The cost of being wrong is one superfluous password prompt; the cost of not
    # retrying is root patching that cannot start at all.
    _should_retry = _privilege_error or _auth_error or retry_on_auth_error
    if not _should_retry:
        return subprocess.CompletedProcess(args=cmd, returncode=process.returncode, stdout=stdout)

    logging.info("- Unprivileged hdiutil attach failed, retrying with administrator privileges")

    _needs_admin_password = _sudo_will_prompt()
    admin_password = ""
    if _needs_admin_password:
        admin_password = admin_password_prompt()
        if not admin_password:
            logging.info("- Elevated hdiutil attach cancelled (no administrator password provided)")
            return subprocess.CompletedProcess(args=cmd, returncode=process.returncode, stdout=stdout)

    # Clear com.apple.quarantine before attaching: a quarantined disk image (e.g. a
    # freshly rebuilt/re-extracted payload) can trip hdiutil's authentication gate
    # even when run as root - elevating privileges alone does not clear it. Run it
    # in the same elevated shell as the actual attach so it always has the rights to.
    elevated_shell = (
        # sudo resets the environment (env_reset), so LC_ALL set for the unprivileged
        # attempt does not survive into this one. Re-export it here.
        "export LC_ALL=C; "
        f"xattr -d com.apple.quarantine {shlex.quote(str(dmg_path))} 2>/dev/null; "
        + " ".join(shlex.quote(str(arg)) for arg in cmd)
    )
    # '-k' clears any cached sudo credential timestamp, so a previous sudo in this
    # session cannot silently change how much of stdin sudo consumes. It does NOT
    # force a prompt where sudoers says NOPASSWD - that case is handled by asking
    # sudo up front (_sudo_will_prompt) and sending no password line at all.
    elevated_cmd = ["/usr/bin/sudo", "-S", "-k", "/bin/sh", "-c", elevated_shell]

    elevated_process = subprocess.Popen(elevated_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env)
    # sudo -S reads exactly one line from stdin for its own password, then hands the
    # remaining, still-open stdin through to the shell (and on to hdiutil's -stdinpass)
    stdin_payload = (admin_password + "\n" if _needs_admin_password else "") + (password or "")
    elevated_stdout, _ = elevated_process.communicate(input=stdin_payload.encode())

    if elevated_process.returncode == 0:
        logging.info("- Mounted (elevated)")
        return subprocess.CompletedProcess(args=cmd, returncode=0, stdout=elevated_stdout)

    # Der Fehlertext wird protokolliert, damit ein Fehlschlag im CLI-Betrieb ueberhaupt
    # sichtbar ist. Bewusst als einzelne Zeile und ohne Sonderbehandlung: die Ausgabe
    # landet in Logs, die Nutzer routinemaessig an Issues anhaengen, enthaelt Pfade und
    # kann je nach hdiutil-Fehlerfall Reste der stdin-Eingabe spiegeln.
    logging.error(f"- Elevated hdiutil attach failed: {elevated_stdout.decode(errors='replace').strip()}")
    return subprocess.CompletedProcess(args=cmd, returncode=elevated_process.returncode, stdout=elevated_stdout)


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
