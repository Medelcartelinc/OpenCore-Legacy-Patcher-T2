#!/usr/bin/env python3
"""
Build-Project.command: Generate OpenCore-Patcher-T2.app and OpenCore-Patcher-T2.pkg
Optimiert für Sicherheit und Stabilität.
"""

import os
import re
import sys
import time
import argparse
import traceback
import subprocess
import threading
import rich
from rich.live import Live
from rich.spinner import Spinner
from pathlib import Path

# Fix: Force the execution directory immediately before importing local modules. 
# This guarantees that 'ci_tooling' looks for assets in the right relative path.
SCRIPT_DIR = Path(__file__).resolve().parent
os.chdir(SCRIPT_DIR)

# Import der internen Module
from ci_tooling.build_modules import (
    application,
    disk_images,
    package,
    sign_notarize
)

def check_file_exists(path: Path) -> None:
    if not path.exists():
        rich.print(f"[red]Error: Expected file/directory not found: {path}[/red]")
        sys.exit(3)

def available_codesigning_identities() -> list:
    """
    Return (SHA-1 hash, name, status) for every valid code signing identity in the keychain

    'security find-identity -v' already filters out expired or otherwise unusable
    certificates. A self signed "Code Signing" certificate made in Keychain Access shows
    up here exactly like a Developer ID one.
    """
    if sys.platform != "darwin":
        return []

    try:
        result = subprocess.run(
            ["/usr/bin/security", "find-identity", "-v", "-p", "codesigning"],
            capture_output=True, text=True, timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as e:
        rich.print(f"[yellow]Warning: could not query signing identities: {e}[/yellow]")
        return []

    identities = []
    for line in result.stdout.splitlines():
        # "security find-identity" hängt bei nicht vertrauenswuerdigen Zertifikaten
        # eine Statusmeldung an, z.B. (CSSMERR_TP_NOT_TRUSTED). Ein selbst signiertes
        # Zertifikat ist damit trotzdem brauchbar: das Helper Tool vergleicht nur die
        # Zertifikatsketten und fuehrt keine Trust-Pruefung durch.
        #
        # "security find-identity" appends a status note for certificates that are not
        # trusted, e.g. (CSSMERR_TP_NOT_TRUSTED). A self signed certificate still works:
        # the helper tool only compares certificate chains and runs no trust evaluation.
        match = re.match(r'\s*\d+\)\s+([0-9A-Fa-f]{40})\s+"(.+?)"\s*(\(CSSMERR_[A-Z_]+\))?\s*$', line)
        if match:
            identities.append((match.group(1), match.group(2), match.group(3)))
    return identities


def resolve_application_identity(requested: str, auto_detect: bool) -> "str | None":
    """
    Decide which identity the app and the privileged helper tool get signed with

    Both must end up carrying the same certificate: at runtime the helper compares its own
    certificate chain against its parent process' chain (ci_tooling/privileged_helper_tool/main.m)
    and refuses to run anything as root when they differ. It runs no trust evaluation, so a
    self signed certificate satisfies it just as well as a Developer ID one - but an unsigned
    or ad-hoc signed build carries no certificates at all and can never pass.
    """
    requested = requested or os.environ.get("MACOS_SIGNING_IDENTITY")
    identities = available_codesigning_identities()

    if requested:
        # Only reject when the lookup actually returned something; an empty list means the
        # query failed or we are not on macOS, which is not evidence the identity is missing.
        if identities and not any(requested in (identity_hash, name) for identity_hash, name, _ in identities):
            rich.print(f"[red]Error: no valid signing identity found matching: {requested}[/red]")
            available = ", ".join(f'"{name}"' for _, name, _ in identities) or "none"
            rich.print(f"[yellow]Available: {available}[/yellow]")
            sys.exit(3)
        return requested

    if auto_detect is False:
        return None

    if not identities:
        rich.print(f"[yellow]Note: no code signing certificate found, the app and helper tool stay unsigned.[/yellow]")
        rich.print(f"[yellow]      The privileged helper tool will refuse to run commands as root unless it was[/yellow]")
        rich.print(f"[yellow]      compiled with 'make debug' (ci_tooling/privileged_helper_tool/README.md).[/yellow]")
        rich.print(f"[yellow]      To sign locally, create a self signed certificate in Keychain Access:[/yellow]")
        rich.print(f"[yellow]      Certificate Assistant > Create a Certificate > Self Signed Root, type Code Signing.[/yellow]")
        return None

    if len(identities) > 1:
        rich.print(f"[yellow]Note: multiple code signing certificates found, none picked automatically:[/yellow]")
        for _, name, _ in identities:
            rich.print(f"[yellow]      - {name}[/yellow]")
        rich.print(f"[yellow]      Pass --application-signing-identity \"<name>\" to choose one.[/yellow]")
        return None

    _, name, status = identities[0]
    rich.print(f"[yellow]Automatically selected signing identity: {name}[/yellow]")
    if status:
        rich.print(f"[yellow]      Note: certificate is not trusted {status} - that is enough for signing,[/yellow]")
        rich.print(f"[yellow]      the helper tool only compares certificate chains.[/yellow]")
    return name


def main() -> None:
    global status, done
    parser = argparse.ArgumentParser(description="Build OpenCore Legacy Patcher Suite")

    # Signing & Notarization
    parser.add_argument("--application-signing-identity", type=str, help="Application Signing Identity")
    parser.add_argument("--installer-signing-identity", type=str, help="Installer Signing Identity")
    parser.add_argument("--notarization-apple-id", type=str, help="Notarization Apple ID")
    parser.add_argument("--notarization-password", type=str, help="Notarization Password (Alternative: Env Var)")
    parser.add_argument("--notarization-team-id", type=str, help="Notarization Team ID")

    # CI/CD & Local Build Parameters
    parser.add_argument("--git-branch", type=str, default=None)
    parser.add_argument("--git-commit-url", type=str, default=None)
    parser.add_argument("--git-commit-date", type=str, default=None)
    parser.add_argument("--reset-dmg-cache", action="store_true")
    parser.add_argument("--reset-pyinstaller-cache", action="store_true")
    parser.add_argument("--no-auto-detect-identity", action="store_true", help="Never pick a signing identity from the keychain automatically")
    
    # Steps
    parser.add_argument("--run-as-individual-steps", action="store_true")
    parser.add_argument("--prepare-application", action="store_true")
    parser.add_argument("--prepare-package", action="store_true")
    parser.add_argument("--prepare-assets", action="store_true")

    args = parser.parse_args()

    # Passwort-Sicherheit: Umgebungsvariable hat Vorrang vor CLI-Argument
    notarization_password = os.environ.get("NOTARIZATION_PASSWORD") or args.notarization_password

    # Resolved once, so the app and the helper tool can never end up signed with two different
    # certificates - which would make the helper reject the app at runtime.
    application_signing_identity = resolve_application_identity(
        args.application_signing_identity,
        auto_detect=args.no_auto_detect_identity is False,
    )

    try:
        # 1. Assets
        if (args.run_as_individual_steps is False) or (args.run_as_individual_steps and args.prepare_assets):
            status = "[1/8] Generating disk images"
            disk_images.GenerateDiskImages(args.reset_dmg_cache).generate()

        # 2. Application
        if (args.run_as_individual_steps is False) or (args.run_as_individual_steps and args.prepare_application):
            status = "[2/8] Signing Helper Tool"
            sign_notarize.SignAndNotarize(
                path=Path("./ci_tooling/privileged_helper_tool/com.dortania.opencore-legacy-patcher.privileged-helper"),
                signing_identity=application_signing_identity,
                notarization_apple_id=args.notarization_apple_id,
                notarization_password=notarization_password,
                notarization_team_id=args.notarization_team_id,
            ).sign_and_notarize()

            status = "[3/8] Building the app"
            application.GenerateApplication(
                reset_pyinstaller_cache=args.reset_pyinstaller_cache,
                git_branch=args.git_branch,
                git_commit_url=args.git_commit_url,
                git_commit_date=args.git_commit_date,
            ).generate()

            check_file_exists(Path("dist/OpenCore-Patcher-T2.app"))
            status = "[4/8] Signing the app"
            sign_notarize.SignAndNotarize(
                path=Path("dist/OpenCore-Patcher-T2.app"),
                signing_identity=application_signing_identity,
                notarization_apple_id=args.notarization_apple_id,
                notarization_password=notarization_password,
                notarization_team_id=args.notarization_team_id,
                entitlements=Path("./ci_tooling/entitlements/entitlements.plist"),
            ).sign_and_notarize()

        # 3. Packages
        if (args.run_as_individual_steps is False) or (args.run_as_individual_steps and args.prepare_package):
            status = "[5/8] Building packages"
            package.GeneratePackage().generate()
            
            # AutoPkg-Assets-T2.pkg is installed by the app itself during auto patching,
            # so it needs a signature just as much as the two user facing packages.
            step = 6
            for pkg in ["OpenCore-Patcher-T2.pkg", "OpenCore-Patcher-Uninstaller.pkg", "AutoPkg-Assets-T2.pkg"]:
                pkg_path = Path(f"dist/{pkg}")
                check_file_exists(pkg_path)
                status = f"[{step}/8] Signing {pkg}"
                sign_notarize.SignAndNotarize(
                    path=pkg_path,
                    signing_identity=args.installer_signing_identity,
                    notarization_apple_id=args.notarization_apple_id,
                    notarization_password=notarization_password,
                    notarization_team_id=args.notarization_team_id,
                ).sign_and_notarize()
                step += 1
            done = True
    except Exception as e:
        rich.print(f"\n[yellow] Building the app stopped because of some error: {e}[/yellow]")
        # Print the traceback too. Without it the message alone gives no file or line,
        # which turns any error raised deep in a build module into a repo-wide hunt.
        traceback.print_exc()
        done = True
        sys.exit(3)

if __name__ == '__main__':
    _start = time.time()
    global status
    global done
    status = "[0/8] Starting"
    done = False
    thread = threading.Thread(target=main)
    thread.start()
    spinner = Spinner(
        "dots",
        text=status
    )

    with Live(spinner, refresh_per_second=10):
        while not done:
            spinner.update(text=status)
            time.sleep(0.1)
    thread.join()
    done = True
    rich.print(f"\n[green]Build script completed in {str(round(time.time() - _start, 2))} seconds.[/green]")
