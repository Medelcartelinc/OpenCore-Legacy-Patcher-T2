"""
gui_update.py: Generate UI for updating the patcher
"""

import wx
import sys
import logging
import threading
import subprocess

from pathlib import Path

from .. import constants

from ..wx_gui import (
    gui_download,
    gui_support
)
from ..support import (
    network_handler,
    updates,
    subprocess_wrapper
)


class UpdateFrame(wx.Frame):
    """
    Create a frame for updating the patcher
    """
    def __init__(self, parent: wx.Frame, title: str, global_constants: constants.Constants, screen_location: wx.Point, url: str = "", version_label: str = "") -> None:
        # CORRECTED: Always call the super-class constructor first to register the window correctly
        super().__init__(parent, title=title, size=(350, 300), style=wx.DEFAULT_FRAME_STYLE & ~(wx.RESIZE_BORDER | wx.MAXIMIZE_BOX))
        
        logging.info("Initializing Update Frame")
        
        # Handle the parent/child UI logic after the super-class is initialized
        if parent:
            self.parent: wx.Frame = parent

            for child in self.parent.GetChildren():
                child.Hide()
            parent.Hide()
        else:
            gui_support.GenerateMenubar(self, global_constants).generate()

        self.title: str = title
        self.constants: constants.Constants = global_constants
        self.screen_location: wx.Point = screen_location
        if parent:
            self.parent.Centre()
            self.screen_location = parent.GetScreenPosition()
        else:
            self.Centre()
            self.screen_location = self.GetScreenPosition()

        if url == "" or version_label == "":
            dict = updates.CheckBinaryUpdates(self.constants).check_binary_updates()
            if dict:
                version_label = dict["Version"]
                url = dict["Link"]
            else:
                logging.error("Failed to receive update info")
                logging.exception("Stack Trace:")
                wx.MessageBox("Failed to get update info", "Critical Error")
                sys.exit(3)
        self.version_label = version_label
        self.url = url

        # Our own releases ship a raw "OpenCore-Patcher-T2.pkg" asset (see updates.py),
        # while the upstream Dortania nightly.link fallback (gui_macos_configeration.py)
        # still ships the original "OpenCore-Patcher.pkg" zipped up - keep expecting
        # whichever one this URL actually points to instead of hardcoding one name.
        self.pkg_download_path = self.constants.payload_path / ("OpenCore-Patcher.pkg" if self.url.endswith(".zip") else "OpenCore-Patcher-T2.pkg")

        logging.info(f"Update URL: {url}")
        logging.info(f"Update Version: {version_label}")

        self.frame: wx.Frame = wx.Frame(
            parent=parent if parent else self,
            title=self.title,
            size=(350, 130),
            pos=self.screen_location,
            style=wx.DEFAULT_FRAME_STYLE ^ wx.RESIZE_BORDER ^ wx.MAXIMIZE_BOX
        )

        # The shared download dialog owns download progress and cancellation.
        try:
            self.title_label = wx.StaticText(self.frame, label="Preparing download...", pos=(-1, 1))
            self.title_label.SetFont(gui_support.font_factory(19, wx.FONTWEIGHT_BOLD))
            self.title_label.Centre(wx.HORIZONTAL)
        except Exception as e:
            logging.error("Failed to download the update")
            logging.exception("Stack Trace:")
            wx.MessageBox("Failed to download the update", "Critical Error")
            sys.exit(3)

        self.progress_bar = wx.Gauge(self.frame, range=100, pos=(10, 50), size=(300, 20))
        self.progress_bar.Centre(wx.HORIZONTAL)
        self.progress_bar_animation = gui_support.GaugePulseCallback(self.constants, self.progress_bar)

        # Instantiating timer variables for the exit countdown
        self.timer_countdown = 5
        self.exit_timer = wx.Timer(self)
        self.Bind(wx.EVT_TIMER, self._on_exit_timer_tick, self.exit_timer)

        file_name = "OpenCore-Patcher.pkg.zip" if self.url.endswith(".zip") else "OpenCore-Patcher-T2.pkg"
        download_obj = network_handler.DownloadObject(self.url, self.constants.payload_path / file_name)
        gui_download.DownloadFrame(
            self.frame,
            title=self.title,
            global_constants=self.constants,
            download_obj=download_obj,
            item_name=self.version_label,
            download_icon=str(self.constants.app_icon_path)
        )

        if download_obj.download_complete is not True:
            logging.error("It failed to download the update")
            sys.exit(3)

        self.frame.Centre()
        self.frame.Show()
        self.progress_bar_animation.start_pulse()

        # Start the remaining update workflow on a background thread.
        threading.Thread(target=self._workflow_thread, daemon=True).start()

    def _workflow_thread(self) -> None:
        """
        Background orchestrator thread. Keeps tasks entirely off the main loop,
        preventing GUI lockups and avoiding hazardous wx.Yield use.
        """
        # --- Phase 1: Extraction ---
        try:
            logging.info("Extract update")
            wx.CallAfter(self._update_status_label, "Extracting update...")
            thread = threading.Thread(target=self._extract_update)
            thread.start()
            gui_support.wait_for_thread(thread)
        except Exception as e:
            logging.error("It failed to extract the update, so it can't be installed.")
            logging.exception("Stack Trace:")
            fallback_text = "Failed to extract the update. If you continue to have this issue, please manually download the update."
            wx.CallAfter(self._handle_fatal_failure, fallback_text, "Critical Error!")
            return

        # --- Phase 2: Installation ---
        try:
            logging.info("Updating")
            wx.CallAfter(self._update_status_label, "Installing update...")
            thread = threading.Thread(target=self._install_update)
            thread.start()
            gui_support.wait_for_thread(thread)
            # --- Phase 4: Verification & Wrap-up ---
            wx.CallAfter(self._finalize_ui_and_start_countdown)
        except Exception as e:
            logging.error("It failed to extract the update, so it can't be installed.")
            logging.exception("Stack Trace:")
            fallback_text = "Failed to install the update. If you continue to have this issue, please manually download the update."
            wx.CallAfter(self._handle_fatal_failure, fallback_text, "Critical Error!")
            return

    # =========================================================================
    # ATOMIC MAIN-THREAD UI MUTATORS (Prevents race conditions / split events)
    # =========================================================================

    def _update_status_label(self, message: str) -> None:
        """Safely alters text components atomically on the main thread."""
        self.title_label.SetLabel(message)
        self.title_label.Centre(wx.HORIZONTAL)

    def _handle_fatal_failure(self, error_msg: str, title: str, is_cancelled: bool = False) -> None:
        """
        Executes atomically on the main thread to completely clean up UI elements 
        and handle script termination instantly, preventing thread race conditions.
        """
        if is_cancelled:
            wx.MessageBox(error_msg, title, wx.OK | wx.ICON_INFORMATION)
        else:
            wx.MessageBox(error_msg, title, wx.OK | wx.ICON_ERROR)

        self.progress_bar_animation.stop_pulse()
        self.progress_bar.Hide()
            
        logging.info("Die App wird geschlossen")
        logging.info("Closing the app")
        sys.exit(3)

    def _finalize_ui_and_start_countdown(self) -> None:
        """Reconstructs the interface layout and initializes the exit timer safely."""
        self.title_label.SetLabel("Update complete!")
        self.title_label.Centre(wx.HORIZONTAL)

        self.progress_bar_animation.stop_pulse()
        self.progress_bar.Hide()

        installed_label = wx.StaticText(self.frame, label=f"{self.version_label} has been installed:", pos=(-1, 35))
        installed_label.SetFont(gui_support.font_factory(13, wx.FONTWEIGHT_BOLD))
        installed_label.Centre(wx.HORIZONTAL)

        installed_path_label = wx.StaticText(self.frame, label='/Library/Application Support/Dortania', pos=(-1, installed_label.GetPosition().y + 20))
        installed_path_label.SetFont(gui_support.font_factory(13, wx.FONTWEIGHT_NORMAL))
        installed_path_label.Centre(wx.HORIZONTAL)

        self.launch_label = wx.StaticText(self.frame, label="Launching update shortly...", pos=(-1, installed_path_label.GetPosition().y + 30))
        self.launch_label.SetFont(gui_support.font_factory(13, wx.FONTWEIGHT_NORMAL))
        self.launch_label.Centre(wx.HORIZONTAL)

        self.frame.SetSize((-1, self.launch_label.GetPosition().y + 60))

        # Fire and forget launch execution thread
        thread = threading.Thread(target=self._launch_update)
        thread.start()
        
        # Fire non-blocking main loop timer event every 1 second (1000ms)
        self.exit_timer.Start(1000)

    def _on_exit_timer_tick(self, event: wx.TimerEvent) -> None:
        """Non-blocking timer callback driven directly by native OS event loop."""
        if self.timer_countdown > 0:
            self.launch_label.SetLabel(f"Closing old process in {self.timer_countdown} seconds")
            self.launch_label.Centre(wx.HORIZONTAL)
            self.timer_countdown -= 1
        else:
            self.exit_timer.Stop()
            sys.exit(0)

    # =========================================================================
    # SYSTEM ACTIONS (Executed inside sub-threads safely)
    # =========================================================================

    def _extract_update(self) -> None:
        logging.debug("Extraction thread started...")
        if not self.url.endswith(".zip"):
            return
        logging.info("Extracting update")
        if Path(self.pkg_download_path).exists():
            subprocess.run(["/bin/rm", "-rf", str(self.pkg_download_path)])

        result = subprocess.run(
            ["/usr/bin/ditto", "-xk", str(self.constants.payload_path / "OpenCore-Patcher.pkg.zip"), str(self.constants.payload_path)], capture_output=True
        )
        if result.returncode != 0:
            logging.error(f"Failed to extract update.")
            logging.exception("Stack Trace:")
            subprocess_wrapper.log(result)
            
            error_str = f"Failed to extract update. Error: {result.stderr.decode('utf-8')}"
            wx.CallAfter(self._handle_fatal_failure, error_str, "Critical Error!")
            # Ensure background thread execution chain halts gracefully
            wx.MessageBox("Since the update failed to extract, we'll close the app for you.", "Critical Error")
            logging.info("Closing the app")
            sys.exit(3)

    def _install_update(self) -> None:
        logging.info(f"Update wird installiert: {self.pkg_download_path}")
        logging.info(f"Installing update: {self.pkg_download_path}")
        result = subprocess_wrapper.run_as_root(["/usr/sbin/installer", "-pkg", str(self.pkg_download_path), "-target", "/"], capture_output=True)
        
        if result.returncode != 0:
            stderr_output = result.stderr.decode("utf-8")
            
            if "User cancelled" in stderr_output:
                logging.info("User cancelled update")
                wx.CallAfter(self._handle_fatal_failure, "User cancelled update", "Update Cancelled", is_cancelled=True)
            else:
                logging.critical("Den App hat fehlgeschalgen, per das Builtin-Update-Instrument zu aktualisieren.")
                logging.critical("The app failed to update via the builtin updater.")
                subprocess_wrapper.log(result)
                logging.error("Auf In-Place-Upgrade wechseln...")
                logging.error("Switching to in-place upgrade instead...")
                subprocess.run(["/usr/bin/open", str(self.pkg_download_path)])
                
                support_url = getattr(self.constants, 'support_url', 'the official repository')
                fallback_msg = f"Failed to install update automatically. Please visit {support_url} to manually download the package and perform an in-place upgrade."
                wx.CallAfter(self._handle_fatal_failure, fallback_msg, "Critical Error!")
            
            sys.exit(1)

    def _launch_update(self) -> None:
        # Same reasoning as pkg_download_path above: an upstream Dortania nightly
        # install still lands as "OpenCore-Patcher.app", only our own T2 releases
        # install as "OpenCore-Patcher-T2.app" (see package.py's _files mapping).
        _app_name = "OpenCore-Patcher.app" if self.url.endswith(".zip") else "OpenCore-Patcher-T2.app"
        try:
            logging.info(f"Aktualisierung beginnen: '/Library/Application Support/Dortania/{_app_name}'")
            logging.info(f"Launching update: '/Library/Application Support/Dortania/{_app_name}'")
            subprocess.Popen([f"/Library/Application Support/Dortania/{_app_name}/Contents/MacOS/OpenCore-Patcher", "--update_installed"])
        except Exception as e:
            logging.error("Das Starten des Aktualisierung durch den Builtin-Update-Instrument hat fehlgeschlagen.")
            logging.error("Launching the update via the builtin updater failed.")
            logging.exception("Stack Trace:")
