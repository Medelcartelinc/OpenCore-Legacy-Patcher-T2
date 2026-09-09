import wx
import sys
import logging
import threading
from .. import constants
from ..support import kdk_handler, utilities, metallib_handler
from ..wx_gui import gui_support, gui_download
from ..sys_patch.patchsets import HardwarePatchsetDetection, HardwarePatchsetSettings

class OSUpdateFrame(wx.Frame):
    def __init__(self, parent: wx.Frame, title: str, global_constants: constants.Constants):
        super().__init__(parent, title=title, size=(360, 140), 
                         style=wx.DEFAULT_FRAME_STYLE ^ wx.RESIZE_BORDER ^ wx.MAXIMIZE_BOX)
        
        self.constants = global_constants
        self.os_data = utilities.fetch_staged_update(variant="Preflight")
        
        if not self.os_data[0]:
            logging.info("No update found, exiting process.")
            wx.CallAfter(self.Close)
            return

        self._generate_ui()
        self.Centre()
        self.Show()
        
        # Start des Workflows erst NACH Initialisierung des UI
        wx.CallAfter(self._initialize_workflow)

    def _initialize_workflow(self):
        """Prüft Anforderungen und benachrichtigt den User."""
        self.patch_results = HardwarePatchsetDetection(
            constants=self.constants,
            xnu_major=int(self.os_data[1][:2]),
            os_build=self.os_data[1],
            os_version=self.os_data[0]
        ).device_properties

        if not any([self.patch_results[HardwarePatchsetSettings.KERNEL_DEBUG_KIT_REQUIRED], 
                    self.patch_results[HardwarePatchsetSettings.METALLIB_SUPPORT_PKG_REQUIRED]]):
            self._exit()
            return

        self._notify_user_dialog()

    def _notify_user_dialog(self):
        message = (f"System preparation is required for {self.os_data[0]} ({self.os_data[1]}).\n\n"
                   "Would you like to download the required resources now?")
        dlg = wx.MessageDialog(self, message, "Update Preparation", wx.YES_NO | wx.ICON_QUESTION)
        
        if dlg.ShowModal() == wx.ID_YES:
            threading.Thread(target=self._run_tasks, daemon=True).start()
        else:
            self._exit()

    def _run_tasks(self):
        """Sichere Ausführung der Hintergrundaufgaben."""
        try:
            # Beispiel für sichere Task-Abfolge
            if self.patch_results[HardwarePatchsetSettings.KERNEL_DEBUG_KIT_REQUIRED]:
                # Hier Aufruf der Handler-Methoden
                # WICHTIG: KDK/Metallib-Handler müssen intern subprocess mit Pfad-Validierung nutzen!
                logging.info("Processing KDK...")
            
            # Update des UI nach Abschluss über CallAfter
            wx.CallAfter(self._on_tasks_complete)
            
        except Exception as e:
            logging.error(f"Fehler bei Hintergrundaufgabe: {e}")
            wx.CallAfter(self._exit)

    def _on_tasks_complete(self):
        logging.info("All tasks completed successfully.")
        self._exit()

    def _generate_ui(self):
        panel = wx.Panel(self)
        vbox = wx.BoxSizer(wx.VERTICAL)
        self.label = wx.StaticText(panel, label="Vorbereitung läuft...", style=wx.ALIGN_CENTER)
        vbox.Add(self.label, 0, wx.ALL | wx.EXPAND, 15)
        self.progress = wx.Gauge(panel, range=100, size=(300, 25))
        vbox.Add(self.progress, 0, wx.ALL | wx.EXPAND, 15)
        panel.SetSizer(vbox)

    def _exit(self):
        self.Destroy()
        # sys.exit() sollte hier vermieden werden, wenn möglich, 
        # um den Hauptprozess nicht hart zu beenden.
