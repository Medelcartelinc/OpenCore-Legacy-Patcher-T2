import re

with open('opencore_legacy_patcher/wx_gui/gui_sys_patch_display.py', 'r') as f:
    content = f.read()

new_func = """
    def _generate_elements_display_patches(self, frame: wx.Frame = None) -> None:
        frame = self if not frame else frame

        title_label = wx.StaticText(frame, label="ROOT PATCHES", pos=(-1, 10))
        title_label.SetFont(gui_support.font_factory(19, wx.FONTWEIGHT_BOLD))
        title_label.Centre(wx.HORIZONTAL)

        # Label: Fetching patches...
        available_label = wx.StaticText(frame, label="Fetching patches for host...", pos=(-1, title_label.GetPosition()[1] + title_label.GetSize()[1] + 10))
        available_label.SetFont(gui_support.font_factory(13, wx.FONTWEIGHT_BOLD))
        available_label.Centre(wx.HORIZONTAL)

        # Progress bar
        progress_bar = wx.Gauge(frame, range=100, pos=(-1, available_label.GetPosition()[1] + available_label.GetSize()[1] + 10), size=(250, 20))
        progress_bar.Centre(wx.HORIZONTAL)
        progress_bar_animation = gui_support.GaugePulseCallback(self.constants, progress_bar)
        progress_bar_animation.start_pulse()

        # Set window height
        frame.SetSize((-1, progress_bar.GetPosition()[1] + progress_bar.GetSize()[1] + 40))

        # Fetch patches
        patches: dict = {}
        def _fetch_patches(self) -> None:
            nonlocal patches
            patches = HardwarePatchsetDetection(constants=self.constants).device_properties

        thread = threading.Thread(target=_fetch_patches, args=(self,))
        thread.start()

        frame.ShowWindowModal()
        gui_support.wait_for_thread(thread)
        frame.Close()

        progress_bar.Hide()
        progress_bar_animation.stop_pulse()
        available_label.Hide()

        # Build custom UI
        current_y = title_label.GetPosition()[1] + title_label.GetSize()[1] + 20

        def add_info_pair(label_text, value_text, y_pos):
            lbl = wx.StaticText(frame, label=label_text, pos=(-1, y_pos))
            lbl.SetFont(gui_support.font_factory(13, wx.FONTWEIGHT_BOLD))
            lbl.Centre(wx.HORIZONTAL)
            y_pos += lbl.GetSize()[1] + 5

            val = wx.StaticText(frame, label=value_text, pos=(-1, y_pos))
            val.SetFont(gui_support.font_factory(13, wx.FONTWEIGHT_NORMAL))
            val.Centre(wx.HORIZONTAL)
            y_pos += val.GetSize()[1] + 15
            return y_pos

        current_y = add_info_pair("Model:", str(self.constants.computer.real_model), current_y)

        t1_status = "DETECTED" if self.constants.computer.t1_chip else "NOT DETECTED"
        current_y = add_info_pair("T1 Security:", t1_status, current_y)

        gpu_status = "NOT DETECTED"
        if self.constants.computer.dgpu:
            for dgpu in self.constants.computer.dgpu:
                if dgpu.arch == getattr(self.constants.computer.dgpu[0].Archs, "Polaris", ""):
                    gpu_status = "DETECTED"
                    break
        # Fallback to general detection if Polaris not explicitly identified but present in patches
        if gpu_status == "NOT DETECTED":
            has_polaris_patch = any("AMD Polaris" in p for p in patches if patches[p] is True)
            if has_polaris_patch:
                gpu_status = "DETECTED"

        current_y = add_info_pair("AMD Polaris:", gpu_status, current_y)

        wifi_status = "NOT DETECTED"
        if self.constants.computer.wifi:
            wifi_status = f"{self.constants.computer.wifi.vendor_name} {self.constants.computer.wifi.vendor_id:04X}:{self.constants.computer.wifi.device_id:04X}"
        current_y = add_info_pair("Wi-Fi:", wifi_status, current_y)

        lbl = wx.StaticText(frame, label="Available Root Patches:", pos=(-1, current_y))
        lbl.SetFont(gui_support.font_factory(13, wx.FONTWEIGHT_BOLD))
        lbl.Centre(wx.HORIZONTAL)
        current_y += lbl.GetSize()[1] + 10

        has_any_patches = False
        for patch in patches:
            if not patch.startswith("Settings") and not patch.startswith("Validation") and patches[patch] is True:
                patch_lbl = wx.StaticText(frame, label=patch.split(": ")[1] if ": " in patch else patch, pos=(-1, current_y))
                patch_lbl.SetFont(gui_support.font_factory(13, wx.FONTWEIGHT_NORMAL))
                patch_lbl.Centre(wx.HORIZONTAL)
                current_y += patch_lbl.GetSize()[1] + 5
                has_any_patches = True

        if not has_any_patches:
            patch_lbl = wx.StaticText(frame, label="None", pos=(-1, current_y))
            patch_lbl.SetFont(gui_support.font_factory(13, wx.FONTWEIGHT_NORMAL))
            patch_lbl.Centre(wx.HORIZONTAL)
            current_y += patch_lbl.GetSize()[1] + 5

        current_y += 15

        start_button = wx.Button(frame, label="APPLY ROOT PATCHES", pos=(10, current_y), size=(200, 30))
        start_button.Bind(wx.EVT_BUTTON, lambda event: self.on_start_root_patching(patches))
        start_button.SetFont(gui_support.font_factory(13, wx.FONTWEIGHT_NORMAL))
        start_button.Centre(wx.HORIZONTAL)
        current_y += start_button.GetSize().height + 5

        # Button: Return to Main Menu
        return_button = wx.Button(frame, label="Return to Main Menu", pos=(10, current_y), size=(180, 30))
        return_button.Bind(wx.EVT_BUTTON, self.on_return_dismiss if self.init_with_parent else self.on_return_to_main_menu)
        return_button.SetFont(gui_support.font_factory(13, wx.FONTWEIGHT_NORMAL))
        return_button.Centre(wx.HORIZONTAL)
        self.return_button = return_button

        if not has_any_patches:
            start_button.Disable()
        else:
            self.available_patches = True
            start_button.SetDefault()

        frame.SetSize((-1, current_y + return_button.GetSize().height + 25))
        frame.ShowWindowModal()
"""

new_content = re.sub(r'    def _generate_elements_display_patches\(self, frame: wx.Frame = None\) -> None:.*?        frame\.ShowWindowModal\(\)\n', new_func, content, flags=re.DOTALL)

with open('opencore_legacy_patcher/wx_gui/gui_sys_patch_display.py', 'w') as f:
    f.write(new_content)
