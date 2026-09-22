"""
image_handler.py: handlers the icons for the app
"""
from pathlib import Path


class GetIcon():
    def __init__(self, icon: str):
        self.icon = icon
        self.get_icon()

    def get_icon(self):
        return Path(__file__).parent.parent.parent.resolve()/ Path("payloads") / Path("Resources/AppIcons") / Path(self.icon)
