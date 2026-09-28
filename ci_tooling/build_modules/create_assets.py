from wx.tools.img2py import img2py
import shutil
from pathlib import Path


class AssetsCreator():
    def __init__(self):
        self.generate_python_file()

    def generate_python_file(self):
        self.python_file = "./dist/OpenCore-Patcher-T2.app/Contents/Resources/Assets"
        with open(self.python_file, "w") as f:
            f.writelines([
                "# THIS FILE IS AUTO-GENERATED. DO NOT EDIT!\n",
                "# EDITING MAY RESULT IN SUDDEN TERMINATION OF THE RUNNING KERNEL!!\n",
                "from wx.lib.embeddedimage import PyEmbeddedImage\n"
            ])
        app_icons_dir = Path("payloads/Resources/AppIcons")
        if not app_icons_dir.is_dir():
            raise FileNotFoundError(f"AppIcons directory not found: {app_icons_dir}")
        for file in sorted(app_icons_dir.iterdir()):
            if file.name.startswith("."):
                continue
            if file.name.endswith(".png"):
                # TODO: make this function shut up
                img2py(image_file=str(file), python_file=self.python_file, append=True, compressed=True, maskClr=None, imgName=file.name, icon=False, catalog=True, functionCompatible=False)
                continue
            if file.name.endswith(".car"):
                shutil.copy(src=str(file), dst="./dist/OpenCore-Patcher-T2.app/Contents/Resources/")
if __name__ == "__main__":
    AssetsCreator()
