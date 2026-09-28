This pull request imlaments the following changes

* change all AppIcons to `png`, the only `icns` left is the App Icon
* change the refrences from using `icns` to `png`, the only exception is the app icon, which for is left as a `icns` for simplicities sake
* change all the 12 ways to ask for the user's password to one, secure way
* fix an issue where one of the function in invalved in the mounting of the root volume was returning the path instead of a bool, which would ean that the ptching system would think that it hadn't mounted because `/System/Volumes/Update/mnt1` is not `True`. 
