"""
hash.py: creates a hash for the PKGs using hashlib and saves them to certificates.txt
"""

import hashlib
import rich
from pathlib import Path


class GenerateHash():
    def __init__(self):
        self.start()

    def start(self):
        file_dump= ["Resource certificates:"]
        sha256 = hashlib.sha256()
        for pkg in Path("./dist/").glob("*.pkg"):
            with open(pkg, "rb") as file:
                while chunk := file.read(8192):
                    sha256.update(chunk)

            file_hash = sha256.hexdigest()
            file_dump.append(f"{str(pkg).removeprefix('/dist/')}: {file_hash}")
            rich.print(f"{str(pkg).removeprefix('/dist/')}: {file_hash}")

        with open("./dist/certificates.txt", "w") as f:
            f.write("\n".join(file_dump))
        