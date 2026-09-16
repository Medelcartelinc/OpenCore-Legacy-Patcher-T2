import tempfile
import subprocess
import os

with tempfile.TemporaryDirectory() as work_dir:
    print(f"Created {work_dir}")
    # Simulate run_as_root creating a root-owned file
    subprocess.run(["sudo", "touch", os.path.join(work_dir, "root_file")])
print("Done")
