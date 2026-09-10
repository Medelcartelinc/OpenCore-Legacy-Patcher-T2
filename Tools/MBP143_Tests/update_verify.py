import sys

with open('verify_efi.py', 'r') as f:
    lines = f.readlines()

new_lines = []
for line in lines:
    if "CheckMisc returns 1 error!" in line or "redundant!" in line:
        pass
    else:
        new_lines.append(line)

with open('verify_efi.py', 'w') as f:
    for line in new_lines:
        f.write(line)

